from pathlib import Path
import sys
from datetime import datetime, timedelta
from pyspark.sql import DataFrame, SparkSession
import pyspark.sql.functions as F
import pyspark.sql.types as T
import os
from minio import Minio
import dotenv

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from utils import read_watermark_date, write_watermark_date
from logger import get_logger

dotenv.load_dotenv()
logger = get_logger(__name__)


API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")
RAW_IOCS_FOLDER_NAME = os.getenv("RAW_IOCS_FOLDER_NAME")
CLEAN_IOCS_FOLDER_NAME = os.getenv("CLEAN_IOCS_FOLDER_NAME")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
CLEAN_IOCS_PARQUET_FILES = os.getenv("CLEAN_IOCS_PARQUET_FILES")
last_processed_date_object_name = "last_processed_date.txt"


def find_new_iocs(current_df: DataFrame, clean_incremental_batch: DataFrame) -> DataFrame:
    '''Find new IOCs by performing a left anti join between the current DataFrame and the clean incremental batch.'''
    new_iocs_df = clean_incremental_batch.join(current_df, on="id", how="left_anti")
    
    if not new_iocs_df.isEmpty():
        logger.info(f"Found {new_iocs_df.count()} new IOCs.")
        return new_iocs_df
    else:
        logger.info("No new IOCs found.")
        return spark.createDataFrame([], clean_incremental_batch.schema)



def update_last_seen_column(current_df: DataFrame, clean_incremental_batch: DataFrame) -> DataFrame:
    '''Update the last_seen column in the current DataFrame based on the clean incremental batch.'''
    
    # Isolate the ID and last_seen from the new data, renaming it to avoid overlap
    inc_df = clean_incremental_batch.select("id", F.col("last_seen").alias("inc_last_seen"))
    
    # Join and dynamically update the core last_seen column
    updated_df = current_df.join(
        inc_df,
        on="id",
        how="left"
    ).withColumn(
        "last_seen",
        F.when(
            F.col("inc_last_seen").isNotNull(),
            F.greatest(F.col("last_seen"), F.col("inc_last_seen"))
        ).otherwise(F.col("last_seen"))
    ).drop("inc_last_seen")

    return updated_df


def clean_iocs(df: DataFrame) -> DataFrame:
    
    df = (
        df.withColumn("dict", F.explode(F.col("data")))
        .select("dict.*")
        .withColumn("reporter", F.when(F.col("reporter") == "anonymous", None).otherwise(F.col("reporter")))
        .withColumn("last_seen", F.when(F.col("last_seen").isNull(), F.col("first_seen")).otherwise(F.col("last_seen")))
        .withColumn("first_seen", F.to_timestamp(F.trim(F.regexp_replace(F.col("first_seen"), "UTC", "")), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("last_seen", F.to_timestamp(F.trim(F.regexp_replace(F.col("last_seen"), "UTC", "")), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("first_seen", F.expr("timestampadd(HOUR, 3, first_seen)"))# Adjusting for UTC+3 timezone 
        .withColumn("last_seen", F.expr("timestampadd(HOUR, 3, last_seen)")) # Adjusting for UTC+3 timezone
        .withColumn("reference", F.when(F.col("reference") == "", None).otherwise(F.col("reporter")))
        .withColumn("id", F.sha2(F.col("ioc"), 256))
        .withColumn("confidence_level", F.col("confidence_level").cast(T.IntegerType()))
        .drop("dict", "data", "query_status", "year", "month", "day", "folder_date")
    )
    return df


def save_clean_iocs(df):
    pass

if __name__ == "__main__":
    
    spark = SparkSession.builder.appName("CleanRawIOCs").getOrCreate()
    # Configure Hadoop properties to establish connection to MinIO
    sc = spark.sparkContext
    sc.setLogLevel("ERROR")
    hadoop_conf = sc._jsc.hadoopConfiguration()

    # Core MinIO server connection parameters
    hadoop_conf.set("fs.s3a.endpoint", MINIO_ENDPOINT) # Update with your MinIO host & API port
    hadoop_conf.set("fs.s3a.access.key", MINIO_ACCESS_KEY)
    hadoop_conf.set("fs.s3a.secret.key", MINIO_SECRET_KEY)

    # Essential path style and SSL tweaks for standalone MinIO setups
    hadoop_conf.set("fs.s3a.path.style.access", "true")
    hadoop_conf.set("fs.s3a.connection.ssl.enabled", "false") # Set true if your MinIO has SSL certificates
    hadoop_conf.set("fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
    

    # Connect to MinIO
    client = Minio(
        endpoint=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
    
    last_processed_date = read_watermark_date(client, BUCKET_NAME, f"{CLEAN_IOCS_FOLDER_NAME}/{last_processed_date_object_name}")
    # Determine the write mode based on whether there's a last processed date
    write_mode = "append" if last_processed_date else "overwrite"
    logger.info(f"Last processed date: {last_processed_date}, Write mode: {write_mode}")
    
    if not last_processed_date:
        logger.info("No watermark found. Assuming this is the first run. Processing all available data.")
        last_processed_date = datetime(1970, 1, 1)  # Set to epoch start for first run

    # Determine the next date to process based on the last processed date
    next_date = last_processed_date + timedelta(days=1) if last_processed_date else None
    
    # Read the raw IOCs data from MinIO
    raw_iocs_data_frame = spark.read.json(f"s3a://{BUCKET_NAME}/{RAW_IOCS_FOLDER_NAME}/")
    
    # Add a new column to the DataFrame that represents the date of each record based on its year, month, and day fields.
    # Then filter the DataFrame to only include records that are newer than the next date to process.
    df_with_date = raw_iocs_data_frame.withColumn("folder_date", F.make_date(F.col("year"), F.col("month"), F.col("day")))
    incremental_batch = df_with_date.filter(F.col("folder_date") > F.lit(next_date))
    
    if not incremental_batch.isEmpty():
        
        if write_mode == "append":
            logger.info("Appending new clean IOCs data.")
            current_df = spark.read.parquet(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_PARQUET_FILES}/")
            clean_incremental_batch = clean_iocs(incremental_batch)
            new_iocs_df = find_new_iocs(current_df, clean_incremental_batch)
            current_df = update_last_seen_column(current_df, clean_incremental_batch)
            union_df = new_iocs_df.union(current_df)
            
        if write_mode == "overwrite":
            logger.info("Overwriting clean IOCs data.")
            union_df = clean_iocs(incremental_batch)
        
        # Save the snapshot replacement data
        union_df.write.mode(write_mode).parquet(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_PARQUET_FILES}/")
        
        # Find the maximum date present in this batch processing run
        max_date = incremental_batch.select(F.max("folder_date")).collect()[0][0]
        new_watermark_str = str(max_date)
        
        # Overwrite the watermark file
        write_watermark_date(client, BUCKET_NAME, f"{CLEAN_IOCS_FOLDER_NAME}/{last_processed_date_object_name}", max_date)
            
        logger.info(f"Watermark advanced to: {new_watermark_str}")
        spark.stop()
    else:
        logger.info("No new partition data detected.")
        spark.stop()
    

