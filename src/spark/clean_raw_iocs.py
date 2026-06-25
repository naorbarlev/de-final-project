from pathlib import Path
import sys
from datetime import timedelta

from pyspark.sql import DataFrame, SparkSession
import pyspark.sql.functions as F
import pyspark.sql.types as T
import os
from minio import Minio
import json
import dotenv

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from utils import read_watermark_date, write_watermark_date

dotenv.load_dotenv()
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")
RAW_IOCS_FOLDER_NAME = os.getenv("RAW_IOCS_FOLDER_NAME")
CLEAN_IOCS_FOLDER_NAME = os.getenv("CLEAN_IOCS_FOLDER_NAME")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
last_processed_date_object_name = "last_processed_date.txt"


def find_new_iocs(current_df: DataFrame, clean_incremental_batch: DataFrame) -> DataFrame:
    '''Find new IOCs by performing a left anti join between the current DataFrame and the clean incremental batch.'''
    new_iocs_df = clean_incremental_batch.join(current_df, on="id", how="left_anti")
    
    if not new_iocs_df.isEmpty():
        print(f"Found {new_iocs_df.count()} new IOCs.")
        return new_iocs_df
    else:
        print("No new IOCs found.")
        return spark.createDataFrame([], clean_incremental_batch.schema)


def update_last_seen_column(current_df: DataFrame, clean_incremental_batch: DataFrame) -> DataFrame:
    '''Update the last_seen column in the current DataFrame based on the clean incremental batch.'''
    updated_df = current_df.alias("current").join(
        clean_incremental_batch.alias("incremental"),
        on="id",
        how="left"
    ).withColumn(
        "last_seen",
        F.when(
            F.col("incremental.last_seen").isNotNull(),
            F.greatest(F.col("current.last_seen"), F.col("incremental.last_seen"))
        ).otherwise(F.col("current.last_seen"))
    ).select("current.*")  # Select only columns from the current DataFrame

    return updated_df


def clean_iocs(df: DataFrame) -> DataFrame:
    
    df = (
        df.withColumn("reporter", F.when(F.col("reporter") == "anonymous", None).otherwise(F.col("reporter")))
        .withColumn("last_seen", F.when(F.col("last_seen").isNull(), F.col("first_seen")).otherwise(F.col("last_seen")))
        .withColumn("first_seen", F.to_timestamp(F.trim(F.regexp_replace(F.col("first_seen"), "UTC", "")), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("last_seen", F.to_timestamp(F.trim(F.regexp_replace(F.col("last_seen"), "UTC", "")), "yyyy-MM-dd HH:mm:ss"))
        .withColumn("first_seen", F.timestamp_add("HOUR", F.col("first_seen"), 3)) # Adjusting for UTC+3 timezone
        .withColumn("last_seen", F.timestamp_add("HOUR", F.col("last_seen"), 3)) # Adjusting for UTC+3 timezone
        .withColumn("reference", F.when(F.col("reference") == "", None).otherwise(F.col("reporter")))
        .withColumn("id", F.sha2(F.col("ioc"), 256))
    )

    return df


def save_clean_iocs(df):
    pass

if __name__ == "__main__":
    
    spark = SparkSession.builder.appName("CleanRawIOCs").getOrCreate()
    # Configure Hadoop properties to establish connection to MinIO
    sc = spark.sparkContext
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
    if not last_processed_date:
        print("No watermark found. Processing all available IOCs.")
        
    next_date = last_processed_date + timedelta(days=1) if last_processed_date else None
    
    # 2. Read the root path (Spark automatically identifies year, month, day columns)
    df = spark.read.json(f"s3a://{BUCKET_NAME}/{RAW_IOCS_FOLDER_NAME}/")
    
    # 3. Create a temporary date column from partitions and filter
    df_with_date = df.withColumn("folder_date", F.to_date(F.concat_ws("-", "year", "month", "day"), "yyyy-MM-dd"))
    incremental_batch = df_with_date.filter(F.col("folder_date") > F.lit(next_date))
    
    # 4. Process and rewrite the watermark based on the data actually read
    if not incremental_batch.isEmpty():
        
        current_df = spark.read.parquet(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_FOLDER_NAME}/")
        
        clean_incremental_batch = clean_iocs(incremental_batch)
        new_iocs_df = find_new_iocs(current_df, clean_incremental_batch)
        current_df = update_last_seen_column(current_df, clean_incremental_batch)
        union_df = new_iocs_df.union(current_df)
        
        # Save the snapshot replacement data
        union_df.write.mode("overwrite").parquet(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_FOLDER_NAME}/")
        
        # Find the maximum date present in this batch processing run
        max_date = incremental_batch.select(F.max("folder_date")).collect()[0][0]
        new_watermark_str = str(max_date)
        
        # Overwrite the watermark file
        write_watermark_date(client, BUCKET_NAME, f"{CLEAN_IOCS_FOLDER_NAME}/{last_processed_date_object_name}", max_date)
            
        print(f"Watermark advanced to: {new_watermark_str}")
    else:
        print("No new partition data detected.")
    

