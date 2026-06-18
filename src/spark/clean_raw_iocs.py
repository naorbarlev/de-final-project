from datetime import timedelta

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
import pyspark.sql.types as T
import os
from minio import Minio
import json
import dotenv
from utils import read_watermark_date

dotenv.load_dotenv()
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")
RAW_IOCS_FOLDER_NAME = os.getenv("RAW_IOCS_FOLDER_NAME")
CLEAN_IOCS_FOLDER_NAME = os.getenv("CLEAN_IOCS_FOLDER_NAME")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
last_processed_date_object_name = "last_processed_date.txt"


def load_iocs(last_processed_date):
    pass


def clean_iocs(df):
    pass


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
    df = spark.read.json(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_FOLDER_NAME}/")
    
    # 3. Create a temporary date column from partitions and filter
    df_with_date = df.withColumn("folder_date", F.to_date(F.concat_ws("-", "year", "month", "day"), "yyyy-MM-dd"))
    incremental_batch = df_with_date.filter(F.col("folder_date") > F.lit(next_date))
    
    # 4. Process and rewrite the watermark based on the data actually read
    if not incremental_batch.isEmpty():
        
        # Save the batch data
        incremental_batch.write.mode("append").parquet("s3a://my-bucket/output/processed_data/")
        
        # Find the maximum date present in this batch processing run
        max_date = incremental_batch.select(F.max("folder_date")).collect()[0][0]
        new_watermark_str = str(max_date)
        
        # Overwrite the watermark file
        pass
            
        print(f"Watermark advanced to: {new_watermark_str}")
    else:
        print("No new partition data detected.")
    
    raw_iocs_df = load_iocs(last_processed_date)
    clean_iocs_df = clean_iocs(raw_iocs_df)
    save_clean_iocs(clean_iocs_df)


