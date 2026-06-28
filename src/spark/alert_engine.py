
from pathlib import Path
import sys
from datetime import datetime, timedelta
from pyspark.sql import DataFrame, SparkSession
import pyspark.sql.functions as F
import pyspark.sql.types as T
import os
import dotenv

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from logger import get_logger

dotenv.load_dotenv()
logger = get_logger(__name__)


NETWORK_LOGS_TOPIC = os.getenv("NETWORK_LOGS_TOPIC")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC")
KAFKA_BROKER = os.getenv("KAFKA_BROKER")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
CLEAN_IOCS_PARQUET_FILES = os.getenv("CLEAN_IOCS_PARQUET_FILES")
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")


def port_scan_detection(batch_df: DataFrame) -> DataFrame:
    pass

def data_exfiltration_detection(batch_df: DataFrame) -> DataFrame:
    pass

def ioc_match_detection(batch_df: DataFrame, ioc_df: DataFrame) -> DataFrame:
    matched_df = batch_df.select("orig, resp").drop_duplicates().join(
        ioc_df.alias("iocs"),
        on=F.col("resp") == F.col("iocs.ip"),
        how="inner"
    ).select("iocs.*", "resp", "orig")
    
    matched_df = matched_df.withColumn("alert_type", F.lit("IOC Match")).withColumn("severity", F.lit("High")).withColumn("timestamp", F.current_timestamp())
    
    pass

def load_ioc_db(spark: SparkSession) -> DataFrame:
    return spark.read.parquet(f"s3a://{BUCKET_NAME}/{CLEAN_IOCS_PARQUET_FILES}/")


if __name__ == "__main__":
    # Initialize Spark Session
    spark = SparkSession.builder \
        .appName("KafkaToKafkaStreaming") \
        .getOrCreate()
        
    sc = spark.sparkContext
    sc.setLogLevel("ERROR")
    hadoop_conf = sc._jsc.hadoopConfiguration()

    # Core MinIO server connection parameters
    hadoop_conf.set("fs.s3a.endpoint", MINIO_ENDPOINT) # Update with your MinIO host & API port
    hadoop_conf.set("fs.s3a.access.key", MINIO_ACCESS_KEY)
    hadoop_conf.set("fs.s3a.secret.key", MINIO_SECRET_KEY)

    hadoop_conf.set("fs.s3a.path.style.access", "true")
    hadoop_conf.set("fs.s3a.connection.ssl.enabled", "false") # Set true if your MinIO has SSL certificates
    hadoop_conf.set("fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
    
    # Read stream from Kafka
    df = spark.readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("subscribe", NETWORK_LOGS_TOPIC) \
        .option("startingOffsets", "latest") \
        .load()

    ioc_df = load_ioc_db(spark=spark)
    
    transformed_df = df.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)")

    # Write stream to Kafka
    query = transformed_df.writeStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("topic", ALERTS_TOPIC) \
        .option("checkpointLocation", "TODO") \
        .start()

    query.awaitTermination()