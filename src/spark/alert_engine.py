
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
from schema import ALERT_SCHEMA, CONN_SCHEMA, HTTP_SCHEMA, DNS_SCHEMA, WIDE_SCHEMA

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
MAX_PORT_THRESHOLD = 10
DATA_EXFIl_THRESHOLD = 100_000_000 #Bytes


def port_scan_detection(batch_df: DataFrame) -> DataFrame:
    scan_counts = (
        batch_df.withWatermark("ts", "10 minutes")
        .groupBy(F.window(F.col("ts"), "1 minute"), F.col("id.orig_h"), F.col("id.resp_h"))
        .agg(
            F.countDistinct(F.col("id.resp_p")).alias("port_count"),
            F.first("uid").alias("log_uid"),
            F.min("ts").alias("event_ts")
        )
    )

    alerts_df = scan_counts.filter(F.col("port_count") > MAX_PORT_THRESHOLD)

    alerts_df = alerts_df.withColumn("alert_type", F.lit("Port Scan"))
    alerts_df = alerts_df.withColumn(
        "severity",
        F.when(F.col("port_count") > MAX_PORT_THRESHOLD * 1.5, F.lit("High")).otherwise(F.lit("Medium"))
    )
    alerts_df = alerts_df.withColumn("alert_ts", F.current_timestamp())
    alerts_df = alerts_df.withColumn(
        "alert_id",
        F.sha2(
            F.concat(
                F.col("alert_ts"),
                F.col("log_uid"),
                F.col("id.orig_h"),
                F.col("id.resp_h")
            ),
            256
        )
    )
    alerts_df = alerts_df.withColumn("ioc_score", F.lit(None).cast(T.IntegerType()))
    alerts_df = alerts_df.withColumn("ioc_source", F.array_repeat(F.lit(None).cast(T.StringType()), 0))
    alerts_df = alerts_df.withColumn("ioc_value", F.array_repeat(F.lit(None).cast(T.StringType()), 0))
    alerts_df = alerts_df.withColumn("tags", F.array(F.lit("port_scan")))

    return alerts_df.select(
        "alert_id",
        "log_uid",
        "alert_type",
        "severity",
        "alert_ts",
        "event_ts",
        F.col("id.orig_h").alias("orig_ip"),
        F.col("id.resp_h").alias("resp_ip"),
        "ioc_score",
        "ioc_source",
        "ioc_value",
        "tags"
    )

def data_exfiltration_detection(batch_df: DataFrame, ioc_df: DataFrame) -> DataFrame:
    normalized_ioc_df = preper_ioc_df(ioc_df)

    ioc_enrichment = (
        batch_df.alias("raw")
        .join(
            normalized_ioc_df.alias("iocs"),
            on=(F.col("raw.id.resp_h") == F.col("iocs.ioc_for_match"))
            | (F.col("raw.id.orig_h") == F.col("iocs.ioc_for_match"))
            | (F.col("raw.query") == F.col("iocs.ioc_for_match"))
            | (F.col("raw.host") == F.col("iocs.ioc_for_match")),
            how="left"
        )
        .groupBy(F.window(F.col("raw.ts"), "2 minute"), F.col("raw.id.orig_h"), F.col("raw.id.resp_h"))
        .agg(
            F.collect_set(F.when(F.col("ioc").isNotNull(), F.col("ioc"))).alias("ioc_value"),
            F.collect_set(F.when(F.col("reporter").isNotNull(), F.col("reporter"))).alias("ioc_source"),
            F.max(F.when(F.col("confidence_level").isNotNull(), F.col("confidence_level"))).alias("ioc_score")
        )
    )

    exfil_summary = (
        batch_df.withWatermark("ts", "10 minutes")
        .groupBy(F.window(F.col("ts"), "2 minute"), F.col("id.orig_h"), F.col("id.resp_h"))
        .agg(
            F.sum(F.col("orig_bytes")).alias("total_orig_bytes"),
            F.first("uid").alias("log_uid"),
            F.min("ts").alias("event_ts")
        )
    )

    alerts_df = exfil_summary.alias("summary").join(
        ioc_enrichment.alias("ioc"),
        on=(F.col("summary.window") == F.col("ioc.window"))
        & (F.col("summary.id.orig_h") == F.col("ioc.id.orig_h"))
        & (F.col("summary.id.resp_h") == F.col("ioc.id.resp_h")),
        how="left"
    )

    alerts_df = alerts_df.filter(F.col("total_orig_bytes") > DATA_EXFIl_THRESHOLD)
    alerts_df = alerts_df.withColumn("alert_type", F.lit("Data Exfiltration"))
    alerts_df = alerts_df.withColumn(
        "severity",
        F.when(F.col("total_orig_bytes") > DATA_EXFIl_THRESHOLD * 2, F.lit("High")).otherwise(F.lit("Medium"))
    )
    alerts_df = alerts_df.withColumn("alert_ts", F.current_timestamp())
    alerts_df = alerts_df.withColumn(
        "alert_id",
        F.sha2(
            F.concat(
                F.col("alert_ts"),
                F.col("log_uid"),
                F.col("summary.id.orig_h"),
                F.col("summary.id.resp_h")
            ),
            256
        )
    )
    alerts_df = alerts_df.withColumn("ioc_score", F.col("ioc.ioc_score"))
    alerts_df = alerts_df.withColumn("ioc_source", F.coalesce(F.col("ioc.ioc_source"), F.array()))
    alerts_df = alerts_df.withColumn("ioc_value", F.coalesce(F.col("ioc.ioc_value"), F.array()))
    alerts_df = alerts_df.withColumn("tags", F.array(F.lit("data_exfiltration")))

    return alerts_df.select(
        "alert_id",
        "log_uid",
        "alert_type",
        "severity",
        "alert_ts",
        "event_ts",
        F.col("summary.id.orig_h").alias("orig_ip"),
        F.col("summary.id.resp_h").alias("resp_ip"),
        "ioc_score",
        "ioc_source",
        "ioc_value",
        "tags"
    )


def preper_ioc_df(ioc_df: DataFrame) -> DataFrame:
     # Normalize IOC matching values so we can match by IP, domain, and answer text.
    normalized_ioc_df = ioc_df.withColumn(
        "ioc_for_match",
        F.when(F.col("ioc_type") == "ip:port", F.split(F.col("ioc"), ":")[0])
         .when(F.col("ioc_type") == "url", F.regexp_extract(F.col("ioc"), r"(?:https?://)?([^/]+)", 1))
         .otherwise(F.col("ioc"))
    )
    return normalized_ioc_df

def ioc_match_detection(batch_df: DataFrame, ioc_df: DataFrame) -> DataFrame:
    
   
    normalized_ioc_df = preper_ioc_df(ioc_df)

    event_df = (
        batch_df.withColumn("answer", F.explode_outer(F.col("answers")))
        .select(
            F.col("uid"),
            F.col("ts"),
            F.col("id.orig_h").alias("orig_ip"),
            F.col("id.resp_h").alias("resp_ip"),
            F.col("query"),
            F.col("answer"),
            F.col("host")
        )
        .drop_duplicates()
    )

    match_condition = (
        (F.col("resp_ip") == F.col("ioc_for_match"))
        | (F.col("query") == F.col("ioc_for_match"))
        | (F.col("answer") == F.col("ioc_for_match"))
        | (F.col("host") == F.col("ioc_for_match"))
    )

    matched_df = event_df.alias("events").join(
        normalized_ioc_df.alias("iocs"),
        on=match_condition,
        how="inner"
    )

    aggregated_df = matched_df.groupBy("uid").agg(
        F.first("uid").alias("log_uid"),
        F.first("resp_ip").alias("resp_ip"),
        F.first("orig_ip").alias("orig_ip"),
        F.first("ts").alias("event_ts"),
        F.array_distinct(F.flatten(F.collect_list("tags"))).alias("tags"),
        F.collect_set("ioc").alias("ioc_value"),
        F.collect_set("reporter").alias("ioc_source"),
        F.max("confidence_level").alias("ioc_score"),
        F.max(F.when(F.col("is_compromised"), 1).otherwise(0)).cast(T.BooleanType()).alias("is_compromised")
    )

    aggregated_df = aggregated_df.withColumn("alert_type", F.lit("IOC Match"))
    aggregated_df = aggregated_df.withColumn(
        "severity",
        F.when(F.col("is_compromised"), F.lit("High")).otherwise(F.lit("Medium"))
    )
    aggregated_df = aggregated_df.withColumn("alert_ts", F.current_timestamp())
    aggregated_df = aggregated_df.withColumn(
        "alert_id",
        F.sha2(F.concat(F.col("alert_ts"), F.col("log_uid"), F.col("resp_ip")), 256)
    )

    return aggregated_df.select(
        "alert_id",
        "log_uid",
        "alert_type",
        "severity",
        "alert_ts",
        "event_ts",
        "orig_ip",
        "resp_ip",
        "ioc_score",
        "ioc_source",
        "ioc_value",
        "tags"
    )


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
    
    # TODO: Check if new iocs are available in the parquet files and load them into a DataFrame
    ioc_df = load_ioc_db(spark=spark)
    
    # Read stream from Kafka
    df = spark.readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("subscribe", NETWORK_LOGS_TOPIC) \
        .option("startingOffsets", "latest") \
        .load()

    parsed_df = df \
        .selectExpr("CAST(value AS STRING) as json_str") \
        .select(F.from_json(F.col("json_str"), WIDE_SCHEMA).alias("data")) \
        .select("data.*")
    
    ioc_match_alert_df = ioc_match_detection(parsed_df, ioc_df)
    port_scan_alert_df = port_scan_detection(parsed_df)
    
    
    alerts_df = SparkSession.createDataFrame([], schema=ALERT_SCHEMA)

    # Write stream to Kafka
    query = alerts_df.writeStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("topic", ALERTS_TOPIC) \
        .option("checkpointLocation", "TODO") \
        .start()

    query.awaitTermination()