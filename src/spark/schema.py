import pyspark.sql.types as T

ALERT_SCHEMA = T.StructType([
    T.StructField("alert_id", T.StringType(), True),
    T.StructField("alert_type", T.StringType(), True),
    T.StructField("severity", T.StringType(), True),
    T.StructField("timestamp", T.TimestampType(), True),
    T.StructField("segment", T.StringType(), True),
    T.StructField("src_ip", T.StringType(), True),
    T.StructField("resp_ip", T.StringType(), True),
    T.StructField("ioc_source", T.StringType(), True),
    T.StructField("ioc_value", T.StringType(), True),
    T.StructField("description", T.StringType(), True)
])
CONN_SCHEMA = None
HTTP_SCHEMA = None
DNS_SCHEMA = None