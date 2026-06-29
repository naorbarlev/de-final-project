import pyspark.sql.types as T

ALERT_SCHEMA = T.StructType([
    T.StructField("alert_id", T.StringType(), True),
    T.StructField("log_uid", T.StringType(), True),
    T.StructField("alert_type", T.StringType(), True),
    T.StructField("severity", T.StringType(), True),
    T.StructField("alert_ts", T.TimestampType(), True),
    T.StructField("event_ts", T.TimestampType(), True),
    T.StructField("orig_ip", T.StringType(), True),
    T.StructField("resp_ip", T.StringType(), True),
    T.StructField("ioc_score", T.IntegerType(), True),
    T.StructField("ioc_source", T.ArrayType(T.StringType()), True),
    T.StructField("ioc_value", T.ArrayType(T.StringType()), True),
    T.StructField("tags", T.ArrayType(T.StringType()), True)
])

CONN_SCHEMA = T.StructType([
    T.StructField("@path", T.StringType(), True),
    T.StructField("sensor_name", T.StringType(), True),
    T.StructField("ts", T.TimestampType(), True),
    T.StructField("uid", T.StringType(), True),
    T.StructField("id.orig_h", T.StringType(), True),
    T.StructField("id.orig_p", T.IntegerType(), True),
    T.StructField("id.resp_h", T.StringType(), True),
    T.StructField("id.resp_p", T.IntegerType(), True),
    T.StructField("proto", T.StringType(), True),
    T.StructField("service", T.StringType(), True),
    T.StructField("duration", T.DoubleType(), True),
    T.StructField("orig_bytes", T.LongType(), True),
    T.StructField("resp_bytes", T.LongType(), True),
    T.StructField("conn_state", T.StringType(), True),
    T.StructField("local_orig", T.BooleanType(), True),
    T.StructField("local_resp", T.BooleanType(), True),
    T.StructField("missed_bytes", T.LongType(), True),
    T.StructField("history", T.StringType(), True),
    T.StructField("orig_pkts", T.LongType(), True),
    T.StructField("orig_ip_bytes", T.LongType(), True),
    T.StructField("resp_pkts", T.LongType(), True),
    T.StructField("resp_ip_bytes", T.LongType(), True),
    T.StructField("tunnel_parents", T.ArrayType(T.StringType()), True),
    T.StructField("orig_l2_addr", T.StringType(), True),
    T.StructField("resp_l2_addr", T.StringType(), True),
    T.StructField("orig_cc", T.StringType(), True),
    T.StructField("resp_cc", T.StringType(), True),
    T.StructField("community_id", T.StringType(), True),
    T.StructField("notice", T.StringType(), True),
])

HTTP_SCHEMA = T.StructType([
    T.StructField("@path", T.StringType(), True),
    T.StructField("sensor_name", T.StringType(), True),
    T.StructField("ts", T.TimestampType(), True),
    T.StructField("uid", T.StringType(), True),
    T.StructField("id.orig_h", T.StringType(), True),
    T.StructField("id.orig_p", T.IntegerType(), True),
    T.StructField("id.resp_h", T.StringType(), True),
    T.StructField("id.resp_p", T.IntegerType(), True),
    T.StructField("trans_depth", T.IntegerType(), True),
    T.StructField("method", T.StringType(), True),
    T.StructField("host", T.StringType(), True),
    T.StructField("uri", T.StringType(), True),
    T.StructField("referrer", T.StringType(), True),
    T.StructField("version", T.StringType(), True),
    T.StructField("user_agent", T.StringType(), True),
    T.StructField("request_body_len", T.LongType(), True),
    T.StructField("response_body_len", T.LongType(), True),
    T.StructField("status_code", T.IntegerType(), True),
    T.StructField("status_msg", T.StringType(), True),
    T.StructField("tags", T.ArrayType(T.StringType()), True),
    T.StructField("proxied", T.ArrayType(T.StringType()), True),
    T.StructField("orig_fuids", T.ArrayType(T.StringType()), True),
    T.StructField("orig_filenames", T.ArrayType(T.StringType()), True),
    T.StructField("orig_mime_types", T.ArrayType(T.StringType()), True),
    T.StructField("resp_fuids", T.ArrayType(T.StringType()), True),
    T.StructField("resp_filenames", T.ArrayType(T.StringType()), True),
    T.StructField("resp_mime_types", T.ArrayType(T.StringType()), True),
])

DNS_SCHEMA = T.StructType([
    T.StructField("@path", T.StringType(), True),
    T.StructField("sensor_name", T.StringType(), True),
    T.StructField("ts", T.TimestampType(), True),
    T.StructField("uid", T.StringType(), True),
    T.StructField("id.orig_h", T.StringType(), True),
    T.StructField("id.orig_p", T.IntegerType(), True),
    T.StructField("id.resp_h", T.StringType(), True),
    T.StructField("id.resp_p", T.IntegerType(), True),
    T.StructField("proto", T.StringType(), True),
    T.StructField("trans_id", T.IntegerType(), True),
    T.StructField("rtt", T.DoubleType(), True),
    T.StructField("query", T.StringType(), True),
    T.StructField("qclass", T.IntegerType(), True),
    T.StructField("qclass_name", T.StringType(), True),
    T.StructField("qtype", T.IntegerType(), True),
    T.StructField("qtype_name", T.StringType(), True),
    T.StructField("rcode", T.IntegerType(), True),
    T.StructField("rcode_name", T.StringType(), True),
    T.StructField("AA", T.BooleanType(), True),
    T.StructField("TC", T.BooleanType(), True),
    T.StructField("RD", T.BooleanType(), True),
    T.StructField("RA", T.BooleanType(), True),
    T.StructField("Z", T.IntegerType(), True),
    T.StructField("answers", T.ArrayType(T.StringType()), True),
    T.StructField("TTLs", T.ArrayType(T.IntegerType()), True),
    T.StructField("rejected", T.BooleanType(), True),
])


def _merge_schemas(*schemas):
    merged_fields = []
    seen_names = set()

    for schema in schemas:
        for field in schema.fields:
            if field.name not in seen_names:
                seen_names.add(field.name)
                merged_fields.append(field)

    return T.StructType(merged_fields)


WIDE_SCHEMA = _merge_schemas(CONN_SCHEMA, HTTP_SCHEMA, DNS_SCHEMA)