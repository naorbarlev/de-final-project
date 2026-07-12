import sys
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import os
import dotenv
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from logger import get_logger
from utils import wait_for_elasticsearch, consume_from_kafka_and_send_to_es, es_index_get_or_create

logger = get_logger(__name__)
dotenv.load_dotenv()

KAFKA_BROKER = os.getenv('KAFKA_BROKER')
NETWORK_LOGS_TOPIC = os.getenv('NETWORK_LOGS_TOPIC')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'elasticsearch')
mapping = {
            "mappings": {
                "properties": {
                    "@path": {"type": "keyword"},
                    "sensor_name": {"type": "keyword"},
                    "ts": {"type": "date", "format": "strict_date_optional_time_nanos"},
                    "uid": {"type": "keyword"},
                    "id.orig_h": {"type": "ip"},
                    "id.orig_p": {"type": "integer"},
                    "id.resp_h": {"type": "ip"},
                    "id.resp_p": {"type": "integer"},
                    "proto": {"type": "keyword"},
                    "service": {"type": "keyword"},
                    "duration": {"type": "double"},
                    "orig_bytes": {"type": "long"},
                    "resp_bytes": {"type": "long"},
                    "conn_state": {"type": "keyword"},
                    "local_orig": {"type": "boolean"},
                    "local_resp": {"type": "boolean"},
                    "missed_bytes": {"type": "long"},
                    "history": {"type": "keyword"},
                    "orig_pkts": {"type": "integer"},
                    "orig_ip_bytes": {"type": "long"},
                    "resp_pkts": {"type": "integer"},
                    "resp_ip_bytes": {"type": "long"},
                    "tunnel_parents": {"type": "keyword"},
                    "orig_l2_addr": {"type": "keyword"},
                    "resp_l2_addr": {"type": "keyword"},
                    "orig_cc": {"type": "keyword"},
                    "resp_cc": {"type": "keyword"},
                    "community_id": {"type": "keyword"},
                    "notice": {"type": "keyword"},
                    "trans_id": {"type": "integer"},
                    "rtt": {"type": "double"},
                    "query": {"type": "keyword"},
                    "qclass": {"type": "integer"},
                    "qclass_name": {"type": "keyword"},
                    "qtype": {"type": "integer"},
                    "qtype_name": {"type": "keyword"},
                    "rcode": {"type": "integer"},
                    "rcode_name": {"type": "keyword"},
                    "AA": {"type": "boolean"},
                    "TC": {"type": "boolean"},
                    "RD": {"type": "boolean"},
                    "RA": {"type": "boolean"},
                    "Z": {"type": "integer"},
                    "answers": {"type": "ip"},
                    "TTLs": {"type": "integer"},
                    "rejected": {"type": "boolean"},
                    "trans_depth": {"type": "integer"},
                    "method": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "uri": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword", "ignore_above": 256}
                        }
                    },
                    "referrer": {"type": "keyword"},
                    "version": {"type": "keyword"},
                    "user_agent": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword", "ignore_above": 256}
                        }
                    },
                    "request_body_len": {"type": "long"},
                    "response_body_len": {"type": "long"},
                    "status_code": {"type": "integer"},
                    "status_msg": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "proxied": {"type": "keyword"},
                    "orig_fuids": {"type": "keyword"},
                    "orig_filenames": {"type": "keyword"},
                    "orig_mime_types": {"type": "keyword"},
                    "resp_fuids": {"type": "keyword"},
                    "resp_filenames": {"type": "keyword"},
                    "resp_mime_types": {"type": "keyword"}
                }
            }
        }

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': 9200, 'scheme': 'http'}])
es_index = os.getenv('ELASTICSEARCH_NETWORK_LOGS_INDEX')

if __name__ == "__main__":
    # Ensure Elasticsearch is up before proceeding
    logger.info(f"Waiting for Elasticsearch at {ELASTICSEARCH_HOST}:9200...")
    try:
        wait_for_elasticsearch(es)
    except RuntimeError as e:
        logger.error(f"ERROR: {e}")
        raise

    # create Kafka consumer after ES is available
    consumer = KafkaConsumer(NETWORK_LOGS_TOPIC, bootstrap_servers=KAFKA_BROKER)

    es_index_get_or_create(es, es_index, mapping)
    consume_from_kafka_and_send_to_es(consumer, es, es_index)