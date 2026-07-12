import sys
from pathlib import Path
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import os
import dotenv

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from logger import get_logger
from utils import wait_for_elasticsearch, consume_from_kafka_and_send_to_es, es_index_get_or_create


logger = get_logger(__name__)
dotenv.load_dotenv()

KAFKA_BROKER = os.getenv('KAFKA_BROKER')
ALERTS_TOPIC = os.getenv('ALERTS_TOPIC')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'elasticsearch')
mapping = {
            "mappings": {
                "properties": {
                    "alert_id": {
                        "type": "keyword"
                    },
                    "log_uid": {
                        "type": "keyword"
                    },
                    "alert_type": {
                        "type": "keyword"
                    },
                    "severity": {
                        "type": "keyword"
                    },
                    "alert_ts": {
                        "type": "date"
                    },
                    "event_ts": {
                        "type": "date"
                    },
                    "orig_ip": {
                        "type": "ip"
                    },
                    "resp_ip": {
                        "type": "ip"
                    },
                    "ioc_score": {
                        "type": "integer"
                    },
                    "ioc_source": {
                        "type": "keyword"
                    },
                    "ioc_value": {
                        "type": "keyword"
                    },
                    "tags": {
                        "type": "keyword"
                    }
                }
            }
        }

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': 9200, 'scheme': 'http'}])
es_index = os.getenv('ELASTICSEARCH_ALERTS_INDEX')


if __name__ == "__main__":
    # Ensure Elasticsearch is up before proceeding
    logger.info(f"Waiting for Elasticsearch at {ELASTICSEARCH_HOST}:9200...")
    try:
        wait_for_elasticsearch(es)
    except RuntimeError as e:
        logger.error(f"ERROR: {e}")
        raise

    # create Kafka consumer after ES is available
    consumer = KafkaConsumer(ALERTS_TOPIC, bootstrap_servers=KAFKA_BROKER)
    es_index_get_or_create(es, es_index, mapping)
    consume_from_kafka_and_send_to_es(consumer, es, es_index)
    