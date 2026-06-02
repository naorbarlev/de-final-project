from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import json
import os
import dotenv

dotenv.load_dotenv()

KAFKA_BROKER = os.getenv('KAFKA_BROKER')
KAFKA_TOPIC = os.getenv('ALERTS_TOPIC')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'elasticsearch')

consumer = KafkaConsumer(KAFKA_TOPIC, bootstrap_servers=KAFKA_BROKER)

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': 9200, 'scheme': 'http'}])
es_index = os.getenv('ELASTICSEARCH_ALERTS_INDEX')

def wait_for_elasticsearch(es_client, retries=30, delay=5):
    """Wait until Elasticsearch responds to ping or raise after retries."""
    import time

    for attempt in range(1, retries + 1):
        try:
            if es_client.ping():
                print(f"Elasticsearch reachable (attempt {attempt})")
                return True
        except Exception as e:
            print(f"Elasticsearch ping failed (attempt {attempt}): {e}")
        time.sleep(delay)
    raise RuntimeError("Elasticsearch not reachable after retries")

def consume_from_kafka():
    print("Consuming data from Kafka...")
    for message in consumer:
        log = message.value
        es.index(index=es_index, body=log)  # Index data into Elasticsearch
        # Here you can add code to process the received data as needed


def es_index_get_or_create(index_name):
    if not es.indices.exists(index=index_name):
        # Define mapping
        # mapping = {}
    
        # Create the index with mapping
        es.indices.create(index=index_name)
        print(f"Created Elasticsearch index: {index_name} with custom mapping")


if __name__ == "__main__":
    # Ensure Elasticsearch is up before proceeding
    print(f"Waiting for Elasticsearch at {ELASTICSEARCH_HOST}:9200...")
    try:
        wait_for_elasticsearch(es)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        raise

    # create Kafka consumer after ES is available
    consumer = KafkaConsumer(KAFKA_TOPIC, bootstrap_servers=KAFKA_BROKER)
    es_index_get_or_create(es_index)
    consume_from_kafka()