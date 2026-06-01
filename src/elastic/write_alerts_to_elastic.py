from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import json
import os
import dotenv

dotenv.load_dotenv()

KAFKA_BROKER = os.getenv('KAFKA_BROKER')
KAFKA_TOPIC = os.getenv('ALERTS_TOPIC')

consumer = KafkaConsumer(KAFKA_TOPIC, bootstrap_servers=KAFKA_BROKER)

es = Elasticsearch([{'host': 'elasticsearch', 'port': 9200, 'scheme': 'http'}])
es_index = os.getenv('ELASTICSEARCH_NETWORK_LOGS_INDEX')


def consume_from_kafka():
    print("Consuming data from Kafka...")
    for message in consumer:
        log = message.value
        es.index(index=es_index, body=log)  # Index data into Elasticsearch
        # Here you can add code to process the received data as needed


def es_index_get_or_create(index_name):
    if not es.indices.exists(index=index_name):
        # Define mapping
        mapping = {}
    
        # Create the index with mapping
        es.indices.create(index=index_name, body=mapping)
        print(f"Created Elasticsearch index: {index_name} with custom mapping")


if __name__ == "__main__":
    es_index_get_or_create(es_index)
    consume_from_kafka()