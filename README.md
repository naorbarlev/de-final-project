# Final Project: Security Analytics Pipeline

This project implements an end-to-end security analytics platform that ingests network telemetry, detects suspicious behavior, stores raw and enriched data, and orchestrates periodic threat-intelligence workflows. It combines Docker, Kafka, Spark, Elasticsearch, Kibana, MinIO, and Airflow in a containerized environment.

## Overview

The pipeline is designed to:

- ingest simulated network logs from a producer service,
- stream events through Kafka,
- detect security alerts with Spark-based logic,
- write logs and alerts into Elasticsearch,
- store IoCs (indicators of compromise) in MinIO,
- orchestrate IoC collection and cleaning with Airflow.

## Architecture

The solution is composed of the following main components:

- Kafka: message bus for network logs and alerts
- Spark: alert detection and data processing
- Elasticsearch + Kibana: storage and visualization of logs and alerts
- MinIO: object storage for IoC datasets
- Airflow: scheduled workflow orchestration
- Corelight-style producer: generates sample network traffic events

### High-level flow

1. A producer generates network log events.
2. Events are published to Kafka topics.
3. Spark jobs consume the stream and detect patterns such as:
   - port scanning,
   - data exfiltration,
   - IOC matches.
4. Alerts and network logs are written to Elasticsearch.
5. Airflow periodically pulls IoCs from an external source, cleans them, and stores results in MinIO.

## Project Structure

- docker-compose.yaml: defines the full infrastructure stack
- src/sensors: log producer service
- src/spark: Spark alert-detection jobs and supporting utilities
- src/elastic: Elasticsearch writers for logs and alerts
- src/airflow: Airflow DAGs and Docker image setup
- src/threat_intell: threat intelligence collection scripts
- data: persistent storage for services such as Kafka, Elasticsearch, and MinIO
- tests: project test coverage

## Prerequisites

Make sure the following are installed:

- Docker
- Docker Compose
- Python 3.9+ (optional for local script execution)

## Environment Configuration

Create an environment file named .env in the project root and provide the required values for the services. The Python scripts expect variables such as:

- NETWORK_LOGS_TOPIC
- ALERTS_TOPIC
- KAFKA_BROKER
- MINIO_ACCESS_KEY
- MINIO_SECRET_KEY
- MINIO_ENDPOINT
- IOCS_BUCKET_NAME
- CLEAN_IOCS_PARQUET_FILES

You can also use the existing .env file in the repository as a starting point if it is already populated in your environment.

## Running the Project

Start the full stack:

```bash
docker compose up -d
```

This will launch the infrastructure services and application containers.

### Useful services and ports

- MinIO Console: http://localhost:9001
- MinIO API: http://localhost:9000
- Kafdrop: http://localhost:9003
- Kibana: http://localhost:5601
- Airflow UI: http://localhost:8082
- Spark Master UI: http://localhost:8080
- Spark Worker UI: http://localhost:8081

## Workflow Details

### 1. Network log ingestion

The producer container simulates network event traffic and pushes it into Kafka. These events are used as the input for downstream detection logic.

### 2. Alert generation

Spark jobs read the incoming data and generate alert records for:

- port scanning,
- suspicious transfer volume,
- matching IoCs from the cleaned threat-feed dataset.

### 3. Elasticsearch integration

Generated alerts and logs are written into Elasticsearch so they can be searched and visualized in Kibana.

### 4. Airflow IoC pipeline

The Airflow DAG named iocs_pipeline runs on a schedule and performs the following tasks:

1. pull IoCs from an external source,
2. clean and transform them,
3. save the results to MinIO for downstream Spark use.

## Development Notes

- The Airflow DAG is defined in src/airflow/dags/iocs_pipeline.py.
- Spark logic for detection lives in src/spark/alert_engine.py.
- The Elasticsearch writers are implemented in src/elastic.
- The producer is implemented in src/sensors/corelight_logs_producer.py.

## Stopping the Environment

To stop and remove the containers:

```bash
docker compose down
```

To remove volumes as well:

```bash
docker compose down -v
```

## Troubleshooting

- If services fail to start, verify Docker has enough resources allocated.
- If Kafka or Elasticsearch are not ready yet, wait a few moments and retry.
- If Airflow does not load the DAG, check that the container volumes and DAG path are mounted correctly.
- If Spark jobs fail, confirm that the required environment variables and MinIO credentials are set correctly.

## License

This project is intended for educational and demonstration purposes.
