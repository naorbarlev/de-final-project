# Security Analytics Pipeline

An end-to-end, containerized security analytics project for generating network telemetry, streaming it through Kafka, detecting suspicious activity with Spark, storing events in Elasticsearch, and refreshing threat-intelligence indicators through Airflow and MinIO.

## What It Does

This project simulates a small SOC-style data pipeline:

- generates Corelight/Zeek-style `conn`, `dns`, and `http` logs
- publishes network logs to Kafka
- runs a Spark Structured Streaming alert engine
- detects IOC matches, port scanning, and possible data exfiltration
- writes raw network logs and generated alerts into Elasticsearch
- provides Kibana for searching and visualizing data
- pulls ThreatFox IoCs with Airflow, cleans them with Spark, and stores them in MinIO as Parquet

## Architecture

High-level flow:

1. `corelight-producer` creates simulated network logs.
2. Logs are written to the Kafka `network-logs` topic.
3. `alert-engine` reads the stream with Spark.
4. Spark loads cleaned IoCs from MinIO and creates alerts for:
   - IOC matches against IPs, domains, DNS answers, and HTTP hosts
   - short-window port scanning
   - high-volume outbound transfer activity
5. Alerts are written back to Kafka on the `alerts` topic.
6. `elastic-logs` writes raw network logs to Elasticsearch.
7. `elastic-alerts` writes generated alerts to Elasticsearch.
8. Kibana is used to inspect the `network-logs` and `alerts` indexes.
9. Airflow runs the `iocs_pipeline` DAG daily to refresh IoC data from ThreatFox into MinIO.

## Main Services

The stack is defined in `docker-compose.yaml` and includes:

- `minio`: object storage for raw and cleaned IoCs
- `zookeeper`: Kafka coordination
- `course-kafka`: Kafka broker
- `kafdrop`: Kafka topic browser
- `spark-master`, `spark-worker`, `spark-worker-2`: Spark cluster
- `alert-engine`: Spark streaming detection job
- `corelight-producer`: simulated Corelight/Zeek log generator
- `elasticsearch`: search storage for logs and alerts
- `kibana`: Elasticsearch UI
- `postgres`: Airflow metadata database
- `airflow-webserver`, `airflow-scheduler`, `airflow-init`: Airflow services
- `elastic-logs`, `elastic-alerts`: Kafka-to-Elasticsearch consumers

## Project Structure

```text
.
├── docker-compose.yaml
├── requirements.txt
├── src
│   ├── airflow
│   │   ├── Dockerfile.airflow
│   │   ├── requirements.txt
│   │   └── dags/iocs_pipeline.py
│   ├── elastic
│   │   ├── Dockerfile.alerts
│   │   ├── Dockerfile.logs
│   │   ├── requirements.txt
│   │   ├── write_alerts_to_elastic.py
│   │   └── write_network_logs_to_elastic.py
│   ├── sensors
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── corelight_logs_producer.py
│   ├── spark
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   ├── alert_engine.py
│   │   ├── clean_raw_iocs.py
│   │   └── schema.py
│   ├── threat_intell
│   │   └── pull_threat_fox_iocs.py
│   ├── logger.py
│   └── utils.py
```

## Prerequisites

- Docker
- Docker Compose
- A ThreatFox API key for IoC collection
- Python 3.9+ if you want to run scripts locally outside Docker

## Configuration

Create a `.env` file in the project root. The containers read this file through Docker Compose.

Example:

```env
THREATFOX_API_KEY="your-threatfox-api-key"

MINIO_ENDPOINT="minio:9000"
MINIO_ACCESS_KEY="minioadmin"
MINIO_SECRET_KEY="minioadmin"
IOCS_BUCKET_NAME="iocs"
RAW_IOCS_FOLDER_NAME="raw-iocs"
CLEAN_IOCS_FOLDER_NAME="clean-iocs"
CLEAN_IOCS_PARQUET_FILES="clean-iocs/files"

KAFKA_BROKER="course-kafka:9092"
NETWORK_LOGS_TOPIC="network-logs"
ALERTS_TOPIC="alerts"
LOG_INTERVAL_MIN_SECONDS="0.5"
LOG_INTERVAL_MAX_SECONDS="2.0"

ELASTICSEARCH_HOST="elasticsearch"
ELASTICSEARCH_NETWORK_LOGS_INDEX="network-logs"
ELASTICSEARCH_ALERTS_INDEX="alerts"

DEMO_MALICIOUS_IPS="38.76.203.127,195.177.94.11,157.20.182.21"
MALICIOUS_DOMAINS="annuncigoogle.it,nathanaelappliances.com"
DEMO_EXFIL_DOMAINS="paintjg.com,daype.com"
```

## Running The Stack

Build and start all services:

```bash
docker compose up -d --build
```

Watch logs for the main pipeline components:

```bash
docker compose logs -f corelight-producer alert-engine elastic-logs elastic-alerts
```

Stop the stack:

```bash
docker compose down
```

Stop the stack and remove persistent volumes:

```bash
docker compose down -v
```

## Service URLs

The Docker Compose file exposes these local ports:

- MinIO API: http://localhost:9001
- MinIO Console: http://localhost:9002
- Kafdrop: http://localhost:9003
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200
- Airflow UI: http://localhost:8082
- Spark Master UI: http://localhost:8080
- Spark Worker 1 UI: http://localhost:8081
- Spark Worker 2 UI: http://localhost:8083

Airflow default login created by `airflow-init`:

- Username: `airflow`
- Password: `airflow`

## Airflow IoC Pipeline

The DAG is defined in `src/airflow/dags/iocs_pipeline.py` and is named `iocs_pipeline`.

It runs daily at midnight and performs:

1. `pull_iocs_from_external_source`: downloads recent IoCs from ThreatFox and stores raw JSON in MinIO.
2. `clean_data_and_save`: runs `src/spark/clean_raw_iocs.py` with Spark, normalizes the IoC dataset, writes Parquet output to MinIO, and updates the processing watermark.

The alert engine expects the cleaned IoC Parquet files to exist at:

```text
s3a://<IOCS_BUCKET_NAME>/<CLEAN_IOCS_PARQUET_FILES>/
```

If `alert-engine` starts before cleaned IoCs are available, run the Airflow DAG first or restart `alert-engine` after the clean IoC dataset has been written.

## Detection Logic

`src/spark/alert_engine.py` contains the streaming detection logic:

- `ioc_match_detection`: compares network fields against cleaned IoCs from MinIO
- `port_scan_detection`: detects one source touching many destination ports in a one-minute window
- `data_exfiltration_detection`: detects more than `100,000,000` outbound bytes in a one-minute source/destination window

Generated alerts are published to Kafka and then indexed into Elasticsearch.

## Elasticsearch Data

Two indexes are created by the writer services:

- `network-logs`: raw Corelight/Zeek-style telemetry
- `alerts`: Spark-generated alert documents

Open Kibana at http://localhost:5601 and create data views for these indexes to inspect the pipeline output.

## Troubleshooting

- If Kafka topics are missing, confirm `NETWORK_LOGS_TOPIC` and `ALERTS_TOPIC` are set before starting Compose.
- If the alert engine fails while loading IoCs, run the Airflow `iocs_pipeline` DAG and verify the cleaned Parquet path exists in MinIO.
- If Elasticsearch writers fail, wait for the Elasticsearch health check to pass and inspect `elastic-logs` or `elastic-alerts` logs.
- If Airflow does not show the DAG, check the `airflow-webserver` and `airflow-scheduler` logs.
- If MinIO cannot be reached from containers, use the internal endpoint `minio:9000`; from the host browser use `localhost:9001` for the API and `localhost:9002` for the console.

## Educational Scope

This project is intended for security analytics, data engineering, and streaming pipeline demonstrations.
