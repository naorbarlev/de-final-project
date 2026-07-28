from datetime import datetime, timedelta
from airflow import DAG
from airflow.providers.apache.spark.operators.spark_submit import SparkSubmitOperator
from airflow.operators.bash import BashOperator
from airflow.operators.dummy import DummyOperator

# Default arguments for all tasks in the DAG
default_args = {
    'owner': 'naorb',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

# Creating the DAG
with DAG(
    'iocs_pipeline',
    default_args=default_args,
    description='Pull IoCs from external source, process them, and upload to minio',
    schedule_interval='0 0 * * *',  # Runs at midnight every day
    start_date=datetime(2023, 1, 1),
    catchup=False,
) as dag:

    # Start task
    start = DummyOperator(
        task_id='start',
    )

    # Data download task
    pull_iocs = BashOperator(
        task_id='pull_iocs_from_external_source',
        bash_command='python3 /opt/airflow/scripts/threat_intell/pull_threat_fox_iocs.py',
    )

    clean_data_and_save = SparkSubmitOperator(
        task_id="clean_data_and_save",
        application="/opt/airflow/scripts/spark/clean_raw_iocs.py",
        conn_id="spark_default",
        packages="org.apache.hadoop:hadoop-aws:3.3.4,com.amazonaws:aws-java-sdk-bundle:1.12.262",
        conf={
            "spark.executor.memory": "1g",
            "spark.driver.memory": "1g"
        }
    )

    # End task
    end = DummyOperator(
        task_id='end',
    )


    start >> pull_iocs >> clean_data_and_save >> end