FROM bitnamilegacy/spark:3.5.1

# 1. Switch to root to install packages and download JARs
USER root

# 2. Update the package manager and install curl (Bitnami images use Debian under the hood)
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*

COPY ./src/spark/requirements.txt /tmp/requirements.txt


RUN pip install --no-cache-dir -r /tmp/requirements.txt

#Define compatible versions for the AWS/Hadoop S3 connectors
ENV HADOOP_VERSION=3.3.4
ENV AWS_SDK_VERSION=1.12.262

#Download the JARs directly into Bitnami's specific Spark jars folder
RUN curl -sS https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-aws/${HADOOP_VERSION}/hadoop-aws-${HADOOP_VERSION}.jar \
    -o /opt/bitnami/spark/jars/hadoop-aws-${HADOOP_VERSION}.jar \
    && curl -sS https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-bundle/${AWS_SDK_VERSION}/aws-java-sdk-bundle-${AWS_SDK_VERSION}.jar \
    -o /opt/bitnami/spark/jars/aws-java-sdk-bundle-${AWS_SDK_VERSION}.jar

#Switch back to Bitnami's default non-root user (1001) for runtime security
USER 1001