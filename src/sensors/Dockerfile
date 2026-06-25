FROM python:3.11-slim

WORKDIR /app

COPY src/sensors/requirements.txt ./
COPY src/logger.py ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/sensors/ ./

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "corelight_logs_producer.py"]
