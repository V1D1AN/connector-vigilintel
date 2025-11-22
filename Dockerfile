FROM python:3.11-slim

LABEL description="Simple VigilIntel connector for OpenCTI"

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/connector

# Install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector
COPY src/vigilintel_connector.py vigilintel_connector.py
COPY src/config.yml config.yml

# Create non-root user
RUN useradd --create-home --shell /bin/bash connector
RUN chown -R connector:connector /opt/connector
USER connector

CMD ["python", "vigilintel_connector.py"]
