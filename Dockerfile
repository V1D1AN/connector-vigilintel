FROM python:3.11-slim

WORKDIR /opt/opencti-connector-vigilintel

# Install system dependencies (libmagic required by pycti)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY config.yml.sample ./config.yml

ENTRYPOINT ["python", "src/vigilintel.py"]