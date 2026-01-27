FROM python:3.11-slim
WORKDIR /opt/opencti-connector-vigilintel
RUN pip install --no-cache-dir pycti>=6.0.0 stix2>=3.0.0 requests>=2.28.0 pyyaml>=6.0
COPY src/ ./src/
COPY config.yml.sample ./config.yml
ENTRYPOINT ["python", "src/vigilintel.py"]
