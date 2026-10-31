# Provena Hub. Build: docker build -t provena-hub .
# Run:   docker run -p 8740:8740 -v provena-data:/data \
#          -e PROVENA_HUB_PASSPHRASE_FILE=/run/secrets/hub_pass provena-hub --tsa https://freetsa.org/tsr
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[server,client]" \
    && useradd --system --uid 10001 provena && mkdir /data && chown provena /data
USER provena
EXPOSE 8740
VOLUME /data
ENTRYPOINT ["provena", "hub", "serve", "--data", "/data", "--host", "0.0.0.0"]
