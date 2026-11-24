# INTENTIONALLY VULNERABLE lab. Publish only to 127.0.0.1 (see docker-compose.yml).
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn>=0.29" "pyjwt>=2.8"
COPY target/ ./target/
ENV LAB_CONTAINER=1 LAB_BIND=0.0.0.0
EXPOSE 8099
USER nobody
CMD ["python", "-m", "target.run"]
