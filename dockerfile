FROM python:3.11-slim

WORKDIR /app

# Optimize layer caching for dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy orchestration files over to app execution boundary
COPY sentinel.py .
COPY sentinel_osint.py .
COPY src/ ./src/

ENV SPIDERFOOT_URL=http://localhost:5001
ENV CHECK_INTERVAL=300

CMD ["python", "sentinel_osint.py"]
