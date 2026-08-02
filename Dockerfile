# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies & build tools (gcc/python3-dev for C-extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libcap2-bin \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user and log directory
RUN groupadd -r sentinel && useradd -r -g sentinel nomadik \
    && mkdir -p /var/log/nomadik_sentinel \
    && chown -R nomadik:sentinel /var/log/nomadik_sentinel

# Set working directory
WORKDIR /app

# Install Python dependencies first (for layer caching)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/

# Give tshark binary network capture privileges without needing full root
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Switch to non-root user
USER nomadik

# Expose FastAPI port
EXPOSE 8000

# Run the Sentinel Analysis Engine
CMD ["python", "main.py"]
