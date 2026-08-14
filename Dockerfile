# Use a stable, official Linux Python base image to eliminate OS/environment mismatches
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies required for native compilation and security packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip to prevent package resolution errors
RUN pip install --no-cache-dir --upgrade pip

# Copy dependency specifications first to optimize layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application source code into the container
COPY . .

# Expose Render's default web service port
EXPOSE 10000

# Set environment variables for production execution
ENV PORT=10000
ENV PYTHONUNBUFFERED=1

# Run the ASGI server (adjust 'main:app' to match your entrypoint package/module)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
