# Use a lightweight Python base image
FROM python:3.9-slim

# Set the working directory to /app
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy all source files into the container
COPY . .

# Set PYTHONPATH so 'src' is discoverable
# Since your code is in /app, adding /app to PYTHONPATH allows 
# 'import src.engine' to resolve correctly
ENV PYTHONPATH=/app

# Execute the runner
ENTRYPOINT ["python3", "src/audit_runner.py"]