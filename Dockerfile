FROM python:3.11-slim
WORKDIR /app
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/core.txt -r requirements/api.txt
COPY src/ src/
COPY rules/ rules/
EXPOSE 8080
CMD ["uvicorn", "security_sentinel.main_app:app", "--host", "0.0.0.0", "--port", "8080"]
