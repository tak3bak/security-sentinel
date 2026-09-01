from fastapi import FastAPI

app = FastAPI(
    title="Nomadik Security Sentinel",
    description="Active-defense security monitoring, inspection, and compliance API",
    version="0.1.0"
)

@app.get("/")
def read_root():
    return {"status": "online", "service": "Nomadik Security Sentinel API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
