from fastapi import FastAPI
try:
    from security_sentinel.billing_handler import router as billing_router
except ImportError:
    from api.billing_handler import router as billing_router

app = FastAPI(
    title="Nomadik Security Sentinel",
    description="Active-defense security monitoring, inspection, and compliance API",
    version="0.1.0"
)

# Commercial Billing Router
app.include_router(billing_router)

@app.get("/")
def read_root():
    return {"status": "online", "service": "Nomadik Security Sentinel API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
