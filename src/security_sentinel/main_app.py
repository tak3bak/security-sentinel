from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from security_sentinel.chokepoint_finder import router as chokepoints_router
from security_sentinel.evidence_investigator import router as investigation_router

app = FastAPI(
    title="Nomadik Security Sentinel API Gateway",
    description="Active defense microservices for threat detection, remediation chokepoints, and compliance evidence.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chokepoints_router)
app.include_router(investigation_router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Nomadik Security Sentinel",
        "version": "1.0.0",
        "modules": {
            "file_watcher": "active",
            "file_inspector": "active",
            "edr_threat_rules": "active",
            "chokepoint_finder": "active",
            "evidence_investigator": "active"
        }
    }
