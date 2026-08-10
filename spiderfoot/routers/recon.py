# -*- coding: utf-8 -*-
from fastapi import APIRouter, HTTPException, BackgroundTasks, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import logging
from sflib import SpiderFoot

router = APIRouter(prefix="/api/v1/recon", tags=["Reconnaissance"])
logger = logging.getLogger("security-sentinel")

DEFAULT_OPTS = {
    "_internettlds": "com\nnet\norg\nedu\ngov\nio\nsite\n",
    "httpuseragent": "SecuritySentinel-Agent/1.0"
}

class ReconTargetRequest(BaseModel):
    target: str = Field(..., description="Target domain, host, or IP address to scan")
    module: Optional[str] = Field("sfp_dns", description="Reconnaissance module to execute")

class ReconResponse(BaseModel):
    status: str
    target: str
    message: str
    task_id: Optional[str] = None

def execute_recon_task(target: str, module: str):
    """Background task handler for executing recon logic securely."""
    try:
        sf = SpiderFoot(DEFAULT_OPTS)
        logger.info(f"Initializing reconnaissance for target: {target} using module: {module}")
        
        if not sf.validHost(target, sf.opts.get("_internettlds")) and not sf.validIP(target):
            logger.error(f"Invalid target provided for background execution: {target}")
            return
            
        logger.info(f"Reconnaissance validation passed for {target}. Executing workflow...")
    except Exception as e:
        logger.exception(f"Error during reconnaissance execution for {target}: {str(e)}")

@router.post("/scan", response_model=ReconResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_recon_scan(payload: ReconTargetRequest, background_tasks: BackgroundTasks):
    try:
        sf = SpiderFoot(DEFAULT_OPTS)
        target = payload.target.strip()
        
        is_host = sf.validHost(target, sf.opts.get("_internettlds"))
        is_ip = sf.validIP(target)
        
        if not is_host and not is_ip:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target format: '{target}'. Must be a valid domain, host, or IP address."
            )
            
        task_id = sf.hashstring(f"{target}-{payload.module}")
        background_tasks.add_task(execute_recon_task, target, payload.module)
        
        return ReconResponse(
            status="accepted",
            target=target,
            message="Reconnaissance task successfully queued.",
            task_id=task_id
        )
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Failed to process recon request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while processing the recon request."
        )
