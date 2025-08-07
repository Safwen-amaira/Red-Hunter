from fastapi import APIRouter, Depends, HTTPException
from typing import List
from ..detection.engine import DetectionEngine

router = APIRouter(prefix="/security", tags=["Security"])

@router.post("/scan")
async def scan_payload(payload: str):
    engine = DetectionEngine()
    result = engine.analyze({"body": payload})
    return {
        "is_malicious": result["action"] != "allow",
        "threats": result["threats"],
        "score": result["score"]
    }

@router.get("/ip/reputation/{ip_address}")
async def check_ip_reputation(ip_address: str):
    # Would integrate with threat intelligence feeds
    return {
        "ip": ip_address,
        "reputation": "unknown",
        "last_seen": None
    }