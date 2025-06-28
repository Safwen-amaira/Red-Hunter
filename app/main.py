from fastapi import FastAPI
from pydantic import BaseModel
from .detect import is_malicious
from .agent import generate_ai_response

app = FastAPI(
    title="Red-Hunter Server",
    description="Cybersecurity Agent built by Amaira Safwen"
)

class LogInput(BaseModel):
    logs: str

@app.post("/scan")
async def scan_logs(data: LogInput):
    logs = data.logs

    if is_malicious(logs):
        ai_msg = generate_ai_response(logs)
        return {
            "status": "alert",
            "message": ai_msg
        }
    else:
        return {
            "status": "safe",
            "message": "No threats detected. — Red-Hunter, built by Amaira Safwen, Software Engineering Student."
        }
