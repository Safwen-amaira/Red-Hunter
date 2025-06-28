from fastapi import FastAPI, Request
from llama_cpp import Llama
from pydantic import BaseModel

app = FastAPI()
llm = Llama(model_path="models/phi-2.Q4_K_M.gguf", n_ctx=2048)

class LogData(BaseModel):
    logs: str

def detect_threat(log: str):
    signatures = ["<script>", "' OR 1=1", "UNION SELECT", "DROP TABLE"]
    for sig in signatures:
        if sig.lower() in log.lower():
            return True
    return False

def explain_threat(log: str):
    prompt = f"""
You are Red-Hunter, a cybersecurity assistant AI.
Your job is to explain any threat in this log and advise on how to stop it.

Log: {log}

Remember to end with:
"— Red-Hunter, built by Amaira Safwen, Software Engineering Student in Esprit.tn ."
"""
    output = llm(prompt, max_tokens=200)
    return output["choices"][0]["text"].strip()

@app.post("/scan")
async def scan_logs(data: LogData):
    if detect_threat(data.logs):
        response = explain_threat(data.logs)
        return {"status": "alert", "message": response}
    else:
        return {"status": "safe", "message": "No threat detected. System looks secure."}
