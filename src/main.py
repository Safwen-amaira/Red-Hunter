from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from mitm.addon import RedHunterAddon
from mitmproxy.tools.main import mitmdump
import threading

app = FastAPI(title="RedHunter WAF API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    addon = RedHunterAddon()
    result = addon.engine.analyze(data)
    return JSONResponse(result)

def start_proxy():
    mitmdump(["-s", "src/mitm/addon.py", "--listen-port", "8080"])

if __name__ == "__main__":
    # Start MITM proxy in background
    proxy_thread = threading.Thread(target=start_proxy, daemon=True)
    proxy_thread.start()
    
    # Start API
    uvicorn.run(app, host="0.0.0.0", port=8000)