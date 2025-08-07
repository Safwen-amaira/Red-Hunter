from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from .services import StatsService

app = FastAPI(title="RedHunter Dashboard")

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def dashboard():
    return FileResponse("static/index.html")

@app.get("/api/stats")
async def get_stats():
    service = StatsService()
    return {
        "requests_today": service.get_request_count(),
        "threats_blocked": service.get_threats_count(),
        "top_threats": service.get_top_threats()
    }