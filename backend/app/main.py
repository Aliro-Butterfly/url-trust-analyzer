from contextlib import asynccontextmanager

from fastapi import FastAPI

from .database import fetch_history, initialize_database, save_analysis
from .schemas import AnalysisResponse, AnalyzeRequest, HistoryItem
from .services.analyzer import AnalyzerService


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(title="URL Trust Analyzer - Backend", version="0.1.0", lifespan=lifespan)
analyzer_service = AnalyzerService()


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalyzeRequest) -> AnalysisResponse:
    result = await analyzer_service.analyze(request)
    save_analysis(result.model_dump())
    return result


@app.get("/history", response_model=list[HistoryItem])
def history() -> list[HistoryItem]:
    return fetch_history()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
