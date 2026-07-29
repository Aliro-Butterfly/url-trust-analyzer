from fastapi import FastAPI

from .schemas import AnalysisResponse, AnalyzeRequest
from .services.analyzer import AnalyzerService

app = FastAPI(title="URL Trust Analyzer - Backend", version="0.1.0")
analyzer_service = AnalyzerService()


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalyzeRequest) -> AnalysisResponse:
    return await analyzer_service.analyze(request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
