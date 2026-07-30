from fastapi import FastAPI
from pydantic import BaseModel

from src.core.scanner import Scanner

app = FastAPI(
    title="SentinelScan API",
    version="1.0.0",
    description="Container Security Scanner Backend",
)

scanner = Scanner()


class ImageRequest(BaseModel):
    image: str


@app.get("/")
def root():
    return {
        "message": "Welcome to SentinelScan API!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan/image")
def scan_image(request: ImageRequest):
    return scanner.scan_image(request.image)