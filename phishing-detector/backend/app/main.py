import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.email import router as email_router

DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000,http://localhost:5173,"
    "http://127.0.0.1:3000,http://127.0.0.1:5173"
)

cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]

app = FastAPI(title="Phishing Email Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
