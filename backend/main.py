from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes import system, analyze, forensic, admin
from prometheus_fastapi_instrumentor import Instrumentor

app = FastAPI(title="NTAV SecuLab V2.0", description="Never Trust, Always Verify Security Platform")

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우트 등록
app.include_router(system.router, prefix="/api/system", tags=["System Auditor"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["Threat Analysis Hall"])
app.include_router(forensic.router, prefix="/api/forensic", tags=["Codec Lab"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin & Audit"])

@app.get("/health")
async def health_check():
    return {"status": "healthy", "engine": "NTAV-Core V2.0"}

# 모니터링 계측
Instrumentor().instrument(app).expose(app)
