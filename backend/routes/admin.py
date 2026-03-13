from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.models.session import get_db
from backend.models.database import AuditLog

router = APIRouter()

@router.get("/logs")
async def get_audit_logs(db: Session = Depends(get_db)):
    """
    전체 시스템 감사 로그를 조회합니다.
    """
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
