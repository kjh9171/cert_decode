from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.models.session import get_db
from backend.models.database import ScanResult
from backend.services.audit_service import calculate_integrity_score, generate_ai_one_liner
import json

router = APIRouter()

@router.post("/upload")
async def upload_scan_result(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    result.json 파일을 업로드하여 무결성을 분석하고 결과를 저장합니다.
    """
    try:
        content = await file.read()
        data = json.loads(content)
        
        # 'results' 키가 있는지 확인 (기존 main.py 결과 구조 기준)
        results = data.get("results", [])
        
        score = calculate_integrity_score(results)
        ai_comment = generate_ai_one_liner(score)
        
        # 요약 통계 계산
        summary = {
            "high": len([r for r in results if r.get("impact") == "상" and r.get("result") == "Fail"]),
            "mid": len([r for r in results if r.get("impact") == "중" and r.get("result") == "Fail"]),
            "low": len([r for r in results if r.get("impact") == "하" and r.get("result") == "Fail"])
        }
        
        # DB 저장
        db_result = ScanResult(
            target_host=data.get("host", "Unknown"),
            score=score,
            summary=summary,
            raw_data=results,
            ntav_comment=ai_comment
        )
        db.add(db_result)
        db.commit()
        db.refresh(db_result)
        
        return {
            "id": db_result.id,
            "score": score,
            "ntav_comment": ai_comment,
            "summary": summary,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"분석 실패: {str(e)}")

@router.get("/history")
async def get_scan_history(db: Session = Depends(get_db)):
    """
    과거 점검 이력을 조회합니다.
    """
    return db.query(ScanResult).order_by(ScanResult.created_at.desc()).all()
