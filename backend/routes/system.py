from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.models.session import get_db
from backend.models.database import ScanResult
from backend.services.audit_service import calculate_integrity_score, generate_ai_one_liner, CentOSAuditParser

@router.post("/upload")
async def upload_scan_result(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    result.json 또는 result.txt 파일을 업로드하여 무결성을 분석합니다.
    """
    try:
        content = await file.read()
        filename = file.filename.lower()
        
        if filename.endswith(".json"):
            data = json.loads(content)
            results = data.get("results", [])
            host = data.get("host", "Unknown")
        else:
            # 텍스트 파일(쉘 스크립트 결과) 파싱
            text_content = content.decode('utf-8', errors='replace')
            parsed_data = CentOSAuditParser.parse_text(text_content)
            results = parsed_data.get("results", [])
            host = parsed_data.get("host", "CentOS-Server")

        score = calculate_integrity_score(results)
        ai_comment = generate_ai_one_liner(score)
        
        # 요약 통계
        summary = {
            "high": len([r for r in results if r.get("impact") == "상" and r.get("result") == "Fail"]),
            "mid": len([r for r in results if r.get("impact") == "중" and r.get("result") == "Fail"]),
            "low": len([r for r in results if r.get("impact") == "하" and r.get("result") == "Fail"])
        }
        
        # DB 저장
        db_result = ScanResult(
            target_host=host,
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
            "host": host,
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
