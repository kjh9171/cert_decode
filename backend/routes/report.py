from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import FileResponse
from backend.services.report_service import generate_scan_report
import os

router = APIRouter()

@router.post("/generate")
async def generate_report(scan_data: dict = Body(...)):
    """
    분석 데이터를 기반으로 PDF 리포트를 생성하고 파일을 반환합니다.
    """
    try:
        report_path = generate_scan_report(scan_data)
        
        if not os.path.exists(report_path):
            raise HTTPException(status_code=500, detail="리포트 생성에 실패했습니다.")
            
        return FileResponse(
            path=report_path,
            filename=os.path.basename(report_path),
            media_type='application/pdf'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
