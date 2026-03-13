from fastapi import APIRouter, UploadFile, File, HTTPException
from backend.services.threat_service import analyze_file_threat

router = APIRouter()

@router.post("/file")
async def analyze_file(file: UploadFile = File(...)):
    """
    업로드된 보안 위협 파일을 분석하고 MITRE ATT&CK 맵을 반환합니다.
    """
    try:
        content = await file.read()
        result = analyze_file_threat(file.filename, content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"위협 분석 실패: {str(e)}")
