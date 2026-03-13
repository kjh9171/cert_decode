from fastapi import APIRouter, Body
from backend.services.forensic_service import process_forensic_data

router = APIRouter()

@router.post("/process")
async def process_data(
    data_type: str = Body(...), 
    raw_data: str = Body(...), 
    action: str = Body("decode")
):
    """
    포렌식 데이터를 처리(인코딩/디코딩)하고 AI 설명을 제공합니다.
    """
    return process_forensic_data(data_type, raw_data, action)
