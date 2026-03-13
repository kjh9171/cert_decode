from fastapi import APIRouter, Body
from backend.services.forensic_service import decode_forensic_data

router = APIRouter()

@router.post("/decode")
async def decode_data(data_type: str = Body(...), raw_data: str = Body(...)):
    """
    포렌식 데이터를 디코딩하고 AI 설명을 제공합니다.
    """
    return decode_forensic_data(data_type, raw_data)
