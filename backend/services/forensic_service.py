from typing import Dict
import base64

def decode_forensic_data(data_type: str, raw_data: str) -> Dict:
    """
    이메일 헤더, Base64, 또는 간단한 패킷 데이터를 디코딩하고 AI 설명을 생성합니다.
    """
    decoded_text = ""
    explanation = ""
    
    try:
        if data_type == "base64":
            decoded_text = base64.b64decode(raw_data).decode('utf-8', errors='replace')
            explanation = "Base64 인코딩된 데이터를 평문으로 복구하였습니다. 인코딩 뒤에 숨겨진 악성 스크립트나 URL이 있는지 확인하십시오."
        elif data_type == "header":
            # 간단한 헤더 파싱 모사
            decoded_text = raw_data # 실제로는 이메일 라이브러리 활용
            explanation = "이메일 헤더를 분석 중입니다. 발신자 IP와 수신 경로(Received)의 일관성을 검증하십시오."
        else:
            decoded_text = raw_data
            explanation = "입력된 데이터를 원문 그대로 표시합니다. 비정상적인 제어 문나 패턴을 수동 수색하십시오."
            
        return {
            "type": data_type,
            "decoded": decoded_text,
            "ai_explanation": explanation,
            "status": "Success"
        }
    except Exception as e:
        return {
            "status": "Error",
            "message": str(e)
        }
