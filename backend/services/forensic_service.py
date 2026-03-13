import base64
import urllib.parse
import re
from typing import Dict

def legacy_gubun_parser(raw_data: str) -> str:
    """
    JS gubun.js 로직을 파이썬으로 이식한 포렌식 파서입니다.
    특정 오프셋(10~61)의 데이터를 추출하고 특수 제어 문자를 정제합니다.
    """
    lines = raw_data.split('\n')
    processed_parts = []
    
    for line in lines:
        if len(line) < 10:
            continue
            
        # substring(10, 61) 추출
        chunk = line[10:61]
        
        # 기본 치환 (A0->20, 00->20, 0A->0D 등)
        chunk = chunk.replace('A0', '20').replace('00', '20').replace('0A', '0D')
        chunk = chunk.replace('0a', '0d')
        
        # 공백 처리
        chunk = chunk.rstrip()
        chunk = chunk.replace(' ', '%')
        
        # 중복 % 제거
        chunk = re.sub(r'%+', '%', chunk)
        
        # removeEnter3/4 모사 (개행 제어 문자를 공백으로)
        for target in ["%0a", "%0d", "%0A", "%0D"]:
            chunk = chunk.replace(target, "%20")
            
        # 중복 공백 인코딩 제거
        chunk = chunk.replace("%20%20", "%20")
        
        processed_parts.append(chunk)
        
    return "".join(processed_parts)

def process_forensic_data(data_type: str, raw_data: str, action: str = "decode") -> Dict:
    """
    포렌식 데이터를 처리(인코딩/디코딩)하고 AI 설명을 생성합니다.
    action: "decode" 또는 "encode"
    """
    processed_text = ""
    explanation = ""
    
    try:
        if action == "decode":
            if data_type == "base64":
                processed_text = base64.b64decode(raw_data).decode('utf-8', errors='replace')
                explanation = "Base64 인코딩 뒤에 숨겨진 악성 페이로드나 C2 주소 유무를 확인하십시오."
            elif data_type == "url":
                processed_text = urllib.parse.unquote_plus(raw_data)
                explanation = "URL 인코딩된 문자열을 복구했습니다. % 헥스 코드 뒤에 숨은 난독화된 스크립트 패턴을 분석하십시오."
            elif data_type == "hex":
                clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_data)
                processed_text = bytes.fromhex(clean_hex).decode('utf-8', errors='replace')
                explanation = "16진수 바이너리 데이터를 텍스트로 변환했습니다. 쉘코드 매직 넘버나 특징적인 문자열을 수색하십시오."
            elif data_type == "gubun":
                processed_text = legacy_gubun_parser(raw_data)
                explanation = "레거시 로그 파서(gubun1)를 통해 추출된 핵심 데이터입니다."
            elif data_type == "header":
                processed_text = raw_data
                explanation = "이메일 헤더 분석 모드입니다. Received 필드의 IP 경로를 대조하십시오."
            else:
                processed_text = raw_data
                explanation = "원본 데이터를 그대로 출력합니다."
        
        else: # action == "encode"
            if data_type == "base64":
                processed_text = base64.b64encode(raw_data.encode('utf-8')).decode('utf-8')
                explanation = "데이터를 Base64로 인코딩했습니다. 통신 구간에서의 난독화나 데이터 보호 목적으로 사용될 수 있습니다."
            elif data_type == "url":
                processed_text = urllib.parse.quote_plus(raw_data)
                explanation = "데이터를 URL 인코딩했습니다. HTTP 요청 파라미터로 안전하게 전달하기 위한 포맷입니다."
            elif data_type == "hex":
                processed_text = raw_data.encode('utf-8').hex()
                explanation = "데이터를 16진수(Hex) 문자열로 변환했습니다. 바이너리 데이터의 가시성 확보 및 분석에 용이합니다."
            else:
                processed_text = raw_data
                explanation = "해당 타입은 인코딩을 지원하지 않거나 원본을 유지합니다."

        return {
            "type": data_type,
            "action": action,
            "processed": processed_text,
            "ai_explanation": explanation,
            "status": "Success"
        }
    except Exception as e:
        return {
            "status": "Error",
            "message": f"처리 실패 ({action}): {str(e)}"
        }
