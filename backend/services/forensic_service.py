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

def decode_forensic_data(data_type: str, raw_data: str) -> Dict:
    """
    포렌식 데이터를 디코딩하고 AI 설명을 생성합니다.
    사용자가 제공한 레거시 알고리즘(Gubun, URL, Hex 등)을 포함합니다.
    """
    decoded_text = ""
    explanation = ""
    
    try:
        if data_type == "base64":
            # 표준 Base64 디코딩
            decoded_text = base64.b64decode(raw_data).decode('utf-8', errors='replace')
            explanation = "Base64 인코딩 뒤에 숨겨진 악성 페이로드나 C2 주소 유무를 확인하십시오."
            
        elif data_type == "url":
            # URL 디코딩 (JS unescape/decodeURIComponent 모사)
            decoded_text = urllib.parse.unquote_plus(raw_data)
            explanation = "URL 인코딩된 문자열을 복구했습니다. % 헥스 코드 뒤에 숨은 난독화된 스크립트 패턴을 분석하십시오."
            
        elif data_type == "hex":
            # Hex 디코딩 (JS decodeHex 모사)
            clean_hex = re.sub(r'[^0-9a-fA-F]', '', raw_data)
            decoded_text = bytes.fromhex(clean_hex).decode('utf-8', errors='replace')
            explanation = "16진수 바이너리 데이터를 텍스트로 변환했습니다. 쉘코드 매직 넘버나 특징적인 문자열을 수색하십시오."
            
        elif data_type == "gubun":
            # 사용자 제공 특수 파서 (gubun.js/URLTools.vbs 로직)
            decoded_text = legacy_gubun_parser(raw_data)
            explanation = "레거시 로그 파서(gubun1)를 통해 추출된 핵심 데이터입니다. 특정 오프셋의 값이 필터링된 결과이므로 무결성을 검증하십시오."
            
        elif data_type == "header":
            decoded_text = raw_data
            explanation = "이메일 헤더 분석 모드입니다. Received 필드의 IP 경로와 SPF/DKIM 결과치를 대조하십시오."
            
        else:
            decoded_text = raw_data
            explanation = "원본 데이터를 그대로 출력합니다. NTAV AI가 특이 패턴을 탐색 중입니다."
            
        return {
            "type": data_type,
            "decoded": decoded_text,
            "ai_explanation": explanation,
            "status": "Success"
        }
    except Exception as e:
        return {
            "status": "Error",
            "message": f"디코딩 실패: {str(e)}"
        }
