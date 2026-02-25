from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import paramiko
import hashlib
import pefile
import email
from email.policy import default
import io
import os
import re

app = FastAPI()

# 정적 파일 서빙 (HTML)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    return FileResponse('static/index.html')

# ---------------------------------------------------------
# 1. 시스템 점검 엔진 (SSH 기반)
# ---------------------------------------------------------
class SystemCheckRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None

@app.post("/api/system/check")
async def check_system(req: SystemCheckRequest):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    results = []
    score = 100
    
    try:
        # 연결 시도
        if req.private_key:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(req.private_key))
            client.connect(req.host, port=req.port, username=req.username, pkey=pkey, timeout=5)
        else:
            client.connect(req.host, port=req.port, username=req.username, password=req.password, timeout=5)
            
        # 1. OS 정보 확인
        stdin, stdout, stderr = client.exec_command("uname -a")
        os_info = stdout.read().decode().strip()
        results.append({
            "cat": "기본 정보", "title": "OS 버전 확인", 
            "desc": f"연결 성공: {os_info[:50]}...", "result": "양호", "score": 100,
            "guide": "최신 커널 버전을 유지하십시오."
        })

        # 2. Root 로그인 허용 여부 (Linux)
        stdin, stdout, stderr = client.exec_command("grep 'PermitRootLogin' /etc/ssh/sshd_config")
        ssh_config = stdout.read().decode().strip()
        if "yes" in ssh_config:
            results.append({
                "cat": "계정 보안", "title": "Root 원격 접속 제한", 
                "desc": "PermitRootLogin이 Yes로 설정되어 있습니다.", "result": "취약", "score": 0,
                "guide": "/etc/ssh/sshd_config에서 PermitRootLogin no 로 변경 후 sshd 재시작"
            })
            score -= 20
        else:
            results.append({
                "cat": "계정 보안", "title": "Root 원격 접속 제한", 
                "desc": "Root 직접 접속이 제한되어 있습니다.", "result": "양호", "score": 100,
                "guide": "현재 설정을 유지하십시오."
            })

        # 3. 불필요한 포트 확인 (netstat 시뮬레이션 - 권한 문제로 단순화)
        stdin, stdout, stderr = client.exec_command("netstat -tuln | grep :23") # Telnet
        telnet_check = stdout.read().decode().strip()
        if telnet_check:
            results.append({
                "cat": "서비스 관리", "title": "Telnet 서비스", 
                "desc": "보안에 취약한 Telnet(23) 포트가 열려있습니다.", "result": "취약", "score": 0,
                "guide": "Telnet 서비스를 중지하고 SSH를 사용하십시오."
            })
            score -= 20
        else:
            results.append({
                "cat": "서비스 관리", "title": "Telnet 서비스", 
                "desc": "Telnet 서비스가 감지되지 않았습니다.", "result": "양호", "score": 100,
                "guide": "보안 프로토콜을 계속 사용하십시오."
            })

        # 4. 패스워드 정책 (shadow 파일 접근 권한 확인)
        # 실제 점검에서는 루트 권한이 필요하므로, 여기서는 권한 확인으로 대체
        stdin, stdout, stderr = client.exec_command("id -u")
        uid = stdout.read().decode().strip()
        if uid == "0":
             results.append({
                "cat": "권한 관리", "title": "현재 접속 권한", 
                "desc": "Root(관리자) 권한으로 접속되었습니다. 작업에 주의하십시오.", "result": "주의", "score": 80,
                "guide": "일상적인 점검은 일반 계정을 사용하십시오."
            })
        else:
             results.append({
                "cat": "권한 관리", "title": "현재 접속 권한", 
                "desc": "일반 사용자 권한입니다. 시스템 파일을 점검할 수 없습니다.", "result": "양호", "score": 100,
                "guide": "필요 시 sudo를 사용하십시오."
            })

    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"연결 실패: {str(e)}"})
    finally:
        client.close()

    # 점수 보정
    final_score = max(0, min(100, score))
    
    return {"host": req.host, "score": final_score, "results": results}


# ---------------------------------------------------------
# 2. 파일 분석 엔진
# ---------------------------------------------------------
@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    
    # 해시 계산
    md5 = hashlib.md5(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()
    
    analysis_result = {
        "filename": file.filename,
        "size": len(content),
        "md5": md5,
        "sha256": sha256,
        "type": "Unknown",
        "verdict": "Safe"
    }

    # PE 파일(Windows 실행파일) 분석 시도
    try:
        pe = pefile.PE(data=content)
        analysis_result["type"] = "Windows PE Executable"
        # 간단한 악성 징후: 섹션 이름이 이상하거나, 임포트 함수가 의심스러운 경우
        suspicious_imports = [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread"]
        detected_suspicious = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name in suspicious_imports:
                        detected_suspicious.append(imp.name.decode())
        
        if detected_suspicious:
            analysis_result["verdict"] = "Suspicious (High Risk)"
            analysis_result["details"] = f"메모리 조작 API 감지: {', '.join(detected_suspicious)}"
        else:
            analysis_result["verdict"] = "Clean (No Obvious Threats)"
            analysis_result["details"] = "일반적인 PE 구조입니다."
            
    except pefile.PEFormatError:
        analysis_result["type"] = "Data / Script / Document"
        analysis_result["details"] = "실행 파일 포맷이 아닙니다."

    return analysis_result


# ---------------------------------------------------------
# 3. 이메일 헤더 분석 엔진
# ---------------------------------------------------------
class EmailAnalysisRequest(BaseModel):
    header_text: str

@app.post("/api/analyze/email")
async def analyze_email(req: EmailAnalysisRequest):
    try:
        msg = email.message_from_string(req.header_text, policy=default)
        
        headers = []
        for key, value in msg.items():
            headers.append({"key": key, "val": value})
            
        # 홉(Received) 분석
        received = msg.get_all("Received", [])
        hops = []
        for r in received:
            # IP 추출 (간단한 정규식)
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', r)
            hops.append({"raw": r[:60]+"...", "ips": ips})

        # 인증 결과 추출
        auth_results = msg.get("Authentication-Results", "정보 없음")
        
        verdict = "Normal"
        if "fail" in auth_results.lower():
            verdict = "Spam/Phishing Detected"
        
        return {
            "subject": msg.get("Subject", "제목 없음"),
            "from": msg.get("From", "발신자 없음"),
            "hops": hops,
            "auth_status": auth_results,
            "headers": headers[:10], # 너무 많으면 10개만
            "verdict": verdict
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"파싱 오류: {str(e)}"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
