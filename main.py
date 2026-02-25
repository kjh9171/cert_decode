from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import paramiko
import hashlib
import pefile
import email
from email.policy import default
import io
import os
import re

app = FastAPI()

# 정적 파일 서빙 설정
if not os.path.exists("static"):
    os.makedirs("static")

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    return FileResponse('static/index.html')

# ---------------------------------------------------------
# 1. 시스템 점검 엔진
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
        if req.private_key:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(req.private_key))
            client.connect(req.host, port=req.port, username=req.username, pkey=pkey, timeout=10)
        else:
            client.connect(req.host, port=req.port, username=req.username, password=req.password, timeout=10)
            
        stdin, stdout, stderr = client.exec_command("uname -a")
        os_info = stdout.read().decode().strip()
        results.append({"cat": "기본", "title": "OS 확인", "desc": os_info[:50], "result": "양호", "score": 100, "guide": "안전함"})

        # 추가 점검 항목 (생략 방지를 위해 하드코딩된 체크리스트와 병합 가능)
        # 실제 점검 로직은 여기에 더 추가될 수 있습니다.
        
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"SSH 연결 실패: {str(e)}"})
    finally:
        client.close()
    return {"host": req.host, "score": score, "results": results}

# ---------------------------------------------------------
# 2. 파일 분석 엔진
# ---------------------------------------------------------
@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        
        res = {
            "filename": file.filename,
            "size": len(content),
            "md5": md5,
            "sha256": sha256,
            "type": "General Data",
            "verdict": "Safe (General)",
            "details": "위험 징후가 발견되지 않았습니다."
        }

        # 확장자 기반 1차 판별
        ext = file.filename.split('.')[-1].lower()
        if ext in ['exe', 'dll', 'sys', 'scr']:
            res["type"] = "Windows Executable"
            try:
                pe = pefile.PE(data=content)
                res["verdict"] = "Clean (PE)"
                # 위험 API 체크
                suspicious = [b"VirtualAlloc", b"CreateRemoteThread", b"WriteProcessMemory"]
                found = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name in suspicious: found.append(imp.name.decode())
                if found:
                    res["verdict"] = "Suspicious (High Risk)"
                    res["details"] = f"위험 API 감지: {', '.join(found)}"
            except:
                res["verdict"] = "Corrupted PE"
        
        return res
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ---------------------------------------------------------
# 3. 이메일 분석 엔진
# ---------------------------------------------------------
class EmailAnalysisRequest(BaseModel):
    header_text: str

@app.post("/api/analyze/email")
async def analyze_email(req: EmailAnalysisRequest):
    try:
        msg = email.message_from_string(req.header_text, policy=default)
        hops = []
        received = msg.get_all("Received", [])
        for r in received:
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', r)
            hops.append({"raw": r[:100], "ips": ips})
            
        return {
            "subject": msg.get("Subject", "No Subject"),
            "from": msg.get("From", "Unknown"),
            "hops": hops,
            "auth_status": msg.get("Authentication-Results", "None"),
            "verdict": "Normal" if "fail" not in str(msg.get("Authentication-Results")).lower() else "Phishing Suspected"
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
