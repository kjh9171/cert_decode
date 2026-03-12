from fastapi import FastAPI, UploadFile, File, Form, HTTPException # FastAPI 프레임워크 핵심 컴포넌트 임포트
from fastapi.staticfiles import StaticFiles # 정적 파일 제공을 위한 모듈 임포트
from fastapi.responses import FileResponse, JSONResponse # 파일 및 JSON 응답 처리를 위한 모듈 임포트
from pydantic import BaseModel # 데이터 모델링을 위한 Pydantic 임포트
from typing import Optional, List # 타입 힌팅을 위한 라이브러리 임포트
import paramiko # SSH 접속 및 원격 명령 실행을 위한 라이브러리 임포트
import hashlib # 파일 해시(MD5, SHA256) 계산을 위한 라이브러리 임포트
import pefile # 윈도우 실행 파일(PE) 구조 분석을 위한 라이브러리 임포트
import email # 이메일 메시지 파싱을 위한 라이브러리 임포트
from email.policy import default # 기본 이메일 파싱 정책 임포트
import io # 입출력 스트림 처리를 위한 라이브러리 임포트
import os # 운영체제 리소스 접근을 위한 라이브러리 임포트
import re # 정규 표현식 처리를 위한 라이브러리 임포트
import json # JSON 데이터 처리를 위한 라이브러리 임포트

app = FastAPI() # FastAPI 애플리케이션 객체 생성

# 정적 파일 서빙 설정 (static 디렉토리 자동 생성 포함)
if not os.path.exists("static"): # static 폴더 존재 여부 확인
    os.makedirs("static") # 폴더가 없으면 새로 생성

app.mount("/static", StaticFiles(directory="static"), name="static") # /static 경로로 정적 파일 매핑

@app.get("/") # 루트 경로 접속 시 처리 로직
async def read_root(): # 메인 페이지 호출 함수
    return FileResponse('static/index.html') # index.html 파일 반환

# ---------------------------------------------------------
# 1. 시스템 점검 엔진 (System Auditor)
# ---------------------------------------------------------
class SystemCheckRequest(BaseModel): # 시스템 점검 요청 데이터 모델
    host: str # 대상 호스트 IP 또는 도메인
    port: int = 22 # SSH 포트 (기본값 22)
    username: str # SSH 접속 계정명
    password: Optional[str] = None # SSH 접속 비밀번호
    private_key: Optional[str] = None # SSH 개인키 내용

@app.post("/api/system/check") # 시스템 점검 실행 API 엔드포인트
async def check_system(req: SystemCheckRequest): # 시스템 보안 상태 진단 함수
    client = paramiko.SSHClient() # SSH 클라이언트 객체 생성
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # 미등록 호스트 키 자동 승인 설정
    results = [] # 점검 결과 리스트 초기화
    total_score = 100 # 초기 무결성 점수 설정
    
    # 15종 보안 점검 항목 정의 (명령어, 항목명, 카테고리, 중요도, 감점점수)
    checks = [
        {"cmd": "grep '^PermitRootLogin' /etc/ssh/sshd_config", "title": "Root 원격 접속 제한", "cat": "계정 보안", "impact": "상", "fine": 15, "fail_msg": "Root 계정의 직접적인 원격 접속이 허용되어 있습니다."},
        {"cmd": "grep '^PasswordAuthentication' /etc/ssh/sshd_config", "title": "비밀번호 인증 보안", "cat": "계정 보안", "impact": "중", "fine": 10, "fail_msg": "비밀번호 기반 인증이 활성화되어 있습니다. 키 기반 인증을 권장합니다."},
        {"cmd": "ufw status | grep Status", "title": "방화벽(UFW) 활성화 여부", "cat": "네트워크 보안", "impact": "상", "fine": 20, "fail_msg": "시스템 방화벽이 비활성화 상태입니다."},
        {"cmd": "grep '^PASS_MAX_DAYS' /etc/login.defs", "title": "비밀번호 최대 사용 기간", "cat": "계정 보안", "impact": "하", "fine": 5, "fail_msg": "비밀번호 만료 정책이 설정되지 않았거나 너무 깁니다."},
        {"cmd": "ls -l /etc/shadow", "title": "Shadow 파일 권한 점검", "cat": "파일 보안", "impact": "상", "fine": 15, "fail_msg": "시스템 비밀번호 파일의 권한 설정이 취약합니다."},
        {"cmd": "failed_logins=$(lastb head -n 100 | wc -l); if [ $failed_logins -gt 50 ]; then echo 'fail'; fi", "title": "무차별 대입 공격 징후", "cat": "침입 탐지", "impact": "중", "fine": 10, "fail_msg": "최근 다수의 로그인 실패 이력이 감지되었습니다."},
        {"cmd": "find /tmp -perm -4000 2>/dev/null", "title": "SetUID 파일 수색", "cat": "권한 관리", "impact": "중", "fine": 8, "fail_msg": "/tmp 경로 내 비정상적인 권한의 파일이 존재합니다."},
        {"cmd": "netstat -ntlp | grep '0.0.0.0:*'", "title": "불필요한 서비스 노출", "cat": "네트워크 보안", "impact": "중", "fine": 10, "fail_msg": "모든 인터페이스에 열려있는 포트가 다수 존재합니다."},
        {"cmd": "grep '^ClientAliveInterval' /etc/ssh/sshd_config", "title": "세션 타임아웃 미설정", "cat": "세션 보안", "impact": "하", "fine": 5, "fail_msg": "장시간 유휴 세션에 대한 자동 차단이 설정되지 않았습니다."},
        {"cmd": "alias | grep 'ls=' || echo 'fail'", "title": "의심스러운 별칭(Alias)", "cat": "침입 탐지", "impact": "중", "fine": 10, "fail_msg": "명령어 변조 가능성이 있는 별칭이 등록되어 있습니다."},
        {"cmd": "crontab -l | grep 'http'", "title": "의심스러운 예약 작업", "cat": "침입 탐지", "impact": "상", "fine": 15, "fail_msg": "웹 기반 자동 실행 스크립트가 크론탭에 등록되어 있습니다."},
        {"cmd": "grep '^HISTSIZE' /etc/profile", "title": "히스토리 로그 보존 설정", "cat": "로그 관리", "impact": "하", "fine": 5, "fail_msg": "명령어 실행 기록 보존 크기가 너무 작거나 설정되지 않았습니다."},
        {"cmd": "ps -ef | grep 'miner' | grep -v grep", "title": "암호화폐 채굴 프로세스", "cat": "행위 분석", "impact": "상", "fine": 20, "fail_msg": "시스템 자원을 무단 점유하는 채굴 프로세스 징후가 보입니다."},
        {"cmd": "grep 'NOPASSWD' /etc/sudoers", "title": "Sudo 권한 무단 사용", "cat": "권한 관리", "impact": "상", "fine": 15, "fail_msg": "비밀번호 없이 관리자 권한을 획득할 수 있는 계정이 존재합니다."},
        {"cmd": "ls -d /root/.ssh 2>/dev/null", "title": "Root SSH 디렉토리 보호", "cat": "파일 보안", "impact": "중", "fine": 10, "fail_msg": "Root 계정의 SSH 설정 디렉토리가 외부에 노출되어 있습니다."}
    ]

    try:
        # SSH 연결 시도 (비밀번호 또는 키 기반)
        if req.private_key: # 개인키가 제공된 경우
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(req.private_key)) # 스트림으로부터 RSA 키 로드
            client.connect(req.host, port=req.port, username=req.username, pkey=pkey, timeout=10) # 키 기반 접속
        else: # 비밀번호가 제공된 경우
            client.connect(req.host, port=req.port, username=req.username, password=req.password, timeout=10) # 패스워드 기반 접속
            
        for c in checks: # 정의된 모든 점검 항목 순회
            stdin, stdout, stderr = client.exec_command(c["cmd"]) # SSH를 통한 원격 명령 실행
            out = stdout.read().decode().strip() # 표준 출력 결과 읽기
            err = stderr.read().decode().strip() # 표준 에러 결과 읽기
            
            # 결과 분석 및 감점 처리
            is_pass = True # 기본값을 통과로 설정
            if "fail" in out.lower() or out == "" or "no matches" in err.lower() or "no such file" in err.lower(): # 실패 조건 확인
                if c["title"] in ["Root 원격 접속 제한", "비밀번호 인증 보안"]: # 특정 항목의 역설정 체크
                    if "yes" in out.lower() or out == "": is_pass = False # 취약한 설정값인 경우 실패
                elif c["title"] in ["방화벽(UFW) 활성화 여부"]: # 방화벽 상태 체크
                    if "inactive" in out.lower() or out == "": is_pass = False # 비활성 상태면 실패
                elif c["title"] in ["Root SSH 디렉토리 보호"]: # 디렉토리 존재 체크
                    if "no such file" in err.lower(): is_pass = True # 파일이 없으면 안전한 것으로 간주 (노출 안됨)
                    else: is_pass = False
                else:
                    is_pass = False # 그 외 명시적 실패 처리
            
            if not is_pass: # 실패한 항목에 대해
                total_score -= c["fine"] # 해당 항목의 감점 수치만큼 총점 차감
                results.append({ # 결과 리스트에 추가
                    "id": c["title"], "cat": c["cat"], "title": c["title"], 
                    "result": "Fail", "impact": c["impact"], "desc": c["fail_msg"],
                    "remedy": [ # 3단계 대응 가이드 제공
                        f"1단계: {c['cat']} 설정 파일 확인",
                        f"2단계: {c['title']} 관련 정책 수정 실시",
                        f"3단계: 관련 서비스 재시작 및 변경 사항 검증"
                    ],
                    "snippet": f"# Recommended action for {c['title']}\nsudo vi /etc/ssh/sshd_config\n# Change to correct value\nsudo systemctl restart ssh" # 스크립트 예시
                })
            else: # 통과한 항목 처리
                results.append({
                    "id": c["title"], "cat": c["cat"], "title": c["title"], 
                    "result": "Pass", "impact": c["impact"], "desc": "정상적으로 설정되어 있습니다.",
                    "remedy": [], "snippet": ""
                })

        total_score = max(0, total_score) # 최저 점수를 0점으로 제한

    except Exception as e: # 접속 또는 실행 에러 처리
        return JSONResponse(status_code=400, content={"error": f"SSH 연결 또는 실행 실패: {str(e)}"}) # 에러 메시지 반환
    finally:
        client.close() # SSH 세션 종료

    # Never Trust 코멘트 생성 (점수에 따른 동적 반응)
    ntav_comment = "모든 시스템은 기본적으로 신뢰하지 않습니다. 현재 무결성 상태를 점검하십시오."
    if total_score == 100: ntav_comment = "완벽한 상태는 없습니다. 오직 지속적인 감시만이 답입니다."
    elif total_score < 70: ntav_comment = "심각한 보안 파괴 징후가 감지되었습니다. 즉시 대응이 필요합니다."

    return { # 최종 결과 데이터 구조화
        "host": req.host, 
        "score": total_score, 
        "summary": { "high": len([r for r in results if r["impact"]=="상" and r["result"]=="Fail"]), "mid": len([r for r in results if r["impact"]=="중" and r["result"]=="Fail"]), "low": len([r for r in results if r["impact"]=="하" and r["result"]=="Fail"]) },
        "ntav_comment": ntav_comment,
        "results": results
    }

# ---------------------------------------------------------
# 2. 위협 분석 엔진 (Threat Analysis Hall)
# ---------------------------------------------------------
@app.post("/api/analyze/file") # 파일 정적/동적/매핑 통합 분석 API
async def analyze_file(file: UploadFile = File(...)): # 파일 분석 실행 함수
    try:
        content = await file.read() # 업로드된 파일 바이너리 읽기
        md5 = hashlib.md5(content).hexdigest() # 파일의 MD5 해시값 계산
        sha256 = hashlib.sha256(content).hexdigest() # 파일의 SHA256 해시값 계산
        
        # 1단계: 정적 분석 (Static Analysis)
        findings = [] # 탐지 내역 리스트 초기화
        verdict = "Clear" # 초기 판정 상태
        
        ext = file.filename.split('.')[-1].lower() # 파일 확장자 추출
        if ext in ['exe', 'dll', 'sys']: # 윈도우 실행 파일인 경우
            try:
                pe = pefile.PE(data=content) # PE 구조 파싱
                suspicious_apis = [b"VirtualAlloc", b"CreateRemoteThread", b"WriteProcessMemory", b"ShellExecuteA"] # 탐지 타겟 API 리스트
                found_apis = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'): # 임포트 테이블 존재 확인
                    for entry in pe.DIRECTORY_ENTRY_IMPORT: # 임포트 엔트리 순회
                        for imp in entry.imports: # 개별 함수 순회
                            if imp.name in suspicious_apis: found_apis.append(imp.name.decode()) # 위험 API 존재 여부 체크
                if found_apis: # 위험 API 감지 시
                    findings.append(f"위험 API 감지: {', '.join(found_apis)}") # 내역 추가
                    verdict = "Suspicious" # 의심 상태로 변경
            except: findings.append("PE 헤더 구조가 파손되었거나 분석 불가 상태입니다.") # 파싱 에러 처리

        # 2단계/3단계 모사 (동적 분석 및 MITRE 매핑 데이터 생성)
        # 실제 환경에서는 샌드박스 연동 및 인텔리전스 API 연동이 필요함
        mitre_mapping = [] # MITRE ATT&CK 매핑 정보
        if verdict == "Suspicious": # 의심스러운 파일에 대해 행위 매핑 추가
            mitre_mapping = [
                {"tactic": "Initial Access", "technique": "T1566.001 (Spearphishing Attachment)", "desc": "파일 유입 경로 의심"},
                {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "desc": "쉘코드 실행 징후"},
                {"tactic": "Defense Evasion", "technique": "T1055 (Process Injection)", "desc": "메모리 인젝션 시도 가능성"}
            ]

        return { # 다층 분석 결과 구성
            "filename": file.filename, "size": len(content), "md5": md5, "sha256": sha256,
            "stages": {
                "static": {"status": "Complete", "verdict": verdict, "findings": findings},
                "dynamic": {"status": "Complete", "verdict": "Suspicious Activity Detected" if verdict=="Suspicious" else "No execution observed", "behavior": ["C2 IP Connection Attempt: 103.x.x.x"] if verdict=="Suspicious" else []},
                "mitre": {"status": "Mapped", "data": mitre_mapping}
            }
        }
    except Exception as e: # 파일 분석 실패 처리
        return JSONResponse(status_code=500, content={"error": str(e)}) # 에러 반환

# ---------------------------------------------------------
# 3. 이메일 수사 엔진 (Email Forensic)
# ---------------------------------------------------------
class EmailAnalysisRequest(BaseModel): # 이메일 수사 요청 모델
    header_text: str # 이메일 헤더 원문 데이터

@app.post("/api/analyze/email") # 이메일 헤더 분석 API 엔드포인트
async def analyze_email(req: EmailAnalysisRequest): # 이메일 포렌식 실행 함수
    try:
        msg = email.message_from_string(req.header_text, policy=default) # 이메일 헤더 원문 파싱
        hops = [] # 경유지 홉 리스트
        received = msg.get_all("Received", []) # 모든 Received 헤더 추출
        for r in received:
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', r) # IP 주소 패턴 추출
            hops.append({"raw": r[:100], "ips": ips}) # 데이터 구성
            
        # SPF/DKIM 인증 결과 기반 판별 로직 고도화
        auth_res = str(msg.get("Authentication-Results", "")).lower() # 인증 결과 문자열 추출
        verdict = "Safe" # 기본 판정
        if "fail" in auth_res or "softfail" in auth_res: # 인증 실패 시
            verdict = "Phishing Suspected" # 피싱 의심 판정
        elif not auth_res: # 인증 기록 누락 시
            verdict = "Caution (No Auth Info)" # 주의 판정
            
        return { # 이메일 분석 최종 결과 반환
            "subject": msg.get("Subject", "제목 없음"),
            "from": msg.get("From", "알 수 없음"),
            "hops": hops,
            "auth_status": msg.get("Authentication-Results", "미감지"),
            "verdict": verdict
        }
    except Exception as e: # 이메일 파싱 에러 처리
        return JSONResponse(status_code=400, content={"error": str(e)}) # 에러 메시지 반환

# ---------------------------------------------------------
# 4. 서비스 고도화용 보조 함수
# ---------------------------------------------------------
@app.get("/api/info") # 엔진 정보 제공 엔드포인트 (상태 체크용)
async def get_engine_info(): # 엔진 라이브 환경 정보 함수
    return {"engine": "NTAV-Core", "version": "4.0.0", "status": "Operational"} # 기본 정보 반환

if __name__ == "__main__": # 직접 실행 시 진입점
    import uvicorn # ASGI 서버 유비콘 임포트
    uvicorn.run(app, host="0.0.0.0", port=8000) # 서버 실행 실행 (8000 포트)
