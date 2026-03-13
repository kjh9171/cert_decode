import re
from typing import List, Dict

# 점검 항목별 마스터 데이터 (항목번호: {상세정보})
CHECKLIST_MASTER = {
    "1.1": {"title": "패스워드 미존재 계정", "impact": "상", "desc": "모든 계정에 패스워드가 존재해야 합니다.", "cause": "관리 소홀 또는 계정 생성 시 설정 누락", "phenom": "비인가자의 즉각적인 시스템 접근 및 권한 탈취", "solution": "비밀번호가 없는 계정에 패스워드를 설정하거나 불필요한 경우 삭제"},
    "1.2": {"title": "UID 0 계정 점검", "impact": "상", "desc": "root 이외에 UID가 0인 계정이 없어야 합니다.", "cause": "백도어 설치 또는 공격자에 의한 계정 권한 상승", "phenom": "여러 사용자가 관리자 권한을 가짐으로써 책임 추적성 상실 및 보안 붕괴", "solution": "root 이외의 계정에서 UID 0을 제거하거나 계정 삭제"},
    "1.3": {"title": "불필요한 계정 존재", "impact": "하", "desc": "lp, uucp, nuucp 계정이 존재하지 않아야 합니다.", "cause": "기본 설치 시 제거되지 않은 시스템 서비스 계정", "phenom": "불필요한 계정을 통한 잠재적 서비스 취약점 공격 지점 제공", "solution": "사용하지 않는 uucp, lp 등의 계정 삭제"},
    "1.4": {"title": "시스템 계정 쉘 제한", "impact": "중", "desc": "로그인이 필요 없는 계정에 nologin 부여 여부", "cause": "서비스 계정에 범용 쉘(bash 등)이 할당되어 있음", "phenom": "서비스 계정을 이용한 대화형 로그인 및 악성 스크립트 실행 가능", "solution": "시스템 계정의 쉘을 /sbin/nologin 또는 /bin/false로 변경"},
    "1.5": {"title": "/etc/passwd 권한 설정", "impact": "상", "desc": "파일 권한이 644 또는 444여야 합니다.", "cause": "잘못된 권한 설정으로 인한 일반 사용자 수정 가능성", "phenom": "계정 정보의 위변조를 통한 시스템 장악 위험", "solution": "chmod 644 /etc/passwd 명령 실행"},
    "1.6": {"title": "/etc/group 권한 설정", "impact": "중", "desc": "파일 권한이 644 또는 444여야 합니다.", "cause": "그룹 정보의 부적절한 노출 또는 수정 허용", "phenom": "사용자 그룹 권한 상승 공격에 악용될 수 있음", "solution": "chmod 644 /etc/group 명령 실행"},
    "1.7": {"title": "/etc/shadow 권한 설정", "impact": "상", "desc": "파일 권한이 400 또는 600여야 합니다.", "cause": "암호 해시값이 담긴 파일에 대한 과도한 읽기 권한", "phenom": "일반 사용자가 암호 해시를 탈취하여 무차별 대입 공격 수행 가능", "solution": "chmod 600 /etc/shadow 명령 실행"},
    "1.8": {"title": "패스워드 최소 길이 설정", "impact": "중", "desc": "최소 길이가 8자 이상이어야 합니다.", "cause": "단순한 암호 사용 허용으로 인한 취약성", "phenom": "무차별 대입 공격(Brute Force)에 취약함", "solution": "/etc/login.defs에서 PASS_MIN_LEN 8 이상 설정"},
    "1.9": {"title": "패스워드 최대 사용 기간", "impact": "중", "desc": "최대 기간이 90일 이하여야 합니다.", "cause": "장기간 암호 미변경으로 인한 유출 위험 누적", "phenom": "유출된 암호가 영구히 사용될 가능성", "solution": "/etc/login.defs에서 PASS_MAX_DAYS 90 이하 설정"},
    "1.10": {"title": "패스워드 복잡도 규정", "impact": "상", "desc": "영문/숫자/특수문자 포함 여부", "cause": "패스워드 생성 규칙 부재", "phenom": "예측 가능한 단순 암호 사용으로 계정 탈취 위험", "solution": "/etc/pam.d/system-auth 등에서 복잡도 설정 강화"},
    "2.1": {"title": "su 명령어 권한 제한", "impact": "상", "desc": "특정 그룹만 su 명령을 사용할 수 있어야 함", "cause": "일반 사용자의 관리자 권한 획득 시도 허용", "phenom": "인가되지 않은 사용자의 root 권한 탈취 빈번 발생", "solution": "chmod 4750 /bin/su 설정 및 wheel 그룹 활용"},
    "2.2": {"title": "Telnet 서비스 비활성화", "impact": "상", "desc": "Telnet 서비스를 중단하고 SSH 사용 권고", "cause": "암호화되지 않은 평문 통신 서비스 사용", "phenom": "네트워크 스니핑을 통한 아이디/패스워드 유출", "solution": "Telnet 서비스 중지 및 securetty 설정 강화"},
    "2.3": {"title": "FTP root 로그인 제한", "impact": "상", "desc": "FTP 서비스 사용 시 root 접근 금지", "cause": "원격 관리자 직접 접근 허용으로 인한 위험", "phenom": "FTP 서버 탈취 시 관리자 권한 즉각 노출", "solution": "/etc/ftpusers 파일에 root 추가"},
    "2.4": {"title": "Anonymous FTP 제한", "impact": "중", "desc": "익명 FTP 접속이 비활성화되어야 함", "cause": "불특정 다수의 서버 자원 접근 허용", "phenom": "악성 파일 배포 및 서버 저장공간 점유 공격", "solution": "vsftpd.conf에서 anonymous_enable=NO 설정"},
    "2.5": {"title": "세션 타임아웃 설정", "impact": "중", "desc": "300초(5분) 이하로 설정되어야 함", "cause": "자리 비움 시 세션 유지로 인한 무단 사용 위험", "phenom": "물리적으로 접근 가능한 타인에 의한 명령 실행", "solution": "/etc/profile에서 TMOUT=300 설정"},
    "2.6": {"title": "r-services 비활성화", "impact": "상", "desc": "rsh, rlogin, rexec 서비스 중단 권고", "cause": "IP 기반 인증 방식의 취약한 서비스 가동", "phenom": "IP 스푸핑을 통한 원격지 무인증 침투 가능", "solution": "r-command 관련 서비스 비활성화 및 삭제"},
    "2.7": {"title": "NFS 공유 설정 점검", "impact": "상", "desc": "Everyone 공유 등 취약한 설정 배제", "cause": "부적절한 접근 제어로 네트워크 공유 노출", "phenom": "중요 파일 시스템의 비인가 복제 및 위변조", "solution": "/etc/exports 파일을 확인하여 접근 가능 IP 제한"},
    "3.1": {"title": "Crontab 파일 권한", "impact": "상", "desc": "일반 사용자의 쓰기 권한 삭제", "cause": "스케줄러 직접 수정을 통한 악성 코드 실행 가능성", "phenom": "특정 시간대에 자동으로 관리자 권한 백도어 실행", "solution": "chmod 600 /etc/crontab 및 하위 파일 권한 수정"},
    "3.2": {"title": "PATH 경로 설정", "impact": "하", "desc": "현재 디렉토리(.)가 PATH 맨 뒤에 있거나 없어야 함", "cause": "환경 변수 오염을 통한 트로이 목마 공격 위험", "phenom": "명령어 실행 시 의도치 않은 로컬 악성 프로그램 실행", "solution": "PATH 환경 변수에서 '.' 제거 또는 최하단으로 이동"},
    "3.3": {"title": "UMASK 설정", "impact": "중", "desc": "022 이상으로 설정되어야 함", "cause": "파일 생성 시 기본 부여되는 과도한 권한", "phenom": "생성된 데이터가 타인에게 노출되거나 수정됨", "solution": "/etc/profile 또는 .bashrc에서 umask 022 설정"},
    "3.4": {"title": "/etc/hosts 권한", "impact": "중", "desc": "일반 사용자의 쓰기 권한 삭제", "cause": "DNS 정보의 로컬 변조 가능성", "phenom": "잘못된 호스트 연결을 통한 피싱 또는 데이터 유출", "solution": "chmod 644 /etc/hosts 설정"},
    "3.5": {"title": "xinetd.conf 권한", "impact": "중", "desc": "일반 사용자의 쓰기 권한 삭제", "cause": "네트워크 서비스 설정의 무단 변경 위험", "phenom": "비인가 서비스 가동 및 침투 경로 확보", "solution": "chmod 600 /etc/xinetd.conf 설정"},
    "3.6": {"title": "/etc/hosts.equiv 권한", "impact": "상", "desc": "일반 사용자의 쓰기 권한 삭제", "cause": "트러스트 관계 악용을 통한 무인증 로그인", "phenom": "망 전체의 보안이 도미노처럼 붕괴될 위험", "solution": "chmod 600 /etc/hosts.equiv 또는 파일 삭제"},
    "4.1": {"title": "/etc/services 권한", "impact": "하", "desc": "일반 사용자의 쓰기 권한 삭제", "cause": "포트 번호 정보의 변조 가능성", "phenom": "서비스 포트 매핑 오류 유도 및 가용성 저해", "solution": "chmod 644 /etc/services 설정"},
    "4.2": {"title": "불필요한 서비스 중지", "impact": "상", "desc": "finger, tftp 등 취약한 서비스 비활성화", "cause": "사용하지 않는 잠재적 위험 서비스 가동", "phenom": "알려진 취약점을 통한 원격 코드 실행 공격 지점 노출", "solution": "불필요한 서비스 프로세스 킬 및 설정 비활성화"},
    "4.3": {"title": "서비스 배너 정보 숨김", "impact": "하", "desc": "배너에 OS 버전 등 정보가 노출되지 않아야 함", "cause": "서버 정보가 외부에 투명하게 공개됨", "phenom": "공격자가 특정 버전에 최적화된 공격 도구 선정 가능", "solution": "/etc/issue, SMTP/FTP banner 설정 변경"},
    "4.4": {"title": "SNMP Community 취약점", "impact": "중", "desc": "public, private 등 기본값 사용 금지", "cause": "보안 설정이 되지 않은 네트워크 모니터링 서비스", "phenom": "커뮤니티 문자열 탈취를 통한 시스템 정보 유출", "solution": "SNMP 사용 시 Community String을 난해하게 변경"},
    "5.1": {"title": "로그 기록 설정 확인", "impact": "상", "desc": "중요 시스템 이벤트 로깅 설정 여부", "cause": "감사 추적을 위한 로깅 정책 부재", "phenom": "보안 사고 발생 시 원인 분석 및 대응 불가능", "solution": "rsyslog.conf에서 중요 Facility/Level 로깅 설정"},
    "5.2": {"title": "접속 기록(authpriv) 설정", "impact": "상", "desc": "사용자 접속 및 인증 관련 로그 기록", "cause": "인증 시도 및 실패 기록 누락", "phenom": "부인 방지 불가 및 비인가 시도 탐지 누락", "solution": "rsyslog.conf에 authpriv.info /var/log/secure 설정"},
    "5.3": {"title": "정기적 보안 패치 정책", "impact": "상", "desc": "최신 보안 패치 적용 프로세스 존재 여부", "cause": "관리 체계 미비로 인한 구형 취약점 방치", "phenom": "알려진 1-day 취약점에 의한 즉각적인 시스템 수중 낙하", "solution": "주기적인 yum/dnf update 및 보안 권고문 모니터링"}
}

class CentOSAuditParser:
    @staticmethod
    def parse_text(content: str) -> Dict:
        """
        CentOS 쉘 스크립트 실행 결과 텍스트를 파싱하여 구조화된 데이터로 변환합니다.
        """
        results = []
        host = "Unknown"
        
        # 호스트 정보 추출 시도
        host_match = re.search(r"-------------------- uname -a --------------------------\s*\n(.*?)\n", content, re.S)
        if host_match:
            host = host_match.group(1).split()[1] if len(host_match.group(1).split()) > 1 else "CentOS-Server"

        # TOTAL 섹션 찾기
        total_section_match = re.search(r" === TOTAL ===\n(.*?)(?:\n\n|\Z)", content, re.S)
        if total_section_match:
            total_content = total_section_match.group(1)
            line_pattern = re.compile(r"(\d+\.\d+)\s+(GOOD|BAD|N/A)")
            for match in line_pattern.finditer(total_content):
                item_id, item_result = match.groups()
                master = CHECKLIST_MASTER.get(item_id, {})
                
                results.append({
                    "id": item_id,
                    "title": master.get("title", f"점검 항목 {item_id}"),
                    "result": "Pass" if item_result == "GOOD" else ("Fail" if item_result == "BAD" else "N/A"),
                    "impact": master.get("impact", "중"),
                    "desc": master.get("desc", ""),
                    "cause": master.get("cause", "알 수 없는 원인"),
                    "phenom": master.get("phenom", "이상 징후 없음"),
                    "solution": master.get("solution", "수동 확인 필요")
                })
        
        return {
            "host": host,
            "results": results
        }

def calculate_integrity_score(results):
    """
    구조화된 결과를 바탕으로 무결성 점수를 계산합니다.
    """
    if not results:
        return 0
    
    # 가중치 설정
    weights = {"상": 15, "중": 10, "하": 5}
    total_penalty = 0
    
    for r in results:
        if r.get("result") == "Fail":
            penalty = weights.get(r.get("impact", "중"), 10)
            total_penalty += penalty
            
    return max(0, 100 - total_penalty)

def generate_ai_one_liner(score):
    if score == 100:
        return "완벽한 성벽은 없습니다. 지금 이 순간에도 적의 침투는 계속되고 있습니다."
    elif score >= 80:
        return "안정적인 상태이나, 미세한 균열이 거대한 붕괴의 시작일 수 있습니다."
    elif score >= 60:
        return "신뢰의 경계가 무너졌습니다. 즉각적인 요새 보강이 필요합니다."
    else:
        return "시스템이 적의 수중에 떨어지기 직전입니다. 모든 연결을 끊고 전면 재검토하십시오."
