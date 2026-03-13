import hashlib
import pefile
from typing import List, Dict

def analyze_file_threat(filename: str, content: bytes) -> Dict:
    """
    파일의 정적 분석 및 MITRE ATT&CK 매핑을 수행합니다.
    """
    md5 = hashlib.md5(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()
    
    findings = []
    verdict = "Clear"
    mitre_mapping = []
    
    ext = filename.split('.')[-1].lower()
    
    # 윈도우 실행 파일 분석 (PE)
    if ext in ['exe', 'dll', 'sys']:
        try:
            pe = pefile.PE(data=content)
            suspicious_apis = {
                b"VirtualAlloc": "T1055 (Process Injection)",
                b"CreateRemoteThread": "T1055 (Process Injection)",
                b"WriteProcessMemory": "T1055 (Process Injection)",
                b"ShellExecuteA": "T1059 (Command and Scripting Interpreter)",
                b"GetProcAddress": "T1027 (Obfuscated Files or Information)"
            }
            
            found_apis = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name in suspicious_apis:
                            found_apis.append(imp.name.decode())
                            t_code = suspicious_apis[imp.name]
                            if not any(m['technique'] == t_code for m in mitre_mapping):
                                mitre_mapping.append({
                                    "tactic": "Execution/Defense Evasion",
                                    "technique": t_code,
                                    "desc": f"위험 API 발견: {imp.name.decode()}"
                                })
            
            if found_apis:
                findings.append(f"의심스러운 임포트 API 감지: {', '.join(found_apis)}")
                verdict = "Suspicious"
        except Exception:
            findings.append("파일 구조 분석 실패 (손상된 PE 헤더)")
            verdict = "Broken"

    return {
        "filename": filename,
        "md5": md5,
        "sha256": sha256,
        "verdict": verdict,
        "findings": findings,
        "mitre_mapping": mitre_mapping,
        "analysis_type": "Static + MITRE Mapping"
    }
