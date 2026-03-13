import json

def calculate_integrity_score(results):
    """
    점검 결과 리스트를 분석하여 0~100점 사이의 무결성 점수를 계산합니다.
    """
    if not results:
        return 0
        
    weights = {"상": 15, "중": 10, "하": 5}
    total_fine = 0
    
    for r in results:
        if r.get("result") == "Fail":
            impact = r.get("impact", "중")
            total_fine += weights.get(impact, 10)
            
    score = max(0, 100 - total_fine)
    return score

def generate_ai_one_liner(score):
    """
    무결성 점수에 따른 제로 트러스트 관점의 필살 한줄평 생성
    """
    if score == 100:
        return "완벽한 성벽은 없습니다. 지금 이 순간에도 적의 침투는 계속되고 있습니다."
    elif score >= 80:
        return "안정적인 상태이나, 미세한 균열이 거대한 붕괴의 시작일 수 있습니다."
    elif score >= 60:
        return "신뢰의 경계가 무너졌습니다. 즉각적인 요새 보강이 필요합니다."
    else:
        return "시스템이 적의 수중에 떨어지기 직전입니다. 모든 연결을 끊고 전면 재검토하십시오."
