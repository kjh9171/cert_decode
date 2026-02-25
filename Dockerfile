# 경량화된 파이썬 이미지 사용
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 패키지 설치를 위한 requirements.txt 복사
COPY requirements.txt .

# 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY main.py .
# 정적 파일(HTML 등)을 위한 디렉토리 생성 및 복사
RUN mkdir static
COPY index.html static/

# FastAPI 기본 포트 노출
EXPOSE 8000

# 서버 실행 (메인 앱)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
