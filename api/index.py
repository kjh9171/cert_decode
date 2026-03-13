import sys
import os

# backend 디렉토리를 경로에 추가하여 패키지 임포트 가능하게 설정
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from backend.main import app

# Vercel은 이 파일을 서버리스 함수로 실행하며 app 객체를 노출해야 합니다.
handler = app
