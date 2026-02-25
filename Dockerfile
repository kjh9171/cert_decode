# 가볍고 보안에 강한 Nginx Alpine 이미지를 기반으로 사용합니다
FROM nginx:alpine

# 우리가 작성한 index.html 파일을 Nginx의 웹 루트 디렉토리로 복사합니다
COPY index.html /usr/share/nginx/html/index.html

# Nginx가 80번 포트에서 요청을 대기하도록 설정합니다
EXPOSE 80

# Nginx 서버를 백그라운드가 아닌 포어그라운드에서 실행하여 컨테이너가 유지되도록 합니다
CMD ["nginx", "-g", "daemon off;"]
