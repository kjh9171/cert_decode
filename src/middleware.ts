import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // 인증을 확인할 세션 쿠키 이름
  const sessionCookie = request.cookies.get('ntav_session');

  // 보호할 경로(대시보드 루트)에 접근하는데, 인증 쿠키가 없다면 로그인으로 포워딩
  if (request.nextUrl.pathname === '/' && !sessionCookie) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // 로그인 페이지 접근 시, 이미 인증 쿠키가 있다면 대시보드로 다시 포워딩
  if (request.nextUrl.pathname.startsWith('/login') && sessionCookie) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  // 그 외 API, 정적 파일 등은 통과
  return NextResponse.next();
}

// 미들웨어 매칭 설정 (대시보드 라우트와 로그인 라우트에서만 실행)
export const config = {
  matcher: ['/', '/login'],
};
