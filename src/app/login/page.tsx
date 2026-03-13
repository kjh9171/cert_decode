"use client";

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
// Framer Motion: 고성능 애니메이션 라이브러리로 보안 플랫폼의 역동적인 UI 구현
import { motion, AnimatePresence } from 'framer-motion';
// Lucide React: 일관성 있는 디자인 언어를 위한 보안/시스템 아이콘 세트
import { Shield, Lock, User, Mail, ChevronRight, Activity, Eye, EyeOff } from 'lucide-react';

/**
 * NTAV SecuLab V2.0 - 통합 인증(Auth) 컴포넌트
 * 'Never Trust, Always Verify' 철학을 반영하여 견고하고 전문적인 UI 제공
 */
export default function LoginPage() {
  const router = useRouter();

  // 모드 전환 상태 (login / signup)
  const [mode, setMode] = useState<'login'|'signup'>('login');
  // 비밀번호 가시성 토글 상태
  const [showPassword, setShowPassword] = useState(false);
  // 로딩 상태 (서버 통신 시뮬레이션)
  const [isLoading, setIsLoading] = useState(false);

  // 배경의 사이버네틱 그리드 효과를 위한 간단한 처리
  const bgGridStyle = {
    backgroundImage: `radial-gradient(circle at 2px 2px, rgba(34, 197, 94, 0.05) 1px, transparent 0)`,
    backgroundSize: '40px 40px',
  };

  /**
   * 폼 제출 처리 핸들러
   * 향후 FastAPI 백엔드 및 neonDB와 연동될 핵심 로직 위치
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    // 보안 플랫폼 느낌을 주기 위한 지연 시간 (서버 통신 시뮬레이션)
    setTimeout(() => {
      setIsLoading(false);
      // 실제 구현 시 여기서 JWT 토큰 발급 등 통신을 수행
      // 인증 성공 시뮬레이션 후 메인 대시보드 강제 리다이렉션
      router.push('/');
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4 font-sans selection:bg-emerald-500/30" style={bgGridStyle}>
      
      {/* 배경 장식 요소: 하이테크 느낌을 주는 글로우 효과 */}
      <div className="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] bg-emerald-900/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="fixed bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-900/10 blur-[120px] rounded-full pointer-events-none" />

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md relative z-10"
      >
        {/* 상단 로고 및 슬로건 세션 */}
        <div className="text-center mb-8">
          <motion.div 
            whileHover={{ scale: 1.05 }}
            className="inline-flex items-center justify-center p-3 bg-emerald-500/10 rounded-2xl border border-emerald-500/20 mb-4"
          >
            <Shield className="w-10 h-10 text-emerald-400" strokeWidth={1.5} />
          </motion.div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">
            NTAV <span className="text-emerald-400 font-extralight text-2xl uppercase tracking-widest">SecuLab V2.0</span>
          </h1>
          <p className="text-slate-400 text-sm font-medium uppercase tracking-[0.2em]">
            Never Trust, Always Verify
          </p>
        </div>

        {/* 인증 카드 섹션: 글래스모피즘 적용 */}
        <div className="bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
          
          {/* 상단 진행 바 (로딩 중일 때 표시) */}
          <AnimatePresence>
            {isLoading && (
              <motion.div 
                initial={{ scaleX: 0 }} 
                animate={{ scaleX: 1 }} 
                exit={{ opacity: 0 }}
                className="absolute top-0 left-0 right-0 h-1 bg-emerald-500 origin-left" 
              />
            )}
          </AnimatePresence>

          {/* 로그인/회원가입 탭 스위처 */}
          <div className="flex bg-black/40 p-1 rounded-xl mb-8 border border-white/5">
            <button 
              type="button"
              onClick={() => setMode('login')}
              className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all duration-300 ${mode === 'login' ? 'bg-emerald-500 text-slate-950 shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
              로그인
            </button>
            <button 
              type="button"
              onClick={() => setMode('signup')}
              className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all duration-300 ${mode === 'signup' ? 'bg-emerald-500 text-slate-950 shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
              회원가입
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* 회원가입 시에만 표시되는 '이름' 필드 */}
            <AnimatePresence mode="wait">
              {mode === 'signup' && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="space-y-1 overflow-hidden"
                >
                  <label className="text-xs font-bold text-slate-400 ml-1 uppercase">사용자 이름</label>
                  <div className="relative group">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-emerald-400 transition-colors" />
                    <input 
                      type="text" 
                      placeholder="User Name"
                      required={mode === 'signup'}
                      className="w-full bg-black/20 border border-white/10 rounded-xl py-3 pl-10 pr-4 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all text-sm"
                    />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* 이메일 입력 필드 (공통) */}
            <div className="space-y-1">
              <label className="text-xs font-bold text-slate-400 ml-1 uppercase">이메일 주소</label>
              <div className="relative group">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-emerald-400 transition-colors" />
                <input 
                  type="email" 
                  placeholder="name@company.com"
                  required
                  className="w-full bg-black/20 border border-white/10 rounded-xl py-3 pl-10 pr-4 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all text-sm"
                />
              </div>
            </div>

            {/* 비밀번호 입력 필드 (공통) */}
            <div className="space-y-1">
              <div className="flex justify-between items-center px-1">
                <label className="text-xs font-bold text-slate-400 uppercase">비밀번호</label>
                {mode === 'login' && <button type="button" className="text-[10px] text-emerald-400 hover:underline">비밀번호 찾기</button>}
              </div>
              <div className="relative group">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-emerald-400 transition-colors" />
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="••••••••"
                  required
                  className="w-full bg-black/20 border border-white/10 rounded-xl py-3 pl-10 pr-10 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all text-sm"
                />
                <button 
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* 제출 버튼 */}
            <motion.button
              whileTap={{ scale: 0.98 }}
              disabled={isLoading}
              type="submit"
              className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 text-white font-bold py-3 rounded-xl shadow-lg shadow-emerald-900/20 flex items-center justify-center space-x-2 hover:from-emerald-500 hover:to-teal-500 transition-all disabled:opacity-50 mt-4 group"
            >
              {isLoading ? (
                <Activity className="w-5 h-5 animate-spin" />
              ) : (
                <>
                  <span>{mode === 'login' ? '플랫폼 접속' : '계정 생성'}</span>
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </motion.button>
          </form>

          {/* 푸터 문구 */}
          <div className="mt-8 pt-6 border-t border-white/5 text-center">
            <p className="text-slate-500 text-xs">
              본 시스템은 인가된 사용자만 접근 가능합니다.<br/>
              모든 접속 로그는 <span className="text-emerald-500/70 underline underline-offset-2 italic">NTAV 감사 엔진</span>에 의해 모니터링됩니다.
            </p>
          </div>
        </div>

        {/* 하단 보조 정보 */}
        <div className="mt-6 flex justify-center space-x-6 text-slate-500 text-xs font-medium uppercase tracking-tighter">
          <span className="flex items-center gap-1"><Activity className="w-3 h-3 text-emerald-500" /> System: Stable</span>
          <span className="flex items-center gap-1"><Shield className="w-3 h-3 text-emerald-500" /> SSL: Encrypted</span>
        </div>
      </motion.div>
    </div>
  );
}
