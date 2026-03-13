"use client";

import { useState } from "react";
import { Shield, Activity, Lock, Search, FileText, Binary, Settings } from "lucide-react";
import SystemAuditor from "@/components/SystemAuditor";
import ThreatAnalyzer from "@/components/ThreatAnalyzer";
import CodecLab from "@/components/CodecLab";
import AdminPanel from "@/components/AdminPanel";

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("dashboard");

  return (
    <div className="space-y-8">
      {/* Header section */}
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold">
            {activeTab === "dashboard" ? "보안 관제 대시보드" : 
             activeTab === "auditor" ? "시스템점검실 (Auditor)" : 
             activeTab === "threat" ? "위협분석실 (Forensics)" : 
             activeTab === "admin" ? "보안 감사 센터 (Admin)" : "코덱연구소 (Utility)"}
          </h2>
          <p className="text-zinc-400 mt-2">"Never Trust, Always Verify" - 모든 접근과 수정을 의심하십시오.</p>
        </div>
        <div className="flex gap-2">
           <button 
             onClick={() => setActiveTab("dashboard")}
             className={`px-4 py-2 rounded-lg text-sm transition-all ${activeTab === 'dashboard' ? 'bg-blue-600 text-white' : 'bg-zinc-900 border border-white/10 text-zinc-400'}`}
           >
             대시보드
           </button>
           <button 
             onClick={() => setActiveTab("auditor")}
             className={`px-4 py-2 rounded-lg text-sm transition-all ${activeTab === 'auditor' ? 'bg-blue-600 text-white' : 'bg-zinc-900 border border-white/10 text-zinc-400'}`}
           >
             점검실
           </button>
           <button 
             onClick={() => setActiveTab("threat")}
             className={`px-4 py-2 rounded-lg text-sm transition-all ${activeTab === 'threat' ? 'bg-amber-600 text-white' : 'bg-zinc-900 border border-white/10 text-zinc-400'}`}
           >
             분석실
           </button>
           <button 
             onClick={() => setActiveTab("codec")}
             className={`px-4 py-2 rounded-lg text-sm transition-all ${activeTab === 'codec' ? 'bg-emerald-600 text-white' : 'bg-zinc-900 border border-white/10 text-zinc-400'}`}
           >
             연구소
           </button>
           <button 
             onClick={() => setActiveTab("admin")}
             className={`px-4 py-2 rounded-lg text-sm transition-all ${activeTab === 'admin' ? 'bg-purple-600 text-white' : 'bg-zinc-900 border border-white/10 text-zinc-400'}`}
           >
             감사
           </button>
        </div>
      </div>

      {activeTab === "dashboard" ? (
        <>
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { icon: <Shield className="text-blue-500" />, label: "무결성 점수", value: "95/100" },
              { icon: <Activity className="text-amber-500" />, label: "진행 중인 분석", value: "3 건" },
              { icon: <Lock className="text-emerald-500" />, label: "보호된 자산", value: "128 개" },
              { icon: <Search className="text-zinc-400" />, label: "오늘의 로그", value: "1.2k" },
            ].map((stat, i) => (
              <div key={i} className="glass p-6 hover-scale glow-blue bg-zinc-900/40">
                <div className="flex justify-between items-start mb-4">
                  {stat.icon}
                  <span className="text-xs text-zinc-500">LIVE</span>
                </div>
                <p className="text-sm text-zinc-400">{stat.label}</p>
                <p className="text-2xl font-bold mt-1">{stat.value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* System Auditor Card */}
            <section className="glass p-8 space-y-4 border-t-4 border-blue-500">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-blue-500/10 rounded-lg">
                  <FileText className="text-blue-500" />
                </div>
                <h3 className="text-xl font-bold">시스템점검실</h3>
              </div>
              <p className="text-zinc-400 text-sm">
                무결성 점수를 계산하고 AI 한줄 평을 제공합니다.
              </p>
              <button 
                onClick={() => setActiveTab("auditor")}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors"
              >
                진입하기
              </button>
            </section>

            {/* Threat Analysis Card */}
            <section className="glass p-8 space-y-4 border-t-4 border-amber-500">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-amber-500/10 rounded-lg">
                  <Activity className="text-amber-500" />
                </div>
                <h3 className="text-xl font-bold">위협분석실</h3>
              </div>
              <p className="text-zinc-400 text-sm">
                파일 정밀 분석 및 MITRE 매핑을 수행합니다.
              </p>
              <button 
                onClick={() => setActiveTab("threat")}
                className="w-full py-3 bg-amber-600 hover:bg-amber-700 rounded-lg font-medium transition-colors"
              >
                진입하기
              </button>
            </section>

            {/* Codec Lab Card */}
            <section className="glass p-8 space-y-4 border-t-4 border-emerald-500">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-emerald-500/10 rounded-lg">
                  <Binary className="text-emerald-500" />
                </div>
                <h3 className="text-xl font-bold">코덱연구소</h3>
              </div>
              <p className="text-zinc-400 text-sm">
                데이터 디코딩 및 AI 포렌식 설명을 제공합니다.
              </p>
              <button 
                onClick={() => setActiveTab("codec")}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-medium transition-colors"
              >
                진입하기
              </button>
            </section>
          </div>

          {/* Admin Quick Link */}
          <div className="mt-8">
            <button 
              onClick={() => setActiveTab("admin")}
              className="glass w-full p-4 flex items-center justify-center gap-2 hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest text-zinc-500 hover:text-purple-400"
            >
              <Settings size={14} /> 보안 감사 및 관리 패널 열기
            </button>
          </div>
        </>
      ) : activeTab === "auditor" ? (
        <SystemAuditor />
      ) : activeTab === "threat" ? (
        <ThreatAnalyzer />
      ) : activeTab === "admin" ? (
        <AdminPanel />
      ) : (
        <CodecLab />
      )}
    </div>
  );
}
