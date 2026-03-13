"use client";

import { useState, useEffect } from "react";
import { Shield, Clock, User, MessageSquare, RefreshCw } from "lucide-react";

export default function AdminPanel() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/admin/logs");
      const data = await response.json();
      setLogs(data);
    } catch (error) {
      console.error("Failed to fetch logs", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="space-y-6">
      <div className="glass p-8 border-l-4 border-purple-500 flex justify-between items-center">
        <div>
          <h3 className="text-xl font-bold mb-2 flex items-center gap-2">
            <Shield className="text-purple-500" />
            보안 감사 로그 (Audit Logs)
          </h3>
          <p className="text-zinc-400 text-sm">
            시스템 내에서 발생하는 모든 주요 이벤트를 추적하고 기록합니다. 
          </p>
        </div>
        <button 
          onClick={fetchLogs}
          className="p-3 bg-zinc-900 border border-white/5 rounded-lg hover:bg-zinc-800 transition-all text-zinc-400"
          title="새로고침"
        >
          <RefreshCw size={20} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      {/* System Health Section (Simulated monitoring) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "CPU Usage", value: "12%", color: "text-emerald-500" },
          { label: "Memory", value: "128MB", color: "text-blue-500" },
          { label: "API Latency", value: "45ms", color: "text-emerald-500" },
          { label: "Daily Errors", value: "0", color: "text-zinc-500" },
        ].map((metric, i) => (
          <div key={i} className="glass p-4 bg-zinc-900/20 flex flex-col items-center border-t-2 border-purple-500/30">
            <span className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1">{metric.label}</span>
            <span className={`text-xl font-black ${metric.color}`}>{metric.value}</span>
          </div>
        ))}
      </div>

      <div className="glass overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-zinc-900/80 border-b border-white/5">
              <tr>
                <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">시간</th>
                <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">대상</th>
                <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">이벤트</th>
                <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">상세 내용</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono text-xs">
              {logs.length > 0 ? logs.map((log, idx) => (
                <tr key={idx} className="hover:bg-white/5 transition-colors">
                  <td className="px-6 py-4 text-zinc-400 flex items-center gap-2">
                    <Clock size={12} />
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-1 text-blue-400">
                      <User size={12} /> {log.user_id || "SYSTEM"}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-0.5 rounded-full border ${
                      log.action.includes("FAIL") ? "bg-red-500/10 border-red-500/30 text-red-500" :
                      log.action.includes("UPLOAD") ? "bg-blue-500/10 border-blue-500/30 text-blue-500" :
                      "bg-emerald-500/10 border-emerald-500/30 text-emerald-500"
                    }`}>
                      {log.action}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-zinc-500 flex items-center gap-2">
                      <MessageSquare size={12} /> {log.details}
                    </span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-zinc-600 grayscale italic">
                    {loading ? "데이터를 불러오는 중입니다..." : "기록된 감사 로그가 없습니다."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
