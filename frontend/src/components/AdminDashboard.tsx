"use client";

import { useState, useEffect } from "react";
import { ShieldCheck, History, User } from "lucide-react";

export default function AdminDashboard() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetch("http://localhost:8000/api/admin/logs")
      .then(res => res.json())
      .then(data => setLogs(data))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="glass p-8 space-y-6">
      <div className="flex items-center gap-3 border-b border-white/5 pb-6">
        <ShieldCheck className="text-blue-500" size={28} />
        <div>
          <h3 className="text-2xl font-bold">Admin 감사 정보</h3>
          <p className="text-zinc-500 text-sm">시스템 내부 활동 및 권한 변동 사항 실시간 기록</p>
        </div>
      </div>

      <div className="space-y-4">
        {logs.length > 0 ? (
          logs.map((log: any, i) => (
            <div key={i} className="flex items-center justify-between p-4 bg-zinc-950/50 border border-white/5 rounded-lg">
               <div className="flex items-center gap-4">
                 <div className="p-2 bg-zinc-900 rounded-full">
                   <User size={16} className="text-zinc-400" />
                 </div>
                 <div>
                   <p className="text-sm font-medium">{log.action}</p>
                   <p className="text-xs text-zinc-500">{log.endpoint} • {log.ip_address}</p>
                 </div>
               </div>
               <span className="text-xs text-zinc-600">{new Date(log.timestamp).toLocaleString()}</span>
            </div>
          ))
        ) : (
          <div className="text-center py-20 text-zinc-600 text-sm italic">
            기록된 시스템 감사 로그가 없습니다.
          </div>
        )}
      </div>
    </div>
  );
}
