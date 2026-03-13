"use client";

import { useState } from "react";
import { Search, ShieldAlert, Cpu, Network, Map, FileSearch } from "lucide-react";

export default function ThreatAnalyzer() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/api/analyze/file", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Analysis failed", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass p-8 border-l-4 border-amber-500">
        <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
          <ShieldAlert className="text-amber-500" />
          위협 분석실 (Forensics)
        </h3>
        <p className="text-zinc-400 text-sm mb-6">
          의심스러운 실행 파일(EXE, DLL)을 업로드하여 정적 분석 및 MITRE ATT&CK 매핑을 수행합니다.
        </p>

        <div className="flex items-center gap-4">
          <label className="flex-1 border-2 border-dashed border-zinc-700 rounded-lg p-4 cursor-pointer hover:border-amber-500 transition-colors text-center">
            <input 
              type="file" 
              className="hidden" 
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <span className="text-zinc-500 text-sm">
              {file ? file.name : "분석 대상 파일 선택"}
            </span>
          </label>
          <button 
            onClick={handleAnalyze}
            disabled={!file || loading}
            className="px-6 py-4 bg-amber-600 hover:bg-amber-700 disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg font-bold transition-all"
          >
            {loading ? "분석 중..." : "정밀 스캔"}
          </button>
        </div>
      </div>

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-in fade-in duration-500">
          {/* File Overview */}
          <div className="glass p-6 space-y-4">
            <h4 className="font-bold flex items-center gap-2">
              <FileSearch size={18} className="text-blue-400" />
              파일 정보
            </h4>
            <div className="space-y-2 text-sm">
              <p className="flex justify-between"><span className="text-zinc-500">파일명</span> <span>{result.filename}</span></p>
              <p className="flex justify-between"><span className="text-zinc-500">판정</span> <span className={result.verdict === 'Clear' ? 'text-emerald-500' : 'text-red-500 font-bold'}>{result.verdict}</span></p>
              <div className="pt-2 border-t border-white/5 space-y-1">
                <p className="text-[10px] text-zinc-500 uppercase tracking-widest">MD5</p>
                <p className="font-mono text-[10px] break-all text-zinc-400">{result.md5}</p>
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div className="glass p-6 lg:col-span-2 space-y-4">
            <h4 className="font-bold flex items-center gap-2">
              <Map size={18} className="text-amber-400" />
              MITRE ATT&CK 매핑
            </h4>
            {result.mitre_mapping.length > 0 ? (
              <div className="space-y-3">
                {result.mitre_mapping.map((m: any, idx: number) => (
                  <div key={idx} className="bg-zinc-900/60 border border-white/5 p-4 rounded-lg flex gap-4 items-start">
                    <div className="p-2 bg-amber-500/10 rounded border border-amber-500/20 text-amber-500 text-xs font-bold">
                       {m.technique.split(' ')[0]}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-white">{m.technique}</p>
                      <p className="text-xs text-zinc-400 mt-1">{m.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-32 flex items-center justify-center text-zinc-600 text-sm border border-dashed border-zinc-800 rounded-lg">
                매핑된 공격 기술이 없습니다.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
