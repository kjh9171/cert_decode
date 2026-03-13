"use client";

import { useState } from "react";
import { Upload, FileJson, CheckCircle2, AlertTriangle, XCircle, Copy } from "lucide-react";

export default function SystemAuditor() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/api/system/upload", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Upload failed", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass p-8 border-l-4 border-blue-500">
        <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
          <FileJson className="text-blue-500" />
          Audit Log 분석기
        </h3>
        <p className="text-zinc-400 text-sm mb-6">
          보안 점검 스크립트 실행 결과(`result.txt`) 또는 `result.json` 파일을 업로드하여 NTAV AI 포괄 분석을 시작하십시오.
        </p>

        <div className="flex items-center gap-4">
          <label className="flex-1 border-2 border-dashed border-zinc-700 rounded-lg p-4 cursor-pointer hover:border-blue-500 transition-colors text-center">
            <input 
              type="file" 
              className="hidden" 
              accept=".json,.txt"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <span className="text-zinc-500 text-sm">
              {file ? file.name : "파일 선택 또는 드래그 (.json, .txt)"}
            </span>
          </label>
          <button 
            onClick={handleUpload}
            disabled={!file || loading}
            className="px-6 py-4 bg-blue-600 hover:bg-blue-700 disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg font-bold transition-all shadow-lg hover:shadow-blue-500/20"
          >
            {loading ? "분석 중..." : "분석 실행"}
          </button>
        </div>
      </div>

      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          {/* AI One-liner Section */}
          <div className="bg-blue-900/20 border border-blue-500/30 p-6 rounded-xl flex justify-between items-center">
            <div>
              <p className="text-xs text-blue-400 font-bold mb-1 tracking-widest uppercase">NTAV AI 한줄 평</p>
              <h4 className="text-lg font-medium text-white italic">"{result.ntav_comment}"</h4>
            </div>
            <button 
              onClick={async () => {
                const response = await fetch("/api/report/generate", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ ...result, type: "System Audit" }),
                });
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `NTAV_Audit_Report_${new Date().getTime()}.pdf`;
                document.body.appendChild(a);
                a.click();
                a.remove();
              }}
              className="px-4 py-2 bg-zinc-900 hover:bg-zinc-800 border border-blue-500/30 text-blue-400 rounded-lg text-xs font-bold transition-all flex items-center gap-2"
            >
              <Copy size={14} /> 리포트 다운로드
            </button>
          </div>

          {/* Integrity Score Gauge */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="glass p-6 text-center space-y-2">
              <p className="text-zinc-400 text-sm">무결성 지수</p>
              <div className="text-4xl font-black text-blue-500">{result.score}%</div>
              <div className="w-full bg-zinc-800 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-blue-500 h-full transition-all duration-1000" 
                  style={{ width: `${result.score}%` }}
                />
              </div>
            </div>
            <div className="glass p-6 md:col-span-2">
               <p className="text-zinc-400 text-sm mb-4">위험도 요약</p>
               <div className="flex gap-8">
                 <div className="flex items-center gap-2">
                   <XCircle className="text-red-500" size={18} />
                   <span className="text-sm">높음: <span className="text-white font-bold">{result.summary.high}</span></span>
                 </div>
                 <div className="flex items-center gap-2">
                   <AlertTriangle className="text-amber-500" size={18} />
                   <span className="text-sm">중간: <span className="text-white font-bold">{result.summary.mid}</span></span>
                 </div>
                 <div className="flex items-center gap-2">
                   <CheckCircle2 className="text-emerald-500" size={18} />
                   <span className="text-sm">낮음: <span className="text-white font-bold">{result.summary.low}</span></span>
                 </div>
               </div>
            </div>
          </div>

          {/* Detail List */}
          <div className="glass overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-900/80 border-b border-white/5">
                <tr>
                  <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">점검 사항</th>
                  <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">결과</th>
                  <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">중요도</th>
                  <th className="px-6 py-4 font-medium text-zinc-500 uppercase tracking-wider">상세 분석 및 조치</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {result.results.map((item: any, idx: number) => (
                  <tr key={idx} className="hover:bg-white/5 transition-colors group">
                    <td className="px-6 py-4">
                      <div className="font-medium text-zinc-200">{item.title}</div>
                      <div className="text-[10px] text-zinc-500 mt-0.5 font-mono">{item.id}</div>
                    </td>
                    <td className="px-6 py-4">
                      {item.result === "Pass" ? (
                        <span className="text-emerald-500 flex items-center gap-1 font-bold">
                          <CheckCircle2 size={14} /> GOOD
                        </span>
                      ) : (
                        <span className="text-red-500 flex items-center gap-1 font-bold">
                          <XCircle size={14} /> BAD
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] border ${
                        item.impact === "상" ? "bg-red-500/10 border-red-500/30 text-red-400" :
                        item.impact === "중" ? "bg-amber-500/10 border-amber-500/30 text-amber-400" :
                        "bg-zinc-500/10 border-zinc-500/30 text-zinc-400"
                      }`}>
                        {item.impact}
                      </span>
                    </td>
                    <td className="px-6 py-4 space-y-2 max-w-md">
                      {item.result === "Fail" ? (
                        <div className="space-y-1.5 p-3 bg-red-500/5 rounded-lg border border-red-500/10">
                          <div className="text-[11px] text-red-300 leading-relaxed"><span className="font-bold text-red-500 mr-1">[원인]</span> {item.cause}</div>
                          <div className="text-[11px] text-amber-300 leading-relaxed"><span className="font-bold text-amber-500 mr-1">[현상]</span> {item.phenom}</div>
                          <div className="text-[11px] text-emerald-300 leading-relaxed"><span className="font-bold text-emerald-500 mr-1">[대책]</span> {item.solution}</div>
                        </div>
                      ) : (
                        <span className="text-zinc-500 text-xs italic">{item.desc || "기준 준수 중"}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
