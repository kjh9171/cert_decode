"use client";

import { useState } from "react";
import { Binary, Terminal, Info, Zap, Trash2 } from "lucide-react";

export default function CodecLab() {
  const [dataType, setDataType] = useState("base64");
  const [rawData, setRawData] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleDecode = async () => {
    if (!rawData) return;
    setLoading(true);
    
    try {
      const response = await fetch("http://localhost:8000/api/forensic/decode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data_type: dataType, raw_data: rawData }),
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Decoding failed", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass p-8 border-l-4 border-emerald-500">
        <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
          <Binary className="text-emerald-500" />
          코덱연구소 (Utility)
        </h3>
        <p className="text-zinc-400 text-sm mb-6">
          인코딩된 데이터나 이메일 헤더를 입력하여 원문을 복구하고 AI의 기술적 분석 설명을 확인하십시오.
        </p>

        <div className="space-y-4">
          <div className="flex gap-4">
            {["base64", "header", "raw"].map((type) => (
              <button
                key={type}
                onClick={() => setDataType(type)}
                className={`px-4 py-2 rounded-lg text-xs uppercase tracking-widest font-bold transition-all border ${
                  dataType === type ? 'bg-emerald-600 border-emerald-500 text-white' : 'bg-zinc-900 border-white/5 text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
          
          <textarea 
            className="w-full h-40 bg-zinc-950 border border-white/5 rounded-lg p-4 font-mono text-sm focus:border-emerald-500 outline-none transition-all placeholder:text-zinc-700"
            placeholder="여기에 인코딩된 데이터를 입력하십시오..."
            value={rawData}
            onChange={(e) => setRawData(e.target.value)}
          />

          <div className="flex justify-between items-center">
            <button 
              onClick={() => { setRawData(""); setResult(null); }}
              className="px-4 py-2 text-zinc-500 hover:text-zinc-300 flex items-center gap-2 text-sm"
            >
              <Trash2 size={16} /> 초기화
            </button>
            <button 
              onClick={handleDecode}
              disabled={!rawData || loading}
              className="px-8 py-3 bg-emerald-600 hover:bg-emerald-700 disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg font-bold transition-all shadow-lg hover:shadow-emerald-500/20 flex items-center gap-2"
            >
              <Zap size={18} /> {loading ? "분석 중..." : "AI 디코딩"}
            </button>
          </div>
        </div>
      </div>

      {result && result.status === "Success" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in slide-in-from-bottom-2 duration-500">
          <div className="glass p-6 space-y-4">
            <h4 className="font-bold flex items-center gap-2">
              <Terminal size={18} className="text-emerald-400" />
              복구된 원문
            </h4>
            <div className="bg-zinc-950 p-4 rounded border border-white/5 font-mono text-xs break-all max-h-60 overflow-y-auto">
              {result.decoded}
            </div>
          </div>

          <div className="glass p-6 space-y-4 border-l-4 border-blue-500">
            <h4 className="font-bold flex items-center gap-2">
              <Info size={18} className="text-blue-400" />
              AI 분석 가이드
            </h4>
            <div className="bg-blue-500/5 p-4 rounded border border-blue-500/20">
              <p className="text-sm leading-relaxed text-blue-100 italic">
                {result.ai_explanation}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
