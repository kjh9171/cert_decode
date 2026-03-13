"use client";

import { useState } from "react";
import { Binary, Terminal, Info, Zap, Trash2 } from "lucide-react";

export default function CodecLab() {
  const [dataType, setDataType] = useState("base64");
  const [action, setAction] = useState<"decode" | "encode">("decode");
  const [rawData, setRawData] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleProcess = async () => {
    if (!rawData) return;
    setLoading(true);
    
    try {
      const response = await fetch("/api/forensic/process", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data_type: dataType, raw_data: rawData, action: action }),
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Processing failed", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="glass p-8 border-l-4 border-emerald-500">
        <div className="flex justify-between items-start mb-4">
          <div>
            <h3 className="text-xl font-bold flex items-center gap-2">
              <Binary className="text-emerald-500" />
              코덱연구소 (Utility)
            </h3>
            <p className="text-zinc-400 text-sm mt-1">
              데이터의 인코딩/디코딩 및 AI 포렌식 분석 설명을 확인하십시오.
            </p>
          </div>
          <div className="flex bg-zinc-950 p-1 rounded-lg border border-white/5">
            <button 
              onClick={() => setAction("decode")}
              className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${action === 'decode' ? 'bg-emerald-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              DECODE
            </button>
            <button 
              onClick={() => setAction("encode")}
              className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${action === 'encode' ? 'bg-blue-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              ENCODE
            </button>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex flex-wrap gap-4">
            {["base64", "url", "hex", "gubun", "header", "raw"].map((type) => (
              <button
                key={type}
                onClick={() => setDataType(type)}
                className={`px-4 py-2 rounded-lg text-xs uppercase tracking-widest font-bold transition-all border ${
                  dataType === type ? (action === 'decode' ? 'bg-emerald-600 border-emerald-500' : 'bg-blue-600 border-blue-500') + ' text-white' : 'bg-zinc-900 border-white/5 text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
          
          <textarea 
            className={`w-full h-40 bg-zinc-950 border border-white/5 rounded-lg p-4 font-mono text-sm focus:border-${action === 'decode' ? 'emerald' : 'blue'}-500 outline-none transition-all placeholder:text-zinc-700`}
            placeholder={action === "decode" ? "디코딩할 데이터를 입력하십시오..." : "인코딩할 데이터를 입력하십시오..."}
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
              onClick={handleProcess}
              disabled={!rawData || loading}
              className={`px-8 py-3 ${action === 'decode' ? 'bg-emerald-600 hover:bg-emerald-700 shadow-emerald-500/20' : 'bg-blue-600 hover:bg-blue-700 shadow-blue-500/20'} disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg font-bold transition-all shadow-lg flex items-center gap-2`}
            >
              <Zap size={18} /> {loading ? "처리 중..." : (action === "decode" ? "AI 디코딩" : "AI 인코딩")}
            </button>
          </div>
        </div>
      </div>

      {result && result.status === "Success" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in slide-in-from-bottom-2 duration-500">
          <div className="glass p-6 space-y-4">
            <h4 className="font-bold flex items-center gap-2">
              <Terminal size={18} className={action === 'decode' ? "text-emerald-400" : "text-blue-400"} />
              처리 결과 ({action.toUpperCase()})
            </h4>
            <div className={`bg-zinc-950 p-4 rounded border ${action === 'decode' ? 'border-emerald-500/20' : 'border-blue-500/20'} font-mono text-xs break-all max-h-60 overflow-y-auto`}>
              {result.processed}
            </div>
          </div>

          <div className="glass p-6 space-y-4 border-l-4 border-purple-500">
            <h4 className="font-bold flex items-center gap-2">
              <Info size={18} className="text-purple-400" />
              NTAV AI 분석 가이드
            </h4>
            <div className="bg-purple-500/5 p-4 rounded border border-purple-500/20">
              <p className="text-sm leading-relaxed text-purple-100 italic">
                {result.ai_explanation}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
