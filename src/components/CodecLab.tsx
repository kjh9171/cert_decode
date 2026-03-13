"use client";

import { useState, useEffect } from "react";
import { Binary, Terminal, Info, Zap, Trash2, Cpu } from "lucide-react";
import {
  urlEncode, urlDecode,
  utf8Encode, utf8Decode,
  base64Encode, base64Decode,
  hexEncode, hexDecode,
  refinePacketDump,
  charCodeEncode, charCodeDecode
} from "../lib/codecUtils";

export default function CodecLab() {
  const [dataType, setDataType] = useState<"base64" | "url" | "hex" | "gubun1" | "gubun2" | "utf8" | "charcode">("base64");
  const [action, setAction] = useState<"decode" | "encode">("decode");
  const [rawData, setRawData] = useState("");
  const [liveResult, setLiveResult] = useState("");
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  // 실시간 변환 로직 (Client Side)
  useEffect(() => {
    if (!rawData) {
      setLiveResult("");
      return;
    }

    let res = "";
    if (action === "encode") {
      switch (dataType) {
        case "base64": res = base64Encode(rawData); break;
        case "url": res = urlEncode(rawData); break;
        case "hex": res = hexEncode(rawData); break;
        case "utf8": res = utf8Encode(rawData); break;
        case "charcode": res = charCodeEncode(rawData); break;
        default: res = "Encoding not supported for this type.";
      }
    } else {
      switch (dataType) {
        case "base64": res = base64Decode(rawData); break;
        case "url": res = urlDecode(rawData); break;
        case "hex": res = hexDecode(rawData); break;
        case "utf8": res = utf8Decode(rawData); break;
        case "charcode": res = charCodeDecode(rawData); break;
        case "gubun1": res = refinePacketDump(rawData, 1); break;
        case "gubun2": res = refinePacketDump(rawData, 2); break;
        default: res = "Decoding not supported for this type.";
      }
    }
    setLiveResult(res);
  }, [rawData, dataType, action]);

  const handleAiAnalysis = async () => {
    if (!liveResult) return;
    setLoading(true);
    
    try {
      // 기존 API 엔드포인트를 호출하되, 이미 변환된 데이터를 분석용으로만 전송 
      // (기존 백엔드가 변환까지 같이 했다면, 향후 백엔드를 분석 전용으로 수정 권장)
      const response = await fetch("/api/forensic/process", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // 단순 분석의 경우 raw 데이터와 변환된 데이터를 함께 전송하여 의미론적 분석 요청
        body: JSON.stringify({ data_type: dataType, raw_data: rawData, action: action, pre_processed: liveResult }),
      });
      const data = await response.json();
      setAiAnalysis(data);
    } catch (error) {
      console.error("AI Analysis failed", error);
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
              데이터의 즉각적인 인코딩/디코딩 및 AI 포렌식 분석을 지원합니다.
            </p>
          </div>
          <div className="flex bg-zinc-950 p-1 rounded-lg border border-white/5">
            <button 
              onClick={() => { setAction("decode"); setAiAnalysis(null); }}
              className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${action === 'decode' ? 'bg-emerald-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              DECODE
            </button>
            <button 
              onClick={() => { setAction("encode"); setAiAnalysis(null); }}
              className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${action === 'encode' ? 'bg-blue-600 text-white shadow-lg' : 'text-zinc-500 hover:text-zinc-300'}`}
            >
              ENCODE
            </button>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {(["base64", "url", "hex", "utf8", "charcode"] as const).map((type) => (
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
            {action === "decode" && (["gubun1", "gubun2"] as const).map((type) => (
               <button
                 key={type}
                 onClick={() => setDataType(type)}
                 className={`px-4 py-2 rounded-lg text-xs uppercase tracking-widest font-bold transition-all border ${
                   dataType === type ? 'bg-emerald-600 border-emerald-500 text-white' : 'bg-zinc-900 border-white/5 text-zinc-500 hover:text-zinc-300'
                 }`}
               >
                 {type} (Packet)
               </button>
            ))}
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <textarea 
              className={`w-full h-48 bg-zinc-950 border border-white/5 rounded-lg p-4 font-mono text-sm focus:border-${action === 'decode' ? 'emerald' : 'blue'}-500 outline-none transition-all placeholder:text-zinc-700`}
              placeholder={action === "decode" ? "디코딩할 데이터를 입력하십시오..." : "인코딩할 데이터를 입력하십시오..."}
              value={rawData}
              onChange={(e) => setRawData(e.target.value)}
            />
            <div className={`w-full h-48 bg-zinc-950 border border-white/5 rounded-lg p-4 font-mono text-sm overflow-y-auto ${!liveResult ? 'text-zinc-700' : 'text-zinc-200'}`}>
               {!liveResult ? "실시간 변환 결과가 이곳에 표시됩니다." : liveResult}
            </div>
          </div>

          <div className="flex justify-between items-center">
            <button 
              onClick={() => { setRawData(""); setLiveResult(""); setAiAnalysis(null); }}
              className="px-4 py-2 text-zinc-500 hover:text-zinc-300 flex items-center gap-2 text-sm"
            >
              <Trash2 size={16} /> 초기화
            </button>
            <button 
              onClick={handleAiAnalysis}
              disabled={!liveResult || loading}
              className="px-8 py-3 bg-purple-600 hover:bg-purple-700 shadow-purple-500/20 shadow-lg disabled:bg-zinc-800 disabled:text-zinc-600 rounded-lg font-bold transition-all flex items-center gap-2"
            >
              {loading ? <Cpu size={18} className="animate-pulse" /> : <Zap size={18} />}
              {loading ? "AI 분석 중..." : "AI 정밀 포렌식 분석"}
            </button>
          </div>
        </div>
      </div>

      {aiAnalysis && (
        <div className="glass p-6 space-y-4 border-l-4 border-purple-500 animate-in fade-in duration-500">
          <h4 className="font-bold flex items-center gap-2">
            <Info size={18} className="text-purple-400" />
            NTAV AI 분석 가이드
          </h4>
          <div className="bg-purple-500/5 p-4 rounded border border-purple-500/20">
            <p className="text-sm leading-relaxed text-purple-100 italic">
              {aiAnalysis.ai_explanation || "AI가 이 데이터의 구조적 의미나 잠재적 위협 요소를 분석한 결과입니다. (백엔드 응답을 확인하세요)"}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
