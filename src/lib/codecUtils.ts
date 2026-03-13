// src/lib/codecUtils.ts

/**
 * 1. URL Encode / Decode
 * 기존 VBScript `URLEncode`, `URLDecode` 기능 및 Javascript `urlEncode1`, `urlDecode1` 호환
 */
export const urlEncode = (str: string): string => {
  try {
    // VBScript의 방식은 기본적으로 공백을 '+'로, 기타 허용하지 않는 문자를 '%XX' 형태의 Hex로 변환합니다.
    // encodeURIComponent를 사용하여 RFC 3986 에 따르되, 공백을 '+' 로 표현하는 레거시와의 호환성을 위해 추가 처리합니다.
    let encoded = encodeURIComponent(str);
    encoded = encoded.replace(/%20/g, '+');
    return encoded;
  } catch (e) {
    console.error("URL Encode Error:", e);
    return "";
  }
};

export const urlDecode = (str: string): string => {
  try {
    // '+' 를 ' ' 로 치환 후 decodeURIComponent 적용
    let decodedStr = str.replace(/\+/g, ' ');
    return decodeURIComponent(decodedStr);
  } catch (e) {
    console.error("URL Decode Error:", e);
    return str; // 디코딩 오류 시 원본 반환
  }
};


/**
 * 2. UTF-8 Encode / Decode
 * 기존 자바스크립트 `utf8_Encode`, `utf8_Decode` 기능 호환
 * TextEncoder 및 TextDecoder 등 브라우저 Native API를 사용하여 성능을 극대화합니다.
 */
export const utf8Encode = (str: string): string => {
  try {
    // encodeURIComponent를 사용하면 UTF-8 바이트 시퀀스의 퍼센트 인코딩된 문자열을 얻을 수 있습니다.
    // 기존 로직은 escape를 최종 반환하므로 해당 포맷에 맞춥니다.
    // 그러나 현대적인 관점에서는 단순히 바이트 변환을 원하므로, Hex 형태의 문자열로 반환하거나 퍼센트 인코딩을 반환할 수 있습니다.
    // 기존 로직 호환을 위해 퍼센트 인코딩 (encodeURIComponent) 결과를 일관성 있게 사용합니다.
    return encodeURIComponent(str);
  } catch (e) {
    console.error("UTF-8 Encode Error:", e);
    return "";
  }
};

export const utf8Decode = (str: string): string => {
  try {
    // 퍼센트 인코딩된 문자열 복원
    return decodeURIComponent(str);
  } catch (e) {
    console.error("UTF-8 Decode Error:", e);
    return str;
  }
};


/**
 * 3. Base64 Encode / Decode
 * 기존 자바스크립트 `encodeBase64`, `decodeBase64` 호환
 * 브라우저 Native API `btoa`, `atob`를 이용해 처리 속도 최적화
 */
export const base64Encode = (str: string): string => {
  try {
    // 유니코드 문자가 섞여있을 때 btoa 가 실패할 수 있으므로, 먼저 URI Component로 인코딩 후 btoa 처리
    const utf8Bytes = encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => {
      return String.fromCharCode(parseInt(p1, 16));
    });
    return btoa(utf8Bytes);
  } catch (e) {
    console.error("Base64 Encode Error:", e);
    return "";
  }
};

export const base64Decode = (str: string): string => {
  try {
    // atob로 디코딩 후 URI Component 디코딩하여 유니코드 복원
    const decodedBytes = atob(str);
    const utf8Str = decodedBytes.split('').map((c) => {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join('');
    return decodeURIComponent(utf8Str);
  } catch (e) {
    console.error("Base64 Decode Error:", e);
    return "Invalid Base64 Input";
  }
};


/**
 * 4. HEX Encode / Decode
 * 문자열을 Hex 문자열 구조로 바꾸거나, Hex 문자열 구조에서 복원하는 기능
 */
export const hexEncode = (str: string): string => {
  try {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        const h = str.charCodeAt(i).toString(16).padStart(2, '0');
        hex += h;
    }
    return hex;
  } catch (e) {
    console.error("Hex Encode Error:", e);
    return "";
  }
};

export const hexDecode = (str: string): string => {
  try {
    // 기존 VBScript 로직: 숫자 및 영문자 외 공백 등 제거
    const cleanStr = str.replace(/[^0-9a-fA-F]/g, '');
    let result = '';
    for (let i = 0; i < cleanStr.length; i += 2) {
      result += String.fromCharCode(parseInt(cleanStr.substring(i, i + 2), 16));
    }
    return result;
  } catch (e) {
    console.error("Hex Decode Error:", e);
    return "Invalid Hex Input";
  }
};


/**
 * 5. Packet Gubun 1 & 2 (패킷 정제)
 * 기존 자바스크립트 `gubun1`, `gubun2` 및 `removeEnter` 등 호환
 * 보안장비(WAF, IDS) 등에서 덤프뜬 [000] 등의 헤더가 포함된 패킷 로그를 정제하여 디코딩 가능 형태로 변환합니다.
 */
export const refinePacketDump = (str: string, type: 1 | 2): string => {
  try {
    const lines = str.split(/\r?\n/);
    let result = "";

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // '[000]' 형식 헤더를 가진 줄들에서 특정 인덱스 (6부터 56) 영역 데이터 추출
      // 제공된 소스를 기반으로 6번째 인덱스부터의 길이 추출 로직 이식
      if (line.length >= 6) {
          result += line.substring(6, Math.min(56, line.length));
      }
    }

    if (type === 1) {
       result = result.replace(/A0/gi, '20')
                      .replace(/00/g, '20')
                      .replace(/0A/gi, '0D')
                      .replace(/\s*$/g, '')
                      .replace(/\s\s/g, '%')
                      .replace(/\s/g, '%')
                      .replace(/%%/gi, '%');
       
       // removeEnter 1, 2 공통
       result = result.replace(/%0a/gi, '%20')
                      .replace(/%0d/gi, '%20')
                      .replace(/%09/gi, '%20')
                      .replace(/%20%20/g, '%20');

       return result;

    } else {
       result = result.replace(/A0/gi, '20') // gubun2 에서는 00, 0a 치환
                      .replace(/00/g, '20')
                      .replace(/0a/gi, '0d')
                      .replace(/\s*$/g, '')
                      .replace(/\s\s/g, '%')
                      .replace(/\s/g, '%')
                      .replace(/%%/gi, '%');
                      
        return result;
    }
  } catch (e) {
    console.error("Packet Refine Error:", e);
    return str;
  }
}

/**
 * 6. CharCode Encode / Decode
 * 문자열의 각 문자를 ASCII/UTF-16 코드 값 배열 (ex "72, 101, 108") 로 변환 또는 복원
 */
export const charCodeEncode = (str: string): string => {
  try {
    let result = [];
    for(let i=0; i<str.length; i++) {
        result.push(str.charCodeAt(i));
    }
    return result.join(", ");
  } catch (e) {
    console.error("CharCode Encode Error:", e);
    return "";
  }
}

export const charCodeDecode = (str: string): string => {
    try {
        const codes = str.split(",").map(s => parseInt(s.trim()));
        let result = "";
        for(let i=0; i<codes.length; i++){
            if(!isNaN(codes[i])) {
                result += String.fromCharCode(codes[i]);
            }
        }
        return result;
    } catch (e) {
        console.error("CharCode Decode Error:", e);
        return "Invalid CharCode Input";
    }
}
