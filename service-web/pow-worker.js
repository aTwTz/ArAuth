// arauth PoW Worker：暴搜 SHA-256(challenge ‖ counter) 前 N 位为零的
// counter（DESIGN.md 第 6 节）。counter 为 8 字节大端——nonce 对服务器
// 只是拼接在 challenge 后的原始字节，无编码约定。在 Worker 内跑不卡 UI。
//
// 协议：收 {challenge: base64url, difficulty: 位数}；
// 定期回 {progress: 已尝试次数}；找到后回 {nonce: base64url} 并结束。
'use strict';

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// 逐位检查 hash 前 n 位是否全零（支持非整字节位数，与服务器口径一致）。
function hasLeadingZeroBits(hash, n) {
  for (let i = 0; i < n; i++) {
    if (hash[i >> 3] & (0x80 >> (i & 7))) return false;
  }
  return true;
}

onmessage = async (e) => {
  const challenge = b64urlDecode(e.data.challenge);
  const difficulty = e.data.difficulty;
  const buf = new Uint8Array(challenge.length + 8);
  buf.set(challenge, 0);
  const view = new DataView(buf.buffer);
  for (let i = 0; ; i++) {
    // 8 字节大端计数器（setUint32 默认大端）。
    view.setUint32(challenge.length, Math.floor(i / 0x100000000));
    view.setUint32(challenge.length + 4, i >>> 0);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
    if (hasLeadingZeroBits(hash, difficulty)) {
      postMessage({ nonce: b64urlEncode(buf.subarray(challenge.length)) });
      return;
    }
    if (i % 4096 === 4095) postMessage({ progress: i + 1 });
  }
};
