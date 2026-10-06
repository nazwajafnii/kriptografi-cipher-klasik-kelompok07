/* ciphers.js - 7 cipher klasik (Shift, Substitution, Affine, Vigenere, Hill, Permutation, OTP)
 * Mode teks  : alfabet 26 huruf (A-Z), karakter non-huruf dibuang.
 * Mode file  : alfabet 256 (byte), semua byte (termasuk header file) ikut dienkripsi.
 */
(function (root) {
  'use strict';

  const mod = (a, m) => ((a % m) + m) % m;
  function gcd(a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { [a, b] = [b, a % b]; } return a; }
  function modInv(a, m) {
    a = mod(a, m);
    let r0 = m, r1 = a, t0 = 0, t1 = 1;
    while (r1) { const q = Math.floor(r0 / r1); [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
    return r0 === 1 ? mod(t0, m) : null;
  }
  function ints(s) {
    const t = String(s).trim();
    if (!t) throw new Error('Kunci tidak boleh kosong.');
    const a = t.split(/[\s,;]+/).filter(Boolean).map(Number);
    if (a.some(x => !Number.isInteger(x))) throw new Error('Kunci harus berupa bilangan bulat (pisahkan dengan koma).');
    return a;
  }
  const lettersOnly = s => String(s).toUpperCase().replace(/[^A-Z]/g, '');
  const toInts = s => Uint8Array.from(lettersOnly(s), c => c.charCodeAt(0) - 65);
  const toText = a => { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(65 + a[i]); return s; };
  const group5 = s => s.replace(/(.{5})(?=.)/g, '$1 ');

  // ---------- parsing kunci ----------
  function detM(M, m) {
    const n = M.length;
    if (n === 1) return mod(M[0][0], m);
    let s = 0;
    for (let j = 0; j < n; j++) {
      const minor = M.slice(1).map(r => r.filter((_, c) => c !== j));
      s = mod(s + (j % 2 ? -1 : 1) * M[0][j] * detM(minor, m), m);
    }
    return s;
  }
  function parseHill(key, m) {
    const t = String(key).trim();
    let nums;
    if (/^[A-Za-z\s]+$/.test(t)) {
      const L = lettersOnly(t);
      nums = [...L].map(c => (m === 26 ? c.charCodeAt(0) - 65 : c.charCodeAt(0)));
    } else nums = ints(t).map(x => mod(x, m));
    const n = Math.round(Math.sqrt(nums.length));
    if (n * n !== nums.length || n < 2 || n > 4)
      throw new Error('Kunci Hill harus berisi n×n angka/huruf dengan n = 2, 3, atau 4 (4, 9, atau 16 entri).');
    const M = []; for (let i = 0; i < n; i++) M.push(nums.slice(i * n, i * n + n).map(x => mod(x, m)));
    const inv = modInv(detM(M, m), m);
    if (inv === null) throw new Error('Matriks kunci tidak punya invers modulo ' + m + ' (determinan tidak relatif prima dengan ' + m + ').');
    const Mi = [];
    for (let i = 0; i < n; i++) {
      Mi.push([]);
      for (let j = 0; j < n; j++) {
        const minor = M.filter((_, r) => r !== j).map(r => r.filter((_, c) => c !== i));
        Mi[i].push(mod(inv * ((i + j) % 2 ? -1 : 1) * detM(minor, m), m));
      }
    }
    return { n, M, Mi };
  }
  function mulberry32(a) {
    return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }
  function substTable(key, m) {
    const T = [];
    if (m === 26) {
      const L = lettersOnly(key);
      if (!L) throw new Error('Kunci substitusi: isi 26 huruf unik atau sebuah kata kunci.');
      const seen = new Set();
      for (const c of L) { const v = c.charCodeAt(0) - 65; if (!seen.has(v)) { seen.add(v); T.push(v); } }
      for (let v = 0; v < 26; v++) if (!seen.has(v)) T.push(v);
    } else {
      if (!String(key)) throw new Error('Kunci tidak boleh kosong.');
      let h = 2166136261; for (const b of new TextEncoder().encode(key)) { h ^= b; h = Math.imul(h, 16777619); }
      const rnd = mulberry32(h); for (let i = 0; i < 256; i++) T.push(i);
      for (let i = 255; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [T[i], T[j]] = [T[j], T[i]]; }
    }
    const Ti = new Array(m); T.forEach((v, i) => { Ti[v] = i; });
    return { T, Ti };
  }
  function parsePerm(key) {
    const t = String(key).trim(); let p;
    if (/^[\d\s,;]+$/.test(t)) {
      const a = ints(t), b = a.length;
      if (b < 2 || !a.every(v => v >= 1 && v <= b) || new Set(a).size !== b)
        throw new Error('Kunci permutasi harus berupa permutasi 1..n, contoh: 3,1,4,2.');
      p = a.map(v => v - 1);
    } else {
      const ch = [...t.replace(/\s/g, '')]; if (ch.length < 2) throw new Error('Kata kunci permutasi minimal 2 karakter.');
      const idx = ch.map((_, i) => i).sort((x, y) => ch[x].charCodeAt(0) - ch[y].charCodeAt(0) || x - y);
      p = new Array(ch.length); idx.forEach((orig, rank) => { p[orig] = rank; });
    }
    const pi = new Array(p.length); p.forEach((v, i) => { pi[v] = i; });
    return { p, pi, b: p.length };
  }

  /** Mengubah kunci (string) menjadi objek kunci siap pakai. otpBytes = Uint8Array isi file kunci OTP. */
  function parseKey(cipher, key, m, otpBytes) {
    switch (cipher) {
      case 'shift': { const a = ints(key); if (a.length !== 1) throw new Error('Kunci shift berupa satu bilangan bulat.'); return mod(a[0], m); }
      case 'affine': {
        const a = ints(key); if (a.length !== 2) throw new Error('Kunci affine berupa dua bilangan: a,b (contoh 5,8).');
        const ai = modInv(a[0], m);
        if (ai === null) throw new Error('Nilai a=' + a[0] + ' tidak relatif prima dengan ' + m + ' (gcd harus 1).');
        return { a: mod(a[0], m), b: mod(a[1], m), ai };
      }
      case 'vigenere': {
        if (m === 26) { const L = lettersOnly(key); if (!L) throw new Error('Kunci Vigenere harus berisi huruf.'); return toInts(L); }
        const b = new TextEncoder().encode(String(key)); if (!b.length) throw new Error('Kunci tidak boleh kosong.'); return b;
      }
      case 'subst': return substTable(key, m);
      case 'hill': return parseHill(key, m);
      case 'perm': return parsePerm(key);
      case 'otp': {
        if (!otpBytes || !otpBytes.length) throw new Error('Pilih file kunci One-Time Pad terlebih dahulu.');
        return m === 26 ? toInts(new TextDecoder().decode(otpBytes)) : otpBytes;
      }
    }
    throw new Error('Cipher tidak dikenal.');
  }

  /** Enkripsi/dekripsi array bilangan d (Uint8Array, nilai < m). */
  function apply(cipher, dec, d, K, m) {
    const n = d.length, padv = m === 26 ? 23 : 0; // 'X' atau byte 0
    let o;
    switch (cipher) {
      case 'shift': o = new Uint8Array(n); { const k = dec ? -K : K; for (let i = 0; i < n; i++) o[i] = mod(d[i] + k, m); } return o;
      case 'affine': o = new Uint8Array(n);
        for (let i = 0; i < n; i++) o[i] = dec ? mod(K.ai * (d[i] - K.b), m) : mod(K.a * d[i] + K.b, m); return o;
      case 'vigenere': o = new Uint8Array(n);
        for (let i = 0; i < n; i++) { const k = K[i % K.length] % m; o[i] = mod(d[i] + (dec ? -k : k), m); } return o;
      case 'otp':
        if (K.length < n) throw new Error('Kunci OTP terlalu pendek: butuh ' + n + ' karakter, tersedia ' + K.length + '.');
        o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = mod(d[i] + (dec ? -K[i] : K[i]), m); return o;
      case 'subst': { const t = dec ? K.Ti : K.T; o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = t[d[i]]; return o; }
      case 'hill': {
        const b = K.n, A = dec ? K.Mi : K.M;
        if (dec && n % b) throw new Error('Panjang cipherteks harus kelipatan ' + b + ' untuk Hill Cipher.');
        const len = Math.ceil(n / b) * b, s = new Uint8Array(len).fill(padv); s.set(d); o = new Uint8Array(len);
        for (let q = 0; q < len; q += b) for (let i = 0; i < b; i++) {
          let sum = 0; for (let j = 0; j < b; j++) sum += A[i][j] * s[q + j]; o[q + i] = sum % m; }
        return o;
      }
      case 'perm': {
        const b = K.b;
        if (dec && n % b) throw new Error('Panjang cipherteks harus kelipatan ' + b + ' untuk Permutation Cipher.');
        const len = Math.ceil(n / b) * b, s = new Uint8Array(len).fill(padv); s.set(d); o = new Uint8Array(len);
        for (let q = 0; q < len; q += b) for (let j = 0; j < b; j++) {
          if (dec) o[q + K.p[j]] = s[q + j]; else o[q + j] = s[q + K.p[j]]; }
        return o;
      }
    }
    throw new Error('Cipher tidak dikenal.');
  }

  // ---------- mode teks ----------
  function encryptText(cipher, key, otpBytes, plain) {
    const K = parseKey(cipher, key, 26, otpBytes), d = toInts(plain);
    if (!d.length) throw new Error('Plainteks tidak berisi huruf A-Z.');
    return toText(apply(cipher, false, d, K, 26));
  }
  function decryptText(cipher, key, otpBytes, ct) {
    const K = parseKey(cipher, key, 26, otpBytes), d = toInts(ct);
    if (!d.length) throw new Error('Cipherteks tidak berisi huruf A-Z.');
    return toText(apply(cipher, true, d, K, 26));
  }

  // ---------- mode file (byte) ----------
  const MAGIC = [0x43, 0x52, 0x59, 0x31]; // "CRY1"
  function encryptFile(cipher, key, otpBytes, name, data) {
    const K = parseKey(cipher, key, 256, otpBytes);
    const nb = new TextEncoder().encode(name || 'file');
    const payload = new Uint8Array(2 + nb.length + data.length);
    payload[0] = nb.length >> 8; payload[1] = nb.length & 255; payload.set(nb, 2); payload.set(data, 2 + nb.length);
    const enc = apply(cipher, false, payload, K, 256);
    const out = new Uint8Array(8 + enc.length);
    out.set(MAGIC, 0);
    new DataView(out.buffer).setUint32(4, payload.length);
    out.set(enc, 8);
    return out;
  }
  function decryptFile(cipher, key, otpBytes, container) {
    if (container.length < 8 || MAGIC.some((v, i) => container[i] !== v)) throw new Error('Bukan file cipherteks dari program ini.');
    const plen = new DataView(container.buffer, container.byteOffset).getUint32(4);
    const K = parseKey(cipher, key, 256, otpBytes);
    const dec = apply(cipher, true, container.subarray(8), K, 256).subarray(0, plen);
    const nl = (dec[0] << 8) | dec[1];
    if (dec.length < 2 + nl) throw new Error('Kunci salah atau file rusak.');
    const name = new TextDecoder().decode(dec.subarray(2, 2 + nl));
    return { name, data: dec.slice(2 + nl) };
  }

  const API = { mod, gcd, modInv, group5, lettersOnly, parseKey, apply, encryptText, decryptText, encryptFile, decryptFile };
  if (typeof module !== 'undefined' && module.exports) module.exports = API; else root.KC = API;
})(typeof window !== 'undefined' ? window : globalThis);
