// Browser-side encrypt + decrypt for the postcard pipeline.
// Encrypt: utf-8 -> zlib -> AES-256-GCM -> Reed-Solomon -> base64
// Decrypt: base64 -> Reed-Solomon -> AES-256-GCM -> zlib -> utf-8
//
// Reed-Solomon parameters are matched to Python `reedsolo`'s defaults:
//   primitive polynomial 0x11d, generator 2, fcr 0, nsize 255, nsym 20.

// === GF(256) tables ===


const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]];
const gfDiv = (a, b) => {
  if (a === 0) return 0;
  if (b === 0) throw new Error("GF divide by zero");
  return GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255];
};
const gfPow = (x, p) => {
  if (x === 0) return 0;
  let r = (GF_LOG[x] * p) % 255;
  if (r < 0) r += 255;
  return GF_EXP[r];
};
const gfInverse = (x) => GF_EXP[255 - GF_LOG[x]];

function gfPolyMul(p, q) {
  const r = new Array(p.length + q.length - 1).fill(0);
  for (let j = 0; j < q.length; j++) {
    if (q[j] === 0) continue;
    const lq = GF_LOG[q[j]];
    for (let i = 0; i < p.length; i++) {
      if (p[i] !== 0) r[i + j] ^= GF_EXP[GF_LOG[p[i]] + lq];
    }
  }
  return r;
}

const gfPolyScale = (p, x) => p.map(c => gfMul(c, x));

function gfPolyAdd(p, q) {
  const r = new Array(Math.max(p.length, q.length)).fill(0);
  for (let i = 0; i < p.length; i++) r[i + r.length - p.length] = p[i];
  for (let i = 0; i < q.length; i++) r[i + r.length - q.length] ^= q[i];
  return r;
}

function gfPolyEval(poly, x) {
  let y = poly[0];
  for (let i = 1; i < poly.length; i++) y = gfMul(y, x) ^ poly[i];
  return y;
}

// === Reed-Solomon decoder ===

const NSIZE = 255;
const NSYM = 20;

function rsCalcSyndromes(msg, nsym) {
  const synd = [0];
  for (let i = 0; i < nsym; i++) synd.push(gfPolyEval(msg, gfPow(2, i)));
  return synd;
}

function rsFindErrorLocator(synd, nsym) {
  let errLoc = [1];
  let oldLoc = [1];
  for (let i = 0; i < nsym; i++) {
    const K = i + 1;
    let delta = synd[K];
    for (let j = 1; j < errLoc.length; j++) {
      delta ^= gfMul(errLoc[errLoc.length - 1 - j], synd[K - j]);
    }
    oldLoc = [...oldLoc, 0];
    if (delta !== 0) {
      if (oldLoc.length > errLoc.length) {
        const newLoc = gfPolyScale(oldLoc, delta);
        oldLoc = gfPolyScale(errLoc, gfInverse(delta));
        errLoc = newLoc;
      }
      errLoc = gfPolyAdd(errLoc, gfPolyScale(oldLoc, delta));
    }
  }
  while (errLoc.length && errLoc[0] === 0) errLoc.shift();
  if ((errLoc.length - 1) * 2 > nsym) {
    throw new Error("Too many errors to correct");
  }
  return errLoc;
}

function rsFindErrors(errLocReversed, nmess) {
  const errs = errLocReversed.length - 1;
  const errPos = [];
  for (let i = 0; i < nmess; i++) {
    if (gfPolyEval(errLocReversed, gfPow(2, i)) === 0) {
      errPos.push(nmess - 1 - i);
    }
  }
  if (errPos.length !== errs) throw new Error("Could not locate errors");
  return errPos;
}

function rsFindErrataLocator(coefPos) {
  let eLoc = [1];
  for (const p of coefPos) {
    eLoc = gfPolyMul(eLoc, gfPolyAdd([1], [gfPow(2, p), 0]));
  }
  return eLoc;
}

function rsFindErrorEvaluator(syndReversed, errLoc, nsym) {
  // omega = (synd_rev * err_loc) mod x^(nsym+1)
  const mul = gfPolyMul(syndReversed, errLoc);
  return mul.length > nsym + 1 ? mul.slice(mul.length - (nsym + 1)) : mul;
}

function rsCorrectErrata(msg, synd, errPos) {
  const coefPos = errPos.map(p => msg.length - 1 - p);
  const errLoc = rsFindErrataLocator(coefPos);
  const syndRev = synd.slice().reverse();
  let errEval = rsFindErrorEvaluator(syndRev, errLoc, errLoc.length - 1);
  errEval = errEval.slice().reverse();

  const X = coefPos.map(cp => gfPow(2, cp));
  const E = new Array(msg.length).fill(0);

  for (let i = 0; i < X.length; i++) {
    const Xi = X[i];
    const XiInv = gfInverse(Xi);
    let errLocPrime = 1;
    for (let j = 0; j < X.length; j++) {
      if (j !== i) errLocPrime = gfMul(errLocPrime, 1 ^ gfMul(XiInv, X[j]));
    }
    if (errLocPrime === 0) throw new Error("Errata: zero derivative");

    let y = gfPolyEval(errEval.slice().reverse(), XiInv);
    y = gfMul(gfPow(Xi, 1), y);  // fcr = 0, exponent is 1 - fcr = 1
    E[errPos[i]] = gfDiv(y, errLocPrime);
  }

  const corrected = msg.slice();
  for (let i = 0; i < msg.length; i++) corrected[i] ^= E[i];
  return corrected;
}

function rsDecodeBlock(block, nsym) {
  let msg = Array.from(block);
  let synd = rsCalcSyndromes(msg, nsym);
  if (synd.every(s => s === 0)) return msg.slice(0, msg.length - nsym);

  const errLoc = rsFindErrorLocator(synd, nsym);
  const errPos = rsFindErrors(errLoc.slice().reverse(), msg.length);
  msg = rsCorrectErrata(msg, synd, errPos);

  synd = rsCalcSyndromes(msg, nsym);
  if (!synd.every(s => s === 0)) throw new Error("Could not correct message");
  return msg.slice(0, msg.length - nsym);
}

export function rsDecode(bytes, nsym = NSYM) {
  const out = [];
  for (let i = 0; i < bytes.length; i += NSIZE) {
    const block = bytes.slice(i, i + NSIZE);
    const decoded = rsDecodeBlock(block, nsym);
    for (const b of decoded) out.push(b);
  }
  return new Uint8Array(out);
}

// === Reed-Solomon encoder ===

function rsGeneratorPoly(nsym) {
  let g = [1];
  for (let i = 0; i < nsym; i++) {
    g = gfPolyMul(g, [1, gfPow(2, i)]);
  }
  return g;
}

function rsEncodeBlock(msg, nsym) {
  const gen = rsGeneratorPoly(nsym);
  const out = new Array(msg.length + gen.length - 1).fill(0);
  for (let i = 0; i < msg.length; i++) out[i] = msg[i];
  for (let i = 0; i < msg.length; i++) {
    const coef = out[i];
    if (coef !== 0) {
      for (let j = 1; j < gen.length; j++) out[i + j] ^= gfMul(gen[j], coef);
    }
  }
  // Synthetic division clobbers the data positions; restore them.
  for (let i = 0; i < msg.length; i++) out[i] = msg[i];
  return out;
}

export function rsEncode(bytes, nsym = NSYM) {
  const blockData = NSIZE - nsym;
  const out = [];
  for (let i = 0; i < bytes.length; i += blockData) {
    const block = Array.from(bytes.slice(i, i + blockData));
    const encoded = rsEncodeBlock(block, nsym);
    for (const b of encoded) out.push(b);
  }
  return new Uint8Array(out);
}

// === Helpers ===

const stripWhitespace = (s) => s.replace(/\s+/g, "");

function hexToBytes(hex) {
  const clean = stripWhitespace(hex).toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("Invalid hex (odd length)");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error(`Invalid hex char near position ${i * 2}`);
    bytes[i] = byte;
  }
  return bytes;
}

function b64ToBytes(b64) {
  const clean = stripWhitespace(b64);
  const bin = atob(clean);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function requireSubtle() {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(
      "Web Crypto unavailable. Open this page via https://, localhost, or 127.0.0.1 " +
      "(not 0.0.0.0 or a raw LAN IP) - browsers gate crypto.subtle behind secure contexts.",
    );
  }
}

// === Pipeline ===

export async function decryptPostcard(keyB64, nonceHex, ciphertextB64) {
  requireSubtle();
  const keyBytes = b64ToBytes(keyB64);
  if (keyBytes.length !== 32) {
    throw new Error(`Key must be 32 bytes, got ${keyBytes.length}`);
  }
  const nonceBytes = hexToBytes(nonceHex);
  if (nonceBytes.length !== 12) {
    throw new Error(`Nonce must be 12 bytes, got ${nonceBytes.length}`);
  }

  const rsEncoded = b64ToBytes(ciphertextB64);
  const ciphertext = rsDecode(rsEncoded, NSYM);

  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const compressed = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonceBytes },
    key,
    ciphertext,
  );

  const inflated = await new Response(
    new Blob([compressed]).stream().pipeThrough(new DecompressionStream("deflate")),
  ).arrayBuffer();

  return new TextDecoder("utf-8").decode(inflated);
}

// Encrypt a plaintext string. If keyB64 is null/empty, a fresh 32-byte key is generated.
// Returns { keyB64, nonceHex, ciphertextB64 }.
export async function encryptPostcard(plaintext, keyB64 = null) {
  requireSubtle();

  const keyBytes = keyB64 && keyB64.trim()
    ? b64ToBytes(keyB64)
    : crypto.getRandomValues(new Uint8Array(32));
  if (keyBytes.length !== 32) {
    throw new Error(`Key must be 32 bytes, got ${keyBytes.length}`);
  }

  const nonceBytes = crypto.getRandomValues(new Uint8Array(12));

  const compressed = await new Response(
    new Blob([new TextEncoder().encode(plaintext)])
      .stream()
      .pipeThrough(new CompressionStream("deflate")),
  ).arrayBuffer();

  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonceBytes },
    cryptoKey,
    compressed,
  );

  const rsEncoded = rsEncode(new Uint8Array(ciphertext), NSYM);

  return {
    keyB64: bytesToB64(keyBytes),
    nonceHex: bytesToHex(nonceBytes),
    ciphertextB64: bytesToB64(rsEncoded),
  };
}
