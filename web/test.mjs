// Cross-verifies the JS pipeline against the Python pipeline.
//
// 1. JS decrypt against fresh Python-encrypted ciphertext (clean + whitespace + RS recovery)
// 2. JS encrypt -> JS decrypt round-trip
// 3. JS encrypt -> Python decrypt cross-compat
//
// Run via: make test-web

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decryptPostcard, encryptPostcard } from "./decrypt.js";

const SAMPLE = "Greetings from the Italian Alps. The hike up to Rifugio Lagazuoi " +
  "was steeper than the map suggested but the view at the top was worth every " +
  "blister. We watched marmots play near the snowfield. The cheese here is " +
  "dangerous. Hope the deploy held over the weekend. See you on Monday.";

const dir = mkdtempSync(join(tmpdir(), "postcard-test-"));
let failed = 0;
function ok(name, cond, detail = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ": " + detail : ""}`);
  if (!cond) failed++;
}

const py = (args) => execFileSync("uv", ["run", "postcard.py", ...args], { cwd: ".." });

try {
  // === Section 1: Python encrypt -> JS decrypt ===
  writeFileSync(join(dir, "msg.txt"), SAMPLE);
  py(["keygen", "--out", join(dir, "k")]);
  py(["encrypt", "--key", join(dir, "k"), "--input", join(dir, "msg.txt"),
      "--out", join(dir, "enc"), "--nonce-out", join(dir, "nonce")]);

  const key = readFileSync(join(dir, "k"), "utf-8");
  const nonce = readFileSync(join(dir, "nonce"), "utf-8");
  const ciphertext = readFileSync(join(dir, "enc"), "utf-8");

  const plain = await decryptPostcard(key, nonce, ciphertext);
  ok("py-encrypt -> js-decrypt: matches plaintext", plain === SAMPLE);

  const messy = ciphertext.replace(/.{30}/g, "$&\n   ");
  const plain2 = await decryptPostcard(key, "  " + nonce.trim() + " ", messy);
  ok("py-encrypt -> js-decrypt: tolerates whitespace", plain2 === SAMPLE);

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const ctClean = ciphertext.replace(/\s+/g, "");
  let recovered = 0;
  const trials = 20;
  for (let t = 0; t < trials; t++) {
    const chars = [...ctClean];
    const positions = new Set();
    while (positions.size < 5) {
      const i = Math.floor(Math.random() * chars.length);
      if (chars[i] !== "=") positions.add(i);
    }
    for (const i of positions) {
      let c;
      do { c = B64[Math.floor(Math.random() * 64)]; } while (c === chars[i]);
      chars[i] = c;
    }
    try {
      const out = await decryptPostcard(key, nonce, chars.join(""));
      if (out === SAMPLE) recovered++;
    } catch { /* counts as not recovered */ }
  }
  ok(`py-encrypt -> js-decrypt: RS recovers 5 random flips`, recovered === trials, `${recovered}/${trials}`);

  // === Section 2: JS encrypt -> JS decrypt round-trip ===
  const encResult = await encryptPostcard(SAMPLE);
  ok("js-encrypt: key is 32-byte b64", b64Bytes(encResult.keyB64) === 32);
  ok("js-encrypt: nonce is 12-byte hex", encResult.nonceHex.length === 24);

  const jsRoundtripPlain = await decryptPostcard(
    encResult.keyB64, encResult.nonceHex, encResult.ciphertextB64,
  );
  ok("js-encrypt -> js-decrypt round-trips", jsRoundtripPlain === SAMPLE);

  // === Section 3: JS encrypt -> Python decrypt ===
  writeFileSync(join(dir, "jskey"), encResult.keyB64);
  writeFileSync(join(dir, "jsnonce"), encResult.nonceHex);
  writeFileSync(join(dir, "jsenc"), encResult.ciphertextB64);
  const pyOut = py(["decrypt", "--key", join(dir, "jskey"),
                    "--input", join(dir, "jsenc"),
                    "--nonce", join(dir, "jsnonce")]).toString();
  ok("js-encrypt -> py-decrypt cross-compat", pyOut === SAMPLE,
     pyOut === SAMPLE ? "" : `got ${pyOut.length} chars, expected ${SAMPLE.length}`);

  // === Section 4: JS encrypt with user-supplied key ===
  const userKey = encResult.keyB64;
  const encWithKey = await encryptPostcard("Different message.", userKey);
  ok("js-encrypt with supplied key: echoes that key", encWithKey.keyB64 === userKey);

  console.log(`\n${failed === 0 ? "All tests passed." : `${failed} test(s) failed.`}`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

function b64Bytes(b64) {
  return Buffer.from(b64.trim(), "base64").length;
}
