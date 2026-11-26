// Regressionstests für den V2-Kern (docs/unit7-v2.html): lädt Krypto- und Engine-Block in einen vm-Kontext.
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import vm from "node:vm";
import crypto from "node:crypto";

const html = fs.readFileSync(new URL("../docs/unit7-v2.html", import.meta.url), "utf8");
const a = html.indexOf("const U7 = (function"), b = html.indexOf("const ENGINE = (function");
const e = html.indexOf("})();", html.indexOf("return { techVerify", b)) + 5;
const ctx = { TextEncoder, console }; vm.createContext(ctx);
vm.runInContext(html.slice(a, e) + ";this.U7=U7;this.ENGINE=ENGINE;", ctx);
const ENGINE = ctx.ENGINE;
const SC = JSON.parse(html.match(/const U7_SCENARIOS = (\{.*?\});\n/s)[1]);
const demo = [{ name: "Demo", pubkey: SC.demoPubKey, active: true }];
const run = (i, keys = []) => ENGINE.provenance(Object.assign({ prompt: "", answer: "", claim: "", logText: "", refHashHex: null, trustedKeys: keys }, i));

describe("Sandbox-Fälle (Erwartung aus U7_SCENARIOS)", () => {
  for (const c of SC.cases) it(c.id + " → " + c.expectOverall, () => {
    expect(run({ prompt: c.prompt, answer: c.answer, claim: c.claim, logText: c.logText }, demo).overall).toBe(c.expectOverall);
  });
});

describe("QA-Bericht Runde 2", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
  const keys = [{ name: "Test", pubkey: pub, active: true }];
  const sha = s => crypto.createHash("sha256").update(s, "utf8").digest("hex");
  const SF = ["manifest_version", "run_id", "tool", "timestamp_utc", "operator", "parameters", "tool_output", "answer_sha256", "prompt_sha256", "input_sha256"];
  const man = (answer, extra = {}) => { const m = Object.assign({ manifest_version: "u7/2", run_id: "t", tool: "image_analyzer", timestamp_utc: "2026-11-26T10:00:00Z",
    tool_output: { scope: "full", width: "4000", height: "3000" }, answer_sha256: sha(answer) }, extra);
    const p = {}; for (const f of SF) if (m[f] !== undefined) p[f] = m[f];
    m.public_key = pub; m.signature = crypto.sign(null, Buffer.from(ctx.U7.canonicalJSON(p), "utf8"), privateKey).toString("hex"); return JSON.stringify(m); };
  const P = "Welche Auflösung hat bild.png?", A = "Die Messung ergab eine Auflösung von 4000×3000 Pixeln.";
  it("R2-01: Format-Unterschied ist keine Abweichung", () => expect(run({ answer: "Das Bild hat 1920×1080 Pixeln.", claim: "Die KI sagt, das Bild hat 1920 x 1080 Pixel." }).l3.status).toBe("ÜBEREINSTIMMEND"));
  it("R2-01: wörtliches Zitat mit „definitiv“", () => expect(run({ answer: "Das Bild ist definitiv nicht bearbeitet.", claim: "Die KI sagt: Das Bild ist definitiv nicht bearbeitet." }).l3.status).toBe("ÜBEREINSTIMMEND"));
  it("R2-02: ohne signierte Vorgabe nie VERIFIED", () => expect(run({ prompt: P, answer: A, logText: man(A) }, keys).overall).toBe("TEILWEISE_BELEGT"));
  it("R2-02: mit signierter Vorgabe VERIFIED", () => expect(run({ prompt: P, answer: A, logText: man(A, { prompt_sha256: sha(P) }) }, keys).overall).toBe("VERIFIED"));
  it("R2-02: fremde Vorgabe → prompt_hash_mismatch", () => expect(run({ prompt: "Andere Frage?", answer: A, logText: man(A, { prompt_sha256: sha(P) }) }, keys).tech.D.code).toBe("prompt_hash_mismatch"));
  it("R2-04: CRLF/NFD/Zeilenende → WARNUNG", () => expect(run({ answer: A, logText: man(A + "\n") }, keys).overall).toBe("WARNUNG"));
  it("R2-05/06: „Nein, das ist inkorrekt“ ist keine Bestätigung", () => expect(run({ prompt: "Das stimmt doch, oder?", answer: "Nein, das ist inkorrekt und ungenau formuliert." }).tech.E.status).not.toBe("MIRRORING_DETECTED"));
  it("R2-07: 1,500 = 1500", () => expect(ENGINE.parseNum("1,500")).toBe(1500));
  it("R2-19: Schlüssel kleiner Ordnung abgelehnt", () => {
    const forged = JSON.stringify({ tool: "x", tool_output: { scope: "full" }, answer_sha256: sha(A), public_key: "01" + "00".repeat(31), signature: "5866666666666666666666666666666666666666666666666666666666666666" + "01" + "00".repeat(31) });
    expect(run({ answer: A, logText: forged }, [{ name: "id", pubkey: "01" + "00".repeat(31), active: true }]).tech.D.code).toBe("invalid_signature");
  });
});
