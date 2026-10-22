import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const password = process.env.PASSWORD;
if (!password) {
  console.error("用法: PASSWORD='访问密码' node scripts/seal.mjs");
  process.exit(1);
}

const iterations = 250000;
const crypto = webcrypto;
const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function deriveKey(salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encrypt(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes),
  );
  return { iv: b64(iv), data: b64(cipher) };
}

const full = await readFile(path.join(root, "private/full-fragment.html"));
const brief = await readFile(path.join(root, "private/brief-fragment.html"));

async function renderPdf(fragment, filename) {
  const printHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>${filename}</title>
  <link rel="stylesheet" href="../styles.css">
</head>
<body>
${fragment.toString("utf8")}
</body>
</html>
`;
  const printPath = path.join(root, "private/print.html");
  const pdfPath = path.join(root, "private", filename);
  await writeFile(printPath, printHtml);
  const printed = spawnSync(chrome, [
    "--headless",
    "--disable-gpu",
    "--no-pdf-header-footer",
    "--virtual-time-budget=8000",
    `--print-to-pdf=${pdfPath}`,
    printPath,
  ], { stdio: "inherit" });
  if (printed.status !== 0) process.exit(printed.status ?? 1);
  return readFile(pdfPath);
}

const pdf = await renderPdf(full, "王先生-简历-完整版.pdf");
const briefPdf = await renderPdf(brief, "王先生-简历-简版.pdf");
const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await deriveKey(salt);
const payload = {
  v: 1,
  iter: iterations,
  salt: b64(salt),
  full: await encrypt(key, full),
  brief: await encrypt(key, brief),
  pdf: {
    ...(await encrypt(key, pdf)),
    filename: "王先生-简历-完整版.pdf",
  },
  briefPdf: {
    ...(await encrypt(key, briefPdf)),
    filename: "王先生-简历-简版.pdf",
  },
};
await writeFile(path.join(root, "sealed.json"), JSON.stringify(payload));

const opened = Buffer.from(await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: Buffer.from(payload.full.iv, "base64") },
  key,
  Buffer.from(payload.full.data, "base64"),
));
const text = opened.toString("utf8");
for (const marker of ["个人优势", "项目经历", "系统集成项目管理工程师", "Alo7 货架平台"]) {
  if (!text.includes(marker)) {
    throw new Error(`解密校验失败: ${marker}`);
  }
}
const packed = await readFile(path.join(root, "sealed.json"), "utf8");
if (packed.includes("个人优势") || packed.includes("<address>")) {
  throw new Error("密文中出现了明文");
}
console.log(`sealed ok, full pdf ${pdf.length} bytes, brief pdf ${briefPdf.length} bytes`);
