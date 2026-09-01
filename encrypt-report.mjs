import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const [reportPath, outputPath = 'payload.json'] = process.argv.slice(2);

if (!reportPath) {
  throw new Error('Usage: node encrypt-report.mjs REPORT_PATH [OUTPUT_PATH]');
}

let passcode = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) passcode += chunk;
passcode = passcode.trim();

if (passcode.length < 16) throw new Error('Passcode must be at least 16 characters');

const report = JSON.parse(await readFile(reportPath, 'utf8'));
let salt;
try {
  const previous = JSON.parse(await readFile(outputPath, 'utf8'));
  salt = Buffer.from(previous.salt, 'base64');
} catch {
  salt = randomBytes(16);
}

const key = pbkdf2Sync(passcode, salt, 310000, 32, 'sha256');
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(JSON.stringify(report), 'utf8'), cipher.final()]);
const payload = {
  version: 1,
  generatedAt: new Date().toISOString(),
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  tag: cipher.getAuthTag().toString('base64'),
  ciphertext: ciphertext.toString('base64'),
};

await writeFile(outputPath, `${JSON.stringify(payload)}\n`);
