import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const payloadPath = process.argv[2] || 'payload.json';
const passcode = process.env.H5_PASS;
const apiUrl = process.env.LIVE_API_URL;
const apiToken = process.env.API_ACCESS_TOKEN;

if (!passcode || !apiUrl || !apiToken) throw new Error('Required cloud update secrets are missing');

const payload = JSON.parse(await readFile(payloadPath, 'utf8'));
const salt = Buffer.from(payload.salt, 'base64');
const key = pbkdf2Sync(passcode, salt, 310000, 32, 'sha256');
const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
const report = JSON.parse(Buffer.concat([
  decipher.update(Buffer.from(payload.ciphertext, 'base64')),
  decipher.final(),
]).toString('utf8'));

const response = await fetch(`${apiUrl}/api/analyze`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Radar-Token': apiToken },
  body: JSON.stringify({ action: 'scan' }),
});
if (!response.ok) throw new Error(`Cloud analysis failed: ${response.status}`);
const analysis = await response.json();

function candidate(item) {
  if (!item) return null;
  const riskPerShare = Math.max(0.01, Number(item.price) - Number(String(item.invalidation).match(/[\d.]+/)?.[0] || item.price));
  const feeBudget = Number(report.account?.feePerSide || 1) * 2;
  const riskShares = Math.max(0, Math.floor((Number(report.account?.riskLimit || 0) - feeBudget) / riskPerShare));
  const cashShares = Math.max(0, Math.floor((Number(report.account?.cash || 0) - Number(report.account?.feePerSide || 1)) / Number(item.price)));
  return {
    symbol: item.symbol,
    name: item.name,
    price: item.price,
    changePct: item.changePct,
    catalyst: item.reasons?.slice(0, 2).join('；') || '量价条件候选，新闻催化待核实',
    trigger: item.trigger,
    stop: item.invalidation,
    target: `$${item.firstTarget}`,
    noChase: item.noChase,
    shares: Math.min(riskShares, cashShares),
    status: item.scoreLabel,
    setupScorePct: item.setupScorePct,
  };
}

report.generatedAt = analysis.generatedAt;
report.session = analysis.session?.code || 'unknown';
report.marketClock = analysis.session?.etTime || report.marketClock;
report.dateLabel = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: 'long', day: 'numeric' }).format(new Date());
report.marketState = `${analysis.session?.label || '未知时段'} · ${analysis.scoreInterpretation}`;
report.primary = candidate(analysis.candidates?.[0]);
report.backup = candidate(analysis.candidates?.[1]);
report.directive = report.primary && report.primary.setupScorePct >= 55
  ? `主选 ${report.primary.symbol} 只等触发，未触发就不开仓`
  : '当前未见合格做T机会，保持现金';
report.summary = analysis.warnings?.[0] || '条件分只用于研究排序，不代表上涨概率。';
report.dataStatus = `${analysis.provider} · ${analysis.generatedAt}`;
report.liveSnapshot = analysis;
report.liveApi = { baseUrl: apiUrl, accessToken: apiToken };

const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(JSON.stringify(report), 'utf8'), cipher.final()]);
const next = {
  version: 1,
  generatedAt: new Date().toISOString(),
  salt: payload.salt,
  iv: iv.toString('base64'),
  tag: cipher.getAuthTag().toString('base64'),
  ciphertext: ciphertext.toString('base64'),
};
await writeFile(payloadPath, `${JSON.stringify(next)}\n`);
