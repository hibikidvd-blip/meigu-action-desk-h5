import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const payloadPath = process.argv[2] || 'payload.json';
const T_CANDIDATE_LIMIT = 4;
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
  body: JSON.stringify({
    action: 'scan',
    frozenSymbols: (Array.isArray(report.candidateLedger?.candidates)
      ? report.candidateLedger.candidates
      : [report.candidateLedger?.primary, report.candidateLedger?.backup])
      .map((item) => item?.symbol).filter(Boolean).slice(0, T_CANDIDATE_LIMIT),
    account: {
      cash: Number(report.account?.cash || 0),
      riskLimit: Number(report.account?.riskLimit || 0),
      feePerSide: Number(report.account?.feePerSide ?? 1),
    },
  }),
});
if (!response.ok) throw new Error(`Cloud analysis failed: ${response.status}`);
const analysis = await response.json();

function candidate(item) {
  if (!item) return null;
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
    shares: item.tradeMath?.shares ?? 0,
    status: item.scoreLabel,
    setupScorePct: item.setupScorePct,
    leaderboardScorePct: item.leaderboardScorePct,
    moverRank: item.moverRank,
    setupStatus: item.setupStatus,
    dataStatus: item.dataStatus,
    triggerPrice: item.triggerPrice,
    invalidationPrice: item.invalidationPrice,
    firstTarget: item.firstTarget,
    tradeMath: item.tradeMath,
    openingAudit: item.openingAudit,
  };
}

function savedCandidates() {
  if (Array.isArray(report.candidateLedger?.candidates)) return report.candidateLedger.candidates.filter(Boolean).slice(0, T_CANDIDATE_LIMIT);
  return [report.candidateLedger?.primary, report.candidateLedger?.backup].filter(Boolean).slice(0, T_CANDIDATE_LIMIT);
}

function ledgerResult(dateET, candidates, continuity) {
  return { dateET, candidates, primary: candidates[0] || null, backup: candidates[1] || null, continuity };
}

function continueCandidates() {
  const dateET = analysis.session?.dateET || String(analysis.session?.etTime || '').slice(0, 10);
  const current = new Map((analysis.candidates || []).map((item) => [item.symbol, item]));
  const prior = report.candidateLedger;
  if (!prior || prior.dateET !== dateET) {
    return ledgerResult(dateET, (analysis.candidates || []).slice(0, T_CANDIDATE_LIMIT), '今日4只候选首次冻结');
  }
  const refresh = (saved) => {
    if (!saved) return null;
    return current.get(saved.symbol) || { ...saved, dataStatus: 'missing', quoteStatus: 'scheduled update missing; rank retained' };
  };
  const previous = savedCandidates().map(refresh);
  const retained = previous.filter((item) => item?.setupStatus !== 'invalidated').slice(0, T_CANDIDATE_LIMIT);
  if (!retained.length) return ledgerResult(dateET, [], '4只候选均不合格，保持现金');
  if (previous[0]?.setupStatus === 'invalidated') return ledgerResult(dateET, retained, '主选失效，备选按次序接替');
  return ledgerResult(dateET, retained, '原排名保留');
}

function updatePerformance(primary) {
  const dateET = analysis.session?.dateET || String(analysis.session?.etTime || '').slice(0, 10);
  const records = Array.isArray(report.performance20d) ? report.performance20d : [];
  let record = records.find((item) => item.dateET === dateET);
  if (!record) {
    record = { dateET, symbol: primary?.symbol || null, noTrade: Boolean(analysis.noTrade), createdAt: analysis.generatedAt };
    records.push(record);
  }
  if (primary) {
    if (!record.referencePrice || record.symbol !== primary.symbol) record.referencePrice = primary.price;
    record.symbol = primary.symbol;
    record.score = primary.setupScorePct;
    record.leaderboardScore = primary.leaderboardScorePct;
    record.moverRank = primary.moverRank;
    record.highestPrice = Math.max(Number(record.highestPrice || primary.high), Number(primary.high || primary.price));
    record.lowestPrice = Math.min(Number(record.lowestPrice || primary.low), Number(primary.low || primary.price));
    record.top20 = Number(primary.moverRank) > 0 && Number(primary.moverRank) <= 20;
    const eligibleMovers = Number(analysis.breadth?.eligibleMoverCount || 0);
    record.top10Pct = eligibleMovers > 0 && Number(primary.moverRank) <= Math.max(1, Math.ceil(eligibleMovers * 0.1));
    record.setupStatus = primary.setupStatus;
    if (record.referencePrice) {
      record.mfePct = Number((((record.highestPrice / record.referencePrice) - 1) * 100).toFixed(2));
      record.maePct = Number((((record.lowestPrice / record.referencePrice) - 1) * 100).toFixed(2));
    }
  }
  record.noTrade = Boolean(analysis.noTrade);
  record.updatedAt = analysis.generatedAt;
  report.performance20d = records.slice(-20);
}

const ledger = continueCandidates();
report.candidateLedger = ledger;
updatePerformance(ledger.primary);

report.generatedAt = analysis.generatedAt;
report.session = analysis.session?.code || 'unknown';
report.marketClock = analysis.session?.etTime || report.marketClock;
report.dateLabel = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: 'long', day: 'numeric' }).format(new Date());
report.marketState = `${analysis.session?.label || '未知时段'} · ${analysis.marketGate?.label || '待判断'}`;
report.primary = candidate(ledger.primary);
report.backup = candidate(ledger.backup);
report.shortlist = (ledger.candidates || []).map(candidate);
report.directive = !analysis.noTrade && report.primary && report.primary.setupScorePct >= 55 && report.primary.tradeMath?.gate === 'pass'
  ? `主选 ${report.primary.symbol} 只等触发，未触发就不开仓`
  : '当前未见合格做T机会，保持现金';
report.summary = `${analysis.marketGate?.rationale || ''}${ledger.continuity ? `；${ledger.continuity}` : ''}`;
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
