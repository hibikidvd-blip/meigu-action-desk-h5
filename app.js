const app = document.querySelector('#app');
const KEY_STORAGE = 'meigu-h5-key-v1';
const KEY_EXPIRY = 'meigu-h5-key-expiry-v1';
const LEDGER_STORAGE = 'meigu-h5-candidate-ledger-v1';
const PERFORMANCE_STORAGE = 'meigu-h5-performance-v1';
const TRADE_STORAGE = 'meigu-h5-trades-v1';
const PORTFOLIO_STORAGE = 'meigu-h5-portfolio-v1';
const MAX_T_CANDIDATES = 4;
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
let liveConfig = null;

const bytesFromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
const base64FromBytes = (value) => btoa(String.fromCharCode(...value));

function node(tag, className = '', text = '') {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== '') element.textContent = String(text);
  return element;
}

function readLocalJson(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key));
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function writeLocalJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function validSymbol(value) {
  return /^[A-Z][A-Z0-9.-]{0,9}$/.test(String(value || '').trim().toUpperCase());
}

function normalizedHoldings(items, fallback = []) {
  const originalBySymbol = new Map((fallback || []).map((item) => [item.symbol, item]));
  const unique = new Map();
  (items || []).forEach((item) => {
    const symbol = String(item?.symbol || '').trim().toUpperCase();
    const qty = Math.floor(Number(item?.qty));
    if (!validSymbol(symbol) || !Number.isFinite(qty) || qty <= 0) return;
    const original = originalBySymbol.get(symbol);
    unique.set(symbol, { ...original, symbol, name: original?.name || item?.name || '自定义持仓', qty, action: original?.action || '待分析', tone: original?.tone || 'watch' });
  });
  return [...unique.values()].slice(0, 30);
}

function portfolioFor(report) {
  const defaults = normalizedHoldings(report.holdings || [], report.holdings || []);
  const saved = readLocalJson(PORTFOLIO_STORAGE, null);
  if (!saved || typeof saved !== 'object') return { cash: Number(report.account?.cash || 0), holdings: defaults };
  const cash = Number(saved.cash);
  return {
    cash: Number.isFinite(cash) && cash >= 0 ? Math.min(cash, 10_000_000) : Number(report.account?.cash || 0),
    holdings: normalizedHoldings(saved.holdings, report.holdings || []),
  };
}

function reportWithLocalPortfolio(report) {
  const portfolio = portfolioFor(report);
  return { ...report, account: { ...report.account, cash: portfolio.cash }, holdings: portfolio.holdings };
}

function formatSigned(value, digits = 2) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'N/A';
  return `${numeric >= 0 ? '+' : ''}${numeric.toFixed(digits)}%`;
}

function icon(name) {
  const icons = {
    lock: '<path d="M7 11V8a5 5 0 0 1 10 0v3"/><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M12 15v2"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.4 5.6"/><circle cx="12" cy="12" r="1"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3z"/><path d="m9 12 2 2 4-4"/>',
  };
  const wrapper = document.createElement('span');
  wrapper.className = 'svg-icon';
  wrapper.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name]}</svg>`;
  return wrapper;
}

async function fetchPayload() {
  const response = await fetch(`./payload.json?v=${Date.now()}`, { cache: 'no-store' });
  if (!response.ok) throw new Error('报告暂时无法载入');
  return response.json();
}

async function deriveKey(passcode, salt) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passcode),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt'],
  );
}

async function decryptReport(payload, key) {
  const ciphertext = bytesFromBase64(payload.ciphertext);
  const tag = bytesFromBase64(payload.tag);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const clear = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytesFromBase64(payload.iv), tagLength: 128 },
    key,
    combined,
  );
  return JSON.parse(new TextDecoder().decode(clear));
}

async function rememberKey(key) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  localStorage.setItem(KEY_STORAGE, base64FromBytes(raw));
  localStorage.setItem(KEY_EXPIRY, String(Date.now() + THIRTY_DAYS));
}

async function recalledKey() {
  const raw = localStorage.getItem(KEY_STORAGE);
  const expiry = Number(localStorage.getItem(KEY_EXPIRY) || 0);
  if (!raw || expiry <= Date.now()) {
    localStorage.removeItem(KEY_STORAGE);
    localStorage.removeItem(KEY_EXPIRY);
    return null;
  }
  return crypto.subtle.importKey('raw', bytesFromBase64(raw), { name: 'AES-GCM' }, true, ['decrypt']);
}

function clearKey() {
  localStorage.removeItem(KEY_STORAGE);
  localStorage.removeItem(KEY_EXPIRY);
}

function showLogin(message = '') {
  app.replaceChildren();
  const shell = node('section', 'login-shell');
  const card = node('div', 'login-card');
  const hero = node('div', 'login-hero');
  const logo = node('div', 'logo');
  logo.append(icon('radar'));
  hero.append(logo, node('p', 'eyebrow', '私人投资页面'), node('h1', '', '美股行动台'), node('p', 'subcopy', '输入私人密码后，先会在手机本机解密持仓、候选股同操作计划。'));

  const body = node('div', 'login-body');
  const form = node('form', 'login-form');
  const label = node('label', '', '私人密码');
  label.htmlFor = 'passcode';
  const input = node('input');
  input.id = 'passcode';
  input.type = 'password';
  input.autocomplete = 'current-password';
  input.placeholder = '请输入密码';
  input.required = true;
  const error = node('p', 'error', message);
  error.setAttribute('role', 'alert');
  const button = node('button', 'primary-button', '进入行动台');
  button.type = 'submit';
  const security = node('div', 'security-note');
  security.append(icon('shield'), node('p', '', '成功后 30 日内免重复输入。加密报告只会在这部设备解开。'));
  form.append(label, input, error, button);
  body.append(form, security);
  card.append(hero, body);
  shell.append(card);
  app.append(shell);
  input.focus();

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    button.disabled = true;
    button.textContent = '验证中…';
    error.textContent = '';
    try {
      const payload = await fetchPayload();
      const key = await deriveKey(input.value, bytesFromBase64(payload.salt));
      const report = await decryptReport(payload, key);
      await rememberKey(key);
      renderDashboard(report, payload.generatedAt);
    } catch {
      error.textContent = '密码唔正确，或者报告暂时无法载入。';
      button.disabled = false;
      button.textContent = '进入行动台';
    }
  });
}

function pill(text, tone = '') {
  return node('span', `pill ${tone}`, text);
}

function valueCard(label, value) {
  const card = node('div', 'value-card');
  card.append(node('p', '', label), node('strong', '', value));
  return card;
}

function candidateCard(candidate, title, rank) {
  const card = node('article', 'card candidate-card');
  const head = node('div', 'card-head');
  const titleWrap = node('div', 'title-wrap');
  titleWrap.append(node('span', `rank rank-${rank}`, rank), node('h3', '', title));
  head.append(titleWrap, pill(candidate?.status || '待生成', candidate ? 'green' : 'neutral'));
  card.append(head);
  if (!candidate) {
    card.append(node('p', 'empty-copy', rank === '1' ? '20:30 自动筛选；无合格机会会直接显示今晚不开仓。' : '排在前面的候选失效后才按次序考虑；不会同时开四仓。'));
    return card;
  }
  const quote = node('div', 'quote-line');
  const ticker = node('div');
  ticker.append(node('strong', 'ticker', candidate.symbol), node('span', 'company', candidate.name));
  quote.append(ticker, node('strong', '', `$${Number(candidate.price).toFixed(2)}`));
  const catalyst = node('p', 'catalyst', candidate.catalyst);
  const grid = node('div', 'detail-grid');
  [['入场触发', candidate.trigger], ['不可追价', candidate.noChase], ['止损', candidate.stop], ['目标 / 股数', `${candidate.target} · ${candidate.shares}股`]].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    grid.append(item);
  });
  card.append(quote, catalyst, grid);
  return card;
}

function scanDate(result) {
  return result.session?.dateET || String(result.session?.etTime || '').slice(0, 10) || new Date().toISOString().slice(0, 10);
}

function ledgerCandidates(ledger) {
  if (Array.isArray(ledger?.candidates)) return ledger.candidates.filter(Boolean).slice(0, MAX_T_CANDIDATES);
  return [ledger?.primary, ledger?.backup].filter(Boolean).slice(0, MAX_T_CANDIDATES);
}

function frozenSymbols() {
  const ledger = readLocalJson(LEDGER_STORAGE, null);
  return ledgerCandidates(ledger).map((candidate) => candidate.symbol).filter(Boolean);
}

function candidateRole(index) {
  return index === 0 ? '主选' : `备选 ${index}`;
}

function applyCandidateContinuity(result, action) {
  if (action !== 'scan') {
    result.actionableCandidates = result.candidates || [];
    return result;
  }
  const dateET = scanDate(result);
  const incoming = new Map((result.candidates || []).map((candidate) => [candidate.symbol, candidate]));
  let ledger = readLocalJson(LEDGER_STORAGE, null);
  if (!ledger || ledger.dateET !== dateET) {
    const candidates = (result.candidates || []).slice(0, MAX_T_CANDIDATES);
    ledger = { version: 2, dateET, candidates, primary: candidates[0] || null, backup: candidates[1] || null };
    writeLocalJson(LEDGER_STORAGE, ledger);
    result.actionableCandidates = candidates;
    result.continuity = { label: '今日4只候选已冻结', detail: '主选加3只按次序备用；同一时间只执行一只，不会四只同时入场。' };
    return result;
  }

  const refresh = (saved) => {
    if (!saved) return null;
    const current = incoming.get(saved.symbol);
    return current || { ...saved, dataStatus: 'missing', quoteStatus: '本次实时数据缺失', continuityWarning: '数据缺失不等于转弱；保留排名并等待重查。' };
  };
  const previous = ledgerCandidates(ledger).map(refresh);
  let retained = previous.filter((candidate) => candidate?.setupStatus !== 'invalidated').slice(0, MAX_T_CANDIDATES);
  let label = '原排名保留';
  let detail = '已冻结候选未触发明确失效条件，不因新出现股票而改变次序。';
  if (ledger.version !== 2) {
    const symbols = new Set(retained.map((candidate) => candidate.symbol));
    retained = [...retained, ...(result.candidates || []).filter((candidate) => !symbols.has(candidate.symbol))].slice(0, MAX_T_CANDIDATES);
    label = '旧版名单已扩展为4只';
    detail = '保留原主选和备选次序，并一次性补足其余候选；之后同日不再以新股票替换。';
  } else if (previous[0]?.setupStatus === 'invalidated' && retained.length) {
    label = '主选失效，备选按次序接替';
    detail = `${previous[0].symbol} 已失效；下一只已冻结候选接替主选，不临时加入新股票。`;
  } else if (!retained.length) {
    label = '4只候选均不合格';
    detail = '今日行动分支为现金；其他股票只留在事件雷达。';
  } else {
    const missing = previous.filter((candidate) => candidate?.dataStatus === 'missing').length;
    if (missing) detail = `${missing} 只候选本次数据缺失，保留原次序并等待重查。`;
  }
  ledger = { version: 2, dateET, candidates: retained, primary: retained[0] || null, backup: retained[1] || null };
  writeLocalJson(LEDGER_STORAGE, ledger);
  result.actionableCandidates = retained;
  result.continuity = { label, detail };
  if (!retained.length) result.noTrade = true;
  return result;
}

function updatePerformance(result, action) {
  if (action !== 'scan') return;
  const dateET = scanDate(result);
  const candidate = result.actionableCandidates?.[0] || null;
  const records = readLocalJson(PERFORMANCE_STORAGE, []);
  let record = records.find((item) => item.dateET === dateET);
  if (!record) {
    record = { dateET, symbol: candidate?.symbol || null, noTrade: Boolean(result.noTrade), createdAt: result.generatedAt };
    records.push(record);
  }
  if (candidate) {
    if (!record.referencePrice || record.symbol !== candidate.symbol) record.referencePrice = candidate.price;
    record.symbol = candidate.symbol;
    record.score = candidate.setupScorePct;
    record.leaderboardScore = candidate.leaderboardScorePct;
    record.moverRank = candidate.moverRank;
    record.highestPrice = Math.max(Number(record.highestPrice || candidate.high), Number(candidate.high || candidate.price));
    record.lowestPrice = Math.min(Number(record.lowestPrice || candidate.low), Number(candidate.low || candidate.price));
    const eligibleMovers = Number(result.breadth?.eligibleMoverCount || 0);
    record.top20 = Number(candidate.moverRank) > 0 && Number(candidate.moverRank) <= 20;
    record.top10Pct = eligibleMovers > 0 && Number(candidate.moverRank) <= Math.max(1, Math.ceil(eligibleMovers * 0.1));
    record.setupStatus = candidate.setupStatus;
  }
  record.noTrade = Boolean(result.noTrade);
  record.updatedAt = result.generatedAt;
  writeLocalJson(PERFORMANCE_STORAGE, records.slice(-20));
}

function statusTone(value) {
  if (/valid|pass|通过|可进攻|优先/.test(String(value))) return 'green';
  if (/invalid|reject|失效|不开仓/.test(String(value))) return 'red';
  return 'gold-light';
}

function marketGateCard(result) {
  const card = node('section', 'market-gate-card');
  const top = node('div', 'market-gate-top');
  const title = node('div');
  title.append(node('span', '', '大市门槛'), node('strong', '', result.marketGate?.label || '待判断'));
  top.append(title, pill(result.session?.label || '未知时段', statusTone(result.marketGate?.label)));
  const grid = node('div', 'market-metrics');
  [['SPY', formatSigned(result.marketGate?.spyChangePct)], ['QQQ', formatSigned(result.marketGate?.qqqChangePct)], ['上涨宽度', `${result.breadth?.advancePct ?? 'N/A'}%`]].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    grid.append(item);
  });
  const sectors = node('div', 'sector-strip');
  (result.leadingSectors || []).slice(0, 4).forEach((sector) => sectors.append(pill(`${sector.sector} ${formatSigned(sector.medianChangePct)}`, sector.medianChangePct > 0 ? 'green' : 'neutral')));
  card.append(top, node('p', '', result.marketGate?.rationale || ''), grid, sectors);
  return card;
}

function auditBlock(audit) {
  const details = node('details', 'audit-block');
  const summary = node('summary');
  summary.append(node('strong', '', '09:35 ET 审计'), pill(audit?.label || '待执行', statusTone(audit?.status)));
  details.append(summary);
  const checks = node('div', 'audit-checks');
  (audit?.checks || []).forEach((check) => {
    const row = node('div');
    row.append(node('strong', '', check.item), pill(check.status, statusTone(check.status)), node('span', '', check.detail));
    checks.append(row);
  });
  details.append(checks);
  return details;
}

function liveCandidateCard(candidate, rank, role = '') {
  const card = node('article', 'live-result-card');
  const top = node('div', 'live-result-top');
  const identity = node('div');
  identity.append(node('span', 'role-label', role || `候选 ${rank + 1}`), node('strong', 'ticker', candidate.symbol), node('span', 'company', candidate.name));
  const scoreStack = node('div', 'score-stack');
  const setupScore = node('div', 'score-badge');
  setupScore.append(node('strong', '', `${candidate.setupScorePct}%`), node('span', '', '做T条件分'));
  const boardScore = node('div', 'score-badge board-score');
  boardScore.append(node('strong', '', `${candidate.leaderboardScorePct ?? '—'}%`), node('span', '', '榜前条件分'));
  scoreStack.append(setupScore, boardScore);
  top.append(identity, scoreStack);

  const quote = node('div', 'live-quote');
  quote.append(
    node('strong', '', `$${Number(candidate.price).toFixed(2)}`),
    node('span', Number(candidate.changePct) >= 0 ? 'up' : 'down', formatSigned(candidate.changePct)),
    pill(candidate.scoreLabel, statusTone(candidate.scoreLabel)),
    pill(candidate.setupStatus || 'unknown', statusTone(candidate.setupStatus)),
  );
  if (candidate.moverRank) quote.append(pill(`流动性榜 #${candidate.moverRank}`, 'neutral'));

  if (candidate.catalyst) {
    const catalyst = node('div', 'catalyst-box');
    catalyst.append(node('strong', '', `${candidate.catalyst.category} · ${candidate.catalyst.evidenceStatus}`), node('span', '', candidate.catalyst.title));
    card.append(top, quote, catalyst);
  } else {
    card.append(top, quote, node('p', 'no-catalyst', '未发现可核实催化线索；不可只因价格上升而入场。'));
  }

  const reasonList = node('ul', 'reason-list');
  (candidate.reasons || []).slice(0, 6).forEach((reason) => reasonList.append(node('li', '', reason)));
  const math = candidate.tradeMath || {};
  const plan = node('div', 'live-plan');
  [
    ['观察触发', candidate.trigger], ['失效条件', candidate.invalidation], ['首个目标', `$${candidate.firstTarget}`],
    ['最高追价', candidate.noChase], ['时间止损', candidate.timeStop],
    ['股数 / 净R', math.shares === null || math.shares === undefined ? '待计算' : `${math.shares}股 · ${math.netR ?? 'N/A'}R`],
  ].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    plan.append(item);
  });
  const foot = node('p', 'live-result-foot', `${candidate.quoteStatus} · ${candidate.feeNote}`);
  card.append(reasonList, plan, auditBlock(candidate.openingAudit), foot);
  if (candidate.continuityWarning) card.append(node('p', 'continuity-warning', candidate.continuityWarning));
  if (rank === 0) card.classList.add('primary-live');
  return card;
}

function dailyStructureBlock(daily) {
  const section = node('section', 'daily-structure');
  const head = node('div', 'subsection-head');
  head.append(node('strong', '', '日线结构'), pill(daily?.label || '日线资料不足', statusTone(daily?.label)));
  section.append(head);
  if (!daily || daily.dataStatus === 'insufficient') {
    section.append(node('p', 'daily-note', daily?.signals?.[0] || '日线资料不足，暂不把它解读成弱势。'));
    return section;
  }
  const grid = node('div', 'daily-metrics');
  [
    ['20／50／200日', `${daily.ma20 ?? 'N/A'} / ${daily.ma50 ?? 'N/A'} / ${daily.ma200 ?? 'N/A'}`],
    ['近5／20／60日', `${formatSigned(daily.ret5)} / ${formatSigned(daily.ret20)} / ${formatSigned(daily.ret60)}`],
    ['相对SPY 20／60日', `${formatSigned(daily.relative20)} / ${formatSigned(daily.relative60)}`],
    ['20日高低', `${daily.low20 ?? 'N/A'} – ${daily.high20 ?? 'N/A'}`],
    ['距20日线', formatSigned(daily.extensionPct)],
    ['量／20日均量', daily.volumeRatio20 === null ? 'N/A' : `${daily.volumeRatio20}x`],
  ].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    grid.append(item);
  });
  section.append(grid);
  const signals = node('ul', 'daily-signal-list');
  (daily.signals || []).slice(0, 5).forEach((signal) => signals.append(node('li', '', signal)));
  section.append(signals);
  if (daily.candles?.length) {
    const candles = node('div', 'candle-strip');
    daily.candles.forEach((bar) => {
      const candle = node('div', `candle-chip ${bar.close >= bar.open ? 'up' : 'down'}`);
      candle.append(node('span', '', String(bar.date || '').slice(0, 5)), node('strong', '', `${bar.open}→${bar.close}`), node('small', '', `H ${bar.high} · L ${bar.low}`));
      candles.append(candle);
    });
    section.append(candles);
  }
  return section;
}

function researchLayersBlock(review) {
  const section = node('section', 'research-layers');
  const head = node('div', 'subsection-head');
  head.append(node('strong', '', '公司／事件资料层'), pill('资料分层', 'neutral'));
  section.append(head);
  const facts = review?.researchLayers?.company || {};
  const grid = node('div', 'daily-metrics research-metrics');
  [
    ['市值', facts.marketCap || 'N/A'], ['P/E', facts.peRatio || 'N/A'], ['EPS', facts.eps || 'N/A'],
    ['一年目标价', facts.oneYearTarget || 'N/A'], ['Beta', facts.beta || 'N/A'], ['股息率／股息', facts.dividendYield || 'N/A'],
  ].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    grid.append(item);
  });
  const notes = node('div', 'research-notes');
  [review?.researchLayers?.eventStatus, review?.researchLayers?.earnings, review?.researchLayers?.analyst, review?.researchLayers?.ownership]
    .filter(Boolean).forEach((text) => notes.append(node('p', '', text)));
  section.append(grid, notes);
  return section;
}

function buildCandidateCard(candidate, rank) {
  const card = node('article', 'live-result-card build-result-card');
  const plan = candidate.buildPlan || {};
  const top = node('div', 'live-result-top');
  const identity = node('div');
  identity.append(node('span', 'role-label', `建仓研究候选 ${rank + 1}`), node('strong', 'ticker', candidate.symbol), node('span', 'company', candidate.name));
  const score = node('div', 'score-badge');
  score.append(node('strong', '', `${plan.score ?? '—'}%`), node('span', '', '建仓匹配度'));
  top.append(identity, score);
  const quote = node('div', 'live-quote');
  quote.append(node('strong', '', `$${Number(candidate.price).toFixed(2)}`), node('span', Number(candidate.changePct) >= 0 ? 'up' : 'down', formatSigned(candidate.changePct)), pill(plan.status || '待审查', statusTone(plan.status)));
  card.append(top, quote);
  if (candidate.catalyst) {
    const catalyst = node('div', 'catalyst-box');
    catalyst.append(node('strong', '', `${candidate.catalyst.category} · ${candidate.catalyst.evidenceStatus}`), node('span', '', candidate.catalyst.title));
    card.append(catalyst);
  }
  const reasons = node('ul', 'reason-list');
  (plan.reasons || []).forEach((reason) => reasons.append(node('li', '', reason)));
  const planGrid = node('div', 'live-plan build-plan');
  [
    ['建仓价格区间', plan.zone || 'N/A'], ['确认条件', plan.trigger || 'N/A'], ['结构失效', plan.invalidation || 'N/A'],
    ['首个目标／R', `${plan.firstTarget ? `$${plan.firstTarget}` : 'N/A'} · ${plan.estimatedR ?? 'N/A'}R`], ['不追条件', plan.noChase || 'N/A'], ['下一步', plan.nextStep || 'N/A'],
  ].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    planGrid.append(item);
  });
  card.append(reasons, planGrid, dailyStructureBlock(candidate.daily));
  card.append(node('p', 'live-result-foot', `${candidate.quoteStatus} · ${candidate.earningsRisk ? '当日财报风险，普通建仓计划暂停。' : '价格区间为日线研究区域；券商报价和点差须另行复核。'}`));
  return card;
}

function holdingAnalysisCard(candidate) {
  const card = node('article', 'live-result-card position-result-card');
  const review = candidate.holdingReview || {};
  const top = node('div', 'live-result-top');
  const identity = node('div');
  identity.append(node('span', 'role-label', '持仓／自选完整体检'), node('strong', 'ticker', candidate.symbol), node('span', 'company', candidate.name));
  top.append(identity, pill(review.state || '待评估', statusTone(review.state)));
  const quote = node('div', 'live-quote');
  quote.append(node('strong', '', `$${Number(candidate.price).toFixed(2)}`), node('span', Number(candidate.changePct) >= 0 ? 'up' : 'down', formatSigned(candidate.changePct)), pill(candidate.daily?.label || '日线待取得', statusTone(candidate.daily?.label)));
  card.append(top, quote);
  const action = node('div', 'position-action');
  action.append(node('strong', '', '当前复核要点'), node('span', '', review.action || '等待日线与事件资料。'));
  card.append(action, dailyStructureBlock(candidate.daily), researchLayersBlock(review));
  if (candidate.catalyst) {
    const catalyst = node('div', 'catalyst-box');
    catalyst.append(node('strong', '', `${candidate.catalyst.category} · ${candidate.catalyst.evidenceStatus}`), node('span', '', candidate.catalyst.title));
    card.append(catalyst);
  }
  const plan = review.buildPlan || {};
  const levels = node('div', 'live-plan compact-plan');
  [
    ['建仓／加仓研究区', plan.zone || 'N/A'], ['日线失效位', plan.invalidationPrice ? `$${plan.invalidationPrice}` : 'N/A'],
    ['首个结构目标', plan.firstTarget ? `$${plan.firstTarget}` : 'N/A'], ['建仓研究状态', plan.status || 'N/A'],
  ].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    levels.append(item);
  });
  card.append(levels, node('p', 'live-result-foot', '这是持仓／自选的状态体检；不把短线T计划自动套用到原本的中长线持仓。'));
  return card;
}

function eventRadarBlock(events) {
  const section = node('section', 'radar-block');
  const head = node('div', 'subsection-head');
  head.append(node('strong', '', '催化事件雷达'), pill(`${events.length} 条线索`, 'neutral'));
  section.append(head);
  if (!events.length) {
    section.append(node('p', 'live-empty', '暂未发现财报、FDA/临床、订单、并购、监管、产品或分析师修正线索。'));
    return section;
  }
  const list = node('div', 'event-list');
  events.forEach((event) => {
    const item = event.url ? node('a', 'event-item') : node('div', 'event-item');
    if (event.url) { item.href = event.url; item.target = '_blank'; item.rel = 'noopener noreferrer'; }
    const top = node('div');
    top.append(node('strong', '', event.symbol), pill(event.category, 'gold-light'));
    item.append(top, node('span', '', event.title), node('small', '', `${event.created} · ${event.publisher} · ${event.actionability}`));
    list.append(item);
  });
  section.append(list);
  return section;
}

function macroBlock(events) {
  if (!events?.length) return null;
  const section = node('section', 'macro-block');
  section.append(node('strong', '', '今日高影响经济事件'));
  events.forEach((event) => section.append(node('p', '', `${event.etTime} · ${event.event}${event.consensus ? ` · 预期 ${event.consensus}` : ''}`)));
  section.append(node('small', '', '若事件在 10:00 ET 公布，通常等公布后约5分钟再做开盘审计。'));
  return section;
}

function performanceBlock(report) {
  const section = node('section', 'performance-block');
  const localRecords = readLocalJson(PERFORMANCE_STORAGE, []);
  const cloudRecords = Array.isArray(report.performance20d) ? report.performance20d : [];
  const merged = [...cloudRecords, ...localRecords].reduce((map, item) => map.set(`${item.dateET}-${item.symbol || 'cash'}`, item), new Map());
  const records = [...merged.values()].sort((left, right) => String(left.dateET).localeCompare(String(right.dateET))).slice(-20);
  const trades = readLocalJson(TRADE_STORAGE, []).slice(-20);
  const top20 = records.filter((item) => item.top20).length;
  const top10 = records.filter((item) => item.top10Pct).length;
  const excursions = records.filter((item) => item.referencePrice && item.highestPrice && item.lowestPrice);
  const mfe = excursions.length ? excursions.reduce((sum, item) => sum + ((item.highestPrice / item.referencePrice) - 1) * 100, 0) / excursions.length : null;
  const mae = excursions.length ? excursions.reduce((sum, item) => sum + ((item.lowestPrice / item.referencePrice) - 1) * 100, 0) / excursions.length : null;
  const netPnl = trades.length ? trades.reduce((sum, item) => sum + Number(item.netPnl || 0), 0) : null;
  const head = node('div', 'subsection-head');
  head.append(node('strong', '', '20个交易日滚动复盘'), pill(`${records.length}/20 日`, 'neutral'));
  const metrics = node('div', 'performance-grid');
  [['前20名次数', `${top20}`], ['前10%次数', `${top10}`], ['平均MFE', formatSigned(mfe)], ['平均MAE', formatSigned(mae)], ['已记录净盈亏', netPnl === null ? 'N/A' : `$${netPnl.toFixed(2)}`]].forEach(([label, value]) => {
    const item = node('div');
    item.append(node('span', '', label), node('strong', '', value));
    metrics.append(item);
  });

  const form = node('form', 'trade-log-form');
  const primary = ledgerCandidates(readLocalJson(LEDGER_STORAGE, null))[0] || null;
  const ticker = node('input'); ticker.placeholder = '代码'; ticker.value = primary?.symbol || '';
  const entry = node('input'); entry.type = 'number'; entry.step = '0.001'; entry.placeholder = '实际买价';
  const exit = node('input'); exit.type = 'number'; exit.step = '0.001'; exit.placeholder = '实际卖价';
  const shares = node('input'); shares.type = 'number'; shares.step = '1'; shares.min = '1'; shares.placeholder = '股数'; shares.value = primary?.tradeMath?.shares || '';
  const save = node('button', 'action-button secondary', '记录实际成交'); save.type = 'submit';
  const feedback = node('span', 'trade-feedback', '实际成交需手动记录；系统不会连接券商落单。');
  form.append(ticker, entry, exit, shares, save, feedback);
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const qty = Number(shares.value);
    const buy = Number(entry.value);
    const sell = Number(exit.value);
    if (!ticker.value || !Number.isFinite(qty) || qty <= 0 || !Number.isFinite(buy) || !Number.isFinite(sell)) {
      feedback.textContent = '请填写代码、买价、卖价及股数。';
      return;
    }
    const fee = Number(report.account?.feePerSide ?? 1) * 2;
    const net = (sell - buy) * qty - fee;
    const risk = primary?.invalidationPrice ? Math.max(0.01, (buy - primary.invalidationPrice) * qty + fee) : null;
    const stored = readLocalJson(TRADE_STORAGE, []);
    stored.push({ dateET: new Date().toISOString().slice(0, 10), symbol: ticker.value.toUpperCase(), buy, sell, shares: qty, netPnl: net, realizedR: risk ? net / risk : null });
    writeLocalJson(TRADE_STORAGE, stored.slice(-40));
    feedback.textContent = `已记录：费用后 ${net >= 0 ? '+' : ''}$${net.toFixed(2)}。重新分析即可刷新汇总。`;
    entry.value = ''; exit.value = '';
  });
  section.append(head, metrics, form);
  return section;
}

function renderLiveResults(container, result, action, report) {
  container.replaceChildren();
  const meta = node('div', 'live-meta');
  meta.append(pill(result.session?.label || '未知时段', 'green'), node('span', '', `${result.session?.etTime || ''} · ${result.provider || ''}`));
  container.append(meta, marketGateCard(result));
  const macro = macroBlock(result.macroEvents);
  if (macro) container.append(macro);
  if (result.continuity) {
    const continuity = node('div', 'continuity-box');
    continuity.append(node('strong', '', result.continuity.label), node('span', '', result.continuity.detail));
    container.append(continuity);
  }
  if (result.noTrade) container.append(node('p', 'live-empty no-trade-box', action === 'build' ? '当前不建立新仓。候选保留在研究名单，等待大市、日线结构、事件和券商执行条件同时合格。' : '当前行动分支：保持现金。候选只供观察，必须等大市、触发、费用后净R及券商审计同时合格。'));
  const displayed = action === 'scan' ? (result.actionableCandidates || []) : (result.candidates || []);
  if (!displayed.length) {
    container.append(node('p', 'live-empty', '暂时无足够数据或无合格候选，保持现金／稍后重试。'));
  } else {
    const list = node('div', 'live-result-list');
    displayed.forEach((candidate, index) => {
      if (action === 'build') list.append(buildCandidateCard(candidate, index));
      else if (action === 'analyze') list.append(holdingAnalysisCard(candidate));
      else list.append(liveCandidateCard(candidate, index, candidateRole(index)));
    });
    container.append(list);
  }
  if (action === 'scan') container.append(eventRadarBlock(result.eventRadar || []), performanceBlock(report));
  if (action === 'build' || action === 'analyze') container.append(eventRadarBlock(result.eventRadar || []));
  const warning = node('div', 'live-warning');
  (result.warnings || []).forEach((text) => warning.append(node('p', '', text)));
  container.append(warning);
}

async function requestLiveAnalysis(action, symbols, button, results, report) {
  if (!liveConfig?.baseUrl || !liveConfig?.accessToken) {
    results.replaceChildren(node('p', 'live-empty', '云端分析尚未连接，请等待下一次部署。'));
    return;
  }
  button.disabled = true;
  const original = button.textContent;
  button.textContent = '分析中…';
  results.replaceChildren(node('div', 'live-loading', '正在读取当前市场时段与行情…'));
  try {
    const response = await fetch(`${liveConfig.baseUrl}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Radar-Token': liveConfig.accessToken },
      body: JSON.stringify({
        action,
        symbols,
        frozenSymbols: action === 'scan' ? frozenSymbols() : [],
        account: {
          cash: Number(report.account?.cash || 0),
          riskLimit: Number(report.account?.riskLimit || 0),
          feePerSide: Number(report.account?.feePerSide ?? 1),
        },
      }),
    });
    if (!response.ok) throw new Error('分析服务暂时不可用');
    const result = applyCandidateContinuity(await response.json(), action);
    updatePerformance(result, action);
    renderLiveResults(results, result, action, report);
  } catch {
    results.replaceChildren(node('p', 'live-empty error-box', '即时分析暂时失败，请稍后再试；正式报告仍可正常查看。'));
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function portfolioEditor(originalReport, report, encryptedAt) {
  const section = node('section', 'section portfolio-editor-section');
  const head = node('div', 'section-title simple');
  head.append(node('h2', '', '账户与持仓资料'), pill('本机可修改', 'green'));
  const card = node('form', 'card portfolio-editor');
  const intro = node('p', 'portfolio-intro', '现金会用于即时筛选的股数和费用后净R；持仓列表会用于「分析现有持仓」。资料只保存在当前设备。');
  const cashLabel = node('label', 'portfolio-cash-label', '可用现金（USD）');
  const cash = node('input');
  cash.type = 'number';
  cash.step = '0.01';
  cash.min = '0';
  cash.inputMode = 'decimal';
  cash.value = Number(report.account?.cash || 0).toFixed(2);
  cashLabel.append(cash);

  const holdingsTitle = node('div', 'portfolio-holdings-head');
  holdingsTitle.append(node('strong', '', '持仓股票'), node('span', '', '代码与股数'));
  const rows = node('div', 'portfolio-holding-rows');
  const appendRow = (holding = {}) => {
    const row = node('div', 'portfolio-holding-row');
    const symbol = node('input');
    symbol.type = 'text'; symbol.maxLength = 10; symbol.placeholder = '代码'; symbol.value = holding.symbol || '';
    symbol.autocomplete = 'off'; symbol.autocapitalize = 'characters';
    const qty = node('input');
    qty.type = 'number'; qty.step = '1'; qty.min = '1'; qty.inputMode = 'numeric'; qty.placeholder = '股数'; qty.value = holding.qty || '';
    const remove = node('button', 'remove-holding-button', '移除');
    remove.type = 'button';
    remove.addEventListener('click', () => row.remove());
    row.append(symbol, qty, remove);
    rows.append(row);
  };
  report.holdings.forEach(appendRow);
  const add = node('button', 'action-button secondary', '+ 增加持仓');
  add.type = 'button';
  add.addEventListener('click', () => appendRow());
  const actions = node('div', 'portfolio-actions');
  const save = node('button', 'action-button primary', '保存账户资料');
  save.type = 'submit';
  const reset = node('button', 'action-button secondary', '恢复云端原始资料');
  reset.type = 'button';
  const feedback = node('span', 'portfolio-feedback', '');
  reset.addEventListener('click', () => {
    localStorage.removeItem(PORTFOLIO_STORAGE);
    renderDashboard(originalReport, encryptedAt);
  });
  actions.append(save, reset);
  card.append(intro, cashLabel, holdingsTitle, rows, add, actions, feedback);
  card.addEventListener('submit', (event) => {
    event.preventDefault();
    const nextCash = Number(cash.value);
    const nextHoldings = [...rows.querySelectorAll('.portfolio-holding-row')].map((row) => ({
      symbol: row.querySelector('input[type="text"]')?.value || '',
      qty: row.querySelector('input[type="number"]')?.value || '',
    }));
    const normalized = normalizedHoldings(nextHoldings, originalReport.holdings || []);
    const nonBlankRows = nextHoldings.filter((item) => String(item.symbol || '').trim() || String(item.qty || '').trim()).length;
    if (!Number.isFinite(nextCash) || nextCash < 0 || normalized.length !== nonBlankRows) {
      feedback.textContent = '请填写有效现金金额，以及每只持仓的正确代码和正整数股数。';
      return;
    }
    writeLocalJson(PORTFOLIO_STORAGE, { cash: nextCash, holdings: normalized, savedAt: new Date().toISOString() });
    renderDashboard(originalReport, encryptedAt);
  });
  section.append(head, card);
  return section;
}

function liveTools(report) {
  const section = node('section', 'section live-tools');
  const head = node('div', 'section-title simple');
  const title = node('div');
  title.append(node('p', 'eyebrow dark-text', 'LIVE CLOUD ANALYSIS'), node('h2', '', '即时分析'));
  head.append(title, pill('无需等定时', 'green'));

  const panel = node('div', 'card live-control-card');
  const intro = node('p', 'live-intro', '做T、建仓研究和持仓体检是三条路线：先查事件，再看大市、行业、日线结构、相对强度、量价与费用。建仓候选显示的是研究价格区和失效条件，不是自动买入指令。');
  const quickActions = node('div', 'quick-actions');
  const holdingsButton = node('button', 'action-button secondary', '分析现有持仓');
  const scanButton = node('button', 'action-button primary', '一键筛选可做T');
  const buildButton = node('button', 'action-button build', '筛选可建仓');
  const custom = node('div', 'custom-symbols');
  const input = node('input');
  input.placeholder = '输入股票，例如 NVDA, TSLA, AAPL';
  input.inputMode = 'text';
  input.autocomplete = 'off';
  input.maxLength = 100;
  const customButton = node('button', 'action-button secondary', '分析自选');
  const results = node('div', 'live-results');

  holdingsButton.addEventListener('click', () => {
    const symbols = report.holdings.map((item) => item.symbol);
    if (!symbols.length) {
      results.replaceChildren(node('p', 'live-empty error-box', '请先在「账户与持仓资料」加入至少一只持仓股票。'));
      return;
    }
    requestLiveAnalysis('analyze', symbols, holdingsButton, results, report);
  });
  scanButton.addEventListener('click', () => requestLiveAnalysis('scan', [], scanButton, results, report));
  buildButton.addEventListener('click', () => requestLiveAnalysis('build', [], buildButton, results, report));
  customButton.addEventListener('click', () => {
    const symbols = input.value.toUpperCase().split(/[\s,，]+/).filter(Boolean);
    if (!symbols.length) {
      results.replaceChildren(node('p', 'live-empty error-box', '请先输入至少一个股票代码。'));
      return;
    }
    requestLiveAnalysis('analyze', symbols, customButton, results, report);
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      customButton.click();
    }
  });
  quickActions.append(holdingsButton, scanButton, buildButton);
  custom.append(input, customButton);
  panel.append(intro, quickActions, custom, results);
  section.append(head, panel);
  return section;
}

function renderDashboard(originalReport, encryptedAt) {
  const report = reportWithLocalPortfolio(originalReport);
  app.replaceChildren();
  liveConfig = report.liveApi || null;
  const page = node('div', 'page');
  const topbar = node('header', 'topbar');
  const brand = node('div', 'brand');
  const logo = node('div', 'mini-logo');
  logo.append(icon('radar'));
  const brandText = node('div');
  brandText.append(node('strong', '', '美股行动台'), node('span', '', '每日筛选 · 持仓风控'));
  brand.append(logo, brandText);
  const logout = node('button', 'ghost-button', '退出');
  logout.type = 'button';
  logout.addEventListener('click', () => { clearKey(); showLogin(); });
  topbar.append(brand, logout);

  const hero = node('section', 'dashboard-hero');
  const status = node('div', 'status-row');
  status.append(pill(`${report.dateLabel} · ${report.marketClock}`, 'dark'), pill(report.marketState, 'gold'));
  hero.append(status, node('p', 'hero-label', '今晚总指令'), node('h1', '', report.directive), node('p', 'hero-summary', report.summary));
  const values = node('div', 'value-grid');
  values.append(valueCard('当前现金', `$${Number(report.account.cash).toFixed(2)}`), valueCard('单笔风险上限', `$${report.account.riskLimit}`));
  hero.append(values, node('p', 'account-rule', report.account.rule));

  const picksTitle = node('div', 'section-title');
  picksTitle.append(node('div', '', ''), node('span', '', '不是涨幅榜追高名单'));
  picksTitle.firstChild.append(node('p', 'eyebrow dark-text', "TONIGHT'S SHORTLIST"), node('h2', '', '今晚做T候选'));
  const picks = node('section', 'section');
  const candidateGrid = node('div', 'candidate-grid');
  const shortlist = (Array.isArray(report.shortlist) && report.shortlist.length ? report.shortlist : [report.primary, report.backup]).slice(0, MAX_T_CANDIDATES);
  for (let index = 0; index < MAX_T_CANDIDATES; index += 1) {
    candidateGrid.append(candidateCard(shortlist[index], candidateRole(index), String(index + 1)));
  }
  picks.append(picksTitle, candidateGrid);

  const holdings = node('section', 'section');
  const holdingsHead = node('div', 'section-title simple');
  holdingsHead.append(node('h2', '', '持仓行动'), pill(`${report.holdings.length} 个持仓`, 'neutral'));
  const holdingsCard = node('div', 'card holdings-list');
  report.holdings.forEach((holding) => {
    const row = node('div', 'holding-row');
    const identity = node('div');
    identity.append(node('strong', '', holding.symbol), node('span', '', `${holding.name} · ${holding.qty}股`));
    const tone = holding.tone === 'hold' ? 'green' : holding.tone === 'risk' ? 'red' : 'gold-light';
    row.append(identity, pill(holding.action, tone));
    holdingsCard.append(row);
  });
  holdings.append(holdingsHead, holdingsCard);

  const schedule = node('section', 'section');
  schedule.append(node('h2', 'plain-title', '每日流程'));
  const scheduleCard = node('div', 'card timeline');
  report.schedule.forEach((item) => {
    const row = node('div', `timeline-row ${item.active ? 'active' : ''}`);
    row.append(node('time', '', item.time));
    const copy = node('div');
    copy.append(node('strong', '', item.title), node('span', '', item.body));
    row.append(copy);
    scheduleCard.append(row);
  });
  schedule.append(scheduleCard);

  const footer = node('footer');
  footer.append(node('p', '', report.note), node('p', '', `加密报告更新时间：${encryptedAt ? new Date(encryptedAt).toLocaleString('zh-HK', { hour12: false }) : '待更新'}`));

  page.append(topbar, hero, portfolioEditor(originalReport, report, encryptedAt), liveTools(report), picks, holdings, schedule, footer);
  app.append(page);
}

async function start() {
  try {
    const key = await recalledKey();
    if (!key) return showLogin();
    const payload = await fetchPayload();
    const report = await decryptReport(payload, key);
    renderDashboard(report, payload.generatedAt);
  } catch {
    clearKey();
    showLogin('报告已更新，请重新输入密码。');
  }
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}));
}

start();
