const app = document.querySelector('#app');
const KEY_STORAGE = 'meigu-h5-key-v1';
const KEY_EXPIRY = 'meigu-h5-key-expiry-v1';
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

const bytesFromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
const base64FromBytes = (value) => btoa(String.fromCharCode(...value));

function node(tag, className = '', text = '') {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== '') element.textContent = String(text);
  return element;
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
    card.append(node('p', 'empty-copy', rank === '1' ? '20:30 自动筛选；无合格机会会直接显示今晚不开仓。' : '主选失效后先考虑，不会同时开两仓。'));
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

function renderDashboard(report, encryptedAt) {
  app.replaceChildren();
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
  picksTitle.firstChild.append(node('p', 'eyebrow dark-text', "TONIGHT'S SHORTLIST"), node('h2', '', '今晚候选'));
  const picks = node('section', 'section');
  const candidateGrid = node('div', 'candidate-grid');
  candidateGrid.append(candidateCard(report.primary, '主选', '1'), candidateCard(report.backup, '备选', '2'));
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

  page.append(topbar, hero, picks, holdings, schedule, footer);
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
