// Biko - frontend (JS puro). Toda regra de segurança real está no backend (server.js);
// aqui a interface apenas se adapta ao perfil do usuário logado.

const $app = document.getElementById('app');
const state = {
  user: null, view: 'login', tab: 'home', resetEmail: '',
  users: [], filters: { search: '', role: '', status: '' },          // gestão de usuários (admin)
  search: { q: '', category: '', maxPrice: '', sort: '' }, results: [], total: 0, categories: null, // busca
  orders: [], orderFilter: '', myServices: [],
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const initials = (n) => n.split(' ').filter(Boolean).slice(0, 2).map((p) => p[0]).join('').toUpperCase();
const ROLE_LABEL = { admin: 'Admin', cliente: 'Cliente', prestador: 'Prestador' };

function toast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = 'toast'), 3000);
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* sem corpo */ }
  if (!res.ok) {
    // Sessão expirada / conta desativada no meio do uso -> volta para o login
    if ((res.status === 401 || res.status === 403) && state.user && url !== '/api/auth/login') {
      state.user = null; state.view = 'login';
      render();
      toast(data.error || 'Sessão encerrada.', true);
    }
    const err = new Error(data.error || 'Erro inesperado.');
    err.fields = data.fields || {};
    err.status = res.status;
    throw err;
  }
  return data;
}

function showFieldErrors(form, fields) {
  form.querySelectorAll('.field-error').forEach((e) => (e.textContent = ''));
  form.querySelectorAll('input.invalid').forEach((i) => i.classList.remove('invalid'));
  Object.entries(fields || {}).forEach(([name, msg]) => {
    const el = form.querySelector(`[data-err="${name}"]`);
    const input = form.querySelector(`[name="${name}"]`);
    if (el) el.textContent = msg;
    if (input) input.classList.add('invalid');
  });
}
function formAlert(form, msg, type = '') {
  let a = form.querySelector('.alert');
  if (!msg) { if (a) a.remove(); return; }
  if (!a) { a = document.createElement('div'); form.insertBefore(a, form.querySelector('button[type=submit]')); }
  a.className = 'alert ' + type;
  a.textContent = msg;
}

// ---------- validação no cliente (espelha o backend) ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function pwError(p) {
  if (p.length < 8) return 'A senha deve ter no mínimo 8 caracteres.';
  if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) return 'A senha deve conter letras e números.';
  return '';
}

// ---------- telas de autenticação ----------
function authShell(inner) {
  return `<div class="screen pad">
    <div class="logo">b</div><div class="brand">biko</div>
    ${inner}
  </div>`;
}

function viewLogin() {
  $app.innerHTML = authShell(`
    <div class="tagline">Encontre quem precisa no pedágio e fecha o serviço rápido.</div>
    <form id="f" novalidate>
      <label for="email">E-mail</label>
      <input id="email" name="email" type="email" autocomplete="username" placeholder="exemplo@email.com">
      <div class="field-error" data-err="email"></div>
      <div class="row-between"><label for="password">Senha</label><button type="button" class="link" id="forgot">Esqueci a senha</button></div>
      <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Sua senha">
      <div class="field-error" data-err="password"></div>
      <button class="btn" type="submit">Entrar</button>
    </form>
    <div class="footer-text">Não tem conta? <button class="link" id="goReg">Cadastre-se</button></div>
    <div class="footer-text" style="font-size:12px">Demo: admin@biko.com / Admin@123<br>cliente@biko.com / Cliente@123<br>prestador@biko.com / Prestador@123<br>joana@biko.com / Joana@123 (prestadora)</div>
  `);
  const f = document.getElementById('f');
  document.getElementById('goReg').onclick = () => { state.view = 'register'; render(); };
  document.getElementById('forgot').onclick = () => { state.view = 'forgot'; render(); };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const email = f.email.value.trim(), password = f.password.value;
    const fields = {};
    if (!EMAIL_RE.test(email)) fields.email = 'Informe um e-mail válido.';
    if (!password) fields.password = 'Informe a senha.';
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
    try {
      const { user } = await api('POST', '/api/auth/login', { email, password });
      enterApp(user);
    } catch (err) { formAlert(f, err.message); }
    btn.disabled = false;
  };
}

function viewRegister() {
  let role = 'cliente';
  $app.innerHTML = authShell(`
    <div class="tagline">Crie sua conta</div>
    <form id="f" novalidate>
      <label>Quero usar o Biko como</label>
      <div class="seg"><button type="button" data-role="cliente" class="on">Cliente</button><button type="button" data-role="prestador">Prestador</button></div>
      <label for="name">Nome completo</label>
      <input id="name" name="name" autocomplete="name"><div class="field-error" data-err="name"></div>
      <label for="email">E-mail</label>
      <input id="email" name="email" type="email" autocomplete="username"><div class="field-error" data-err="email"></div>
      <label for="phone">Telefone</label>
      <input id="phone" name="phone" type="tel" placeholder="(47) 99999-9999"><div class="field-error" data-err="phone"></div>
      <label for="password">Senha</label>
      <input id="password" name="password" type="password" autocomplete="new-password" placeholder="Mín. 8 caracteres, letras e números"><div class="field-error" data-err="password"></div>
      <label for="confirm">Confirmar senha</label>
      <input id="confirm" name="confirm" type="password" autocomplete="new-password"><div class="field-error" data-err="confirm"></div>
      <button class="btn" type="submit">Criar conta</button>
    </form>
    <div class="footer-text">Já tem conta? <button class="link" id="goLogin">Entrar</button></div>
  `);
  const f = document.getElementById('f');
  document.getElementById('goLogin').onclick = () => { state.view = 'login'; render(); };
  f.querySelectorAll('.seg button').forEach((b) => (b.onclick = () => {
    role = b.dataset.role;
    f.querySelectorAll('.seg button').forEach((x) => x.classList.toggle('on', x === b));
  }));
  f.onsubmit = async (e) => {
    e.preventDefault();
    const v = Object.fromEntries(new FormData(f));
    const fields = {};
    if (v.name.trim().length < 3) fields.name = 'Informe o nome completo (mín. 3 caracteres).';
    if (!EMAIL_RE.test(v.email.trim())) fields.email = 'Informe um e-mail válido.';
    const pe = pwError(v.password); if (pe) fields.password = pe;
    if (v.password !== v.confirm) fields.confirm = 'As senhas não conferem.';
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
    try {
      const { user } = await api('POST', '/api/auth/register', { name: v.name, email: v.email, phone: v.phone, password: v.password, role });
      toast('Conta criada com sucesso!');
      enterApp(user);
    } catch (err) { showFieldErrors(f, err.fields); formAlert(f, err.message); }
    btn.disabled = false;
  };
}

function viewForgot() {
  $app.innerHTML = authShell(`
    <div class="tagline">Recuperar senha</div>
    <form id="f" novalidate>
      <label for="email">E-mail da sua conta</label>
      <input id="email" name="email" type="email" placeholder="exemplo@email.com"><div class="field-error" data-err="email"></div>
      <button class="btn" type="submit">Enviar código</button>
    </form>
    <div class="footer-text"><button class="link" id="back">Voltar ao login</button> · <button class="link" id="hasCode">Já tenho um código</button></div>
  `);
  const f = document.getElementById('f');
  document.getElementById('back').onclick = () => { state.view = 'login'; render(); };
  document.getElementById('hasCode').onclick = () => { state.view = 'reset'; render(); };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const email = f.email.value.trim();
    if (!EMAIL_RE.test(email)) return showFieldErrors(f, { email: 'Informe um e-mail válido.' });
    showFieldErrors(f, {});
    try {
      const r = await api('POST', '/api/auth/forgot', { email });
      formAlert(f, r.message, 'ok');
      if (r.devToken) {
        const d = document.createElement('div');
        d.className = 'alert info';
        d.innerHTML = `Modo demonstração (em produção iria por e-mail). Seu código:<br><b>${esc(r.devToken)}</b>`;
        f.insertBefore(d, f.querySelector('button[type=submit]'));
        state.resetToken = r.devToken;
        f.querySelector('button[type=submit]').textContent = 'Continuar';
        f.onsubmit = (ev) => { ev.preventDefault(); state.view = 'reset'; render(); };
      }
    } catch (err) { formAlert(f, err.message); }
  };
}

function viewReset() {
  $app.innerHTML = authShell(`
    <div class="tagline">Defina uma nova senha</div>
    <form id="f" novalidate>
      <label for="token">Código de recuperação</label>
      <input id="token" name="token" value="${esc(state.resetToken || '')}"><div class="field-error" data-err="token"></div>
      <label for="password">Nova senha</label>
      <input id="password" name="password" type="password" autocomplete="new-password"><div class="field-error" data-err="password"></div>
      <label for="confirm">Confirmar nova senha</label>
      <input id="confirm" name="confirm" type="password" autocomplete="new-password"><div class="field-error" data-err="confirm"></div>
      <button class="btn" type="submit">Redefinir senha</button>
    </form>
    <div class="footer-text"><button class="link" id="back">Voltar ao login</button></div>
  `);
  const f = document.getElementById('f');
  document.getElementById('back').onclick = () => { state.view = 'login'; render(); };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const v = Object.fromEntries(new FormData(f));
    const fields = {};
    if (!v.token.trim()) fields.token = 'Informe o código.';
    const pe = pwError(v.password); if (pe) fields.password = pe;
    if (v.password !== v.confirm) fields.confirm = 'As senhas não conferem.';
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    try {
      await api('POST', '/api/auth/reset', { token: v.token.trim(), password: v.password });
      state.resetToken = '';
      state.view = 'login'; render();
      toast('Senha redefinida! Faça login.');
    } catch (err) { formAlert(f, err.message); }
  };
}

// ---------- app logado ----------
function enterApp(user) {
  state.user = user;
  state.tab = 'home';
  state.view = 'app';
  render();
}

// ---------- formatação ----------
const brl = (v) => Number(v).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
const dateBR = (d) => String(d).split('-').reverse().join('/');
const fmtDur = (m) => (m < 60 ? `${m} min` : m % 60 === 0 ? `${m / 60} h` : `${Math.floor(m / 60)} h ${m % 60} min`);
const dateTimeBR = (ms) => new Date(ms).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
const pad2 = (n) => String(n).padStart(2, '0');
const ymd = (d) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const toMin = (hhmm) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));
const STATUS_LABEL = { pendente: 'Pendente', confirmado: 'Confirmado', recusado: 'Recusado', concluido: 'Concluído', cancelado: 'Cancelado' };
const CAT_ICON = { 'Telhado & Reparador': '🏠', Encanador: '🔧', Eletricista: '⚡', Pintor: '🎨', Limpeza: '🧹', Jardinagem: '🌿' };
const ACTION_LABEL = { confirmar: 'Confirmar pedido', recusar: 'Recusar', concluir: 'Marcar como concluído', cancelar: 'Cancelar pedido' };
const OPEN_MIN = 7 * 60, CLOSE_MIN = 20 * 60; // mesmo horário de atendimento do backend

// Avatar: foto (se houver) ou iniciais do nome
function avatarHtml(u, cls = '') {
  const inner = u.photo_url ? `<img src="${esc(u.photo_url)}" alt="Foto de ${esc(u.name)}">` : esc(initials(u.name || '?'));
  return `<div class="avatar ${cls}">${inner}</div>`;
}

function navItems() {
  const r = state.user.role;
  const items = [{ id: 'home', ico: '🏠', label: 'Início' }];
  if (r === 'cliente') { items.push({ id: 'search', ico: '🔍', label: 'Buscar' }, { id: 'orders', ico: '📅', label: 'Pedidos' }); }
  if (r === 'prestador') { items.push({ id: 'services', ico: '🛠️', label: 'Serviços' }, { id: 'orders', ico: '📅', label: 'Pedidos' }); }
  if (r === 'admin') { items.push({ id: 'users', ico: '👥', label: 'Usuários' }, { id: 'orders', ico: '📅', label: 'Pedidos' }); }
  items.push({ id: 'account', ico: '👤', label: 'Conta' });
  return items;
}

function shell(content) {
  const u = state.user;
  return `
    <div class="screen">
      <div class="top"><div class="hello">
        <div><h2>Olá, ${esc(u.name.split(' ')[0])} 👋</h2><p>${u.role === 'cliente' ? 'O que você precisa hoje?' : u.role === 'prestador' ? 'Veja seus pedidos de hoje' : 'Painel administrativo'}</p></div>
        ${avatarHtml(u)}
      </div></div>
      ${content}
    </div>
    <nav class="nav">${navItems().map((i) => `<button data-tab="${i.id}" class="${state.tab === i.id ? 'on' : ''}"><span class="ico">${i.ico}</span>${i.label}</button>`).join('')}</nav>`;
}

async function viewApp() {
  const seq = (viewApp.seq = (viewApp.seq || 0) + 1); // ignora respostas atrasadas se o usuário trocar de aba rápido
  $app.innerHTML = shell('<div class="spinner">Carregando…</div>');
  bindNav();
  try {
    const tab = state.tab;
    let html = '';
    if (tab === 'home') html = await homeHtml();
    else if (tab === 'search') html = await searchHtml();
    else if (tab === 'orders') html = await ordersHtml();
    else if (tab === 'services') html = await servicesHtml();
    else if (tab === 'users') { await loadUsers(); html = usersHtml(); }
    else html = accountHtml();
    if (seq !== viewApp.seq) return;
    $app.innerHTML = shell(html);
    bindNav();
    if (tab === 'home') bindHome();
    if (tab === 'search') bindSearch();
    if (tab === 'orders') bindOrders();
    if (tab === 'services') bindServices();
    if (tab === 'users') bindUsers();
    if (tab === 'account') bindAccount();
  } catch (err) {
    if (state.user && seq === viewApp.seq) { $app.innerHTML = shell(`<div class="empty">${esc(err.message)}</div>`); bindNav(); }
  }
}

function goTab(tab) { state.tab = tab; viewApp(); }
function bindNav() {
  $app.querySelectorAll('.nav button').forEach((b) => (b.onclick = () => goTab(b.dataset.tab)));
}

// ---------- início ----------
async function homeHtml() {
  const role = state.user.role;
  if (role === 'prestador') {
    const d = await api('GET', '/api/prestador/painel');
    const prox = d.proximos.length
      ? d.proximos.map(orderCard).join('')
      : '<div class="empty">Nenhum atendimento confirmado por enquanto.</div>';
    return `<div class="stats">
      <div class="stat"><b>${d.resumo.pedidosNovos}</b><small>Pedidos novos</small></div>
      <div class="stat"><b>${d.resumo.avaliacao ?? '—'}</b><small>Avaliação</small></div>
      <div class="stat"><b>${brl(d.resumo.ganhosMes)}</b><small>Ganhos no mês</small></div></div>
      ${d.resumo.pedidosNovos ? `<div class="pad" style="padding-bottom:0"><button class="btn small" id="goPending">Ver ${d.resumo.pedidosNovos} pedido(s) novo(s)</button></div>` : ''}
      <div class="section-title"><span>Próximos atendimentos</span></div>${prox}`;
  }
  if (role === 'admin') {
    const [{ users }, { orders }] = await Promise.all([api('GET', '/api/users'), api('GET', '/api/orders')]);
    const c = (r) => users.filter((u) => u.role === r).length;
    const n = (s) => orders.filter((o) => o.status === s).length;
    return `<div class="stats">
      <div class="stat"><b>${c('cliente')}</b><small>Clientes</small></div>
      <div class="stat"><b>${c('prestador')}</b><small>Prestadores</small></div>
      <div class="stat"><b>${users.filter((u) => !u.active).length}</b><small>Desativados</small></div></div>
      <div class="stats">
      <div class="stat"><b>${orders.length}</b><small>Pedidos</small></div>
      <div class="stat"><b>${n('pendente')}</b><small>Pendentes</small></div>
      <div class="stat"><b>${n('concluido')}</b><small>Concluídos</small></div></div>
      <div class="empty">Use a aba <b>Usuários</b> para gerenciar contas e a aba <b>Pedidos</b> para acompanhar os agendamentos.</div>`;
  }
  const d = await api('GET', '/api/cliente/home');
  return `<div class="promo" id="promo" role="button" tabindex="0"><b>Precisa de um profissional?</b><small>Encontre prestadores disponíveis e agende em poucos toques.</small></div>
    <div class="section-title"><span>Categorias populares</span></div>
    ${d.categorias.map((c) => `<div class="cat" data-cat="${esc(c.nome)}" role="button" tabindex="0"><div class="ci">${CAT_ICON[c.nome] || '🛠️'}</div><div style="flex:1"><b>${esc(c.nome)}</b><small>${esc(c.desc)}</small></div><small>${c.total} serviço(s)</small></div>`).join('')}`;
}

function bindHome() {
  const pending = document.getElementById('goPending');
  if (pending) pending.onclick = () => { state.orderFilter = 'pendente'; goTab('orders'); };
  const promo = document.getElementById('promo');
  if (promo) promo.onclick = () => goTab('search');
  $app.querySelectorAll('[data-cat]').forEach((el) => (el.onclick = () => { state.search.category = el.dataset.cat; goTab('search'); }));
  bindOrderCards();
}

// ---------- busca (cliente) ----------
async function loadCategories() {
  if (!state.categories) state.categories = (await api('GET', '/api/categories')).categories;
  return state.categories;
}
async function runSearch() {
  const s = state.search;
  const q = new URLSearchParams();
  if (s.q) q.set('q', s.q);
  if (s.category) q.set('category', s.category);
  if (s.maxPrice !== '') q.set('max_price', s.maxPrice);
  if (s.sort) q.set('sort', s.sort);
  const d = await api('GET', '/api/search?' + q.toString());
  state.results = d.results; state.total = d.total;
}

async function searchHtml() {
  const cats = await loadCategories();
  await runSearch();
  const s = state.search;
  return `<div class="toolbar">
      <input id="q" type="search" placeholder="O que você procura? (ex.: vazamento, pintura)" value="${esc(s.q)}" maxlength="80">
      <div class="filters">
        <select id="sCat"><option value="">Todas as categorias</option>${cats.map((c) => `<option value="${esc(c.nome)}" ${s.category === c.nome ? 'selected' : ''}>${esc(c.nome)}</option>`).join('')}</select>
        <select id="sSort">${[['', 'Mais relevantes'], ['preco_asc', 'Menor preço'], ['preco_desc', 'Maior preço'], ['nome', 'Nome (A–Z)']].map(([v, l]) => `<option value="${v}" ${s.sort === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      </div>
      <input id="sMax" type="number" inputmode="decimal" min="0" step="1" placeholder="Preço máximo (R$)" value="${esc(s.maxPrice)}">
    </div>
    <div class="count" id="sCount"></div>
    <div id="results"></div>`;
}

function resultsInner() {
  const s = state.search;
  document.getElementById('sCount').textContent = `${state.total} serviço(s) encontrado(s)`;
  if (!state.results.length) {
    const hasFilter = s.q || s.category || s.maxPrice !== '' || s.sort;
    return `<div class="empty">Nenhum resultado encontrado${s.q ? ` para “${esc(s.q)}”` : ''}.<br>Tente outras palavras ou ajuste os filtros.${hasFilter ? '<br><button class="link" id="clearFilters" style="margin-top:10px">Limpar filtros</button>' : ''}</div>`;
  }
  return state.results.map((r) => `<div class="card-item svc">
      ${avatarHtml({ name: r.provider_name, photo_url: r.provider_photo_url }, 'soft')}
      <div class="info"><b>${esc(r.title)}</b><small>${esc(r.provider_name)} · ${esc(r.category)}</small>
        ${r.description ? `<small class="desc">${esc(r.description)}</small>` : ''}
        <div class="meta"><span>${brl(r.price)}</span><span>⏱ ${fmtDur(r.duration_min)}</span></div></div>
      ${state.user.role === 'cliente' ? `<button class="btn small" data-book="${r.id}">Agendar</button>` : ''}</div>`).join('');
}

function paintResults() {
  const box = document.getElementById('results');
  box.innerHTML = resultsInner();
  box.querySelectorAll('[data-book]').forEach((b) => (b.onclick = () => bookModal(state.results.find((r) => r.id === Number(b.dataset.book)))));
  const clear = document.getElementById('clearFilters');
  if (clear) clear.onclick = () => { state.search = { q: '', category: '', maxPrice: '', sort: '' }; viewApp(); };
}

async function refreshResults() {
  try { await runSearch(); paintResults(); } catch (err) { toast(err.message, true); }
}

function bindSearch() {
  let t;
  const q = document.getElementById('q'), max = document.getElementById('sMax');
  const later = (fn) => { clearTimeout(t); t = setTimeout(fn, 300); };
  q.oninput = () => later(() => { state.search.q = q.value.trim(); refreshResults(); });
  max.oninput = () => later(() => { state.search.maxPrice = max.value.trim(); refreshResults(); });
  document.getElementById('sCat').onchange = (e) => { state.search.category = e.target.value; refreshResults(); };
  document.getElementById('sSort').onchange = (e) => { state.search.sort = e.target.value; refreshResults(); };
  paintResults();
}

// ---------- agendamento (modal do cliente) ----------
function bookModal(sv) {
  const today = new Date(), maxDay = new Date(); maxDay.setDate(maxDay.getDate() + 60);
  const ov = document.createElement('div');
  ov.className = 'overlay';
  ov.innerHTML = `<div class="sheet"><h3>Agendar serviço</h3>
    <div class="summary"><b>${esc(sv.title)}</b><small>${esc(sv.provider_name)} · ${brl(sv.price)} · ${fmtDur(sv.duration_min)}</small></div>
    <form id="bf" novalidate>
      <label for="bDate">Data</label><input id="bDate" name="date" type="date" min="${ymd(today)}" max="${ymd(maxDay)}"><div class="field-error" data-err="date"></div>
      <label for="bTime">Horário</label><select id="bTime" name="time" disabled><option value="">Escolha a data primeiro</option></select><div class="field-error" data-err="time"></div>
      <label for="bAddr">Endereço do serviço</label><input id="bAddr" name="address" maxlength="200" placeholder="Rua, número, bairro"><div class="field-error" data-err="address"></div>
      <label for="bNotes">Observações (opcional)</label><textarea id="bNotes" name="notes" rows="3" maxlength="500" placeholder="Conte o que precisa ser feito"></textarea><div class="field-error" data-err="notes"></div>
      <div class="actions" style="margin-top:18px"><button type="button" class="btn secondary" id="cancel" style="margin:0">Voltar</button><button type="submit" class="btn" style="margin:0">Enviar pedido</button></div>
    </form></div>`;
  $app.appendChild(ov);
  const f = ov.querySelector('#bf');
  ov.querySelector('#cancel').onclick = () => ov.remove();
  ov.onclick = (e) => { if (e.target === ov) ov.remove(); };

  async function loadSlots() {
    const date = f.date.value, sel = f.time;
    if (!date) { sel.disabled = true; sel.innerHTML = '<option value="">Escolha a data primeiro</option>'; return; }
    let busy = [];
    try { busy = (await api('GET', `/api/providers/${sv.provider_id}/agenda?date=${date}`)).busy; }
    catch (err) { showFieldErrors(f, { date: err.message }); return; }
    const earliest = Date.now() + 60 * 60000;
    let opts = '', free = 0;
    for (let m = OPEN_MIN; m + sv.duration_min <= CLOSE_MIN; m += 30) {
      const hhmm = `${pad2(Math.floor(m / 60))}:${pad2(m % 60)}`;
      const [y, mo, d] = date.split('-').map(Number);
      const startMs = new Date(y, mo - 1, d, Math.floor(m / 60), m % 60).getTime();
      const taken = busy.some((b) => m < toMin(b.end) && m + sv.duration_min > toMin(b.start));
      const past = startMs < earliest;
      if (!taken && !past) free++;
      opts += `<option value="${hhmm}" ${taken || past ? 'disabled' : ''}>${hhmm}${taken ? ' (ocupado)' : past ? ' (indisponível)' : ''}</option>`;
    }
    sel.innerHTML = `<option value="">${free ? 'Escolha o horário' : 'Sem horários neste dia'}</option>` + opts;
    sel.disabled = !free;
  }
  f.date.onchange = () => { showFieldErrors(f, {}); loadSlots(); };

  f.onsubmit = async (e) => {
    e.preventDefault();
    const fields = {};
    if (!f.date.value) fields.date = 'Escolha a data.';
    if (!f.time.value) fields.time = 'Escolha o horário.';
    if (f.address.value.trim().length < 5) fields.address = 'Informe o endereço do serviço.';
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
    try {
      await api('POST', '/api/orders', { service_id: sv.id, date: f.date.value, time: f.time.value, address: f.address.value, notes: f.notes.value });
      ov.remove();
      toast('Pedido enviado! Aguarde a confirmação do prestador.');
      state.orderFilter = '';
      goTab('orders');
      return;
    } catch (err) {
      showFieldErrors(f, err.fields); formAlert(f, err.message);
      if (err.status === 409) loadSlots(); // alguém ocupou o horário: atualiza a lista
    }
    btn.disabled = false;
  };
}

// ---------- pedidos ----------
function counterpart(o) {
  const r = state.user.role;
  if (r === 'cliente') return `Prestador: ${o.provider.name}`;
  if (r === 'prestador') return `Cliente: ${o.client.name}`;
  return `${o.client.name} → ${o.provider.name}`;
}

function orderCard(o) {
  return `<div class="card-item order" data-order="${o.id}" role="button" tabindex="0">
    <div class="info"><b>${esc(o.service_title)}</b><small>${esc(counterpart(o))}</small>
      <small>📅 ${dateBR(o.date)} · ${o.time}–${o.end_time}</small></div>
    <div class="right"><span class="badge st-${o.status}">${STATUS_LABEL[o.status]}</span><b>${brl(o.price)}</b></div></div>`;
}

async function ordersHtml() {
  const f = state.orderFilter;
  state.orders = (await api('GET', '/api/orders' + (f ? `?status=${f}` : ''))).orders;
  return `<div class="toolbar"><select id="oFilter"><option value="">Todos os status</option>${Object.entries(STATUS_LABEL).map(([v, l]) => `<option value="${v}" ${f === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
    <div class="count">${state.orders.length} pedido(s)</div>
    ${state.orders.length ? state.orders.map(orderCard).join('')
      : `<div class="empty">${f ? 'Nenhum pedido com esse status.' : state.user.role === 'cliente' ? 'Você ainda não fez nenhum pedido.<br>Use a aba Buscar para encontrar um profissional.' : state.user.role === 'prestador' ? 'Você ainda não tem pedidos.<br>Quando um cliente agendar, ele aparecerá aqui.' : 'Nenhum pedido registrado.'}</div>`}`;
}

function bindOrders() {
  document.getElementById('oFilter').onchange = (e) => { state.orderFilter = e.target.value; viewApp(); };
  bindOrderCards();
}
function bindOrderCards() {
  $app.querySelectorAll('[data-order]').forEach((el) => (el.onclick = () => orderModal(Number(el.dataset.order))));
}

async function orderModal(id) {
  let o;
  try { o = (await api('GET', `/api/orders/${id}`)).order; } catch (err) { return toast(err.message, true); }
  const ov = document.createElement('div');
  ov.className = 'overlay';
  const person = (label, p) => `<div class="kv"><span>${label}</span><b>${esc(p.name)}${p.phone ? `<br><small>${esc(p.phone)}</small>` : ''}</b></div>`;
  ov.innerHTML = `<div class="sheet">
    <div class="row-between"><h3>${esc(o.service_title)}</h3><span class="badge st-${o.status}">${STATUS_LABEL[o.status]}</span></div>
    <div class="kv"><span>Quando</span><b>${dateBR(o.date)} · ${o.time}–${o.end_time} (${fmtDur(o.duration_min)})</b></div>
    <div class="kv"><span>Valor</span><b>${brl(o.price)}</b></div>
    <div class="kv"><span>Endereço</span><b>${esc(o.address)}</b></div>
    ${o.notes ? `<div class="kv"><span>Observações</span><b>${esc(o.notes)}</b></div>` : ''}
    ${person('Cliente', o.client)}${person('Prestador', o.provider)}
    ${o.status_reason ? `<div class="kv"><span>Motivo</span><b>${esc(o.status_reason)}</b></div>` : ''}
    <h4 class="sub">Histórico</h4>
    <ul class="timeline">${o.history.map((h) => `<li><span class="dot st-${h.status}"></span><div><b>${STATUS_LABEL[h.status]}</b> <small>${dateTimeBR(h.created_at)}</small><br><small>${esc(h.actor_name || 'Sistema')}${h.note ? ` — ${esc(h.note)}` : ''}</small></div></li>`).join('')}</ul>
    <div id="reasonBox" hidden>
      <label for="reason" id="reasonLabel">Motivo</label><textarea id="reason" rows="2" maxlength="200"></textarea><div class="field-error" data-err="reason"></div>
      <div class="actions" style="margin-top:12px"><button type="button" class="btn secondary" id="reasonBack" style="margin:0">Voltar</button><button type="button" class="btn danger" id="reasonOk" style="margin:0">Confirmar</button></div>
    </div>
    <div id="actionBox" class="stack">
      ${o.actions.map((a) => `<button type="button" class="btn ${a === 'confirmar' || a === 'concluir' ? '' : a === 'recusar' || a === 'cancelar' ? 'danger' : 'secondary'}" data-act="${a}" style="margin-top:10px">${ACTION_LABEL[a]}</button>`).join('')}
      <button type="button" class="btn secondary" id="closeOrder" style="margin-top:10px">Fechar</button>
    </div></div>`;
  $app.appendChild(ov);
  const close = () => ov.remove();
  ov.onclick = (e) => { if (e.target === ov) close(); };
  ov.querySelector('#closeOrder').onclick = close;

  async function send(action, reason) {
    try {
      await api('POST', `/api/orders/${o.id}/status`, { action, reason });
      close();
      toast(action === 'confirmar' ? 'Pedido confirmado.' : action === 'concluir' ? 'Pedido concluído.' : action === 'recusar' ? 'Pedido recusado.' : 'Pedido cancelado.');
      await viewApp();
    } catch (err) {
      const box = ov.querySelector('[data-err="reason"]');
      if (err.fields && err.fields.reason && !ov.querySelector('#reasonBox').hidden) box.textContent = err.fields.reason;
      else { toast(err.message, true); }
    }
  }
  ov.querySelectorAll('[data-act]').forEach((b) => (b.onclick = () => {
    const a = b.dataset.act;
    if (a === 'recusar' || a === 'cancelar') {
      // recusar sempre pede motivo; cancelar pede motivo (obrigatório para prestador/admin, opcional para o cliente)
      const optional = a === 'cancelar' && state.user.id === o.client.id;
      ov.querySelector('#reasonLabel').textContent = optional ? 'Motivo (opcional)' : 'Motivo';
      ov.querySelector('#reasonBox').hidden = false; ov.querySelector('#actionBox').hidden = true;
      ov.querySelector('#reasonOk').onclick = () => send(a, ov.querySelector('#reason').value);
      ov.querySelector('#reasonBack').onclick = () => { ov.querySelector('#reasonBox').hidden = true; ov.querySelector('#actionBox').hidden = false; };
    } else send(a);
  }));
}

// ---------- serviços (prestador) ----------
async function servicesHtml() {
  await loadCategories();
  state.myServices = (await api('GET', '/api/services/mine')).services;
  return `<div class="toolbar"><button class="btn small" id="newService" style="justify-self:end">+ Novo serviço</button></div>
    <div class="count">${state.myServices.length} serviço(s)</div>
    ${state.myServices.length ? state.myServices.map((s) => `<div class="card-item svc">
      <div class="ci">${CAT_ICON[s.category] || '🛠️'}</div>
      <div class="info"><b>${esc(s.title)}</b><small>${esc(s.category)}</small>
        <div class="meta"><span>${brl(s.price)}</span><span>⏱ ${fmtDur(s.duration_min)}</span><span class="badge ${s.active ? 'on' : 'off'}">${s.active ? 'Ativo' : 'Inativo'}</span></div></div>
      <button class="link" data-editsvc="${s.id}">Editar</button></div>`).join('')
      : '<div class="empty">Você ainda não cadastrou serviços.<br>Cadastre um para aparecer na busca dos clientes.</div>'}`;
}

function bindServices() {
  document.getElementById('newService').onclick = () => serviceModal(null);
  $app.querySelectorAll('[data-editsvc]').forEach((b) => (b.onclick = () => serviceModal(state.myServices.find((s) => s.id === Number(b.dataset.editsvc)))));
}

function serviceModal(s) {
  const isNew = !s;
  const ov = document.createElement('div');
  ov.className = 'overlay';
  const durations = [30, 45, 60, 90, 120, 150, 180, 240, 300, 360, 480];
  ov.innerHTML = `<div class="sheet"><h3>${isNew ? 'Novo serviço' : 'Editar serviço'}</h3>
    <form id="sf" novalidate>
      <label>Título</label><input name="title" maxlength="80" value="${esc(s?.title)}" placeholder="Ex.: Troca de torneira"><div class="field-error" data-err="title"></div>
      <label>Categoria</label><select name="category">${state.categories.map((c) => `<option value="${esc(c.nome)}" ${(s?.category || '') === c.nome ? 'selected' : ''}>${esc(c.nome)}</option>`).join('')}</select><div class="field-error" data-err="category"></div>
      <label>Descrição</label><textarea name="description" rows="3" maxlength="300">${esc(s?.description)}</textarea><div class="field-error" data-err="description"></div>
      <label>Preço (R$)</label><input name="price" type="number" inputmode="decimal" min="0" step="0.01" value="${s ? s.price : ''}"><div class="field-error" data-err="price"></div>
      <label>Duração</label><select name="duration_min">${durations.map((d) => `<option value="${d}" ${(s?.duration_min || 60) === d ? 'selected' : ''}>${fmtDur(d)}</option>`).join('')}</select><div class="field-error" data-err="duration_min"></div>
      ${isNew ? '' : `<div class="switch-row"><div><b style="font-size:14px">Serviço ativo</b><div style="font-size:12px;color:var(--muted)">Inativos não aparecem na busca</div></div>
        <label class="toggle"><input type="checkbox" name="active" ${s.active ? 'checked' : ''}><span></span></label></div>`}
      <div class="actions" style="margin-top:18px"><button type="button" class="btn secondary" id="cancel" style="margin:0">Cancelar</button><button type="submit" class="btn" style="margin:0">Salvar</button></div>
    </form></div>`;
  $app.appendChild(ov);
  const f = ov.querySelector('#sf');
  ov.querySelector('#cancel').onclick = () => ov.remove();
  ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const body = { title: f.title.value, category: f.category.value, description: f.description.value, price: f.price.value, duration_min: Number(f.duration_min.value) };
    const fields = {};
    if (body.title.trim().length < 3) fields.title = 'O título deve ter de 3 a 80 caracteres.';
    if (!(Number(body.price) > 0)) fields.price = 'Informe um preço maior que zero.';
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    if (!isNew) body.active = f.active.checked;
    try {
      if (isNew) await api('POST', '/api/services', body); else await api('PATCH', `/api/services/${s.id}`, body);
      ov.remove();
      toast(isNew ? 'Serviço cadastrado.' : 'Serviço atualizado.');
      await viewApp();
    } catch (err) { showFieldErrors(f, err.fields); formAlert(f, err.message); }
  };
}

// ---------- conta / perfil ----------
function accountHtml() {
  const u = state.user;
  return `<div class="pad">
    <div class="photo-row">${avatarHtml(u, 'soft xl')}
      <div style="min-width:0"><b style="font-size:18px;display:block">${esc(u.name)}</b><span class="badge ${u.role}">${ROLE_LABEL[u.role]}</span>
        <div class="photo-actions"><button class="btn small secondary" id="pickPhoto" type="button">${u.photo_url ? 'Trocar foto' : 'Adicionar foto'}</button>${u.photo_url ? '<button class="link danger-link" id="rmPhoto" type="button">Remover</button>' : ''}</div>
        <input type="file" id="photoFile" accept="image/png,image/jpeg,image/webp" hidden></div></div>

    <div class="section-card"><h4>Meus dados</h4>
      <form id="pf" novalidate>
        <label for="pName">Nome completo</label><input id="pName" name="name" autocomplete="name" value="${esc(u.name)}"><div class="field-error" data-err="name"></div>
        <label for="pEmail">E-mail</label><input id="pEmail" name="email" type="email" autocomplete="username" value="${esc(u.email)}"><div class="field-error" data-err="email"></div>
        <label for="pPhone">Telefone</label><input id="pPhone" name="phone" type="tel" autocomplete="tel" value="${esc(u.phone || '')}" placeholder="(47) 99999-9999"><div class="field-error" data-err="phone"></div>
        <div id="pwWrap" hidden><label for="pCur">Senha atual (necessária para trocar o e-mail)</label><input id="pCur" name="currentPassword" type="password" autocomplete="current-password"><div class="field-error" data-err="currentPassword"></div></div>
        <button class="btn" type="submit">Salvar alterações</button>
      </form></div>

    <div class="section-card"><h4>Alterar senha</h4>
      <form id="pwf" novalidate>
        <label for="cur">Senha atual</label><input id="cur" name="currentPassword" type="password" autocomplete="current-password"><div class="field-error" data-err="currentPassword"></div>
        <label for="nw">Nova senha</label><input id="nw" name="newPassword" type="password" autocomplete="new-password" placeholder="Mín. 8 caracteres, letras e números"><div class="field-error" data-err="newPassword"></div>
        <label for="cf">Confirmar nova senha</label><input id="cf" name="confirm" type="password" autocomplete="new-password"><div class="field-error" data-err="confirm"></div>
        <button class="btn" type="submit">Alterar senha</button>
      </form></div>

    <button class="btn danger" id="logout">Sair da conta</button></div>`;
}

// Recorta no centro, reduz para 256x256 e converte para JPEG (a foto fica pequena e dentro do limite do servidor)
function fileToAvatar(file) {
  return new Promise((resolve, reject) => {
    if (!/^image\/(png|jpeg|webp)$/.test(file.type)) return reject(new Error('Escolha uma imagem PNG, JPG ou WEBP.'));
    if (file.size > 8 * 1024 * 1024) return reject(new Error('A imagem é muito grande (máx. 8 MB).'));
    const url = URL.createObjectURL(file), img = new Image();
    img.onload = () => {
      const size = 256, c = document.createElement('canvas'); c.width = c.height = size;
      const side = Math.min(img.width, img.height);
      c.getContext('2d').drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, size, size);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL('image/jpeg', 0.85));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Não foi possível ler essa imagem.')); };
    img.src = url;
  });
}

function bindAccount() {
  document.getElementById('logout').onclick = logout;
  const file = document.getElementById('photoFile');
  document.getElementById('pickPhoto').onclick = () => file.click();
  file.onchange = async () => {
    if (!file.files[0]) return;
    try {
      const image = await fileToAvatar(file.files[0]);
      const { user } = await api('PUT', '/api/me/photo', { image });
      state.user = user; toast('Foto atualizada.'); viewApp();
    } catch (err) { toast(err.message, true); }
    file.value = '';
  };
  const rm = document.getElementById('rmPhoto');
  if (rm) rm.onclick = async () => {
    try { const { user } = await api('DELETE', '/api/me/photo'); state.user = user; toast('Foto removida.'); viewApp(); }
    catch (err) { toast(err.message, true); }
  };

  const pf = document.getElementById('pf');
  const original = state.user.email;
  pf.email.oninput = () => { document.getElementById('pwWrap').hidden = pf.email.value.trim().toLowerCase() === original; };
  pf.onsubmit = async (e) => {
    e.preventDefault();
    const fields = {};
    if (pf.name.value.trim().length < 3) fields.name = 'Informe o nome completo (mín. 3 caracteres).';
    if (!EMAIL_RE.test(pf.email.value.trim())) fields.email = 'Informe um e-mail válido.';
    const changing = pf.email.value.trim().toLowerCase() !== original;
    if (changing && !pf.currentPassword.value) fields.currentPassword = 'Informe a senha atual para trocar o e-mail.';
    showFieldErrors(pf, fields); formAlert(pf, '');
    if (Object.keys(fields).length) return;
    const body = { name: pf.name.value, email: pf.email.value, phone: pf.phone.value };
    if (changing) body.currentPassword = pf.currentPassword.value;
    try {
      const { user } = await api('PATCH', '/api/me', body);
      state.user = user; toast('Dados atualizados.'); viewApp();
    } catch (err) { showFieldErrors(pf, err.fields); formAlert(pf, err.message); }
  };

  const wf = document.getElementById('pwf');
  wf.onsubmit = async (e) => {
    e.preventDefault();
    const fields = {};
    if (!wf.currentPassword.value) fields.currentPassword = 'Informe a senha atual.';
    const pe = pwError(wf.newPassword.value); if (pe) fields.newPassword = pe;
    if (wf.newPassword.value !== wf.confirm.value) fields.confirm = 'As senhas não conferem.';
    showFieldErrors(wf, fields); formAlert(wf, '');
    if (Object.keys(fields).length) return;
    try {
      const r = await api('POST', '/api/me/password', { currentPassword: wf.currentPassword.value, newPassword: wf.newPassword.value });
      wf.reset(); showFieldErrors(wf, {}); toast(r.message || 'Senha alterada.');
    } catch (err) { showFieldErrors(wf, err.fields); formAlert(wf, err.fields && Object.keys(err.fields).length ? '' : err.message); }
  };
}

async function logout() {
  try { await api('POST', '/api/auth/logout'); } catch (e) { /* sessão já inválida */ }
  state.user = null; state.view = 'login'; render();
  toast('Você saiu da conta.');
}

// ---------- gestão de usuários (admin) ----------
async function loadUsers() {
  const q = new URLSearchParams(Object.entries(state.filters).filter(([, v]) => v)).toString();
  state.users = (await api('GET', '/api/users' + (q ? '?' + q : ''))).users;
}

function usersHtml() {
  const f = state.filters;
  return `<div class="toolbar">
      <input id="search" type="search" placeholder="Buscar por nome ou e-mail" value="${esc(f.search)}">
      <div class="filters">
        <select id="fRole"><option value="">Todos os perfis</option>${['admin', 'cliente', 'prestador'].map((r) => `<option value="${r}" ${f.role === r ? 'selected' : ''}>${ROLE_LABEL[r]}</option>`).join('')}</select>
        <select id="fStatus"><option value="">Qualquer status</option><option value="ativo" ${f.status === 'ativo' ? 'selected' : ''}>Ativos</option><option value="inativo" ${f.status === 'inativo' ? 'selected' : ''}>Desativados</option></select>
      </div>
      <button class="btn small" id="newUser" style="justify-self:end">+ Novo usuário</button>
    </div>
    <div class="count">${state.users.length} usuário(s)</div>
    <div id="list">${state.users.length ? state.users.map(userRow).join('') : '<div class="empty">Nenhum resultado encontrado.</div>'}</div>`;
}

function userRow(u) {
  return `<div class="user" data-id="${u.id}">
    ${avatarHtml(u, 'soft')}
    <div class="info"><b>${esc(u.name)}</b><small>${esc(u.email)}</small>
      <div class="badges"><span class="badge ${u.role}">${ROLE_LABEL[u.role]}</span><span class="badge ${u.active ? 'on' : 'off'}">${u.active ? 'Ativo' : 'Desativado'}</span></div></div>
    <button class="link" data-edit="${u.id}">Editar</button></div>`;
}

function bindUsers() {
  let t;
  const search = document.getElementById('search');
  search.oninput = () => { clearTimeout(t); t = setTimeout(async () => { state.filters.search = search.value.trim(); await refreshList(); }, 300); };
  document.getElementById('fRole').onchange = async (e) => { state.filters.role = e.target.value; await refreshList(); };
  document.getElementById('fStatus').onchange = async (e) => { state.filters.status = e.target.value; await refreshList(); };
  document.getElementById('newUser').onclick = () => userModal(null);
  bindRows();
}
function bindRows() {
  $app.querySelectorAll('[data-edit]').forEach((b) => (b.onclick = () => userModal(state.users.find((u) => u.id === Number(b.dataset.edit)))));
}
async function refreshList() {
  try {
    await loadUsers();
    document.querySelector('.count').textContent = `${state.users.length} usuário(s)`;
    document.getElementById('list').innerHTML = state.users.length ? state.users.map(userRow).join('') : '<div class="empty">Nenhum resultado encontrado.</div>';
    bindRows();
  } catch (err) { toast(err.message, true); }
}

function userModal(u) {
  const isNew = !u;
  const self = u && u.id === state.user.id;
  const ov = document.createElement('div');
  ov.className = 'overlay';
  ov.innerHTML = `<div class="sheet"><h3>${isNew ? 'Novo usuário' : 'Editar usuário'}</h3>
    <form id="mf" novalidate>
      <label>Nome completo</label><input name="name" value="${esc(u?.name)}"><div class="field-error" data-err="name"></div>
      <label>E-mail</label><input name="email" type="email" value="${esc(u?.email)}"><div class="field-error" data-err="email"></div>
      <label>Telefone</label><input name="phone" value="${esc(u?.phone)}"><div class="field-error" data-err="phone"></div>
      <label>Perfil</label>
      <select name="role" ${self ? 'disabled' : ''}>${['cliente', 'prestador', 'admin'].map((r) => `<option value="${r}" ${(u?.role || 'cliente') === r ? 'selected' : ''}>${ROLE_LABEL[r]}</option>`).join('')}</select>
      <div class="field-error" data-err="role"></div>
      ${isNew ? `<label>Senha inicial</label><input name="password" type="password" autocomplete="new-password"><div class="field-error" data-err="password"></div>` : `
      <div class="switch-row"><div><b style="font-size:14px">Conta ativa</b><div style="font-size:12px;color:var(--muted)">Desativados não conseguem entrar</div></div>
        <label class="toggle"><input type="checkbox" name="active" ${u.active ? 'checked' : ''} ${self ? 'disabled' : ''}><span></span></label></div>`}
      ${self ? '<div class="alert info" style="word-break:normal">Você não pode desativar nem alterar o perfil da sua própria conta.</div>' : ''}
      <div class="actions" style="margin-top:18px"><button type="button" class="btn secondary" id="cancel" style="margin:0">Cancelar</button><button type="submit" class="btn" style="margin:0">Salvar</button></div>
    </form></div>`;
  $app.appendChild(ov);
  const f = ov.querySelector('#mf');
  ov.querySelector('#cancel').onclick = () => ov.remove();
  ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const body = { name: f.name.value, email: f.email.value, phone: f.phone.value, role: f.role.value };
    const fields = {};
    if (body.name.trim().length < 3) fields.name = 'Informe o nome completo (mín. 3 caracteres).';
    if (!EMAIL_RE.test(body.email.trim())) fields.email = 'Informe um e-mail válido.';
    if (isNew) { body.password = f.password.value; const pe = pwError(body.password); if (pe) fields.password = pe; }
    showFieldErrors(f, fields); formAlert(f, '');
    if (Object.keys(fields).length) return;
    if (!isNew && !self) body.active = f.active.checked;
    if (self) delete body.role;
    try {
      if (isNew) await api('POST', '/api/users', body); else await api('PATCH', `/api/users/${u.id}`, body);
      ov.remove();
      toast(isNew ? 'Usuário criado.' : 'Alterações salvas.');
      await viewApp();
    } catch (err) { showFieldErrors(f, err.fields); formAlert(f, err.message); }
  };
}

// ---------- roteamento ----------
function render() {
  if (state.view === 'app' && state.user) return viewApp();
  if (state.view === 'register') return viewRegister();
  if (state.view === 'forgot') return viewForgot();
  if (state.view === 'reset') return viewReset();
  return viewLogin();
}

// Sessão persistida: ao abrir o app, pergunta ao backend se ainda há sessão válida.
(async function init() {
  try {
    const { user } = await api('GET', '/api/auth/me');
    enterApp(user);
  } catch (e) {
    state.view = 'login';
    render();
  }
})();
