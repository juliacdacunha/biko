// Biko - backend sem dependências externas (Node >= 22.13): http + node:sqlite + crypto.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, hashPassword, verifyPassword, tx } = require('./db');

const COOKIE = 'biko_sid';
const SESSION_MS = 7 * 24 * 60 * 60 * 1000; // sessão persistida por 7 dias
const RESET_MS = 30 * 60 * 1000; // token de recuperação vale 30 min
const ROLES = ['admin', 'cliente', 'prestador'];
// Em produção o código iria por e-mail. Para a demonstração ele é devolvido na resposta.
const SHOW_RESET_TOKEN = process.env.NODE_ENV !== 'production';
const PUBLIC_DIR = path.join(__dirname, 'public');
// Categorias de serviço (a mesma lista vale para cadastro de serviço, busca e tela inicial do cliente)
const CATEGORIES = [
  { nome: 'Telhado & Reparador', desc: 'Telhas, goteiras e reparos' },
  { nome: 'Encanador', desc: 'Vazamentos, instalações, reparos' },
  { nome: 'Eletricista', desc: 'Instalações, fiação, quadros' },
  { nome: 'Pintor', desc: 'Pintura interna e externa' },
  { nome: 'Limpeza', desc: 'Faxina e limpeza pós-obra' },
  { nome: 'Jardinagem', desc: 'Poda, grama e jardins' },
];
const CATEGORY_NAMES = CATEGORIES.map((c) => c.nome);

// ---------- utilidades ----------
const now = () => Date.now();
const newToken = () => crypto.randomBytes(32).toString('hex');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), ...headers });
  res.end(body);
}
function sendBinary(res, status, buf, contentType, headers = {}) {
  res.writeHead(status, { 'Content-Type': contentType, 'Content-Length': buf.length, 'Cache-Control': 'private, max-age=86400', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(buf);
}
class HttpError extends Error {
  constructor(status, message, fields) { super(message); this.status = status; this.fields = fields; }
}
const fail = (status, message, fields) => { throw new HttpError(status, message, fields); };

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
const sessionCookie = (token) => `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}`;
const clearCookie = () => `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;

function readBody(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false;
    const chunks = [];
    req.on('data', (c) => {
      if (tooBig) return; // já estourou o limite: descarta o resto sem guardar na memória
      size += c.length;
      if (size > limit) { tooBig = true; chunks.length = 0; reject(new HttpError(413, 'Corpo da requisição muito grande.')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return;
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new HttpError(400, 'JSON inválido.')); }
    });
    req.on('error', reject);
  });
}

const photoUrl = (id, v) => (v > 0 ? `/api/photo/${id}?v=${v}` : null);
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role, active: !!u.active, created_at: u.created_at, photo_url: photoUrl(u.id, u.photo_v) });

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'A senha deve ter no mínimo 8 caracteres.';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'A senha deve conter letras e números.';
  return null;
}
function validateProfile({ name, email, phone }) {
  const errors = {};
  if (typeof name !== 'string' || name.trim().length < 3) errors.name = 'Informe o nome completo (mín. 3 caracteres).';
  if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) errors.email = 'Informe um e-mail válido.';
  if (phone && !/^[\d\s()+-]{8,20}$/.test(String(phone))) errors.phone = 'Telefone inválido.';
  return errors;
}

function createSession(userId) {
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)').run(token, userId, now() + SESSION_MS);
  return token;
}

// Limitador simples de tentativas de login (por e-mail+IP)
const attempts = new Map();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 10 * 60 * 1000;
const tooManyAttempts = (key) => { const a = attempts.get(key); return !!a && now() - a.first <= WINDOW_MS && a.count >= MAX_ATTEMPTS; };
function registerFailure(key) {
  const a = attempts.get(key);
  if (!a || now() - a.first > WINDOW_MS) attempts.set(key, { count: 1, first: now() });
  else a.count++;
}

// ---------- autenticação / autorização (backend) ----------
// Retorna o usuário da sessão ou lança 401/403. Sessões inválidas são removidas.
function authenticate(ctx) {
  const token = parseCookies(ctx.req)[COOKIE];
  if (!token) fail(401, 'Não autenticado.');
  const row = db.prepare('SELECT u.*, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(token);
  if (!row || row.expires_at < now()) {
    if (row) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    ctx.headers['Set-Cookie'] = clearCookie();
    fail(401, 'Sessão expirada. Faça login novamente.');
  }
  if (!row.active) {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.id);
    ctx.headers['Set-Cookie'] = clearCookie();
    fail(403, 'Sua conta está desativada.');
  }
  ctx.user = row;
  ctx.token = token;
}

function categoryList() {
  const counts = Object.fromEntries(db.prepare(`SELECT s.category, COUNT(*) AS n FROM services s JOIN users u ON u.id = s.provider_id
    WHERE s.active = 1 AND u.active = 1 AND u.role = 'prestador' GROUP BY s.category`).all().map((r) => [r.category, r.n]));
  return CATEGORIES.map((c) => ({ ...c, total: counts[c.nome] || 0 }));
}

// ---------- rotas ----------
const routes = [];
// opts: { auth: bool, roles: [..] }
function route(method, pattern, opts, handler) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, opts, handler });
}

// ----- AUTENTICAÇÃO -----
route('POST', '/api/auth/register', {}, (ctx) => {
  const { name, email, phone, password, role } = ctx.body;
  const errors = validateProfile({ name, email, phone });
  const pwErr = validatePassword(password);
  if (pwErr) errors.password = pwErr;
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  // Auto-cadastro só permite cliente ou prestador; admin nunca é criado por aqui.
  const finalRole = role === 'prestador' ? 'prestador' : 'cliente';
  const mail = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(mail)) fail(409, 'Este e-mail já está cadastrado.', { email: 'E-mail já cadastrado.' });
  const info = db.prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?,?,?,?,?)')
    .run(name.trim(), mail, phone || null, hashPassword(password), finalRole);
  ctx.headers['Set-Cookie'] = sessionCookie(createSession(info.lastInsertRowid));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  return [201, { user: publicUser(user) }];
});

route('POST', '/api/auth/login', {}, (ctx) => {
  const { email, password } = ctx.body;
  if (!email || !password) fail(400, 'Informe e-mail e senha.');
  const mail = String(email).trim().toLowerCase();
  const key = `${mail}|${ctx.req.socket.remoteAddress}`;
  if (tooManyAttempts(key)) fail(429, 'Muitas tentativas. Aguarde alguns minutos e tente novamente.');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(mail);
  if (!user || !verifyPassword(String(password), user.password_hash)) {
    registerFailure(key);
    fail(401, 'E-mail ou senha inválidos.'); // mensagem genérica de propósito
  }
  if (!user.active) fail(403, 'Sua conta está desativada. Fale com o administrador.');
  attempts.delete(key);
  ctx.headers['Set-Cookie'] = sessionCookie(createSession(user.id));
  return [200, { user: publicUser(user) }];
});

route('POST', '/api/auth/logout', { auth: true }, (ctx) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(ctx.token);
  ctx.headers['Set-Cookie'] = clearCookie();
  return [200, { ok: true }];
});

route('GET', '/api/auth/me', { auth: true }, (ctx) => [200, { user: publicUser(ctx.user) }]);

route('POST', '/api/auth/forgot', {}, (ctx) => {
  const mail = String(ctx.body.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(mail)) fail(400, 'Informe um e-mail válido.');
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(mail);
  const out = { message: 'Se o e-mail estiver cadastrado, enviaremos as instruções de recuperação.' };
  if (user) {
    const token = newToken().slice(0, 24);
    db.prepare('INSERT INTO password_resets (token, user_id, expires_at) VALUES (?,?,?)').run(token, user.id, now() + RESET_MS);
    console.log(`[recuperação de senha] ${mail} -> código: ${token}`);
    if (SHOW_RESET_TOKEN) out.devToken = token; // apenas para demonstração
  }
  return [200, out]; // mesma resposta existindo ou não (não revela quais e-mails existem)
});

route('POST', '/api/auth/reset', {}, (ctx) => {
  const { token, password } = ctx.body;
  const pwErr = validatePassword(password);
  if (pwErr) fail(400, pwErr);
  const r = db.prepare('SELECT * FROM password_resets WHERE token = ?').get(String(token || ''));
  if (!r || r.used || r.expires_at < now()) fail(400, 'Código inválido ou expirado. Solicite um novo.');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), r.user_id);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?').run(r.token);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(r.user_id); // derruba sessões antigas
  return [200, { ok: true, message: 'Senha redefinida com sucesso. Faça login.' }];
});

// ----- ÁREAS POR PERFIL (controle de acesso no backend) -----
route('GET', '/api/cliente/home', { auth: true, roles: ['cliente', 'admin'] }, () => [200, { categorias: categoryList() }]);

route('GET', '/api/prestador/painel', { auth: true, roles: ['prestador', 'admin'] }, (ctx) => {
  const id = ctx.user.id;
  const d = new Date(); const monthStart = new Date(d.getFullYear(), d.getMonth(), 1).getTime();
  const novos = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE provider_id = ? AND status = 'pendente'").get(id).n;
  const ganhos = db.prepare("SELECT COALESCE(SUM(price_cents), 0) AS s FROM orders WHERE provider_id = ? AND status = 'concluido' AND completed_ts >= ?").get(id, monthStart).s;
  const proximos = db.prepare(`${ORDER_SELECT} WHERE o.provider_id = ? AND o.status = 'confirmado' ORDER BY o.start_ts LIMIT 3`).all(id).map((o) => orderView(o, ctx.user));
  return [200, { resumo: { pedidosNovos: novos, avaliacao: null, ganhosMes: ganhos / 100 }, proximos, mensagem: 'Aqui o prestador acompanha pedidos e ganhos.' }];
});

// ----- GESTÃO DE USUÁRIOS (somente admin) -----
route('GET', '/api/users', { auth: true, roles: ['admin'] }, (ctx) => {
  const { search = '', role = '', status = '' } = ctx.query;
  const where = [];
  const params = [];
  if (search) { where.push('(name LIKE ? OR email LIKE ?)'); params.push(`%${search}%`, `%${search}%`); }
  if (ROLES.includes(role)) { where.push('role = ?'); params.push(role); }
  if (status === 'ativo') where.push('active = 1');
  if (status === 'inativo') where.push('active = 0');
  const sql = `SELECT * FROM users ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY name COLLATE NOCASE`;
  return [200, { users: db.prepare(sql).all(...params).map(publicUser) }];
});

route('POST', '/api/users', { auth: true, roles: ['admin'] }, (ctx) => {
  const { name, email, phone, password, role } = ctx.body;
  const errors = validateProfile({ name, email, phone });
  const pwErr = validatePassword(password);
  if (pwErr) errors.password = pwErr;
  if (!ROLES.includes(role)) errors.role = 'Perfil inválido.';
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  const mail = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(mail)) fail(409, 'Este e-mail já está cadastrado.', { email: 'E-mail já cadastrado.' });
  const info = db.prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?,?,?,?,?)')
    .run(name.trim(), mail, phone || null, hashPassword(password), role);
  return [201, { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid)) }];
});

route('PATCH', '/api/users/:id', { auth: true, roles: ['admin'] }, (ctx) => {
  const id = Number(ctx.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) fail(404, 'Usuário não encontrado.');
  const b = ctx.body;
  const next = {
    name: b.name !== undefined ? b.name : target.name,
    email: b.email !== undefined ? b.email : target.email,
    phone: b.phone !== undefined ? b.phone : target.phone,
    role: b.role !== undefined ? b.role : target.role,
    active: b.active !== undefined ? (b.active ? 1 : 0) : target.active,
  };
  const errors = validateProfile(next);
  if (!ROLES.includes(next.role)) errors.role = 'Perfil inválido.';
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  // O admin não pode se bloquear nem se rebaixar (evita ficar sem nenhum admin).
  if (id === ctx.user.id && (!next.active || next.role !== 'admin')) {
    fail(400, 'Você não pode desativar nem remover o perfil de admin da sua própria conta.');
  }
  const mail = String(next.email).trim().toLowerCase();
  if (db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(mail, id)) fail(409, 'Este e-mail já está cadastrado.', { email: 'E-mail já cadastrado.' });
  db.prepare('UPDATE users SET name=?, email=?, phone=?, role=?, active=? WHERE id=?')
    .run(String(next.name).trim(), mail, next.phone || null, next.role, next.active, id);
  // Desativou ou mudou de perfil -> derruba as sessões abertas dessa pessoa
  if (!next.active || next.role !== target.role) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  return [200, { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(id)) }];
});

route('POST', '/api/users/:id/password', { auth: true, roles: ['admin'] }, (ctx) => {
  const pwErr = validatePassword(ctx.body.password);
  if (pwErr) fail(400, pwErr);
  const id = Number(ctx.params.id);
  if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(id)) fail(404, 'Usuário não encontrado.');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(ctx.body.password), id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  return [200, { ok: true }];
});

// =====================================================================
// 4. PERFIL DO USUÁRIO (qualquer usuário logado, só mexe na própria conta)
// =====================================================================
const MAX_PHOTO_BYTES = 200 * 1024;
const PHOTO_TYPES = { 'image/png': 'png', 'image/jpeg': 'jpeg', 'image/webp': 'webp' };
// Confere os primeiros bytes do arquivo (não confia só no que o cliente diz que é)
function sniffImage(buf) {
  if (buf.length > 8 && buf[0] === 0x89 && buf.toString('ascii', 1, 4) === 'PNG') return 'image/png';
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

route('PATCH', '/api/me', { auth: true }, (ctx) => {
  const u = ctx.user, b = ctx.body;
  const next = {
    name: b.name !== undefined ? b.name : u.name,
    email: b.email !== undefined ? b.email : u.email,
    phone: b.phone !== undefined ? b.phone : u.phone,
  };
  const errors = validateProfile(next);
  const mail = String(next.email).trim().toLowerCase();
  // Trocar o e-mail (que é o login) exige confirmar a senha atual
  if (!errors.email && mail !== u.email) {
    const key = `pwd|${u.id}`;
    if (!b.currentPassword) errors.currentPassword = 'Informe a senha atual para trocar o e-mail.';
    else if (tooManyAttempts(key)) fail(429, 'Muitas tentativas. Aguarde alguns minutos e tente novamente.');
    else if (!verifyPassword(String(b.currentPassword), u.password_hash)) { registerFailure(key); errors.currentPassword = 'Senha atual incorreta.'; }
  }
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id != ?').get(mail, u.id)) fail(409, 'Este e-mail já está cadastrado.', { email: 'E-mail já cadastrado.' });
  // perfil e status não entram aqui de propósito: ninguém muda o próprio perfil por esta rota
  db.prepare('UPDATE users SET name = ?, email = ?, phone = ? WHERE id = ?')
    .run(String(next.name).trim(), mail, next.phone ? String(next.phone).trim() : null, u.id);
  return [200, { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(u.id)) }];
});

route('POST', '/api/me/password', { auth: true }, (ctx) => {
  const u = ctx.user;
  const { currentPassword, newPassword } = ctx.body;
  const key = `pwd|${u.id}`;
  if (tooManyAttempts(key)) fail(429, 'Muitas tentativas. Aguarde alguns minutos e tente novamente.');
  if (!currentPassword || !verifyPassword(String(currentPassword), u.password_hash)) {
    registerFailure(key);
    fail(400, 'Dados inválidos.', { currentPassword: 'Senha atual incorreta.' });
  }
  const pwErr = validatePassword(newPassword);
  if (pwErr) fail(400, 'Dados inválidos.', { newPassword: pwErr });
  if (newPassword === currentPassword) fail(400, 'Dados inválidos.', { newPassword: 'A nova senha deve ser diferente da atual.' });
  attempts.delete(key);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), u.id);
  // derruba as OUTRAS sessões (outros aparelhos); a atual continua valendo
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(u.id, ctx.token);
  return [200, { ok: true, message: 'Senha alterada com sucesso.' }];
});

route('PUT', '/api/me/photo', { auth: true, bodyLimit: 400 * 1024 }, (ctx) => {
  const m = /^data:(image\/[a-z]+);base64,([A-Za-z0-9+/=]+)$/.exec(String(ctx.body.image || ''));
  if (!m || !PHOTO_TYPES[m[1]]) fail(400, 'Envie uma imagem PNG, JPG ou WEBP.');
  const buf = Buffer.from(m[2], 'base64');
  if (!buf.length) fail(400, 'Imagem vazia.');
  if (buf.length > MAX_PHOTO_BYTES) fail(413, 'A foto deve ter no máximo 200 KB.');
  const real = sniffImage(buf);
  if (!real) fail(400, 'O arquivo enviado não é uma imagem válida.');
  db.prepare('INSERT INTO user_photos (user_id, mime, data) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET mime = excluded.mime, data = excluded.data')
    .run(ctx.user.id, real, buf);
  db.prepare('UPDATE users SET photo_v = photo_v + 1 WHERE id = ?').run(ctx.user.id);
  return [200, { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(ctx.user.id)) }];
});

route('DELETE', '/api/me/photo', { auth: true }, (ctx) => {
  db.prepare('DELETE FROM user_photos WHERE user_id = ?').run(ctx.user.id);
  db.prepare('UPDATE users SET photo_v = 0 WHERE id = ?').run(ctx.user.id);
  return [200, { user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(ctx.user.id)) }];
});

// Qualquer usuário logado pode ver a foto dos outros (aparece nos resultados de busca e nos pedidos)
route('GET', '/api/photo/:id', { auth: true }, (ctx) => {
  const p = db.prepare('SELECT mime, data FROM user_photos WHERE user_id = ?').get(Number(ctx.params.id));
  if (!p) fail(404, 'Sem foto.');
  return [200, Buffer.from(p.data), { contentType: p.mime }];
});

// =====================================================================
// SERVIÇOS DO PRESTADOR (é o que a busca do cliente encontra)
// =====================================================================
const serviceView = (r) => ({
  id: r.id, provider_id: r.provider_id, provider_name: r.provider_name, provider_photo_url: photoUrl(r.provider_id, r.provider_photo_v),
  title: r.title, category: r.category, description: r.description,
  price: r.price_cents / 100, duration_min: r.duration_min, active: !!r.active,
});
const SERVICE_SELECT = `SELECT s.*, u.name AS provider_name, u.photo_v AS provider_photo_v
  FROM services s JOIN users u ON u.id = s.provider_id`;

function validateService(b) {
  const e = {};
  if (typeof b.title !== 'string' || b.title.trim().length < 3 || b.title.trim().length > 80) e.title = 'O título deve ter de 3 a 80 caracteres.';
  if (!CATEGORY_NAMES.includes(b.category)) e.category = 'Escolha uma categoria válida.';
  if (b.description !== undefined && b.description !== null && (typeof b.description !== 'string' || b.description.length > 300)) e.description = 'A descrição pode ter no máximo 300 caracteres.';
  const price = Number(b.price);
  if (b.price === '' || b.price === null || b.price === undefined || !Number.isFinite(price) || price <= 0 || price > 100000) e.price = 'Informe um preço entre R$ 0,01 e R$ 100.000.';
  const dur = Number(b.duration_min);
  if (!Number.isInteger(dur) || dur < 30 || dur > 480 || dur % 15 !== 0) e.duration_min = 'A duração deve ser de 30 a 480 minutos, em múltiplos de 15.';
  return e;
}

route('GET', '/api/categories', { auth: true }, () => [200, { categories: categoryList() }]);

route('GET', '/api/services/mine', { auth: true, roles: ['prestador'] }, (ctx) => {
  const rows = db.prepare(`${SERVICE_SELECT} WHERE s.provider_id = ? ORDER BY s.active DESC, s.title COLLATE NOCASE`).all(ctx.user.id);
  return [200, { services: rows.map(serviceView) }];
});

route('POST', '/api/services', { auth: true, roles: ['prestador'] }, (ctx) => {
  const b = ctx.body;
  const errors = validateService(b);
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  const info = db.prepare('INSERT INTO services (provider_id, title, category, description, price_cents, duration_min) VALUES (?,?,?,?,?,?)')
    .run(ctx.user.id, b.title.trim(), b.category, String(b.description || '').trim(), Math.round(Number(b.price) * 100), Number(b.duration_min));
  return [201, { service: serviceView(db.prepare(`${SERVICE_SELECT} WHERE s.id = ?`).get(info.lastInsertRowid)) }];
});

route('PATCH', '/api/services/:id', { auth: true, roles: ['prestador'] }, (ctx) => {
  const id = Number(ctx.params.id);
  const s = db.prepare('SELECT * FROM services WHERE id = ?').get(id);
  if (!s) fail(404, 'Serviço não encontrado.');
  if (s.provider_id !== ctx.user.id) fail(403, 'Este serviço pertence a outro prestador.');
  const b = ctx.body;
  const next = {
    title: b.title !== undefined ? b.title : s.title,
    category: b.category !== undefined ? b.category : s.category,
    description: b.description !== undefined ? b.description : s.description,
    price: b.price !== undefined ? b.price : s.price_cents / 100,
    duration_min: b.duration_min !== undefined ? b.duration_min : s.duration_min,
  };
  const errors = validateService(next);
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);
  const active = b.active !== undefined ? (b.active ? 1 : 0) : s.active;
  db.prepare('UPDATE services SET title=?, category=?, description=?, price_cents=?, duration_min=?, active=? WHERE id=?')
    .run(next.title.trim(), next.category, String(next.description || '').trim(), Math.round(Number(next.price) * 100), Number(next.duration_min), active, id);
  return [200, { service: serviceView(db.prepare(`${SERVICE_SELECT} WHERE s.id = ?`).get(id)) }];
});

// =====================================================================
// 6. BUSCA (sobre os serviços reais cadastrados, sem acento e sem diferenciar maiúscula)
// =====================================================================
const norm = (s) => String(s ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
const SORTS = ['relevancia', 'preco_asc', 'preco_desc', 'nome'];

route('GET', '/api/search', { auth: true }, (ctx) => {
  const { q = '', category = '', max_price = '', sort = '' } = ctx.query;
  if (q.length > 80) fail(400, 'A busca pode ter no máximo 80 caracteres.');
  if (category && !CATEGORY_NAMES.includes(category)) fail(400, 'Categoria inválida.');
  let maxCents = null;
  if (max_price !== '') {
    const n = Number(max_price);
    if (!Number.isFinite(n) || n < 0) fail(400, 'O preço máximo deve ser um número válido.');
    maxCents = Math.round(n * 100);
  }
  if (sort && !SORTS.includes(sort)) fail(400, 'Ordenação inválida.');
  const limit = Math.min(Math.max(parseInt(ctx.query.limit, 10) || 20, 1), 50);
  const offset = Math.max(parseInt(ctx.query.offset, 10) || 0, 0);

  const where = ["s.active = 1", "u.active = 1", "u.role = 'prestador'"];
  const params = [];
  if (category) { where.push('s.category = ?'); params.push(category); }
  if (maxCents !== null) { where.push('s.price_cents <= ?'); params.push(maxCents); }
  let rows = db.prepare(`${SERVICE_SELECT} WHERE ${where.join(' AND ')}`).all(...params);

  // Cada palavra digitada precisa aparecer em algum campo (título, categoria, descrição ou nome do prestador)
  const terms = norm(q).split(/\s+/).filter(Boolean);
  rows = rows.map((r) => {
    const f = { t: norm(r.title), c: norm(r.category), p: norm(r.provider_name), d: norm(r.description) };
    let score = 0;
    for (const term of terms) {
      const s = (f.t.includes(term) ? 3 : 0) + (f.c.includes(term) ? 2 : 0) + (f.p.includes(term) ? 2 : 0) + (f.d.includes(term) ? 1 : 0);
      if (!s) return null;
      score += s;
    }
    return { r, score };
  }).filter(Boolean);

  const cmpName = (a, b) => a.r.title.localeCompare(b.r.title, 'pt-BR');
  const order = sort || (terms.length ? 'relevancia' : 'nome');
  rows.sort(order === 'preco_asc' ? (a, b) => a.r.price_cents - b.r.price_cents || cmpName(a, b)
    : order === 'preco_desc' ? (a, b) => b.r.price_cents - a.r.price_cents || cmpName(a, b)
    : order === 'relevancia' ? (a, b) => b.score - a.score || cmpName(a, b)
    : cmpName);

  return [200, { total: rows.length, limit, offset, results: rows.slice(offset, offset + limit).map((x) => serviceView(x.r)) }];
});

// Horários já ocupados de um prestador em um dia (sem expor dados de quem agendou)
route('GET', '/api/providers/:id/agenda', { auth: true }, (ctx) => {
  const day = parseLocal(ctx.query.date, '00:00');
  if (!day) fail(400, 'Informe a data no formato AAAA-MM-DD.');
  const from = day.getTime(), to = from + 24 * 3600e3;
  const rows = db.prepare(`SELECT start_ts, end_ts FROM orders WHERE provider_id = ? AND status IN ('pendente','confirmado')
    AND start_ts < ? AND end_ts > ? ORDER BY start_ts`).all(Number(ctx.params.id), to, from);
  return [200, { date: ctx.query.date, busy: rows.map((r) => ({ start: fmtTime(r.start_ts), end: fmtTime(r.end_ts) })) }];
});

// =====================================================================
// 5. AGENDAMENTO / PEDIDOS (regras de negócio)
// =====================================================================
const ACTIVE = ['pendente', 'confirmado'];
const STATUSES = ['pendente', 'confirmado', 'recusado', 'concluido', 'cancelado'];
const OPEN_HOUR = 7, CLOSE_HOUR = 20;           // atendimento das 07:00 às 20:00
const MIN_LEAD_MS = 60 * 60 * 1000;             // agendar com pelo menos 1 h de antecedência
const MAX_AHEAD_MS = 60 * 24 * 3600e3;          // e no máximo 60 dias à frente
const CLIENT_CANCEL_LIMIT_MS = 2 * 3600e3;      // cliente cancela pedido confirmado até 2 h antes

// ação -> { novo status, quem pode, estados de origem permitidos, se exige motivo }
const ACTIONS = {
  confirmar: { to: 'confirmado', from: ['pendente'], who: 'prestador' },
  recusar:   { to: 'recusado',   from: ['pendente'], who: 'prestador', reason: true },
  concluir:  { to: 'concluido',  from: ['confirmado'], who: 'prestador' },
  cancelar:  { to: 'cancelado',  from: ['pendente', 'confirmado'], who: 'participante' },
};

const pad = (n) => String(n).padStart(2, '0');
const fmtDate = (ts) => { const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
function fmtTime(ts) { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; }
// Converte "AAAA-MM-DD" + "HH:MM" em Date local, rejeitando datas que não existem (ex.: 2026-02-31)
function parseLocal(date, time) {
  const dm = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(date || ''));
  const tm = /^(\d{2}):(\d{2})$/.exec(String(time || ''));
  if (!dm || !tm) return null;
  const [y, mo, d, h, mi] = [dm[1], dm[2], dm[3], tm[1], tm[2]].map(Number);
  const dt = new Date(y, mo - 1, d, h, mi, 0, 0);
  if (dt.getFullYear() !== y || dt.getMonth() !== mo - 1 || dt.getDate() !== d || dt.getHours() !== h || dt.getMinutes() !== mi) return null;
  return dt;
}

const ORDER_SELECT = `SELECT o.*, c.name AS client_name, c.phone AS client_phone, c.photo_v AS client_photo_v,
    p.name AS provider_name, p.phone AS provider_phone, p.photo_v AS provider_photo_v
  FROM orders o JOIN users c ON c.id = o.client_id JOIN users p ON p.id = o.provider_id`;

function availableActions(o, user, t = now()) {
  const out = [];
  const isProvider = o.provider_id === user.id, isClient = o.client_id === user.id;
  for (const [name, a] of Object.entries(ACTIONS)) {
    if (!a.from.includes(o.status)) continue;
    if (a.who === 'prestador' && !isProvider) continue;
    if (name === 'concluir' && o.start_ts > t) continue;
    if (name === 'cancelar') {
      if (!(isProvider || isClient || user.role === 'admin')) continue;
      if (isClient && o.status === 'confirmado' && o.start_ts - t < CLIENT_CANCEL_LIMIT_MS) continue;
    }
    out.push(name);
  }
  return out;
}

function orderView(o, user) {
  const seeContact = ['confirmado', 'concluido'].includes(o.status) || user.role === 'admin';
  return {
    id: o.id, status: o.status, status_reason: o.status_reason,
    service_id: o.service_id, service_title: o.service_title, category: o.category, price: o.price_cents / 100,
    date: fmtDate(o.start_ts), time: fmtTime(o.start_ts), end_time: fmtTime(o.end_ts), duration_min: Math.round((o.end_ts - o.start_ts) / 60000),
    address: o.address, notes: o.notes, created_at: o.created_at,
    client: { id: o.client_id, name: o.client_name, photo_url: photoUrl(o.client_id, o.client_photo_v), phone: seeContact ? o.client_phone : null },
    provider: { id: o.provider_id, name: o.provider_name, photo_url: photoUrl(o.provider_id, o.provider_photo_v), phone: seeContact ? o.provider_phone : null },
    actions: availableActions(o, user),
  };
}

function loadOrderFor(user, id) {
  const o = db.prepare(`${ORDER_SELECT} WHERE o.id = ?`).get(id);
  // quem não participa do pedido (e não é admin) recebe 404, como se ele não existisse
  if (!o || !(user.role === 'admin' || o.client_id === user.id || o.provider_id === user.id)) fail(404, 'Pedido não encontrado.');
  return o;
}
function addEvent(orderId, status, actorId, note) {
  db.prepare('INSERT INTO order_events (order_id, status, actor_id, note, created_at) VALUES (?,?,?,?,?)').run(orderId, status, actorId, note || null, now());
}

route('POST', '/api/orders', { auth: true, roles: ['cliente'] }, (ctx) => {
  const b = ctx.body;
  const errors = {};
  const serviceId = Number(b.service_id);
  const s = Number.isInteger(serviceId) ? db.prepare(`SELECT s.*, u.active AS u_active, u.role AS u_role FROM services s JOIN users u ON u.id = s.provider_id WHERE s.id = ?`).get(serviceId) : null;
  if (!s || !s.active || !s.u_active || s.u_role !== 'prestador') fail(404, 'Este serviço não está mais disponível.');
  if (s.provider_id === ctx.user.id) fail(400, 'Você não pode contratar o seu próprio serviço.');

  const start = parseLocal(b.date, b.time);
  const address = typeof b.address === 'string' ? b.address.trim() : '';
  const notes = typeof b.notes === 'string' ? b.notes.trim() : '';
  if (address.length < 5 || address.length > 200) errors.address = 'Informe o endereço do serviço (5 a 200 caracteres).';
  if (notes.length > 500) errors.notes = 'As observações podem ter no máximo 500 caracteres.';
  if (!start) errors.date = 'Informe uma data e um horário válidos.';
  else {
    const t = now(), startTs = start.getTime(), endTs = startTs + s.duration_min * 60000;
    const end = new Date(endTs);
    if (start.getMinutes() % 15 !== 0) errors.time = 'Os horários começam em múltiplos de 15 minutos.';
    else if (startTs < t + MIN_LEAD_MS) errors.time = 'Agende com pelo menos 1 hora de antecedência.';
    else if (startTs > t + MAX_AHEAD_MS) errors.date = 'Só é possível agendar até 60 dias à frente.';
    else if (start.getHours() < OPEN_HOUR || fmtDate(endTs) !== fmtDate(startTs) || end.getHours() > CLOSE_HOUR || (end.getHours() === CLOSE_HOUR && end.getMinutes() > 0)) {
      errors.time = `O atendimento é das ${pad(OPEN_HOUR)}:00 às ${pad(CLOSE_HOUR)}:00 e o serviço dura ${s.duration_min} min.`;
    }
  }
  if (Object.keys(errors).length) fail(400, 'Dados inválidos.', errors);

  const startTs = start.getTime(), endTs = startTs + s.duration_min * 60000;
  const id = tx(() => {
    // Conflito de horário: nem o prestador nem o cliente podem ter dois pedidos ativos sobrepostos.
    const overlap = (col, uid) => db.prepare(`SELECT 1 FROM orders WHERE ${col} = ? AND status IN ('pendente','confirmado') AND start_ts < ? AND end_ts > ?`).get(uid, endTs, startTs);
    if (overlap('provider_id', s.provider_id)) fail(409, 'O prestador já tem um compromisso nesse horário. Escolha outro.', { time: 'Horário indisponível.' });
    if (overlap('client_id', ctx.user.id)) fail(409, 'Você já tem outro pedido nesse horário.', { time: 'Você já tem um pedido nesse horário.' });
    const t = now();
    const info = db.prepare(`INSERT INTO orders (client_id, provider_id, service_id, service_title, category, price_cents, start_ts, end_ts, address, notes, status, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?, 'pendente', ?, ?)`).run(ctx.user.id, s.provider_id, s.id, s.title, s.category, s.price_cents, startTs, endTs, address, notes, t, t);
    addEvent(info.lastInsertRowid, 'pendente', ctx.user.id, 'Pedido criado');
    return Number(info.lastInsertRowid);
  });
  return [201, { order: orderView(db.prepare(`${ORDER_SELECT} WHERE o.id = ?`).get(id), ctx.user) }];
});

route('GET', '/api/orders', { auth: true }, (ctx) => {
  const { status = '' } = ctx.query;
  if (status && !STATUSES.includes(status)) fail(400, 'Status inválido.');
  const where = [], params = [];
  if (ctx.user.role === 'cliente') { where.push('o.client_id = ?'); params.push(ctx.user.id); }
  else if (ctx.user.role === 'prestador') { where.push('o.provider_id = ?'); params.push(ctx.user.id); }
  if (status) { where.push('o.status = ?'); params.push(status); }
  const rows = db.prepare(`${ORDER_SELECT} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY o.start_ts DESC, o.id DESC`).all(...params);
  return [200, { orders: rows.map((o) => orderView(o, ctx.user)) }];
});

route('GET', '/api/orders/:id', { auth: true }, (ctx) => {
  const o = loadOrderFor(ctx.user, Number(ctx.params.id));
  const history = db.prepare(`SELECT e.status, e.note, e.created_at, u.name AS actor_name, u.role AS actor_role
    FROM order_events e LEFT JOIN users u ON u.id = e.actor_id WHERE e.order_id = ? ORDER BY e.id`).all(o.id);
  return [200, { order: { ...orderView(o, ctx.user), history } }];
});

route('POST', '/api/orders/:id/status', { auth: true }, (ctx) => {
  const action = String(ctx.body.action || '');
  const a = ACTIONS[action];
  if (!a) fail(400, 'Ação inválida.');
  const reason = typeof ctx.body.reason === 'string' ? ctx.body.reason.trim() : '';
  const id = tx(() => {
    const o = loadOrderFor(ctx.user, Number(ctx.params.id));
    const isProvider = o.provider_id === ctx.user.id, isClient = o.client_id === ctx.user.id;
    // 1) quem pode fazer a ação
    if (a.who === 'prestador' && !isProvider) fail(403, 'Só o prestador deste pedido pode fazer isso.');
    if (action === 'cancelar' && !(isProvider || isClient || ctx.user.role === 'admin')) fail(403, 'Você não pode cancelar este pedido.');
    // 2) o status atual permite? (pedido encerrado não muda mais)
    if (!a.from.includes(o.status)) fail(409, `Não é possível ${action} um pedido que está "${o.status}".`);
    // 3) regras de cada ação
    const t = now();
    if (action === 'concluir' && o.start_ts > t) fail(400, 'Só é possível concluir depois do horário agendado.');
    if (action === 'cancelar' && isClient && o.status === 'confirmado' && o.start_ts - t < CLIENT_CANCEL_LIMIT_MS) {
      fail(400, 'Pedido confirmado só pode ser cancelado pelo cliente até 2 horas antes. Fale com o prestador.');
    }
    const needReason = a.reason || (action === 'cancelar' && !isClient);
    if (needReason && reason.length < 3) fail(400, 'Informe o motivo.', { reason: 'Informe o motivo (mín. 3 caracteres).' });
    if (reason.length > 200) fail(400, 'O motivo pode ter no máximo 200 caracteres.', { reason: 'Máximo de 200 caracteres.' });
    db.prepare('UPDATE orders SET status = ?, status_reason = ?, completed_ts = ?, updated_at = ? WHERE id = ?')
      .run(a.to, reason || null, a.to === 'concluido' ? t : null, t, o.id);
    addEvent(o.id, a.to, ctx.user.id, reason || null);
    return o.id;
  });
  return [200, { order: orderView(db.prepare(`${ORDER_SELECT} WHERE o.id = ?`).get(id), ctx.user) }];
});

// ---------- arquivos estáticos ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Forbidden'); } // evita ../
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- servidor ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    return serveStatic(req, res, url.pathname);
  }
  const ctx = { req, res, headers: {}, query: Object.fromEntries(url.searchParams), params: {}, body: {} };
  try {
    let matched = null;
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.re.exec(url.pathname);
      if (m) { matched = r; r.keys.forEach((k, i) => (ctx.params[k] = decodeURIComponent(m[i + 1]))); break; }
    }
    if (!matched) fail(404, 'Rota não encontrada.');
    if (req.method !== 'GET') {
      ctx.body = await readBody(req, matched.opts.bodyLimit);
      if (typeof ctx.body !== 'object' || ctx.body === null || Array.isArray(ctx.body)) fail(400, 'JSON inválido.');
    }
    if (matched.opts.auth) authenticate(ctx);
    if (matched.opts.roles && !matched.opts.roles.includes(ctx.user.role)) fail(403, 'Você não tem permissão para acessar este recurso.');
    const [status, data, extra] = matched.handler(ctx);
    if (Buffer.isBuffer(data)) sendBinary(res, status, data, extra.contentType, ctx.headers);
    else send(res, status, data, ctx.headers);
  } catch (err) {
    if (err instanceof HttpError) return send(res, err.status, { error: err.message, fields: err.fields }, ctx.headers);
    console.error(err);
    send(res, 500, { error: 'Erro interno do servidor.' });
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  server.listen(PORT, () => console.log(`Biko rodando em http://localhost:${PORT}`));
}
module.exports = server;
