// Testes automatizados de ponta a ponta (backend). Rodar com:  node --disable-warning=ExperimentalWarning test.js
const os = require('os');
const path = require('path');
const fs = require('fs');
const assert = require('assert');

// banco temporário, para não mexer no biko.db real
const tmp = path.join(os.tmpdir(), `biko-test-${Date.now()}.db`);
process.env.BIKO_DB = tmp;
const server = require('./server');

let base;
let passed = 0;
const results = [];

const cookieJar = new WeakMap();
const cookieOf = async (c) => cookieJar.get(c) || '';
function client() {
  let cookie = '';
  const fn = async (method, url, body) => {
    const res = await fetch(base + url, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const sc = res.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
    let data = {};
    try { data = await res.json(); } catch (e) { /* não é JSON */ }
    return { status: res.status, data, res };
  };
  const wrapped = async (...a) => { const r = await fn(...a); cookieJar.set(wrapped, cookie); return r; };
  return wrapped;
}

async function t(name, fn) {
  try { await fn(); passed++; results.push(`  ✔ ${name}`); }
  catch (e) { results.push(`  ✘ ${name}\n      ${e.message}`); process.exitCode = 1; }
}

(async () => {
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;

  const anon = (method, url, body) => client()(method, url, body); // sem cookie: cada chamada é um visitante novo
  const admin = client(), cliente = client(), prest = client();

  await t('serve a página inicial', async () => {
    const r = await fetch(base + '/');
    assert.strictEqual(r.status, 200);
    assert.ok((await r.text()).includes('id="app"'));
  });
  await t('bloqueia path traversal nos arquivos estáticos', async () => {
    const r = await fetch(base + '/..%2fserver.js');
    assert.ok([403, 404].includes(r.status));
    assert.ok(!(await r.text()).includes('createServer'));
  });

  // ---------- LOGIN ----------
  await t('login sem campos -> 400', async () => assert.strictEqual((await anon('POST', '/api/auth/login', {})).status, 400));
  await t('login com senha errada -> 401 com mensagem genérica', async () => {
    const r = await anon('POST', '/api/auth/login', { email: 'admin@biko.com', password: 'errada123' });
    assert.strictEqual(r.status, 401);
    assert.strictEqual(r.data.error, 'E-mail ou senha inválidos.');
  });
  await t('login com e-mail inexistente -> mesma mensagem (não revela existência)', async () => {
    const r = await anon('POST', '/api/auth/login', { email: 'naoexiste@x.com', password: 'qualquer1' });
    assert.strictEqual(r.status, 401);
    assert.strictEqual(r.data.error, 'E-mail ou senha inválidos.');
  });
  await t('login válido dos 3 perfis', async () => {
    assert.strictEqual((await admin('POST', '/api/auth/login', { email: 'admin@biko.com', password: 'Admin@123' })).data.user.role, 'admin');
    assert.strictEqual((await cliente('POST', '/api/auth/login', { email: 'cliente@biko.com', password: 'Cliente@123' })).data.user.role, 'cliente');
    assert.strictEqual((await prest('POST', '/api/auth/login', { email: 'prestador@biko.com', password: 'Prestador@123' })).data.user.role, 'prestador');
  });
  await t('resposta de login não vaza o hash da senha', async () => {
    const r = await anon('POST', '/api/auth/login', { email: 'admin@biko.com', password: 'Admin@123' });
    assert.ok(!JSON.stringify(r.data).includes('password'));
  });
  await t('cookie de sessão é HttpOnly', async () => {
    const r = await anon('POST', '/api/auth/login', { email: 'admin@biko.com', password: 'Admin@123' });
    assert.ok(r.res.headers.get('set-cookie').includes('HttpOnly'));
  });

  // ---------- CADASTRO ----------
  await t('cadastro inválido -> 400 com erros por campo', async () => {
    const r = await anon('POST', '/api/auth/register', { name: 'Jo', email: 'x', password: '123' });
    assert.strictEqual(r.status, 400);
    assert.ok(r.data.fields.name && r.data.fields.email && r.data.fields.password);
  });
  const novo = client();
  await t('cadastro válido -> 201 e já fica logado', async () => {
    const r = await novo('POST', '/api/auth/register', { name: 'Ana Souza', email: 'Ana@Teste.com', phone: '(47) 98888-7777', password: 'Senha1234' });
    assert.strictEqual(r.status, 201);
    assert.strictEqual(r.data.user.email, 'ana@teste.com');
    assert.strictEqual((await novo('GET', '/api/auth/me')).status, 200);
  });
  await t('cadastro com e-mail repetido -> 409', async () => {
    const r = await anon('POST', '/api/auth/register', { name: 'Outra Ana', email: 'ana@teste.com', password: 'Senha1234' });
    assert.strictEqual(r.status, 409);
    assert.ok(r.data.fields.email);
  });
  await t('auto-cadastro NUNCA cria admin (role=admin vira cliente)', async () => {
    const r = await anon('POST', '/api/auth/register', { name: 'Hacker X', email: 'hacker@x.com', password: 'Senha1234', role: 'admin' });
    assert.strictEqual(r.data.user.role, 'cliente');
  });
  await t('cadastro como prestador funciona', async () => {
    const r = await anon('POST', '/api/auth/register', { name: 'Pedro Pedreiro', email: 'pedro@x.com', password: 'Senha1234', role: 'prestador' });
    assert.strictEqual(r.data.user.role, 'prestador');
  });

  // ---------- SESSÃO / LOGOUT ----------
  await t('sessão persiste (/me) e sem cookie dá 401', async () => {
    assert.strictEqual((await cliente('GET', '/api/auth/me')).data.user.email, 'cliente@biko.com');
    assert.strictEqual((await anon('GET', '/api/auth/me')).status, 401);
  });
  await t('logout invalida a sessão no servidor', async () => {
    const login = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'cliente@biko.com', password: 'Cliente@123' }) });
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const withCookie = (method, url) => fetch(base + url, { method, headers: { Cookie: cookie } });
    assert.strictEqual((await withCookie('GET', '/api/auth/me')).status, 200);
    assert.strictEqual((await withCookie('POST', '/api/auth/logout')).status, 200);
    // o MESMO cookie, reaproveitado depois do logout, não pode mais funcionar
    assert.strictEqual((await withCookie('GET', '/api/auth/me')).status, 401);
  });
  await t('logout exige estar logado', async () => assert.strictEqual((await anon('POST', '/api/auth/logout')).status, 401));

  // ---------- RECUPERAÇÃO DE SENHA ----------
  await t('forgot responde igual para e-mail existente e inexistente', async () => {
    const a = await anon('POST', '/api/auth/forgot', { email: 'ana@teste.com' });
    const b = await anon('POST', '/api/auth/forgot', { email: 'ninguem@teste.com' });
    assert.strictEqual(a.status, 200); assert.strictEqual(b.status, 200);
    assert.strictEqual(a.data.message, b.data.message);
    assert.ok(a.data.devToken && !b.data.devToken);
  });
  await t('fluxo completo de redefinição de senha', async () => {
    const { data } = await anon('POST', '/api/auth/forgot', { email: 'ana@teste.com' });
    assert.strictEqual((await anon('POST', '/api/auth/reset', { token: data.devToken, password: 'fraca' })).status, 400);
    assert.strictEqual((await anon('POST', '/api/auth/reset', { token: 'tokeninvalido', password: 'NovaSenha99' })).status, 400);
    assert.strictEqual((await anon('POST', '/api/auth/reset', { token: data.devToken, password: 'NovaSenha99' })).status, 200);
    assert.strictEqual((await anon('POST', '/api/auth/reset', { token: data.devToken, password: 'OutraSenha99' })).status, 400); // token de uso único
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'Senha1234' })).status, 401);
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'NovaSenha99' })).status, 200);
    assert.strictEqual((await novo('GET', '/api/auth/me')).status, 401); // sessão antiga foi derrubada
  });

  // ---------- PERFIS / CONTROLE DE ACESSO ----------
  await t('rotas protegidas sem login -> 401', async () => {
    for (const u of ['/api/users', '/api/cliente/home', '/api/prestador/painel']) assert.strictEqual((await anon('GET', u)).status, 401, u);
  });
  await t('cliente NÃO acessa área de admin nem de prestador (403)', async () => {
    assert.strictEqual((await cliente('GET', '/api/users')).status, 403);
    assert.strictEqual((await cliente('GET', '/api/prestador/painel')).status, 403);
    assert.strictEqual((await cliente('POST', '/api/users', { name: 'X Y Z', email: 'z@z.com', password: 'Senha1234', role: 'admin' })).status, 403);
    assert.strictEqual((await cliente('PATCH', '/api/users/1', { role: 'cliente' })).status, 403);
  });
  await t('prestador NÃO acessa área de cliente nem de admin (403)', async () => {
    assert.strictEqual((await prest('GET', '/api/cliente/home')).status, 403);
    assert.strictEqual((await prest('GET', '/api/users')).status, 403);
  });
  await t('cada perfil acessa a própria área (200)', async () => {
    assert.strictEqual((await cliente('GET', '/api/cliente/home')).status, 200);
    assert.strictEqual((await prest('GET', '/api/prestador/painel')).status, 200);
    assert.strictEqual((await admin('GET', '/api/users')).status, 200);
  });

  // ---------- GESTÃO DE USUÁRIOS ----------
  let anaId;
  await t('admin lista usuários e filtra por busca/perfil/status', async () => {
    const all = (await admin('GET', '/api/users')).data.users;
    assert.ok(all.length >= 6);
    anaId = all.find((u) => u.email === 'ana@teste.com').id;
    assert.strictEqual((await admin('GET', '/api/users?search=ana')).data.users.every((u) => /ana/i.test(u.name + u.email)), true);
    assert.ok((await admin('GET', '/api/users?role=prestador')).data.users.every((u) => u.role === 'prestador'));
    assert.strictEqual((await admin('GET', '/api/users?search=zzzzzz')).data.users.length, 0); // estado "nenhum resultado"
  });
  await t('admin cria usuário (validação, duplicidade e perfil inválido)', async () => {
    assert.strictEqual((await admin('POST', '/api/users', { name: 'A', email: 'x', password: '1', role: 'cliente' })).status, 400);
    assert.strictEqual((await admin('POST', '/api/users', { name: 'Fulano Teste', email: 'fulano@x.com', password: 'Senha1234', role: 'chefe' })).status, 400);
    const ok = await admin('POST', '/api/users', { name: 'Fulano Teste', email: 'fulano@x.com', password: 'Senha1234', role: 'prestador' });
    assert.strictEqual(ok.status, 201);
    assert.strictEqual((await admin('POST', '/api/users', { name: 'Fulano Teste', email: 'fulano@x.com', password: 'Senha1234', role: 'prestador' })).status, 409);
  });
  await t('admin edita dados e atribui outro perfil', async () => {
    const r = await admin('PATCH', `/api/users/${anaId}`, { name: 'Ana Souza Lima', role: 'prestador' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.data.user.role, 'prestador');
    assert.strictEqual(r.data.user.name, 'Ana Souza Lima');
  });
  await t('edição valida e-mail duplicado, perfil inválido e usuário inexistente', async () => {
    assert.strictEqual((await admin('PATCH', `/api/users/${anaId}`, { email: 'cliente@biko.com' })).status, 409);
    assert.strictEqual((await admin('PATCH', `/api/users/${anaId}`, { role: 'deus' })).status, 400);
    assert.strictEqual((await admin('PATCH', '/api/users/99999', { name: 'Nome Qualquer' })).status, 404);
  });
  await t('desativar usuário: derruba sessão, bloqueia login e reativar libera', async () => {
    const vit = client();
    await vit('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'NovaSenha99' });
    assert.strictEqual((await vit('GET', '/api/auth/me')).status, 200);
    assert.strictEqual((await admin('PATCH', `/api/users/${anaId}`, { active: false })).data.user.active, false);
    assert.strictEqual((await vit('GET', '/api/auth/me')).status, 401);
    const r = await anon('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'NovaSenha99' });
    assert.strictEqual(r.status, 403);
    assert.ok(/desativada/i.test(r.data.error));
    assert.ok((await admin('GET', '/api/users?status=inativo')).data.users.some((u) => u.id === anaId));
    await admin('PATCH', `/api/users/${anaId}`, { active: true });
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'NovaSenha99' })).status, 200);
  });
  await t('admin não pode desativar nem rebaixar a si mesmo', async () => {
    const me = (await admin('GET', '/api/auth/me')).data.user;
    assert.strictEqual((await admin('PATCH', `/api/users/${me.id}`, { active: false })).status, 400);
    assert.strictEqual((await admin('PATCH', `/api/users/${me.id}`, { role: 'cliente' })).status, 400);
    assert.strictEqual((await admin('GET', '/api/auth/me')).status, 200);
  });
  await t('admin redefine senha de outro usuário', async () => {
    assert.strictEqual((await admin('POST', `/api/users/${anaId}/password`, { password: 'fraca' })).status, 400);
    assert.strictEqual((await admin('POST', `/api/users/${anaId}/password`, { password: 'SenhaDoAdmin1' })).status, 200);
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: 'ana@teste.com', password: 'SenhaDoAdmin1' })).status, 200);
  });
  await t('mudar o perfil de alguém derruba a sessão dele (permissões novas só após novo login)', async () => {
    const p = client();
    await p('POST', '/api/auth/login', { email: 'pedro@x.com', password: 'Senha1234' });
    const pid = (await p('GET', '/api/auth/me')).data.user.id;
    assert.strictEqual((await p('GET', '/api/prestador/painel')).status, 200);
    await admin('PATCH', `/api/users/${pid}`, { role: 'cliente' });
    assert.strictEqual((await p('GET', '/api/prestador/painel')).status, 401);
  });

  // =====================================================================
  // 4. PERFIL DO USUÁRIO
  // =====================================================================
  const { db: rawDb } = require('./db'); // mesmo banco temporário do servidor (para simular passagem de tempo)
  const pad2 = (n) => String(n).padStart(2, '0');
  const ymd = (d) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
  const inDays = (n) => { const d = new Date(); d.setDate(d.getDate() + n); return ymd(d); };
  const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  async function newUser(email, name, role = 'cliente', password = 'Senha1234') {
    const c = client();
    const r = await c('POST', '/api/auth/register', { name, email, phone: '(47) 98888-0000', password, role });
    assert.strictEqual(r.status, 201, `cadastro de ${email}: ${r.data.error}`);
    return { c, id: r.data.user.id, email, password };
  }

  const perfil = await newUser('perfil@teste.com', 'Paula Perfil');

  await t('perfil: rotas exigem login (401)', async () => {
    assert.strictEqual((await anon('PATCH', '/api/me', { name: 'X Y Z' })).status, 401);
    assert.strictEqual((await anon('POST', '/api/me/password', {})).status, 401);
    assert.strictEqual((await anon('PUT', '/api/me/photo', {})).status, 401);
    assert.strictEqual((await anon('DELETE', '/api/me/photo')).status, 401);
  });
  await t('perfil: edita nome e telefone e os dados persistem em um novo login', async () => {
    const r = await perfil.c('PATCH', '/api/me', { name: 'Paula Souza', phone: '(47) 97777-1111' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.data.user.name, 'Paula Souza');
    const again = client();
    await again('POST', '/api/auth/login', { email: perfil.email, password: perfil.password });
    const me = (await again('GET', '/api/auth/me')).data.user;
    assert.strictEqual(me.name, 'Paula Souza');
    assert.strictEqual(me.phone, '(47) 97777-1111');
  });
  await t('perfil: valida nome, e-mail e telefone (erro por campo)', async () => {
    const r = await perfil.c('PATCH', '/api/me', { name: 'ab', email: 'invalido', phone: 'abc' });
    assert.strictEqual(r.status, 400);
    assert.ok(r.data.fields.name && r.data.fields.email && r.data.fields.phone);
  });
  await t('perfil: não dá para mudar o próprio perfil nem o status por esta rota', async () => {
    const r = await perfil.c('PATCH', '/api/me', { role: 'admin', active: false });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.data.user.role, 'cliente');
    assert.strictEqual(r.data.user.active, true);
    assert.strictEqual((await perfil.c('GET', '/api/users')).status, 403);
  });
  await t('perfil: trocar e-mail exige a senha atual correta e o login passa a usar o novo', async () => {
    assert.strictEqual((await perfil.c('PATCH', '/api/me', { email: 'novo.perfil@teste.com' })).data.fields.currentPassword !== undefined, true);
    const wrong = await perfil.c('PATCH', '/api/me', { email: 'novo.perfil@teste.com', currentPassword: 'errada123' });
    assert.strictEqual(wrong.status, 400);
    const ok = await perfil.c('PATCH', '/api/me', { email: 'Novo.Perfil@teste.com', currentPassword: perfil.password });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.data.user.email, 'novo.perfil@teste.com');
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: perfil.email, password: perfil.password })).status, 401);
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: 'novo.perfil@teste.com', password: perfil.password })).status, 200);
    perfil.email = 'novo.perfil@teste.com';
  });
  await t('perfil: e-mail de outra pessoa -> 409', async () => {
    const r = await perfil.c('PATCH', '/api/me', { email: 'admin@biko.com', currentPassword: perfil.password });
    assert.strictEqual(r.status, 409);
  });
  await t('senha: atual errada, nova fraca e nova igual à atual são recusadas', async () => {
    assert.ok((await perfil.c('POST', '/api/me/password', { currentPassword: 'errada123', newPassword: 'NovaSenha99' })).data.fields.currentPassword);
    assert.ok((await perfil.c('POST', '/api/me/password', { currentPassword: perfil.password, newPassword: 'curta' })).data.fields.newPassword);
    assert.ok((await perfil.c('POST', '/api/me/password', { currentPassword: perfil.password, newPassword: perfil.password })).data.fields.newPassword);
  });
  await t('senha: troca com sucesso, antiga deixa de valer, outras sessões caem e a atual continua', async () => {
    const outra = client();
    await outra('POST', '/api/auth/login', { email: perfil.email, password: perfil.password });
    assert.strictEqual((await outra('GET', '/api/auth/me')).status, 200);
    const r = await perfil.c('POST', '/api/me/password', { currentPassword: perfil.password, newPassword: 'OutraSenha55' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual((await outra('GET', '/api/auth/me')).status, 401);
    assert.strictEqual((await perfil.c('GET', '/api/auth/me')).status, 200);
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: perfil.email, password: perfil.password })).status, 401);
    assert.strictEqual((await anon('POST', '/api/auth/login', { email: perfil.email, password: 'OutraSenha55' })).status, 200);
    perfil.password = 'OutraSenha55';
  });
  await t('senha: bloqueia força bruta na senha atual (429)', async () => {
    const u = await newUser('brutepwd@teste.com', 'Bruno Brute');
    let last;
    for (let i = 0; i < 6; i++) last = await u.c('POST', '/api/me/password', { currentPassword: 'chute' + i, newPassword: 'NovaSenha99' });
    assert.strictEqual(last.status, 429);
  });
  await t('foto: recusa arquivo que não é imagem, tipo falso e formato não permitido', async () => {
    assert.strictEqual((await perfil.c('PUT', '/api/me/photo', { image: 'oi' })).status, 400);
    assert.strictEqual((await perfil.c('PUT', '/api/me/photo', { image: 'data:image/gif;base64,R0lGODlhAQABAAAAACw=' })).status, 400);
    const fake = 'data:image/png;base64,' + Buffer.from('isto é só texto, não um PNG').toString('base64');
    assert.strictEqual((await perfil.c('PUT', '/api/me/photo', { image: fake })).status, 400);
  });
  await t('foto: acima de 200 KB -> 413', async () => {
    const big = 'data:image/png;base64,' + Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(210 * 1024, 1)]).toString('base64');
    assert.strictEqual((await perfil.c('PUT', '/api/me/photo', { image: big })).status, 413);
    const huge = 'data:image/png;base64,' + 'A'.repeat(500 * 1024);
    assert.strictEqual((await perfil.c('PUT', '/api/me/photo', { image: huge })).status, 413);
  });
  await t('foto: envia, outro usuário logado consegue ver, persiste no login e pode ser removida', async () => {
    const r = await perfil.c('PUT', '/api/me/photo', { image: PNG });
    assert.strictEqual(r.status, 200);
    assert.ok(r.data.user.photo_url && r.data.user.photo_url.startsWith(`/api/photo/${perfil.id}`));
    const img = await fetch(base + r.data.user.photo_url, { headers: { Cookie: await cookieOf(cliente) } });
    assert.strictEqual(img.status, 200);
    assert.strictEqual(img.headers.get('content-type'), 'image/png');
    assert.strictEqual((await img.arrayBuffer()).byteLength, Buffer.from(PNG.split(',')[1], 'base64').length);
    assert.strictEqual((await anon('GET', `/api/photo/${perfil.id}`)).status, 401);
    const again = client();
    const login = await again('POST', '/api/auth/login', { email: perfil.email, password: perfil.password });
    assert.ok(login.data.user.photo_url);
    const del = await perfil.c('DELETE', '/api/me/photo');
    assert.strictEqual(del.data.user.photo_url, null);
    assert.strictEqual((await perfil.c('GET', `/api/photo/${perfil.id}`)).status, 404);
  });

  // =====================================================================
  // SERVIÇOS DO PRESTADOR
  // =====================================================================
  const prest2 = await newUser('eletro@teste.com', 'Eduardo Eletro', 'prestador');
  let svcId;
  const goodService = { title: 'Instalação de tomadas', category: 'Eletricista', description: 'Tomadas novas e troca.', price: 80, duration_min: 60 };

  await t('serviços: só prestador cadastra (cliente 403, sem login 401)', async () => {
    assert.strictEqual((await cliente('POST', '/api/services', goodService)).status, 403);
    assert.strictEqual((await anon('POST', '/api/services', goodService)).status, 401);
  });
  await t('serviços: valida título, categoria, preço e duração', async () => {
    const r = await prest2.c('POST', '/api/services', { title: 'ab', category: 'Mágico', price: -5, duration_min: 20 });
    assert.strictEqual(r.status, 400);
    assert.ok(r.data.fields.title && r.data.fields.category && r.data.fields.price && r.data.fields.duration_min);
    assert.strictEqual((await prest2.c('POST', '/api/services', { ...goodService, price: 'abc' })).status, 400);
  });
  await t('serviços: prestador cria e lista os próprios', async () => {
    const r = await prest2.c('POST', '/api/services', goodService);
    assert.strictEqual(r.status, 201);
    assert.strictEqual(r.data.service.price, 80);
    svcId = r.data.service.id;
    assert.ok((await prest2.c('GET', '/api/services/mine')).data.services.some((s) => s.id === svcId));
    assert.strictEqual((await cliente('GET', '/api/services/mine')).status, 403);
  });
  await t('serviços: outro prestador não edita (403) e inexistente dá 404', async () => {
    assert.strictEqual((await prest('PATCH', `/api/services/${svcId}`, { price: 1 })).status, 403);
    assert.strictEqual((await prest2.c('PATCH', '/api/services/99999', { price: 1 })).status, 404);
  });
  await t('serviços: edita preço e desativa/reativa (some e volta na busca)', async () => {
    const e = await prest2.c('PATCH', `/api/services/${svcId}`, { price: 95.5 });
    assert.strictEqual(e.data.service.price, 95.5);
    assert.strictEqual((await prest2.c('PATCH', `/api/services/${svcId}`, { price: 0 })).status, 400);
    const find = async () => (await cliente('GET', '/api/search?q=tomadas')).data.results.some((s) => s.id === svcId);
    assert.strictEqual(await find(), true);
    await prest2.c('PATCH', `/api/services/${svcId}`, { active: false });
    assert.strictEqual(await find(), false);
    await prest2.c('PATCH', `/api/services/${svcId}`, { active: true });
    assert.strictEqual(await find(), true);
  });

  // =====================================================================
  // 6. BUSCA
  // =====================================================================
  await t('busca: exige login e traz as categorias', async () => {
    assert.strictEqual((await anon('GET', '/api/search')).status, 401);
    const c = (await cliente('GET', '/api/categories')).data.categories;
    assert.ok(c.length >= 6 && c.every((x) => x.nome));
    assert.ok((await cliente('GET', '/api/cliente/home')).data.categorias.find((x) => x.nome === 'Encanador').total >= 1);
  });
  await t('busca: sem filtro lista os serviços ativos de prestadores ativos', async () => {
    const r = (await cliente('GET', '/api/search')).data;
    assert.ok(r.total >= 6 && r.results.length === r.total);
    assert.ok(r.results.every((s) => s.active && s.provider_name));
  });
  await t('busca: ignora acento e maiúscula, e procura em título, categoria, descrição e prestador', async () => {
    assert.ok((await cliente('GET', '/api/search?q=ENCANADÓR')).data.results.some((s) => s.category === 'Encanador'));
    assert.ok((await cliente('GET', '/api/search?q=goteiras')).data.results.some((s) => /telhado/i.test(s.title)));
    assert.ok((await cliente('GET', '/api/search?q=' + encodeURIComponent('joana'))).data.results.every((s) => s.provider_name.includes('Joana')));
  });
  await t('busca: várias palavras funcionam como E (todas precisam aparecer)', async () => {
    assert.strictEqual((await cliente('GET', '/api/search?q=vazamentos+carlos')).data.total, 1);
    assert.strictEqual((await cliente('GET', '/api/search?q=vazamentos+joana')).data.total, 0);
  });
  await t('busca: sem resultado devolve lista vazia (estado "nenhum resultado")', async () => {
    const r = await cliente('GET', '/api/search?q=zzzzxyz');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.data.total, r.data.results.length], [0, 0]);
  });
  await t('busca: caracteres especiais não quebram nem viram curinga', async () => {
    for (const q of ['%', "'; DROP TABLE users;--", '_', '\\']) {
      const r = await cliente('GET', '/api/search?q=' + encodeURIComponent(q));
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.data.total, 0, q);
    }
    assert.strictEqual((await admin('GET', '/api/users')).status, 200);
  });
  await t('busca: filtro por categoria e por preço máximo', async () => {
    const cat = (await cliente('GET', '/api/search?category=Pintor')).data.results;
    assert.ok(cat.length >= 1 && cat.every((s) => s.category === 'Pintor'));
    const cheap = (await cliente('GET', '/api/search?max_price=130')).data.results;
    assert.ok(cheap.length >= 1 && cheap.every((s) => s.price <= 130));
  });
  await t('busca: ordenação por preço e paginação', async () => {
    const asc = (await cliente('GET', '/api/search?sort=preco_asc')).data.results.map((s) => s.price);
    assert.deepStrictEqual(asc, [...asc].sort((a, b) => a - b));
    const desc = (await cliente('GET', '/api/search?sort=preco_desc')).data.results.map((s) => s.price);
    assert.deepStrictEqual(desc, [...desc].sort((a, b) => b - a));
    const p1 = (await cliente('GET', '/api/search?sort=preco_asc&limit=2&offset=0')).data;
    const p2 = (await cliente('GET', '/api/search?sort=preco_asc&limit=2&offset=2')).data;
    assert.strictEqual(p1.results.length, 2);
    assert.ok(p1.total > 2 && p1.results[0].id !== p2.results[0].id);
  });
  await t('busca: parâmetros inválidos -> 400', async () => {
    for (const qs of ['category=Mágico', 'max_price=abc', 'max_price=-1', 'sort=aleatorio', 'q=' + 'a'.repeat(81)]) {
      assert.strictEqual((await cliente('GET', '/api/search?' + qs)).status, 400, qs);
    }
  });
  await t('busca: não mostra serviço de prestador desativado nem de quem virou cliente', async () => {
    const tmp = await newUser('sumido@teste.com', 'Sumido Silva', 'prestador');
    await tmp.c('POST', '/api/services', { ...goodService, title: 'Serviço do sumido' });
    const has = async () => (await cliente('GET', '/api/search?q=sumido')).data.total > 0;
    assert.strictEqual(await has(), true);
    await admin('PATCH', `/api/users/${tmp.id}`, { active: false });
    assert.strictEqual(await has(), false);
    await admin('PATCH', `/api/users/${tmp.id}`, { active: true });
    assert.strictEqual(await has(), true);
    await admin('PATCH', `/api/users/${tmp.id}`, { role: 'cliente' });
    assert.strictEqual(await has(), false);
  });

  // =====================================================================
  // 5. AGENDAMENTO / PEDIDOS
  // =====================================================================
  const svc = async (title) => (await cliente('GET', '/api/search?q=' + encodeURIComponent(title))).data.results[0];
  const vaza = await svc('Reparo de vazamentos');   // Carlos, 60 min, R$ 120
  const chuveiro = await svc('chuveiro');           // Carlos, 90 min, R$ 150
  const faxina = await svc('Faxina');               // Joana, 240 min
  const book = (who, service, date, time, extra = {}) =>
    who('POST', '/api/orders', { service_id: service.id, date, time, address: 'Rua das Flores, 120 - Centro', notes: '', ...extra });
  const cliente2 = await newUser('cliente2@teste.com', 'Clara Dois');
  const D = (n) => inDays(n);

  await t('pedido: só cliente cria (prestador/admin 403, sem login 401)', async () => {
    assert.strictEqual((await book(prest, vaza, D(10), '10:00')).status, 403);
    assert.strictEqual((await book(admin, vaza, D(10), '10:00')).status, 403);
    assert.strictEqual((await book(anon, vaza, D(10), '10:00')).status, 401);
  });
  let o1;
  await t('pedido: cliente cria com sucesso (pendente, preço copiado, horário final calculado, histórico)', async () => {
    const r = await book(cliente, vaza, D(10), '10:00', { notes: 'Pia da cozinha' });
    assert.strictEqual(r.status, 201);
    o1 = r.data.order;
    assert.strictEqual(o1.status, 'pendente');
    assert.strictEqual(o1.price, 120);
    assert.strictEqual(o1.end_time, '11:00');
    assert.strictEqual(o1.provider.name, 'Carlos Silva');
    const h = (await cliente('GET', `/api/orders/${o1.id}`)).data.order.history;
    assert.deepStrictEqual(h.map((e) => e.status), ['pendente']);
  });
  await t('pedido: valida data/hora (passado, <1h, >60 dias, data inexistente, minutos, fora do expediente)', async () => {
    const f = async (d, h, extra) => (await book(cliente, vaza, d, h, extra));
    assert.ok((await f(D(-1), '10:00')).data.fields.time);
    const soon = new Date(Date.now() + 30 * 60000); soon.setMinutes(Math.ceil(soon.getMinutes() / 15) * 15, 0, 0);
    assert.ok((await f(ymd(soon), `${pad2(soon.getHours())}:${pad2(soon.getMinutes())}`)).data.fields.time);
    assert.ok((await f(D(90), '10:00')).data.fields.date);
    assert.ok((await f('2027-02-31', '10:00')).data.fields.date);
    assert.ok((await f('amanhã', '10:00')).data.fields.date);
    assert.ok((await f(D(11), '10:10')).data.fields.time);
    assert.ok((await f(D(11), '06:00')).data.fields.time);
    assert.ok((await f(D(11), '19:30')).data.fields.time);   // 19:30 + 60 min passa das 20:00
    assert.strictEqual((await f(D(11), '19:00')).status, 201); // termina às 20:00 em ponto: pode
  });
  await t('pedido: valida endereço, observações e serviço inexistente/inativo', async () => {
    assert.ok((await book(cliente, vaza, D(12), '10:00', { address: 'rua' })).data.fields.address);
    assert.ok((await book(cliente, vaza, D(12), '10:00', { notes: 'x'.repeat(501) })).data.fields.notes);
    assert.strictEqual((await cliente('POST', '/api/orders', { service_id: 99999, date: D(12), time: '10:00', address: 'Rua das Flores, 120' })).status, 404);
    await prest2.c('PATCH', `/api/services/${svcId}`, { active: false });
    assert.strictEqual((await book(cliente, { id: svcId }, D(12), '10:00')).status, 404);
    await prest2.c('PATCH', `/api/services/${svcId}`, { active: true });
  });
  await t('conflito: mesmo horário, horário sobreposto e cliente com 2 pedidos ao mesmo tempo -> 409', async () => {
    assert.strictEqual((await book(cliente2.c, vaza, D(10), '10:00')).status, 409);     // idêntico ao o1
    assert.strictEqual((await book(cliente2.c, vaza, D(10), '10:30')).status, 409);     // começa no meio do o1
    assert.strictEqual((await book(cliente2.c, chuveiro, D(10), '09:15')).status, 409); // 09:15-10:45 invade o o1
    const own = await book(cliente, faxina, D(10), '10:30');                            // outra prestadora, mas o cliente já está ocupado
    assert.strictEqual(own.status, 409);
    assert.ok(own.data.fields.time);
  });
  await t('conflito: horário colado (termina às 11:00, outro começa às 11:00) é permitido', async () => {
    assert.strictEqual((await book(cliente2.c, vaza, D(10), '11:00')).status, 201);
    assert.strictEqual((await book(cliente2.c, chuveiro, D(10), '08:30')).status, 201); // 08:30-10:00 termina exatamente quando o o1 começa
  });
  await t('conflito: duas requisições simultâneas pelo mesmo horário -> só uma passa', async () => {
    const a = await newUser('corrida1@teste.com', 'Corrida Um'), b = await newUser('corrida2@teste.com', 'Corrida Dois');
    const [r1, r2] = await Promise.all([book(a.c, vaza, D(15), '14:00'), book(b.c, vaza, D(15), '14:00')]);
    assert.deepStrictEqual([r1.status, r2.status].sort(), [201, 409]);
  });
  await t('agenda do prestador mostra horários ocupados (e valida a data)', async () => {
    const r = (await cliente('GET', `/api/providers/${vaza.provider_id}/agenda?date=${D(10)}`)).data;
    assert.ok(r.busy.some((b) => b.start === '10:00' && b.end === '11:00'));
    assert.strictEqual((await cliente('GET', `/api/providers/${vaza.provider_id}/agenda?date=lixo`)).status, 400);
    assert.ok(!JSON.stringify(r).includes('Maria'), 'não pode expor quem agendou');
  });
  await t('status: quem não participa não vê o pedido (404); admin vê; ação inválida -> 400', async () => {
    assert.strictEqual((await cliente2.c('GET', `/api/orders/${o1.id}`)).status, 404);
    assert.strictEqual((await prest2.c('POST', `/api/orders/${o1.id}/status`, { action: 'confirmar' })).status, 404);
    assert.strictEqual((await admin('GET', `/api/orders/${o1.id}`)).status, 200);
    assert.strictEqual((await prest('POST', `/api/orders/${o1.id}/status`, { action: 'explodir' })).status, 400);
    assert.strictEqual((await cliente('GET', '/api/orders/abc')).status, 404);
  });
  await t('status: telefone da outra parte só aparece depois de confirmado', async () => {
    assert.strictEqual((await cliente('GET', `/api/orders/${o1.id}`)).data.order.provider.phone, null);
    assert.strictEqual((await prest('GET', `/api/orders/${o1.id}`)).data.order.client.phone, null);
  });
  await t('status: cliente não confirma nem conclui (403); prestador confirma', async () => {
    assert.strictEqual((await cliente('POST', `/api/orders/${o1.id}/status`, { action: 'confirmar' })).status, 403);
    assert.strictEqual((await cliente('POST', `/api/orders/${o1.id}/status`, { action: 'concluir' })).status, 403);
    const r = await prest('POST', `/api/orders/${o1.id}/status`, { action: 'confirmar' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.data.order.status, 'confirmado');
    assert.ok(r.data.order.provider.phone && r.data.order.client.phone);
  });
  await t('status: confirmar duas vezes -> 409 (transição inválida)', async () => {
    assert.strictEqual((await prest('POST', `/api/orders/${o1.id}/status`, { action: 'confirmar' })).status, 409);
  });
  await t('status: concluir antes do horário agendado -> 400', async () => {
    assert.strictEqual((await prest('POST', `/api/orders/${o1.id}/status`, { action: 'concluir' })).status, 400);
    assert.ok(!(await prest('GET', `/api/orders/${o1.id}`)).data.order.actions.includes('concluir'));
  });
  await t('status: concluir depois do horário atualiza ganhos do mês; depois de concluído nada muda', async () => {
    const before = (await prest('GET', '/api/prestador/painel')).data.resumo.ganhosMes;
    const old = (await prest('GET', '/api/orders?status=confirmado')).data.orders.find((o) => o.date < D(0));
    assert.ok(old, 'pedido de demonstração já passado');
    assert.ok(old.actions.includes('concluir'));
    assert.strictEqual((await prest('POST', `/api/orders/${old.id}/status`, { action: 'concluir' })).data.order.status, 'concluido');
    assert.strictEqual((await prest('GET', '/api/prestador/painel')).data.resumo.ganhosMes, before + old.price);
    for (const action of ['confirmar', 'recusar', 'cancelar', 'concluir']) {
      assert.strictEqual((await prest('POST', `/api/orders/${old.id}/status`, { action, reason: 'teste ok' })).status, 409, action);
    }
    assert.strictEqual((await cliente('POST', `/api/orders/${old.id}/status`, { action: 'cancelar' })).status, 409);
  });
  await t('status: recusar exige motivo e libera o horário', async () => {
    const r = await book(cliente2.c, chuveiro, D(20), '09:00');
    const id = r.data.order.id;
    assert.strictEqual((await book(cliente, chuveiro, D(20), '09:30')).status, 409);
    const sem = await prest('POST', `/api/orders/${id}/status`, { action: 'recusar' });
    assert.strictEqual(sem.status, 400);
    assert.ok(sem.data.fields.reason);
    const ok = await prest('POST', `/api/orders/${id}/status`, { action: 'recusar', reason: 'Estarei viajando' });
    assert.strictEqual(ok.data.order.status, 'recusado');
    assert.strictEqual(ok.data.order.status_reason, 'Estarei viajando');
    assert.strictEqual((await book(cliente, chuveiro, D(20), '09:30')).status, 201); // horário liberado
    assert.strictEqual((await prest('POST', `/api/orders/${id}/status`, { action: 'confirmar' })).status, 409); // recusado é final
  });
  await t('status: cliente cancela pedido pendente sem motivo e o horário é liberado', async () => {
    const r = await book(cliente2.c, faxina, D(25), '13:00');
    const id = r.data.order.id;
    assert.strictEqual((await book(cliente, faxina, D(25), '14:00')).status, 409);
    const c = await cliente2.c('POST', `/api/orders/${id}/status`, { action: 'cancelar' });
    assert.strictEqual(c.data.order.status, 'cancelado');
    assert.strictEqual((await book(cliente, faxina, D(25), '14:00')).status, 201);
  });
  await t('status: cliente não cancela pedido confirmado a menos de 2h; prestador cancela com motivo', async () => {
    const maria = (await cliente('GET', '/api/auth/me')).data.user.id;
    const t0 = Date.now();
    const ins = rawDb.prepare(`INSERT INTO orders (client_id, provider_id, service_id, service_title, category, price_cents, start_ts, end_ts, address, notes, status, created_at, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?, 'confirmado', ?, ?)`).run(maria, vaza.provider_id, vaza.id, 'Reparo (teste 2h)', 'Encanador', 12000, t0 + 90 * 60000, t0 + 150 * 60000, 'Rua X, 1', '', t0, t0);
    const id = Number(ins.lastInsertRowid);
    const cc = await cliente('POST', `/api/orders/${id}/status`, { action: 'cancelar' });
    assert.strictEqual(cc.status, 400);
    assert.ok(/2 horas/.test(cc.data.error));
    assert.ok(!(await cliente('GET', `/api/orders/${id}`)).data.order.actions.includes('cancelar'));
    assert.strictEqual((await prest('POST', `/api/orders/${id}/status`, { action: 'cancelar' })).status, 400); // sem motivo
    const pc = await prest('POST', `/api/orders/${id}/status`, { action: 'cancelar', reason: 'Imprevisto no trabalho' });
    assert.strictEqual(pc.data.order.status, 'cancelado');
  });
  await t('status: cliente cancela pedido confirmado com mais de 2h de antecedência', async () => {
    const r = await book(cliente2.c, vaza, D(30), '16:00');
    await prest('POST', `/api/orders/${r.data.order.id}/status`, { action: 'confirmar' });
    assert.strictEqual((await cliente2.c('POST', `/api/orders/${r.data.order.id}/status`, { action: 'cancelar' })).data.order.status, 'cancelado');
  });
  await t('histórico: cada mudança fica registrada com quem fez e o motivo, em ordem', async () => {
    const r = await book(cliente2.c, chuveiro, D(35), '08:00');
    const id = r.data.order.id;
    await prest('POST', `/api/orders/${id}/status`, { action: 'confirmar' });
    await prest('POST', `/api/orders/${id}/status`, { action: 'cancelar', reason: 'Peça em falta' });
    const h = (await cliente2.c('GET', `/api/orders/${id}`)).data.order.history;
    assert.deepStrictEqual(h.map((e) => e.status), ['pendente', 'confirmado', 'cancelado']);
    assert.strictEqual(h[2].note, 'Peça em falta');
    assert.strictEqual(h[1].actor_name, 'Carlos Silva');
    assert.strictEqual(h[0].actor_role, 'cliente');
  });
  await t('listagem: cada perfil vê só o que é seu; admin vê tudo; filtro por status', async () => {
    const mine = (await cliente('GET', '/api/orders')).data.orders;
    assert.ok(mine.length >= 2 && mine.every((o) => o.client.name === 'Maria Cliente'));
    const theirs = (await prest('GET', '/api/orders')).data.orders;
    assert.ok(theirs.every((o) => o.provider.name === 'Carlos Silva'));
    assert.strictEqual((await prest2.c('GET', '/api/orders')).data.orders.length, 0);
    const all = (await admin('GET', '/api/orders')).data.orders;
    assert.ok(all.length > mine.length + 1 && new Set(all.map((o) => o.client.id)).size > 1);
    assert.ok((await cliente('GET', '/api/orders?status=cancelado')).data.orders.every((o) => o.status === 'cancelado'));
    assert.strictEqual((await cliente('GET', '/api/orders?status=xyz')).status, 400);
    assert.strictEqual((await anon('GET', '/api/orders')).status, 401);
  });
  await t('preço do pedido fica congelado mesmo se o prestador mudar o preço depois', async () => {
    await prest('PATCH', `/api/services/${vaza.id}`, { price: 999 });
    assert.strictEqual((await cliente('GET', `/api/orders/${o1.id}`)).data.order.price, 120);
    await prest('PATCH', `/api/services/${vaza.id}`, { price: 120 });
  });
  await t('painel do prestador mostra pedidos novos reais e próximos agendamentos', async () => {
    const p = (await prest('GET', '/api/prestador/painel')).data;
    const pend = (await prest('GET', '/api/orders?status=pendente')).data.orders.length;
    assert.strictEqual(p.resumo.pedidosNovos, pend);
    assert.ok(Array.isArray(p.proximos));
  });

  // ---------- FORÇA BRUTA ----------
  await t('bloqueia após 5 tentativas erradas (429)', async () => {
    let last;
    for (let i = 0; i < 6; i++) last = await anon('POST', '/api/auth/login', { email: 'forca@bruta.com', password: 'tentativa' + i });
    assert.strictEqual(last.status, 429);
  });

  console.log('\nResultados:\n' + results.join('\n'));
  console.log(`\n${passed}/${results.length} testes passaram`);
  server.close();
  try { fs.rmSync(tmp, { force: true }); fs.rmSync(tmp + '-wal', { force: true }); fs.rmSync(tmp + '-shm', { force: true }); } catch (e) { /* ok */ }
  process.exit(process.exitCode || 0);
})();
