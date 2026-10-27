// Banco SQLite embutido no Node (node:sqlite) - não precisa instalar nada.
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const path = require('path');

const db = new DatabaseSync(process.env.BIKO_DB || path.join(__dirname, 'biko.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  phone         TEXT,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'cliente' CHECK (role IN ('admin','cliente','prestador')),
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS password_resets (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

-- Serviços que cada prestador oferece (é isso que a busca do cliente procura)
CREATE TABLE IF NOT EXISTS services (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title        TEXT NOT NULL,
  category     TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  price_cents  INTEGER NOT NULL CHECK (price_cents > 0),
  duration_min INTEGER NOT NULL CHECK (duration_min BETWEEN 30 AND 480),
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_services_provider ON services(provider_id);

-- Pedidos / agendamentos. O título e o preço do serviço são copiados para o pedido
-- (se o prestador mudar o preço depois, o pedido antigo continua com o valor combinado).
CREATE TABLE IF NOT EXISTS orders (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id     INTEGER NOT NULL REFERENCES users(id),
  provider_id   INTEGER NOT NULL REFERENCES users(id),
  service_id    INTEGER REFERENCES services(id) ON DELETE SET NULL,
  service_title TEXT NOT NULL,
  category      TEXT NOT NULL,
  price_cents   INTEGER NOT NULL,
  start_ts      INTEGER NOT NULL,
  end_ts        INTEGER NOT NULL,
  address       TEXT NOT NULL,
  notes         TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'pendente' CHECK (status IN ('pendente','confirmado','recusado','concluido','cancelado')),
  status_reason TEXT,
  completed_ts  INTEGER,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_provider ON orders(provider_id, start_ts);
CREATE INDEX IF NOT EXISTS idx_orders_client ON orders(client_id, start_ts);

-- Histórico: toda mudança de status fica registrada (quem, quando e o motivo)
CREATE TABLE IF NOT EXISTS order_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id   INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  status     TEXT NOT NULL,
  actor_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  note       TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_order ON order_events(order_id, id);
`);

// Migração leve: bancos criados na versão anterior ganham a coluna photo_v (versão da foto, 0 = sem foto).
// A foto em si fica numa tabela separada para não pesar nas listagens de usuários.
const userCols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
if (!userCols.includes('photo_v')) db.exec('ALTER TABLE users ADD COLUMN photo_v INTEGER NOT NULL DEFAULT 0');
db.exec(`
CREATE TABLE IF NOT EXISTS user_photos (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  mime    TEXT NOT NULL,
  data    BLOB NOT NULL
);
`);

// ---- hash de senha (scrypt + salt aleatório) ----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function verifyPassword(password, stored) {
  const [, salt, hash] = String(stored).split('$');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64);
  const real = Buffer.from(hash, 'hex');
  return test.length === real.length && crypto.timingSafeEqual(test, real);
}

// Transação simples: ou grava tudo, ou não grava nada (usada nas regras de agendamento)
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const out = fn(); db.exec('COMMIT'); return out; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

// Usuários de demonstração (só são criados se o banco estiver vazio)
const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
if (count === 0) {
  const insert = db.prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?,?,?,?,?)');
  insert.run('Administrador Biko', 'admin@biko.com', '(47) 99999-0001', hashPassword('Admin@123'), 'admin');
  insert.run('Maria Cliente', 'cliente@biko.com', '(47) 99999-0002', hashPassword('Cliente@123'), 'cliente');
  insert.run('Carlos Silva', 'prestador@biko.com', '(47) 99999-0003', hashPassword('Prestador@123'), 'prestador');
}

// Dados de demonstração de serviços e pedidos (só se ainda não existir nenhum serviço).
// Assim a busca e a agenda já têm o que mostrar na primeira execução.
if (db.prepare('SELECT COUNT(*) AS n FROM services').get().n === 0) {
  const carlos = db.prepare("SELECT id FROM users WHERE email = 'prestador@biko.com'").get();
  const maria = db.prepare("SELECT id FROM users WHERE email = 'cliente@biko.com'").get();
  if (carlos && maria) {
    let joana = db.prepare("SELECT id FROM users WHERE email = 'joana@biko.com'").get();
    if (!joana) {
      const i = db.prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?,?,?,?,?)')
        .run('Joana Pereira', 'joana@biko.com', '(47) 99999-0004', hashPassword('Joana@123'), 'prestador');
      joana = { id: Number(i.lastInsertRowid) };
    }
    const addService = db.prepare('INSERT INTO services (provider_id, title, category, description, price_cents, duration_min) VALUES (?,?,?,?,?,?)');
    const s1 = addService.run(carlos.id, 'Reparo de vazamentos', 'Encanador', 'Torneiras, canos e descargas com vazamento.', 12000, 60);
    addService.run(carlos.id, 'Instalação de chuveiro elétrico', 'Eletricista', 'Instalação e troca de chuveiro, com fiação segura.', 15000, 90);
    addService.run(joana.id, 'Reparo de telhado e goteiras', 'Telhado & Reparador', 'Troca de telhas e vedação de goteiras.', 28000, 180);
    addService.run(joana.id, 'Pintura de quarto ou sala', 'Pintor', 'Pintura interna com acabamento limpo.', 35000, 240);
    addService.run(joana.id, 'Faxina completa', 'Limpeza', 'Limpeza geral de casa ou apartamento.', 20000, 240);

    // Pedido antigo já confirmado (o prestador consegue marcar como concluído) e um pendente no futuro.
    const at = (daysFromNow, h, m) => { const d = new Date(); d.setDate(d.getDate() + daysFromNow); d.setHours(h, m, 0, 0); return d.getTime(); };
    const addOrder = db.prepare(`INSERT INTO orders (client_id, provider_id, service_id, service_title, category, price_cents,
      start_ts, end_ts, address, notes, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    const addEvent = db.prepare('INSERT INTO order_events (order_id, status, actor_id, note, created_at) VALUES (?,?,?,?,?)');
    const t0 = at(-3, 9, 0);
    const past = addOrder.run(maria.id, carlos.id, s1.lastInsertRowid, 'Reparo de vazamentos', 'Encanador', 12000,
      at(-1, 10, 0), at(-1, 11, 0), 'Rua das Flores, 120 - Centro', 'Vazamento na pia da cozinha.', 'confirmado', t0, t0 + 3600e3);
    addEvent.run(past.lastInsertRowid, 'pendente', maria.id, 'Pedido criado', t0);
    addEvent.run(past.lastInsertRowid, 'confirmado', carlos.id, null, t0 + 3600e3);
    const t1 = Date.now();
    const next = addOrder.run(maria.id, carlos.id, s1.lastInsertRowid, 'Reparo de vazamentos', 'Encanador', 12000,
      at(3, 14, 0), at(3, 15, 0), 'Rua das Flores, 120 - Centro', 'Descarga do banheiro não para de pingar.', 'pendente', t1, t1);
    addEvent.run(next.lastInsertRowid, 'pendente', maria.id, 'Pedido criado', t1);
  }
}

module.exports = { db, hashPassword, verifyPassword, tx };
