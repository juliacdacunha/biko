# Biko — Marketplace de serviços

Atividade avaliativa. Esta versão cobre tudo da tabela de requisitos, menos pagamentos e chat:

1. Login
2. Perfis diferentes (admin, cliente, prestador)
3. Gestão de usuários
4. **Perfil do usuário** (dados, senha, foto)
5. **Agendamento / pedidos / reservas** (com regras de negócio)
6. **Busca** funcional sobre os dados reais

O visual segue o protótipo (azul Biko, laranja de destaque, layout de celular).

## Como rodar

Precisa do **Node.js 22.13 ou mais novo** (https://nodejs.org). Não tem `npm install`: o projeto não usa nenhuma biblioteca externa.

```bash
node --disable-warning=ExperimentalWarning server.js
# ou: npm start
```

Abra http://localhost:3000. O banco `biko.db` é criado sozinho na primeira vez, já com usuários, serviços e pedidos de exemplo.

Para zerar tudo, pare o servidor e apague os arquivos `biko.db*`.

Testes automatizados do backend (80 testes, usam um banco temporário e não mexem no `biko.db`):

```bash
node --disable-warning=ExperimentalWarning test.js
# ou: npm test
```

## Usuários de demonstração

| Perfil    | E-mail               | Senha          |
|-----------|----------------------|----------------|
| Admin     | admin@biko.com       | Admin@123      |
| Cliente   | cliente@biko.com     | Cliente@123    |
| Prestador | prestador@biko.com   | Prestador@123  |
| Prestador | joana@biko.com       | Joana@123      |

Dados de exemplo: 5 serviços (Carlos e Joana), um pedido da Maria já confirmado e com horário no passado (dá para o Carlos marcar como concluído) e um pedido pendente daqui a 3 dias.

## 1 a 3 — Login, perfis e gestão de usuários

Continuam como na entrega anterior:

- Cadastro com validação, senha com hash `scrypt` + salt, mensagem de erro genérica no login, bloqueio depois de 5 falhas em 10 min, recuperação de senha com código de uso único (30 min) e sessão em cookie `HttpOnly` de 7 dias.
- Cada rota da API declara quais perfis podem acessar (sem login → `401`, perfil errado → `403`). A interface só esconde o que não é do perfil; a proteção de verdade está no backend.
- O admin lista (busca, filtro por perfil e status), cria, edita, ativa/desativa e muda o perfil dos usuários. Não pode desativar nem rebaixar a própria conta.

## 4 — Perfil do usuário (aba *Conta*)

- **Editar dados**: nome, telefone e e-mail. Trocar o e-mail (que é o login) pede a **senha atual**. O perfil (admin/cliente/prestador) e o status não mudam por aqui, nem se alguém mandar `role` na requisição.
- **Trocar senha**: pede a senha atual, a nova precisa seguir a regra (8+ caracteres, letras e números) e ser diferente da atual. Depois da troca as **outras sessões** (outros aparelhos) são encerradas e a atual continua. Tem limite de tentativas na senha atual (429).
- **Foto**: o navegador recorta no centro e reduz para 256×256 antes de enviar. O servidor aceita PNG, JPG ou WEBP, confere os bytes do arquivo (não confia só no tipo declarado) e limita a 200 KB. A foto fica no banco e aparece no cabeçalho, nos resultados de busca e nos pedidos. Dá para trocar e remover.
- **Persistência**: tudo é gravado no SQLite; ao sair e entrar de novo os dados e a foto continuam lá.

## 5 — Agendamento / pedidos

O prestador cadastra seus **serviços** (aba *Serviços*: título, categoria, descrição, preço e duração). O cliente escolhe um serviço na busca e agenda data, horário e endereço.

**Regras na criação do pedido**

- Só cliente cria pedido. O serviço e o prestador precisam estar ativos.
- Atendimento das **07:00 às 20:00**; o horário final vem da duração do serviço e não pode passar das 20:00. Horários em múltiplos de 15 min.
- Antecedência mínima de **1 hora** e máxima de **60 dias**. Datas inexistentes (ex.: 31/02) são recusadas.
- **Conflito de horário**: o prestador não pode ter dois pedidos (pendentes ou confirmados) se sobrepondo, e o cliente também não. Horário "colado" (um termina às 11:00 e outro começa às 11:00) é permitido. Se duas pessoas pedirem o mesmo horário ao mesmo tempo, só uma passa (a checagem e a gravação são uma transação). Pedido recusado ou cancelado libera o horário.
- Na tela, os horários já ocupados aparecem desabilitados (vem de `GET /api/providers/:id/agenda`, que não expõe quem agendou).
- O título e o preço são copiados para o pedido, então mudar o preço do serviço depois não altera pedidos antigos.

**Status e quem pode mudar**

| De            | Ação       | Quem faz                     | Para        | Regras |
|---------------|------------|------------------------------|-------------|--------|
| pendente      | confirmar  | prestador do pedido          | confirmado  | |
| pendente      | recusar    | prestador do pedido          | recusado    | motivo obrigatório |
| confirmado    | concluir   | prestador do pedido          | concluído   | só depois do horário agendado |
| pendente / confirmado | cancelar | cliente, prestador ou admin | cancelado | prestador/admin: motivo obrigatório; cliente: opcional, e pedido **confirmado** só até 2 h antes |

- Pedido recusado, concluído ou cancelado é final: qualquer nova ação dá `409`.
- Quem não participa do pedido recebe `404` (como se não existisse); o admin vê todos.
- O telefone da outra parte só aparece depois que o pedido é confirmado.
- **Histórico**: cada mudança grava o novo status, quem fez, quando e o motivo (aparece no detalhe do pedido).
- O painel do prestador mostra pedidos novos, ganhos do mês (soma dos concluídos) e os próximos atendimentos.

## 6 — Busca

Aba *Buscar* do cliente. Procura nos serviços ativos de prestadores ativos:

- Texto livre em título, categoria, descrição e nome do prestador, **sem diferenciar maiúscula nem acento** ("encanadór" acha "Encanador"). Várias palavras funcionam como "E": todas precisam aparecer.
- Filtros por categoria e preço máximo; ordenação por relevância, menor preço, maior preço ou nome; paginação (`limit`/`offset`).
- A busca é feita no código (não com `LIKE`), então `%`, `_` e aspas não viram curinga nem quebram nada.
- Sem resultado, a tela mostra "Nenhum resultado encontrado" com o botão **Limpar filtros**, e o contador mostra 0.
- Serviço de prestador desativado (ou que virou cliente) some da busca na hora.

## Estrutura

```
biko/
├── server.js        # servidor HTTP + rotas da API + regras de acesso e de negócio
├── db.js            # SQLite (node:sqlite): tabelas, migração, hash de senha, dados de exemplo
├── test.js          # testes automatizados do backend (80)
└── public/
    ├── index.html
    ├── style.css
    └── app.js       # telas: login, cadastro, recuperação, início, busca, pedidos, serviços, conta, usuários
```

Tabelas: `users`, `sessions`, `password_resets`, `user_photos`, `services`, `orders`, `order_events`.

## Rotas da API

| Método | Rota                          | Quem acessa            |
|--------|-------------------------------|------------------------|
| POST   | /api/auth/register            | público                |
| POST   | /api/auth/login               | público                |
| POST   | /api/auth/forgot              | público                |
| POST   | /api/auth/reset               | público                |
| GET    | /api/auth/me                  | logado                 |
| POST   | /api/auth/logout              | logado                 |
| PATCH  | /api/me                       | logado (própria conta) |
| POST   | /api/me/password              | logado                 |
| PUT    | /api/me/photo                 | logado                 |
| DELETE | /api/me/photo                 | logado                 |
| GET    | /api/photo/:id                | logado                 |
| GET    | /api/categories               | logado                 |
| GET    | /api/search?q=&category=&max_price=&sort=&limit=&offset= | logado |
| GET    | /api/providers/:id/agenda?date=AAAA-MM-DD | logado     |
| GET    | /api/services/mine            | prestador              |
| POST   | /api/services                 | prestador              |
| PATCH  | /api/services/:id             | prestador (dono)       |
| POST   | /api/orders                   | cliente                |
| GET    | /api/orders?status=           | logado (cada um vê os seus; admin vê todos) |
| GET    | /api/orders/:id               | participantes e admin  |
| POST   | /api/orders/:id/status        | conforme a tabela de status |
| GET    | /api/cliente/home             | cliente, admin         |
| GET    | /api/prestador/painel         | prestador, admin       |
| GET    | /api/users?search=&role=&status= | admin               |
| POST   | /api/users                    | admin                  |
| PATCH  | /api/users/:id                | admin                  |
| POST   | /api/users/:id/password       | admin                  |

## Observações

- Datas e horários dos pedidos usam o fuso do computador onde o servidor roda.
- Na recuperação de senha o código aparece na tela e no console (modo demonstração); em produção iria por e-mail.
- **Fora do escopo**: pagamentos e chat (item 7 da tabela original) e avaliações dos prestadores (a "Avaliação" do painel fica em "—").
