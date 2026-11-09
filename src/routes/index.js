const express = require("express"),
  bcrypt = require("bcryptjs"),
  jwt = require("jsonwebtoken"),
  crypto = require("crypto");

const rateLimit = require("express-rate-limit"),
  multer = require("multer"),
  fs = require("fs"),
  path = require("path");
const { db, publicUser, validEmail, clean, positiveId } = require("../models");
const autenticar = require("../middlewares/auth"),
  { admin, lider } = require("../middlewares/auth");
const EMAIL_LIDER_PRINCIPAL = "admin@techcampus.com";
const ehLiderPrincipal = (usuario) => String(usuario?.email || "").toLowerCase() === EMAIL_LIDER_PRINCIPAL;
const r = express.Router(),
  wrap = (fn) => (req, res, next) =>
    Promise.resolve()
      .then(() => fn(req, res, next))
      .catch(next);
const bad = (res, msg = "Dados inválidos.") =>
  res.status(400).json({ erro: msg });
const get = (table, id) =>
  db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id);
const allowed = (value, values) => values.includes(value);

// Retorna o pedido com os campos usados pela tela do aluno e pelo painel administrativo.
function detalharPedido(id) {
  const pedido = db.prepare(`
    SELECT p.*, u.nome AS cliente, u.email AS cliente_email,
      COALESCE(SUM(i.quantidade * i.preco_unitario_centavos), 0) AS total_centavos,
      pg.id AS pagamento_id, pg.metodo AS pagamento_metodo,
      pg.status AS pagamento_status, pg.tipo_cartao, pg.parcelas,
      pg.valor_entregue_centavos, pg.troco_centavos,
      pg.expira_em AS pagamento_expira_em
    FROM pedidos p
    JOIN usuarios u ON u.id = p.usuario_id
    LEFT JOIN itens_pedido i ON i.pedido_id = p.id
    LEFT JOIN pagamentos pg ON pg.pedido_id = p.id
    WHERE p.id = ?
    GROUP BY p.id
  `).get(id);
  if (!pedido) return null;
  pedido.itens = db.prepare(`
    SELECT i.produto_id, i.quantidade, i.preco_unitario_centavos,
      pr.nome
    FROM itens_pedido i
    JOIN produtos pr ON pr.id = i.produto_id
    WHERE i.pedido_id = ?
    ORDER BY i.id
  `).all(id);
  return pedido;
}

// Esta rota alimenta a tabela administrativa. O LEFT JOIN mantém pedidos
// visíveis mesmo se um registro de pagamento ainda não tiver sido criado.
r.get("/admin/pedidos", autenticar, admin, (req, res) => {
  const status = clean(req.query.status, 30);
  const validStatus = ["pendente", "aprovado", "rejeitado", "entregue", "cancelado"];
  if (status && !validStatus.includes(status)) return bad(res, "Filtro de status inválido.");
  const where = status ? "WHERE p.status = ?" : "";
  const rows = db.prepare(`
    SELECT p.id, p.usuario_id, p.status, p.criado_em,
      u.nome AS cliente, u.email AS cliente_email,
      COALESCE(SUM(i.quantidade * i.preco_unitario_centavos), 0) AS total_centavos,
      pg.id AS pagamento_id, pg.metodo AS pagamento_metodo,
      pg.status AS pagamento_status, pg.tipo_cartao, pg.parcelas,
      pg.valor_entregue_centavos, pg.troco_centavos,
      pg.expira_em AS pagamento_expira_em
    FROM pedidos p
    JOIN usuarios u ON u.id = p.usuario_id
    LEFT JOIN itens_pedido i ON i.pedido_id = p.id
    LEFT JOIN pagamentos pg ON pg.pedido_id = p.id
    ${where}
    GROUP BY p.id
    ORDER BY p.id DESC
  `).all(...(status ? [status] : []));
  res.json(rows);
});

r.get("/pedidos/:id", autenticar, (req, res) => {
  const pedido = detalharPedido(positiveId(req.params.id));
  if (!pedido) return res.status(404).json({ erro: "Pedido não encontrado." });
  if (pedido.usuario_id !== req.usuario.id && req.usuario.papel !== "admin") return res.sendStatus(403);
  res.json(pedido);
});

r.post("/pedidos/:id/pagamento", autenticar, (req, res) => {
  const pedidoId=positiveId(req.params.id), metodo=req.body.metodo;
  if(!allowed(metodo,["pix","cartao","dinheiro"]))return bad(res,"Forma de pagamento inválida.");
  const pedido=get("pedidos",pedidoId);
  if(!pedido)return res.status(404).json({erro:"Pedido não encontrado."});
  if(pedido.usuario_id!==req.usuario.id&&req.usuario.papel!=="admin")return res.sendStatus(403);
  if(pedido.status!=="pendente")return bad(res,"Este pedido não pode receber pagamento.");
  const existente=db.prepare("SELECT * FROM pagamentos WHERE pedido_id=?").get(pedidoId);
  if(existente)return res.json(existente);
  const total=Number(db.prepare("SELECT COALESCE(SUM(quantidade*preco_unitario_centavos),0) AS total FROM itens_pedido WHERE pedido_id=?").get(pedidoId).total);
  let valorEntregue=null,troco=null,tipoCartao=null,parcelas=1;
  if(metodo==="dinheiro"){
    valorEntregue=Number(req.body.valor_entregue_centavos);
    if(!Number.isSafeInteger(valorEntregue)||valorEntregue<total)return bad(res,"Informe um valor em dinheiro igual ou superior ao total.");
    troco=valorEntregue-total;
  }
  if(metodo==="cartao"){
    tipoCartao=req.body.tipo_cartao;
    if(!allowed(tipoCartao,["debito","credito"]))return bad(res,"Selecione débito ou crédito.");
    const max=tipoCartao==="credito"?(total>100000?8:total>50000?5:total>10000?4:total>7500?3:1):1;
    parcelas=Number(req.body.parcelas||1);
    if(!Number.isInteger(parcelas)||parcelas<1||parcelas>max)return bad(res,`Para este valor, o máximo permitido é ${max}x.`);
  }
  const codigo=metodo==="pix"?crypto.randomBytes(16).toString("hex"):null;
  const expiraEm=metodo==="pix"?Date.now()+15*60*1000:null;
  const info=db.prepare(`
    INSERT INTO pagamentos(pedido_id,metodo,valor_centavos,codigo,expira_em,tipo_cartao,valor_entregue_centavos,troco_centavos,parcelas)
    VALUES(?,?,?,?,?,?,?,?,?)
  `).run(pedidoId,metodo,total,codigo,expiraEm,tipoCartao,valorEntregue,troco,parcelas);
  notificarAdmins("Novo pagamento de aluno",`Foi iniciado um pagamento ${metodo.toUpperCase()} para o pedido #${pedido.id} (aluno #${pedido.usuario_id}).`);
  res.status(201).json(get("pagamentos",info.lastInsertRowid));
});

r.post("/pedidos/:id/cancelar", autenticar, (req, res) => {
  const pedido = get("pedidos", positiveId(req.params.id));

  if (!pedido) return res.status(404).json({ erro: "Pedido não encontrado." });

  if (pedido.usuario_id !== req.usuario.id && req.usuario.papel !== "admin")
    return res.sendStatus(403);

  if (pedido.status !== "pendente")
    return bad(res, "Este pedido não pode ser cancelado.");

  db.transaction(() => {
    for (const item of db
      .prepare("SELECT * FROM itens_pedido WHERE pedido_id=?")
      .all(pedido.id)) {
      db.prepare("UPDATE produtos SET estoque=estoque+? WHERE id=?").run(
        item.quantidade,
        item.produto_id,
      );
    }

    db.prepare("UPDATE pedidos SET status='cancelado' WHERE id=?").run(
      pedido.id,
    );

    db.prepare(
      "UPDATE pagamentos SET status='cancelado' WHERE pedido_id=?",
    ).run(pedido.id);
  })();

  res.json(detalharPedido(pedido.id));
});

r.post("/pagamentos/:id/confirmar-simulado", autenticar, (req, res) => {
  // Demonstração local: esta rota simula exclusivamente a confirmação de PIX.
  // Em produção, a confirmação deve vir de um provedor de pagamento (webhook).
  if (process.env.NODE_ENV === "production") {
    return res.status(404).json({ erro: "A simulação de pagamento está disponível apenas no ambiente de demonstração." });
  }

  const pagamento = get("pagamentos", positiveId(req.params.id));
  if (!pagamento)
    return res.status(404).json({ erro: "Pagamento não encontrado." });

  const pedido = get("pedidos", pagamento.pedido_id);
  if (!pedido)
    return res.status(404).json({ erro: "Pedido não encontrado." });

  if (pedido.usuario_id !== req.usuario.id && req.usuario.papel !== "admin")
    return res.sendStatus(403);

  if (pagamento.metodo !== "pix")
    return bad(res, "A simulação está disponível somente para pagamentos PIX.");
  if (pagamento.status !== "pendente")
    return bad(res, "Este pagamento já foi processado.");
  if (pedido.status !== "pendente")
    return bad(res, "Este pedido não está aguardando pagamento.");

  // Confirma o PIX simulado e cria um único código de retirada por pedido.
  db.transaction(() => {
    db.prepare("UPDATE pagamentos SET status='confirmado' WHERE id=?").run(
      pagamento.id,
    );
    const existente = db.prepare("SELECT id FROM tokens_retirada WHERE pedido_id=?").get(pedido.id);
    if (!existente) {
      let token;
      // Token numérico de 6 dígitos, no formato do projeto Demo.
      do {
        token = String(crypto.randomInt(100000, 1000000));
      } while (db.prepare("SELECT id FROM tokens_retirada WHERE token=?").get(token));
      db.prepare(
        "INSERT INTO tokens_retirada(pedido_id, token, expira_em) VALUES(?, ?, ?)",
      ).run(pedido.id, token, Date.now() + 15 * 60 * 1000);
    }
    // PIX confirmado: aprovação automática, sem exigir ação manual no painel.
    if (pagamento.metodo === "pix") {
      db.prepare("UPDATE pedidos SET status='aprovado' WHERE id=? AND status='pendente'").run(pedido.id);
    }
  })();
  const pixAprovado = pagamento.metodo === "pix";
  db.prepare("INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)")
    .run(pedido.usuario_id, pixAprovado ? "Pagamento e pedido confirmados" : "Pagamento confirmado",
      pixAprovado
        ? `O PIX do pedido #${pedido.id} foi confirmado e o pedido foi aprovado automaticamente. Seu token de retirada está disponível por 15 minutos.`
        : `O pagamento do pedido #${pedido.id} foi confirmado. Seu token de retirada está disponível por 15 minutos.`);
  notificarAdmins(pixAprovado ? "Pedido PIX aprovado automaticamente" : "Pagamento de aluno confirmado",
    `Pagamento #${pagamento.id} do pedido #${pedido.id} (aluno #${pedido.usuario_id}) confirmado.`);

  res.json(get("pagamentos", pagamento.id));
});
r.post("/admin/pagamentos/:id/confirmar-presencial", autenticar, admin, (req, res) => {
  const pagamento = get("pagamentos", positiveId(req.params.id));
  if (!pagamento) return res.status(404).json({ erro: "Pagamento não encontrado." });
  if (!["cartao", "dinheiro"].includes(pagamento.metodo)) return bad(res, "Esta confirmação é exclusiva para cartão e dinheiro.");
  if (pagamento.status === "cancelado") return bad(res, "Este pagamento foi cancelado.");
  const pedido = get("pedidos", pagamento.pedido_id);
  if (!pedido || pedido.status !== "pendente") return bad(res, "Este pedido não está aguardando confirmação.");
  db.transaction(() => {
    db.prepare("UPDATE pagamentos SET status='confirmado' WHERE id=? AND status<>'cancelado'").run(pagamento.id);
    db.prepare("UPDATE pedidos SET status='aprovado' WHERE id=? AND status='pendente'").run(pedido.id);
    const existente = db.prepare("SELECT id FROM tokens_retirada WHERE pedido_id=?").get(pedido.id);
    if (!existente) {
      let token;
      do { token = String(crypto.randomInt(100000, 1000000)); }
      while (db.prepare("SELECT id FROM tokens_retirada WHERE token=?").get(token));
      db.prepare("INSERT INTO tokens_retirada(pedido_id,token,expira_em) VALUES(?,?,?)").run(pedido.id, token, Date.now() + 15 * 60 * 1000);
    }
  })();
  db.prepare("INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)")
    .run(pedido.usuario_id, "Pagamento confirmado", `O pagamento presencial do pedido #${pedido.id} foi confirmado. Seu token de retirada está disponível por 15 minutos.`);
  res.json({ ok: true, pagamento: get("pagamentos", pagamento.id), pedido: detalharPedido(pedido.id) });
});

r.patch("/pedidos/:id/status", autenticar, admin, (req, res) => {
  const p = get("pedidos", positiveId(req.params.id)),
    status = req.body.status;
  if (!p) return res.sendStatus(404);
  if (!allowed(status, ["aprovado", "rejeitado", "entregue", "cancelado"]))
    return bad(res);
  if (["rejeitado", "cancelado", "entregue"].includes(p.status))
    return bad(res, "Pedido já finalizado.");
  if (status === "entregue" && p.status !== "aprovado")
    return bad(res, "Aprove o pedido antes da entrega.");
  if (status === "aprovado") {
    const pg = db
      .prepare("SELECT status FROM pagamentos WHERE pedido_id=?")
      .get(p.id);
    if (!pg || pg.status !== "confirmado")
      return bad(res, "Pagamento não confirmado.");
  }
  db.transaction(() => {
    if (["rejeitado", "cancelado"].includes(status))
      for (const i of db
        .prepare("SELECT * FROM itens_pedido WHERE pedido_id=?")
        .all(p.id))
        db.prepare("UPDATE produtos SET estoque=estoque+? WHERE id=?").run(
          i.quantidade,
          i.produto_id,
        );
    db.prepare("UPDATE pedidos SET status=? WHERE id=?").run(status, p.id);
  })();
  res.json(detalharPedido(p.id));
});
// Renovação manual de token expirado, mantendo a regra de um token ativo por pedido.
r.post("/pedidos/:id/token/renovar", autenticar, (req, res) => {
  const pedido = get("pedidos", positiveId(req.params.id));
  if (!pedido) return res.status(404).json({ erro: "Pedido não encontrado." });
  if (pedido.usuario_id !== req.usuario.id && req.usuario.papel !== "admin") return res.sendStatus(403);
  const pagamento = db.prepare("SELECT status FROM pagamentos WHERE pedido_id=?").get(pedido.id);
  if (!pagamento || pagamento.status !== "confirmado") return res.status(409).json({ erro: "O pagamento ainda não foi confirmado." });
  const registro = db.prepare("SELECT * FROM tokens_retirada WHERE pedido_id=?").get(pedido.id);
  if (!registro) return res.status(404).json({ erro: "Token não encontrado." });
  if (registro.usado || pedido.status === "entregue") return res.status(409).json({ erro: "Este pedido já foi retirado." });
  if (["cancelado", "rejeitado"].includes(pedido.status)) return res.status(409).json({ erro: "Pedido cancelado ou rejeitado." });
  let novoToken;
  do { novoToken = String(crypto.randomInt(100000, 1000000)); }
  while (db.prepare("SELECT id FROM tokens_retirada WHERE token=? AND id<>?").get(novoToken, registro.id));
  db.prepare("UPDATE tokens_retirada SET token=?, expira_em=?, criado_em=CURRENT_TIMESTAMP WHERE id=?")
    .run(novoToken, Date.now() + 15 * 60 * 1000, registro.id);
  res.json({ token: novoToken, expiraEm: Date.now() + 15 * 60 * 1000, status: "ativo" });
});

// IoT: validação e confirmação de retirada usando token do pedido pago.
const iotLimit = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: "draft-7", legacyHeaders: false });
r.post(["/iot/validar", "/iot/validate"], iotLimit, (req, res) => {
  const token = clean(req.body.token, 20);
  if (!/^\d{6}$/.test(token)) return res.status(400).json({ valido: false, erro: "Informe um token numérico de 6 dígitos." });
  const registro = db.prepare(`
    SELECT t.*, p.id pedido_id, p.usuario_id, p.status pedido_status,
           pg.status pagamento_status,
           GROUP_CONCAT(pr.nome || ' (x' || i.quantidade || ')', ', ') produtos
    FROM tokens_retirada t
    JOIN pedidos p ON p.id=t.pedido_id
    JOIN pagamentos pg ON pg.pedido_id=p.id
    JOIN itens_pedido i ON i.pedido_id=p.id
    JOIN produtos pr ON pr.id=i.produto_id
    WHERE t.token=? GROUP BY t.id
  `).get(token);
  if (!registro) return res.status(404).json({ valido: false, erro: "Token não encontrado." });
  if (registro.pagamento_status !== "confirmado") return res.status(409).json({ valido: false, erro: "Pagamento ainda não confirmado." });
  if (registro.usado || registro.pedido_status === "entregue") return res.status(409).json({ valido: false, erro: "Token já utilizado." });
  if (registro.pedido_status === "cancelado" || registro.pedido_status === "rejeitado") return res.status(409).json({ valido: false, erro: "Pedido cancelado ou rejeitado." });
  if (registro.expira_em && registro.expira_em < Date.now()) return res.status(410).json({ valido: false, erro: "Token expirado. Solicite ajuda à AAPM." });
  res.json({ valido: true, pedidoId: registro.pedido_id, produtos: registro.produtos, expiraEm: registro.expira_em });
});
r.post(["/iot/confirmar", "/iot/confirm"], iotLimit, (req, res) => {
  const token = clean(req.body.token, 20);
  const registro = db.prepare(`
    SELECT t.*, p.id pedido_id, p.status pedido_status, pg.status pagamento_status
    FROM tokens_retirada t JOIN pedidos p ON p.id=t.pedido_id
    JOIN pagamentos pg ON pg.pedido_id=p.id WHERE t.token=?
  `).get(token);
  if (!registro) return res.status(404).json({ erro: "Token não encontrado." });
  if (registro.pagamento_status !== "confirmado") return res.status(409).json({ erro: "Pagamento ainda não confirmado." });
  if (registro.usado || registro.pedido_status === "entregue") return res.status(409).json({ erro: "Token já utilizado." });
  if (["cancelado", "rejeitado"].includes(registro.pedido_status)) return res.status(409).json({ erro: "Pedido cancelado ou rejeitado." });
  if (registro.expira_em && registro.expira_em < Date.now()) return res.status(410).json({ erro: "Token expirado." });
  try {
    db.transaction(() => {
      const atualizado = db.prepare("UPDATE tokens_retirada SET usado=1, usado_em=CURRENT_TIMESTAMP WHERE id=? AND usado=0").run(registro.id);
      if (!atualizado.changes) throw new Error("Token já utilizado.");
      db.prepare("UPDATE pedidos SET status='entregue' WHERE id=?").run(registro.pedido_id);
      const pedido = get("pedidos", registro.pedido_id);
      db.prepare("INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)")
        .run(pedido.usuario_id, "Retirada confirmada", `O pedido #${pedido.id} foi retirado na máquina TechCampus.`);
    })();
    res.json({ ok: true, mensagem: "Retirada confirmada com sucesso." });
  } catch (e) { res.status(409).json({ erro: e.message || "Não foi possível confirmar a retirada." }); }
});

// Notificações privadas do usuário autenticado.
r.get("/notificacoes", autenticar, (req, res) => {
  res.json(db.prepare("SELECT * FROM notificacoes WHERE usuario_id=? ORDER BY id DESC LIMIT 100").all(req.usuario.id));
});
r.patch("/notificacoes/:id/lida", autenticar, (req, res) => {
  const result = db.prepare("UPDATE notificacoes SET lida=1 WHERE id=? AND usuario_id=?").run(positiveId(req.params.id), req.usuario.id);
  if (!result.changes) return res.sendStatus(404);
  res.json({ ok: true });
});

// Documentos: arquivos privados, acesso autenticado, PDF/JPG/PNG até 50 MB
const uploadDir = path.resolve(__dirname, "../../uploads");
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (_req, file, cb) =>
      cb(
        null,
        crypto.randomUUID() + path.extname(file.originalname).toLowerCase(),
      ),
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) =>
    cb(
      null,
      ["application/pdf", "image/jpeg", "image/png"].includes(file.mimetype),
    ),
});
const fotoUpload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, ["image/jpeg", "image/png"].includes(file.mimetype)),
});
// Foto de perfil privada, armazenada em uploads e acessível somente pelo próprio usuário.
r.post("/perfil/foto", autenticar, (req, res, next) => fotoUpload.single("foto")(req, res, (err) => {
  if (err) return res.status(400).json({ erro: "Envie uma imagem JPG ou PNG de até 20 MB." });
  if (!req.file) return bad(res, "Envie uma imagem JPG ou PNG de até 20 MB.");
  const header = Buffer.alloc(8), fd = fs.openSync(req.file.path, "r");
  fs.readSync(fd, header, 0, 8, 0); fs.closeSync(fd);
  const valido = req.file.mimetype === "image/png"
    ? header.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex"))
    : header[0] === 255 && header[1] === 216 && header[2] === 255;
  if (!valido) { fs.unlinkSync(req.file.path); return bad(res, "O conteúdo não corresponde a uma imagem válida."); }
  const anterior = get("usuarios", req.usuario.id)?.foto_url;
  db.prepare("UPDATE usuarios SET foto_url=? WHERE id=?").run(req.file.filename, req.usuario.id);
  if (anterior && /^[a-f0-9-]+\.(jpg|jpeg|png)$/i.test(anterior)) {
    const antigo = path.join(uploadDir, anterior);
    if (fs.existsSync(antigo)) fs.unlinkSync(antigo);
  }
  res.status(201).json({ foto_url: req.file.filename, mensagem: "Foto atualizada." });
}));
r.get("/perfil/foto", autenticar, (req, res) => {
  const u = get("usuarios", req.usuario.id);
  if (!u?.foto_url) return res.sendStatus(404);
  const arquivo = path.join(uploadDir, path.basename(u.foto_url));
  if (!fs.existsSync(arquivo)) return res.sendStatus(404);
  res.type(path.extname(arquivo).toLowerCase() === ".png" ? "image/png" : "image/jpeg");
  // A mesma URL é usada por contas diferentes; nunca reutilizar foto em cache
  // ao trocar de usuário no mesmo navegador.
  res.set("Cache-Control", "private, no-store, no-cache, must-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Vary", "Authorization, Cookie");
  res.sendFile(arquivo);
});

// Upload de imagem para produtos: apenas administradores, JPG/PNG até 20 MB.
r.post("/produtos/imagem", autenticar, admin, (req, res) => fotoUpload.single("foto")(req, res, (err) => {
  if (err) return res.status(400).json({ erro: "Envie uma imagem JPG ou PNG de até 20 MB." });
  if (!req.file) return bad(res, "Selecione uma imagem JPG ou PNG.");
  const header = Buffer.alloc(8), fd = fs.openSync(req.file.path, "r");
  fs.readSync(fd, header, 0, 8, 0); fs.closeSync(fd);
  const valido = req.file.mimetype === "image/png"
    ? header.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex"))
    : header[0] === 255 && header[1] === 216 && header[2] === 255;
  if (!valido) { fs.unlinkSync(req.file.path); return bad(res, "O arquivo não corresponde a uma imagem válida."); }
  res.status(201).json({ imagem: "/api/produtos/imagens/" + req.file.filename });
}));

// Imagens de produtos são públicas para que a vitrine possa exibi-las.
r.get("/produtos/imagens/:arquivo", (req, res) => {
  const nome = path.basename(req.params.arquivo);
  if (!/^[a-f0-9-]+\.(jpg|jpeg|png)$/i.test(nome)) return res.sendStatus(404);
  const arquivo = path.join(uploadDir, nome);
  if (!fs.existsSync(arquivo)) return res.sendStatus(404);
  res.type(path.extname(arquivo).toLowerCase() === ".png" ? "image/png" : "image/jpeg");
  res.set("Cache-Control", "public, max-age=86400");
  res.sendFile(arquivo);
});

r.post("/documentos", autenticar, (req, res, next) =>
  upload.single("arquivo")(req, res, (err) => {
    if (err) return res.status(400).json({ erro: err.message });
    if (!req.file) return bad(res, "Envie um PDF, JPG ou PNG de até 50 MB.");
    const signatures = {
      "application/pdf": (b) => b.subarray(0, 5).toString() === "%PDF-",
      "image/png": (b) =>
        b.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex")),
      "image/jpeg": (b) => b[0] === 255 && b[1] === 216 && b[2] === 255,
    };
    const header = Buffer.alloc(8),
      fd = fs.openSync(req.file.path, "r");
    fs.readSync(fd, header, 0, 8, 0);
    fs.closeSync(fd);
    if (!signatures[req.file.mimetype](header)) {
      fs.unlinkSync(req.file.path);
      return bad(res, "Conteúdo do arquivo incompatível com o formato.");
    }
    const nome = clean(req.body.nome || req.file.originalname, 150);
    const info = db
      .prepare(
        "INSERT INTO documentos(usuario_id,nome,arquivo,mime,tamanho) VALUES(?,?,?,?,?)",
      )
      .run(
        req.usuario.id,
        nome,
        req.file.filename,
        req.file.mimetype,
        req.file.size,
      );
    notificarAdmins("Novo documento recebido", `O usuário #${req.usuario.id} enviou o documento "${nome}" (#${info.lastInsertRowid}).`);
    res.status(201).json(get("documentos", info.lastInsertRowid));
  }),
);
r.get("/documentos", autenticar, (req, res) =>
  res.json(
    req.usuario.papel === "admin"
      ? db
          .prepare(
            "SELECT id,usuario_id,nome,mime,tamanho,status,observacao,criado_em FROM documentos ORDER BY id DESC",
          )
          .all()
      : db
          .prepare(
            "SELECT id,usuario_id,nome,mime,tamanho,status,observacao,criado_em FROM documentos WHERE usuario_id=? ORDER BY id DESC",
          )
          .all(req.usuario.id),
  ),
);
r.get("/documentos/:id/arquivo", autenticar, (req, res) => {
  const d = get("documentos", positiveId(req.params.id));
  if (!d) return res.sendStatus(404);
  if (d.usuario_id !== req.usuario.id && req.usuario.papel !== "admin")
    return res.sendStatus(403);
  res.type(d.mime);
  res.set(
    "Content-Disposition",
    'inline; filename="documento-' + d.id + path.extname(d.arquivo) + '"',
  );
  res.sendFile(path.join(uploadDir, d.arquivo));
});
r.delete("/documentos/:id", autenticar, (req, res) => {
  const d = get("documentos", positiveId(req.params.id));
  if (!d) return res.sendStatus(404);

  if (d.usuario_id !== req.usuario.id && req.usuario.papel !== "admin")
    return res.sendStatus(403);

  try {
    const arquivo = path.join(uploadDir, d.arquivo);
    if (fs.existsSync(arquivo)) fs.unlinkSync(arquivo);

    db.prepare("DELETE FROM documentos WHERE id=?").run(d.id);
    res.json({ sucesso: true });
  } catch (erro) {
    console.error("Erro ao excluir documento:", erro);
    res.status(500).json({ erro: "Não foi possível excluir o documento." });
  }
});
r.patch("/documentos/:id/status", autenticar, admin, (req, res) => {
  const d = get("documentos", positiveId(req.params.id));
  if (!d) return res.sendStatus(404);
  if (!allowed(req.body.status, ["pendente", "aprovado", "rejeitado"]))
    return bad(res);
  db.prepare("UPDATE documentos SET status=?,observacao=? WHERE id=?").run(
    req.body.status,
    clean(req.body.observacao, 1000),
    d.id,
  );
  db.prepare("INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)")
    .run(d.usuario_id, "Atualização de documento", `O documento "${d.nome}" foi ${req.body.status}. ${clean(req.body.observacao, 500)}`.trim());
  res.json(get("documentos", d.id));
});
// Avisos: publicados são públicos; gerenciamento exige autenticação administrativa.
r.get("/avisos", (_req, res) => {
  res.json(db.prepare("SELECT * FROM avisos WHERE publicado=1 ORDER BY CASE WHEN data_evento IS NULL OR data_evento='' THEN 1 ELSE 0 END, data_evento ASC, id DESC").all());
});
r.get("/admin/avisos", autenticar, admin, (_req, res) => {
  // A lista "Avisos publicados" deve retornar somente avisos ativos.
  // Avisos despublicados pela rota DELETE ficam preservados no banco, mas não reaparecem na interface.
  res.json(db.prepare("SELECT * FROM avisos WHERE publicado=1 ORDER BY data_evento ASC, id DESC").all());
});
r.post("/avisos", autenticar, admin, (req, res) => {
  const titulo = clean(req.body.titulo, 150);
  const conteudo = clean(req.body.conteudo, 5000);
  const categoria = req.body.categoria || "importante";
  const dataEvento = clean(req.body.data_evento, 10);
  const horario = clean(req.body.horario, 5);
  const local = clean(req.body.local, 150);
  if (!titulo || !/^\d{4}-\d{2}-\d{2}$/.test(dataEvento) || !Number.isFinite(Date.parse(dataEvento + "T12:00:00")) || !allowed(categoria, ["evento", "academico", "reuniao", "importante"]) || (horario && !/^\d{2}:\d{2}$/.test(horario))) return bad(res, "Preencha título, categoria e uma data válida.");
  const info = db.prepare("INSERT INTO avisos(titulo,conteudo,categoria,data_evento,horario,local,publicado) VALUES(?,?,?,?,?,?,1)").run(titulo, conteudo, categoria, dataEvento, horario, local);
  const avisoCriado = get("avisos", info.lastInsertRowid);

  // Notifica cada aluno ativo uma única vez quando o aviso é publicado.
  // A edição do aviso não dispara novamente a notificação de criação.
  const alunos = db.prepare("SELECT id FROM usuarios WHERE papel='aluno' AND ativo=1").all();
  const inserirNotificacaoEvento = db.prepare(
    "INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)"
  );
  const dataLegivel = dataEvento.split("-").reverse().join("/");
  const detalhesEvento = [dataLegivel, horario || null, local || null].filter(Boolean).join(" • ");
  const mensagemEvento = [conteudo, detalhesEvento].filter(Boolean).join("\\n\\n");
  const notificarAlunos = db.transaction(() => {
    for (const aluno of alunos) {
      inserirNotificacaoEvento.run(
        aluno.id,
        "Novo evento: " + titulo,
        mensagemEvento
      );
    }
  });
  notificarAlunos();
  res.status(201).json(avisoCriado);
});
r.patch("/avisos/:id", autenticar, admin, (req, res) => {
  const aviso = get("avisos", positiveId(req.params.id));
  if (!aviso || Number(aviso.publicado) !== 1) return res.sendStatus(404);
  if (req.body.ocorrido !== undefined) {
    if (![0, 1, false, true].includes(req.body.ocorrido)) return bad(res, "Estado de ocorrência inválido.");
    db.prepare("UPDATE avisos SET ocorrido=? WHERE id=?").run(Number(req.body.ocorrido), aviso.id);
    return res.json(get("avisos", aviso.id));
  }
  const titulo = req.body.titulo === undefined ? aviso.titulo : clean(req.body.titulo, 150);
  const conteudo = req.body.conteudo === undefined ? aviso.conteudo : clean(req.body.conteudo, 5000);
  const categoria = req.body.categoria === undefined ? aviso.categoria : req.body.categoria;
  const dataEvento = req.body.data_evento === undefined ? aviso.data_evento : clean(req.body.data_evento, 10);
  const horario = req.body.horario === undefined ? aviso.horario : clean(req.body.horario, 5);
  const local = req.body.local === undefined ? aviso.local : clean(req.body.local, 150);
  if (!titulo || !/^\d{4}-\d{2}-\d{2}$/.test(dataEvento || "") || !Number.isFinite(Date.parse(dataEvento + "T12:00:00")) || !allowed(categoria, ["evento", "academico", "reuniao", "importante"]) || (horario && !/^\d{2}:\d{2}$/.test(horario))) return bad(res, "Dados do aviso inválidos.");
  db.prepare("UPDATE avisos SET titulo=?,conteudo=?,categoria=?,data_evento=?,horario=?,local=? WHERE id=?").run(titulo, conteudo, categoria, dataEvento, horario || null, local, aviso.id);
  res.json(get("avisos", aviso.id));
});
r.delete("/avisos/:id", autenticar, admin, (req, res) => {
  const id = positiveId(req.params.id);
  const aviso = get("avisos", id);
  if (!aviso) return res.sendStatus(404);

  // Exclusão lógica: remove do calendário público, mantendo o registro para auditoria.
  // Retorna sucesso também se o aviso já estava despublicado.
  db.prepare("UPDATE avisos SET publicado=0 WHERE id=?").run(id);
  res.status(204).end();
});

// Conteúdo informativo de formatura.
r.get("/formatura", (_req, res) => res.json(db.prepare("SELECT * FROM formatura WHERE publicado=1 ORDER BY id DESC").all()));
r.post("/formatura", autenticar, admin, (req, res) => {
  const titulo = clean(req.body.titulo, 150), descricao = clean(req.body.descricao, 5000), dataEvento = clean(req.body.data_evento, 40);
  if (!titulo || !descricao) return bad(res);
  const info = db.prepare("INSERT INTO formatura(titulo,descricao,data_evento) VALUES(?,?,?)").run(titulo, descricao, dataEvento);
  res.status(201).json(get("formatura", info.lastInsertRowid));
});
r.delete("/formatura/:id", autenticar, admin, (req, res) => {
  const info = db.prepare("UPDATE formatura SET publicado=0 WHERE id=?").run(positiveId(req.params.id));
  res.status(info.changes ? 204 : 404).end();
});

// Agendamentos
r.post("/agendamentos", autenticar, (req, res) => {
  const recurso = clean(req.body.recurso, 120),
    inicio = clean(req.body.inicio, 40),
    fim = clean(req.body.fim, 40);
  if (
    !allowed(recurso, ["Quadra", "Jogos de Tabuleiro"]) ||
    !Number.isFinite(Date.parse(inicio)) ||
    !Number.isFinite(Date.parse(fim)) ||
    Date.parse(inicio) >= Date.parse(fim) ||
    Date.parse(inicio) < Date.now()
  )
    return bad(res, "Recurso ou período inválido.");

  const ocupado = db
    .prepare(
      "SELECT id FROM agendamentos WHERE recurso=? AND status IN ('pendente','aprovado') AND inicio<? AND fim>?",
    )
    .get(recurso, fim, inicio);
  if (ocupado) return res.status(409).json({ erro: "Horário já reservado." });

  const info = db
    .prepare(
      "INSERT INTO agendamentos(usuario_id,recurso,inicio,fim) VALUES(?,?,?,?)",
    )
    .run(req.usuario.id, recurso, inicio, fim);
  res.status(201).json(get("agendamentos", info.lastInsertRowid));
});
// Ajuda / chamados
r.post("/chamados", autenticar, (req, res) => {
  const assunto = clean(req.body.assunto, 150),
    mensagem = clean(req.body.mensagem, 5000);
  if (!assunto || !mensagem) return bad(res);
  const info = db
    .prepare("INSERT INTO chamados(usuario_id,assunto,mensagem) VALUES(?,?,?)")
    .run(req.usuario.id, assunto, mensagem);
  notificarAdmins("Nova dúvida de aluno", `Chamado #${info.lastInsertRowid}: ${assunto}`);
  res.status(201).json(get("chamados", info.lastInsertRowid));
});
r.get("/chamados", autenticar, (req, res) =>
  res.json(
    req.usuario.papel === "admin"
      ? db.prepare("SELECT * FROM chamados ORDER BY id DESC").all()
      : db
          .prepare("SELECT * FROM chamados WHERE usuario_id=? ORDER BY id DESC")
          .all(req.usuario.id),
  ),
);
r.patch("/chamados/:id", autenticar, admin, (req, res) => {
  const c = get("chamados", positiveId(req.params.id));
  if (!c) return res.sendStatus(404);
  if (!allowed(req.body.status, ["aberto", "em_andamento", "resolvido"]))
    return bad(res);
  const resposta = clean(req.body.resposta, 5000);
  db.prepare("UPDATE chamados SET status=?,resposta=? WHERE id=?").run(
    req.body.status, resposta, c.id,
  );
  if (resposta) db.prepare("INSERT INTO notificacoes(usuario_id,titulo,mensagem) VALUES(?,?,?)")
    .run(c.usuario_id, "Resposta da AAPM", `Sua dúvida "${c.assunto}" recebeu uma resposta: ${resposta}`);
  res.json(get("chamados", c.id));
});

// TROCA DE SENHA
r.use(require("./senha"));

// ROTA 404
r.use((_req, res) => res.status(404).json({ erro: "Rota não encontrada." }));
module.exports = r;
