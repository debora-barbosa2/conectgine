require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mysql = require('mysql');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const app = express();
const SALT_ROUNDS = 10;

app.use('/image', express.static(path.join(__dirname, 'public', 'image')));


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cookieParser());

const db = mysql.createConnection({
    port: 3306,
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'conectgine'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Conectado ao banco de dados');
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'segredo-super-secreto-123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"  // <=== USE URL ABSOLUTO
}, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const nome = profile.displayName;

    db.query('SELECT * FROM usuario WHERE email = ?', [email], (err, results) => {
        if (err) return done(err);
        if (results.length > 0) return done(null, results[0]);

        const novoUsuario = { nome, email };
        db.query('INSERT INTO usuario SET ?', novoUsuario, (err, result) => {
            if (err) return done(err);
            novoUsuario.id = result.insertId;
            return done(null, novoUsuario);
        });
    });
}));


passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM usuario WHERE id = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});

// Middleware autenticação usuário comum
const requireAuth = (req, res, next) => {
    if (req.session.user || req.isAuthenticated()) return next();
    res.redirect('/login');
};

// Middleware autenticação profissional
const requireProfAuth = (req, res, next) => {
    if (req.session.professional) return next();
    res.redirect('/login_prof');
};
// Dashboard do profissional
app.get('/index_profissional', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  if (!prof) return res.redirect('/login_prof');

  db.query('SELECT * FROM profissional WHERE id = ?', [prof.id], (err, results) => {
    if (err || results.length === 0) {
      console.error(err);
      return res.redirect('/login_prof');
    }

    res.render('index_profissional', { profissional: results[0] });
  });
});


app.use((req, res, next) => {
    res.locals.user = req.session.user || req.user || null;
    res.locals.professional = req.session.professional || null;
    res.locals.currentPath = req.path;
    next();
});

app.post('/chat', function (req, res) {
    if (req.session.logado) {
        var usuario = req.session.usuario
        var usuarioid = req.session.userid
        var imagem = req.session.foto
        req.session.amigoid = req.body['id']
        var amigoid = req.body['id']
        res.render('chat.ejs', { imagem: imagem, usuario: usuario, usuarioid: usuarioid, amigoid: amigoid })
    }
    else {
        req.session.erro = "É necessário fazer login para acessar essa página"
        res.redirect('/login');
    }
});

app.post('/recebemensagens', function (req, res) {
    usuario_logado = req.session.userid;
    amigo = req.session.amigoid;

    var sql = "INSERT INTO chat (enviou_id, recebeu_id, mensagem, lida) VALUES ?";
    var values = [
        [usuario_logado, amigo, req.body['mensagem'], 0]
    ];
    con.query(sql, [values], function (err, result) {
        if (err) throw err;
        console.log("Numero de registros inseridos: " + result.affectedRows);
    });
    res.send("Mensagem salva");
});

app.post('/buscamensagens', function (req, res) {
    usuario_logado = req.session.userid;
    foto_logado = req.session.foto;
    amigo = req.session.amigoid;
    retorno = ""
    var sql = "SELECT * FROM usuarios where id= ? ORDER BY id;"
    con.query(sql, amigo, function (err, result, fields) {
        if (err) throw err;
        foto_amigo = result[0]['imagem'];
        valores = [usuario_logado, amigo, amigo, usuario_logado]
        sql2 = "SELECT * FROM chat WHERE (enviou_id=? && recebeu_id= ?) or (enviou_id=? && recebeu_id= ?) ORDER BY id  LIMIT 100;";
        con.query(sql2, valores, function (err, mensagens, fields) {
            if (err) throw err;
            mensagens.forEach(function (dados) {
                moment.locale("pt-br");
                var data = moment().format("DD-MM-YYYY kk:mm")
                if (usuario_logado == dados['enviou_id']) {
                    retorno = retorno + "<div class='media media-chat media-chat-reverse'>" +
                        "<img class='avatar' src=imagens/" + foto_logado + ">" +
                        "<div class='media-body'>" +
                        "<p>" + dados['mensagem'] + "<br>" + data + "</p>" +
                        "</div>" +
                        "</div>" +
                        "<div class='media media-meta-day'> </div>"

                } else {
                    retorno = retorno + "<div class='media media-chat'>" +
                        "<img class='avatar' src=imagens/" + foto_amigo + ">" +
                        "<div class='media-body'>" +
                        "<p>" + dados['mensagem'] + "<br>" + data + "</p>" +
                        "</div>" +
                        "</div>" +
                        "<div class='media media-meta-day'> </div>"

                }
            })
            sql3 = "UPDATE chat SET lida=1 WHERE (enviou_id=? && recebeu_id= ?);";
            valores2 = [amigo, usuario_logado]
            con.query(sql3, valores2, function (err, mensagens, fields) {
                if (err) throw err;
            });
            res.send(JSON.stringify(retorno));
        });
    })
});

app.post('/busca-nao-lidas', function (req, res) {
    usuario_logado = req.session.userid;
    foto_logado = req.session.foto;
    amigo = req.session.amigoid;
    retorno = ""
    var sql = "SELECT * FROM usuarios where id= ? ORDER BY id;"
    con.query(sql, amigo, function (err, result, fields) {
        if (err) throw err;
        foto_amigo = result[0]['imagem'];
        valores = [amigo, usuario_logado]
        sql2 = "SELECT * FROM chat WHERE (enviou_id=? && recebeu_id= ?) && lida=0 ORDER BY id  LIMIT 100;";
        con.query(sql2, valores, function (err, mensagens, fields) {
            if (err) throw err;
            mensagens.forEach(function (dados) {
                moment.locale("pt-br");
                var data = moment().format("DD-MM-YYYY kk:mm")
                if (usuario_logado == dados['enviou_id']) {
                    retorno = retorno + "<div class='media media-chat media-chat-reverse'>" +
                        "<img class='avatar' src=imagens/" + foto_logado + ">" +
                        "<div class='media-body'>" +
                        "<p>" + dados['mensagem'] + "<br>" + data + "</p>" +
                        "</div>" +
                        "</div>" +
                        "<div class='media media-meta-day'> </div>"

                } else {
                    retorno = retorno + "<div class='media media-chat'>" +
                        "<img class='avatar' src=imagens/" + foto_amigo + ">" +
                        "<div class='media-body'>" +
                        "<p>" + dados['mensagem'] + "<br>" + data + "</p>" +
                        "</div>" +
                        "</div>" +
                        "<div class='media media-meta-day'> </div>"

                }
            })
            sql3 = "UPDATE chat SET lida=1 WHERE (enviou_id=? && recebeu_id= ?);";
            valores2 = [amigo, usuario_logado]
            con.query(sql3, valores2, function (err, mensagens, fields) {
                if (err) throw err;
            });
            res.send(JSON.stringify(retorno));
        });
    })
});


// Rotas públicas
app.get('/', (req, res) => res.render('index', { title: 'Agende sua Consulta - ConectGine' }));
app.get('/quem-somos', (req, res) => res.render('quem-somos', { title: 'Quem Somos' }));
app.get('/orientacoes', (req, res) => res.render('orientacoes', { title: 'Orientações' }));
//app.get('/especialistas', (req, res) => res.render('especialistas', { title: 'Especialistas' }));

app.get('/cadastro_prof', (req, res) => {
  res.render('cadastro_prof', { title: 'Cadastro Profissional - ConectGine', error: null });
});
// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        req.session.user = {
            id: req.user.id,
            nome: req.user.nome,
            email: req.user.email
        };
        res.redirect('/perfil');
    }
);
// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'image'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas imagens são permitidas!'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024 // Limite de 5MB
  }
});


app.get('/cadastro', (req, res) => {
 res.render('cadastro');
});
app.post('/cadastro', upload.single('imagem'), (req, res) => {
  const {
    nome,
    email,
    senha,
    confirma_senha,
    cidade,
    telefone,
    termos,
    data_nascimento,
  } = req.body;

  const imagem = req.file ? req.file.filename : null;

  // Validação das senhas
  if (senha !== confirma_senha) {
    return res.status(400).send('Senhas não coincidem.');
  }

  // Validação do tamanho da senha
    if (senha.length < 8) {
    return res.status(400).send('A senha deve ter pelo menos 8 caracteres.');
  }

  // Inserção no banco de dados
bcrypt.hash(senha, 10, (err, hash) => {
  if (err) {
    console.error('Erro ao criptografar a senha:', err);
    return res.status(500).send('Erro no servidor.');
  }

  const sql = `
  INSERT INTO usuario (nome, email, senha, data_nascimento, cidade, telefone, imagem)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [nome, email, hash, data_nascimento, cidade, telefone, imagem], (err, result) => {
    if (err) {
      console.error('Erro ao cadastrar:', err);
      return res.status(500).send('Erro ao cadastrar usuário.');
    }

    res.redirect('/login');
  });
});
});


app.get('/login', function (req, res) {
    var erro = ""
    var sucesso = ""
    var usuario = ""
    if (req.session.sucesso) {
        sucesso = req.session.sucesso
        req.session.sucesso = ""
    }
    if (req.session.erro) {
        erro = req.session.erro
        req.session.erro = ""
    }
    if (req.session.usuario) {
        usuario = req.session.usuario
    }
    res.render('login.ejs', { sucesso: sucesso, erro: erro, usuario: usuario });
});

app.post('/login', function (req, res) {

    var senha = req.body['senha'];
    var email = req.body['email']
    var sql = "SELECT * FROM usuario where email = ?";
    db.query(sql, [email], function (err, result) {
        if (err) throw err;
        if (result.length) {
            // método usado para comparar se a senha do banco é igual a uma passada
            bcrypt.compare(senha, result[0]['senha'], function (err, resultado) {
                if (err) throw err;
                if (resultado) {
                    req.session.logado = true;
                    req.session.user = result[0];
                   // req.session.userid = result[0]['id'];
                    //req.session.foto = result[0]['imagem'];
                    req.session.sucesso = "Login realizado com sucesso";
                    res.redirect('/');
                }
                else {
                    req.session.erro = "Senha Inválida"
                    res.redirect('login')
                }
            });
        }
        else {
            req.session.erro = "E-mail não encontrado"
            res.redirect('login')
        }
    });
});




// Rota para upload de foto de perfil (usuário comum)
app.post('/perfil/upload-foto', requireAuth, upload.single('foto'), (req, res) => {
  if (!req.file) {
    return renderPerfil(res, req.session.user, { erroAtualizacao: 'Nenhuma imagem foi enviada' });
  }

  const user = req.session.user || req.user;
  const fotoPath = req.file.filename; // Apenas o nome do arquivo

  db.query('UPDATE usuario SET foto_perfil = ? WHERE id = ?', [fotoPath, user.id], (err) => {
    if (err) {
      console.error(err);
      return renderPerfil(res, user, { erroAtualizacao: 'Erro ao atualizar foto de perfil' });
    }

    // Atualiza a sessão com o novo caminho da foto
    req.session.user.foto_perfil = fotoPath;
    
    // Busca os dados atualizados do usuário
    db.query('SELECT * FROM usuario WHERE id = ?', [user.id], (err, results) => {
      if (err || results.length === 0) return res.redirect('/');
      renderPerfil(res, results[0], { mensagemAtualizacao: 'Foto de perfil atualizada com sucesso!' });
    });
  });
});


// Login profissional
app.get('/login_prof', (req, res) => res.render('login_prof', { title: 'Login Profissional - ConectGine', error: null }));

app.post('/login_prof', (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Preencha email e senha' });
  }

  db.query('SELECT * FROM profissional WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Erro no servidor' });
    }

    if (results.length === 0) {
      return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Credenciais inválidas' });
    }

    const prof = results[0];
    bcrypt.compare(senha, prof.senha, (err, senhaValida) => {
      if (err) {
        console.error(err);
        return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Erro no servidor' });
      }

      if (!senhaValida) {
        return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Credenciais inválidas' });
      }

      req.session.professional = { id: prof.id, nome: prof.nome_completo, email: prof.email };
      res.redirect('/index_profissional');
    });
  });
});

// Cadastro profissional
app.post('/cadastro_prof', upload.single('imagem'), (req, res) => {
  const { 
    nome, 
    email, 
    senha, 
    'confirma-senha': confirmaSenha, 
    especialidade, 
    'outra-especialidade': outraEspecialidade, 
    crm, 
    cidade 
  } = req.body;

  // Validações
  if (!nome || !email || !senha || !confirmaSenha || !especialidade || !crm) {
    return res.status(400).send('Todos os campos obrigatórios devem ser preenchidos.');
  }

  if (senha !== confirmaSenha) {
    return res.status(400).send('As senhas não coincidem.');
  }

  if (senha.length < 8) {
    return res.status(400).send('A senha deve ter pelo menos 8 caracteres.');
  }

  // Se especialidade for "Outra"
  const especialidadeFinal = especialidade === 'Outra' ? (outraEspecialidade || '') : especialidade;

  const imagem = req.file ? req.file.filename : null;

  // Verifica se o email já está cadastrado
  db.query('SELECT id FROM profissional WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro no servidor.');
    }
    if (results.length > 0) {
      return res.status(409).send('E-mail já cadastrado.');
    }

    // Criptografar senha
    bcrypt.hash(senha, SALT_ROUNDS, (err, hashSenha) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Erro ao criptografar senha.');
      }

      const novoProfissional = {
        nome_completo: nome,
        email,
        senha: hashSenha,
        especialidade: especialidadeFinal,
        outra_especialidade: especialidade === 'Outra' ? outraEspecialidade : null,
        registro_profissional: crm,
        cidade,
        imagem
      };

      db.query('INSERT INTO profissional SET ?', novoProfissional, (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Erro ao cadastrar profissional.');
        }

        req.session.professional = { 
          id: result.insertId, 
          nome: nome, 
          email 
        };

        res.redirect('/index_profissional');
      });
    });
  });
});

// Logout comum
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Logout profissional
app.get('/logout_prof', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Função auxiliar para renderizar a página de perfil com mensagens padronizadas
function renderPerfil(res, userData, mensagens = {}) {
  res.render('perfil', {
    title: 'Meu Perfil',
    dados: userData,
    mensagemAtualizacao: mensagens.mensagemAtualizacao || '',
    erroAtualizacao: mensagens.erroAtualizacao || '',
    mensagemSenha: mensagens.mensagemSenha || '',
    erroSenha: mensagens.erroSenha || ''
  });
}

// GET /perfil
app.get('/perfil', requireAuth, (req, res) => {
  const user = req.session.user || req.user;
  db.query('SELECT * FROM usuario WHERE id = ?', [user.id], (err, results) => {
    if (err || results.length === 0) return res.redirect('/');
    renderPerfil(res, results[0]);
  });
});

// POST /perfil/editar
app.post('/perfil/editar', requireAuth, (req, res) => {
  const { nome, email } = req.body;
  const user = req.session.user || req.user;

  if (!nome || !email) {
    return renderPerfil(res, user, { erroAtualizacao: 'Preencha nome e email' });
  }

  db.query('SELECT * FROM usuario WHERE email = ? AND id != ?', [email, user.id], (err, results) => {
    if (err) return renderPerfil(res, user, { erroAtualizacao: 'Erro no servidor' });

    if (results.length > 0) {
      return renderPerfil(res, user, { erroAtualizacao: 'Email já está em uso' });
    }

    db.query('UPDATE usuario SET nome = ?, email = ? WHERE id = ?', [nome, email, user.id], (err) => {
      if (err) return renderPerfil(res, user, { erroAtualizacao: 'Erro ao atualizar dados' });

      req.session.user.nome = nome;
      req.session.user.email = email;

      db.query('SELECT * FROM usuario WHERE id = ?', [user.id], (err, results) => {
        if (err || results.length === 0) return res.redirect('/');
        renderPerfil(res, results[0], { mensagemAtualizacao: 'Dados atualizados com sucesso!' });
      });
    });
  });
});

// POST /perfil/alterar-senha
app.post('/perfil/alterar-senha', requireAuth, (req, res) => {
  const { senha_atual, senha_nova, senha_confirma } = req.body;
  const user = req.session.user || req.user;

  if (!senha_atual || !senha_nova || !senha_confirma) {
    return renderPerfil(res, user, { erroSenha: 'Preencha todos os campos de senha' });
  }

  if (senha_nova !== senha_confirma) {
    return renderPerfil(res, user, { erroSenha: 'Nova senha e confirmação não coincidem' });
  }

  db.query('SELECT * FROM usuario WHERE id = ?', [user.id], (err, results) => {
    if (err || results.length === 0) {
      return renderPerfil(res, user, { erroSenha: 'Usuário não encontrado' });
    }

    const usuarioDB = results[0];

    bcrypt.compare(senha_atual, usuarioDB.senha, (err, match) => {
      if (err) return renderPerfil(res, user, { erroSenha: 'Erro no servidor' });

      if (!match) {
        return renderPerfil(res, user, { erroSenha: 'Senha atual incorreta' });
      }

      bcrypt.hash(senha_nova, SALT_ROUNDS, (err, hash) => {
        if (err) return renderPerfil(res, user, { erroSenha: 'Erro no servidor' });

        db.query('UPDATE usuario SET senha = ? WHERE id = ?', [hash, user.id], (err) => {
          if (err) return renderPerfil(res, user, { erroSenha: 'Erro ao atualizar senha' });

          renderPerfil(res, user, { mensagemSenha: 'Senha alterada com sucesso!' });
        });
      });
    });
  });
});


// Perfil profissional
app.get('/perfil_profissional', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  db.query('SELECT * FROM profissional WHERE id = ?', [prof.id], (err, results) => {
    if (err || results.length === 0) return res.redirect('/');
    res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: results[0] });
  });
});

// Atualizar perfil profissional
app.post('/perfil_profissional/editar', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { nome, email, especialidade, outra_especialidade, registro_profissional, cidade } = req.body;
  const sql = `UPDATE profissional SET nome_completo=?, email=?, especialidade=?, outra_especialidade=?, registro_profissional=?, cidade=? WHERE id=?`;
  db.query(sql, [nome, email, especialidade, outra_especialidade || null, registro_profissional, cidade, prof.id], (err) => {
    if (err) {
      return db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e2, rs) => {
        if (e2 || rs.length === 0) return res.redirect('/');
        res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], erroAtualizacao: 'Erro ao atualizar perfil' });
      });
    }
    db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e2, rs) => {
      if (e2 || rs.length === 0) return res.redirect('/');
      // Atualiza sessão básica
      req.session.professional = { ...req.session.professional, nome_completo: nome, email, especialidade, outra_especialidade, registro_profissional, cidade };
      res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], mensagemAtualizacao: 'Perfil atualizado com sucesso!' });
    });
  });
});

// Alterar senha do profissional
app.post('/perfil_profissional/alterar-senha', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { senha_atual, senha_nova, senha_confirma } = req.body;
  if (!senha_atual || !senha_nova || !senha_confirma || senha_nova !== senha_confirma) {
    return db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e2, rs) => {
      if (e2 || rs.length === 0) return res.redirect('/');
      res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], erroSenha: 'Dados inválidos' });
    });
  }
  db.query('SELECT senha FROM profissional WHERE id=?', [prof.id], (err, rows) => {
    if (err || rows.length === 0) return res.redirect('/');
    bcrypt.compare(senha_atual, rows[0].senha, (e2, ok) => {
      if (e2 || !ok) {
        return db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e3, rs) => {
          if (e3 || rs.length === 0) return res.redirect('/');
          res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], erroSenha: 'Senha atual incorreta' });
        });
      }
      bcrypt.hash(senha_nova, SALT_ROUNDS, (e4, hash) => {
        if (e4) return res.redirect('/');
        db.query('UPDATE profissional SET senha=? WHERE id=?', [hash, prof.id], (e5) => {
          db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e6, rs) => {
            if (e6 || rs.length === 0) return res.redirect('/');
            res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], mensagemSenha: 'Senha alterada com sucesso!' });
          });
        });
      });
    });
  });
});

// Upload de foto do profissional
app.post('/perfil_profissional/upload-foto', requireProfAuth, upload.single('foto'), (req, res) => {
  const prof = req.session.professional;
  if (!req.file) {
    return db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e2, rs) => {
      if (e2 || rs.length === 0) return res.redirect('/');
      res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], erroAtualizacao: 'Nenhuma imagem enviada' });
    });
  }
  const filename = req.file.filename;
  db.query('UPDATE profissional SET imagem=? WHERE id=?', [filename, prof.id], (err) => {
    db.query('SELECT * FROM profissional WHERE id=?', [prof.id], (e2, rs) => {
      if (e2 || rs.length === 0) return res.redirect('/');
      req.session.professional = { ...req.session.professional, imagem: filename };
      res.render('perfil_profissional', { title: 'Meu Perfil Profissional', profissional: rs[0], mensagemAtualizacao: 'Foto atualizada!' });
    });
  });
});

// ===============================
// ORIENTAÇÕES (CRUD no MySQL)
// ===============================

// Listagem pública (todas orientações)
app.get('/orientacoes', (req, res) => {
  db.query('SELECT * FROM orientacoes', (err, results) => {
    if (err) throw err;
    res.render('orientacoes', { orientacoes: results });
  });
});


// Gerenciar orientações do profissional logado
app.get('/orientacoes/gerenciar', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const sql = 'SELECT id, titulo, conteudo, criado_em FROM orientacoes WHERE profissional_id = ? ORDER BY criado_em DESC';
  db.query(sql, [prof.id], (err, rows) => {
    if (err) {
      console.error('Erro ao listar orientações do prof:', err);
      return res.render('gerenciarOrientacao', { orientacoes: [] });
    }
    res.render('gerenciarOrientacao', { orientacoes: rows });
  });
});

// Formulário de cadastro
app.get('/orientacoes/cadastrar', requireProfAuth, (req, res) => {
  res.render('cadastrarOrientacao');
});

// Salvar nova orientação
app.post('/orientacoes/cadastrar', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { titulo, conteudo, icon, bullet1, bullet2, bullet3, bullet4 } = req.body;

  const bullets = JSON.stringify(
    [bullet1, bullet2, bullet3, bullet4].filter(b => b && b.trim() !== '')
  );

  const sql = 'INSERT INTO orientacoes (profissional_id, titulo, conteudo, icon, bullets) VALUES (?, ?, ?, ?, ?)';
  db.query(sql, [prof.id, titulo, conteudo, icon || 'fas fa-notes-medical', bullets], (err) => {
    if (err) {
      console.error('Erro ao cadastrar orientação:', err);
      return res.render('cadastrarOrientacao', { error: 'Erro ao salvar orientação' });
    }
    res.redirect('/orientacoes/gerenciar');
  });
});


// Editar orientação (form)
app.get('/orientacoes/editar/:id', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { id } = req.params;
  const sql = 'SELECT id, titulo, conteudo FROM orientacoes WHERE id = ? AND profissional_id = ?';
  db.query(sql, [id, prof.id], (err, rows) => {
    if (err || rows.length === 0) {
      return res.redirect('/orientacoes/gerenciar');
    }
    res.render('editarOrientacao', { orientacao: rows[0], id });
  });
});

// Salvar edição
app.post('/orientacoes/editar/:id', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { id } = req.params;
  const { titulo, conteudo, icon, bullet1, bullet2, bullet3, bullet4 } = req.body;

  const bullets = JSON.stringify(
    [bullet1, bullet2, bullet3, bullet4].filter(b => b && b.trim() !== '')
  );

  const sql = 'UPDATE orientacoes SET titulo = ?, conteudo = ?, icon = ?, bullets = ? WHERE id = ? AND profissional_id = ?';
  db.query(sql, [titulo, conteudo, icon || 'fas fa-notes-medical', bullets, id, prof.id], (err) => {
    if (err) {
      console.error('Erro ao atualizar orientação:', err);
    }
    res.redirect('/orientacoes/gerenciar');
  });
});


// Excluir orientação
app.post('/orientacoes/excluir/:id', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  const { id } = req.params;
  const sql = 'DELETE FROM orientacoes WHERE id = ? AND profissional_id = ?';
  db.query(sql, [id, prof.id], (err) => {
    if (err) {
      console.error('Erro ao excluir orientação:', err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true });
  });
});

// ===============================
// ROTAS DE AGENDAMENTO
// ===============================

// Listar profissionais (para o <select>)
app.get('/profissionais', (req, res) => {
  const sql = "SELECT id, nome_completo AS nome FROM profissional";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erro ao buscar profissionais:", err);
      return res.status(500).json({ success: false, error: "Erro no servidor" });
    }
    res.json(results);
  });
});

// Página de agendamento
app.get('/agendar', (req, res) => {
  res.render('agendar'); // renderiza agendar.ejs
});

// Criar agendamento
app.post('/agendar', (req, res) => {
  const { profissional_id, data_hora } = req.body;
  const usuario = req.session.user || req.user;

  if (!usuario) {
    return res.status(401).json({ success: false, error: "Usuário não autenticado" });
  }

  const usuario_id = usuario.id;

  const sql = "INSERT INTO agendamentos (usuario_id, profissional_id, data_hora) VALUES (?, ?, ?)";
  db.query(sql, [usuario_id, profissional_id, data_hora], (err, result) => {
    if (err) {
      console.error("Erro ao salvar agendamento:", err);
      return res.status(500).json({ success: false, error: err });
    }

    // Buscar nomes para montar o título do evento
    const sqlInfo = `
      SELECT u.nome AS usuario, p.nome_completo AS profissional 
      FROM usuario u, profissional p
      WHERE u.id = ? AND p.id = ?
    `;
    db.query(sqlInfo, [usuario_id, profissional_id], (err2, rows) => {
      if (err2 || rows.length === 0) {
        console.error("Erro ao buscar nomes:", err2);
        return res.status(500).json({ success: false, error: err2 });
      }

      res.json({
        success: true,
        id: result.insertId,
        usuario: rows[0].usuario,
        profissional: rows[0].profissional
      });
    });
  });
});

// Listar agendamentos (para o calendário)
app.get('/agendamentos', (req, res) => {
  const { prof } = req.query;
  const baseSql = `
    SELECT a.id, u.nome AS usuario, p.nome_completo AS profissional, a.data_hora
    FROM agendamentos a
    JOIN usuario u ON a.usuario_id = u.id
    JOIN profissional p ON a.profissional_id = p.id
  `;
  const sql = prof ? baseSql + ' WHERE a.profissional_id = ?' : baseSql;
  const params = prof ? [prof] : [];
  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Erro ao listar agendamentos:", err);
      return res.status(500).json({ success: false, error: err });
    }

    const eventos = results.map(row => ({
      id: row.id,
      title: `${row.usuario} com ${row.profissional}`,
      start: row.data_hora
    }));

    res.json(eventos);
  });
});

// Excluir agendamento
app.delete('/agendar/:id', (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM agendamentos WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Erro ao excluir agendamento:", err);
      return res.status(500).json({ success: false, error: err });
    }
    res.json({ success: true });
  });
});

// Editar agendamento (remarcar)
app.put('/agendar/:id', (req, res) => {
  const { id } = req.params;
  const { data_hora } = req.body;

  const sql = "UPDATE agendamentos SET data_hora = ? WHERE id = ?";
  db.query(sql, [data_hora, id], (err, result) => {
    if (err) {
      console.error("Erro ao remarcar agendamento:", err);
      return res.status(500).json({ success: false, error: err });
    }
    res.json({ success: true });
  });
});

app.get('/especialistas', (req, res) => {
    const sql = "SELECT * FROM profissional";
    db.query(sql, (err, resultados) => {
        if (err) {
            console.error("Erro ao buscar especialistas:", err);
            return res.send("Erro ao buscar especialistas");
        }
        res.render('especialistas', { especialistas: resultados });
    });
});

// Dashboard do profissional já existe em /index_profissional

// Agenda do profissional
app.get('/agenda', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  if (!prof) return res.redirect('/login_prof');
  res.render('agenda_profissional', { title: 'Minha Agenda', profissional: prof });
});

// Pacientes do profissional
app.get('/pacientes', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  if (!prof) return res.redirect('/login_prof');

  const sql = `
    SELECT DISTINCT u.id, u.nome, u.email, u.imagem,
      (SELECT MAX(c.data) FROM chat c
        WHERE (c.enviou_id = u.id AND c.recebeu_id = ?) OR (c.enviou_id = ? AND c.recebeu_id = u.id)
      ) AS ultima_interacao
    FROM usuario u
    INNER JOIN agendamentos a ON a.usuario_id = u.id
    WHERE a.profissional_id = ?
    ORDER BY u.nome ASC
  `;
  db.query(sql, [prof.id, prof.id, prof.id], (err, rows) => {
    if (err) {
      console.error(err);
      return res.render('pacientes', { pacientes: [], error: 'Erro ao carregar pacientes' });
    }
    res.render('pacientes', { pacientes: rows, error: null });
  });
});

// Gerenciar Orientações (aproveita view existente)
app.get('/orientacao', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  res.render('gerenciarOrientacao', { profissional: prof });
});

// Configurações do profissional (perfil)
app.get('/configuracoes', requireProfAuth, (req, res) => {
  const prof = req.session.professional;
  db.query('SELECT * FROM profissional WHERE id = ?', [prof.id], (err, results) => {
    if (err || results.length === 0) {
      return res.redirect('/login_prof');
    }
    res.render('perfil_profissional', { profissional: results[0] });
  });
});


// Servidor
app.listen(3000, () => console.log('Servidor rodando na porta 3000'));
