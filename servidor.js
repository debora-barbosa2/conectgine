require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mysql = require('mysql');

const app = express();
const SALT_ROUNDS = 10;

const db = mysql.createConnection({
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
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, function (accessToken, refreshToken, profile, done) {
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

// Atualização do callback para salvar dados em req.session.user e redirecionar para /perfil
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

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

const requireAuth = (req, res, next) => {
    if (req.session.user || req.isAuthenticated()) return next();
    res.redirect('/login');
};

const requireProfAuth = (req, res, next) => {
    if (req.session.professional) return next();
    res.redirect('/login_prof');
};

app.use((req, res, next) => {
    res.locals.user = req.session.user || req.user || null;
    res.locals.professional = req.session.professional || null;
    res.locals.currentPath = req.path;
    next();
});

// Páginas públicas
app.get('/', (req, res) => res.render('index', { title: 'Agende sua Consulta - ConectGine' }));
app.get('/quem-somos', (req, res) => res.render('quem-somos', { title: 'Quem Somos' }));
app.get('/servicos', (req, res) => res.render('servicos', { title: 'Serviços' }));
app.get('/especialistas', (req, res) => res.render('especialistas', { title: 'Especialistas' }));

// Login com Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Cadastro e Login - Usuário comum
app.get('/login', (req, res) => res.render('login', { title: 'Login - ConectGine', error: null }));
app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    db.query('SELECT * FROM usuario WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) return res.render('login', { title: 'Login - ConectGine', error: 'Credenciais inválidas' });

        const user = results[0];
        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) return res.render('login', { title: 'Login - ConectGine', error: 'Credenciais inválidas' });

        req.session.user = { id: user.id, nome: user.nome, email: user.email };
        res.redirect('/');
    });
});

app.get('/cadastro', (req, res) => res.render('cadastro', { title: 'Cadastro - ConectGine', error: null }));
app.post('/cadastro', async (req, res) => {
    const { nome, email, senha, 'confirma-senha': confirmaSenha } = req.body;
    if (senha !== confirmaSenha) return res.render('cadastro', { title: 'Cadastro - ConectGine', error: 'As senhas não coincidem' });

    db.query('SELECT * FROM usuario WHERE email = ?', [email], async (err, results) => {
        if (results.length > 0) return res.render('cadastro', { title: 'Cadastro - ConectGine', error: 'Email já cadastrado' });

        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
        const novoUsuario = { nome, email, senha: senhaHash };
        db.query('INSERT INTO usuario SET ?', novoUsuario, (err, result) => {
            if (err) return res.render('cadastro', { title: 'Cadastro - ConectGine', error: 'Erro no servidor' });

            req.session.user = { id: result.insertId, nome, email };
            res.redirect('/');
        });
    });
});

// Cadastro e Login - Profissional
app.get('/login_prof', (req, res) => res.render('login_prof', { title: 'Login Profissional - ConectGine', error: null }));
app.post('/login_prof', (req, res) => {
    const { email, senha } = req.body;
    db.query('SELECT * FROM profissional WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Credenciais inválidas' });

        const prof = results[0];
        const senhaValida = await bcrypt.compare(senha, prof.senha);
        if (!senhaValida) return res.render('login_prof', { title: 'Login Profissional - ConectGine', error: 'Credenciais inválidas' });

        req.session.professional = { id: prof.id, nome: prof.nome_completo, email: prof.email };
        res.redirect('/index_profissional');
    });
});

app.get('/cadastro_prof', (req, res) => res.render('cadastro_prof', { title: 'Cadastro Profissional - ConectGine', error: null }));
app.post('/cadastro_prof', async (req, res) => {
    const { nome, email, senha, 'confirma-senha': confirmaSenha, especialidade, 'outra-especialidade': outraEspecialidade, crm } = req.body;
    if (senha !== confirmaSenha) return res.render('cadastro_prof', { title: 'Cadastro Profissional - ConectGine', error: 'As senhas não coincidem' });

    db.query('SELECT * FROM profissional WHERE email = ?', [email], async (err, results) => {
        if (results.length > 0) return res.render('cadastro_prof', { title: 'Cadastro Profissional - ConectGine', error: 'Email já cadastrado' });

        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
        const novoProf = {
            nome_completo: nome,
            email,
            senha: senhaHash,
            especialidade,
            outra_especialidade: especialidade === 'Outra' ? outraEspecialidade : null,
            registro_profissional: crm
        };

        db.query('INSERT INTO profissional SET ?', novoProf, (err, result) => {
            if (err) return res.render('cadastro_prof', { title: 'Cadastro Profissional - ConectGine', error: 'Erro no servidor' });

            req.session.professional = { id: result.insertId, nome, email };
            res.redirect('/index_profissional');
        });
    });
});

app.get('/index_profissional', requireProfAuth, (req, res) => {
    res.render('index_profissional', { title: 'Área Profissional - ConectGine', nome: req.session.professional.nome });
});

// Página perfil unificada para usuário ou profissional
app.get('/perfil', (req, res) => {
    // Recupera dados do usuário ou profissional da sessão ou passport
    const dados = req.session.user || req.session.professional || req.user;
    if (!dados) return res.redirect('/');

    res.render('perfil', { title: 'Perfil', dados, success: null, error: null });
});

// Logout unificado
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao encerrar a sessão:', err);
            return res.status(500).send('Erro ao fazer logout.');
        }
        req.logout?.(() => {});
        res.redirect('/');
    });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});