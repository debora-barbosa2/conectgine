var mysql = require('mysql');

var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "ConectGine",
});

con.connect(function (err) {
    if (err) throw err;
    console.log("Conectado!");

     const sqlUsuario = `
        CREATE TABLE IF NOT EXISTS usuario (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100),
            email VARCHAR(100),
            senha VARCHAR(100),
            confirma_senha VARCHAR(100),
            data_nascimento DATE,
            cidade VARCHAR(100),
            telefone VARCHAR(20),
            imagem VARCHAR(255)
        );
    `;

    const sqlProfissional = `
        CREATE TABLE IF NOT EXISTS profissional (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            nome_completo VARCHAR(50) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            senha VARCHAR(255) NOT NULL,
            especialidade VARCHAR(50) NOT NULL,
            outra_especialidade VARCHAR(100),
            registro_profissional VARCHAR(50) NOT NULL,
            cidade VARCHAR(100),
            imagem VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;

    const sqlChat = `
        CREATE TABLE IF NOT EXISTS chat (
            id INT AUTO_INCREMENT PRIMARY KEY,
            enviou_id INT UNSIGNED NOT NULL,
            recebeu_id INT UNSIGNED NOT NULL,
            enviou_tipo ENUM('usuario', 'profissional') NOT NULL,
            recebeu_tipo ENUM('usuario', 'profissional') NOT NULL,
            mensagem TEXT NOT NULL,
            data DATETIME DEFAULT CURRENT_TIMESTAMP,
            lida TINYINT DEFAULT 0,
            INDEX idx_conversa (enviou_id, recebeu_id, enviou_tipo, recebeu_tipo),
            INDEX idx_data (data)
        );
    `;

    const sqlAgendamentos = `
        CREATE TABLE IF NOT EXISTS agendamentos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT UNSIGNED NOT NULL,
            profissional_id INT UNSIGNED NOT NULL,
            data_hora DATETIME NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuario(id),
            FOREIGN KEY (profissional_id) REFERENCES profissional(id)
        );
    `;

    const sqlOrientacoes = `
    CREATE TABLE IF NOT EXISTS orientacoes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        profissional_id INT UNSIGNED NOT NULL,
        titulo VARCHAR(100) NOT NULL,
        conteudo TEXT NOT NULL,
        icon VARCHAR(50) DEFAULT 'fas fa-notes-medical',
        bullets JSON,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (profissional_id) REFERENCES profissional(id)
    );
`;


    // Encadeamento correto para garantir a ordem
    con.query(sqlUsuario, (err) => {
        if (err) throw err;
        console.log("Tabela 'usuario' criada!");

        con.query(sqlProfissional, (err) => {
            if (err) throw err;
            console.log("Tabela 'profissional' criada!");

            con.query(sqlChat, (err) => {
                if (err) throw err;
                console.log("Tabela 'chat' criada!");

                con.query(sqlAgendamentos, (err) => {
                    if (err) throw err;
                    console.log("Tabela 'agendamentos' criada!");

                    con.query(sqlOrientacoes, (err) => {
                        if (err) throw err;
                        console.log("Tabela 'orientacoes' criada!");
    setTimeout(() => con.end(), 500);
});
});
                });
            });
        });
    });

