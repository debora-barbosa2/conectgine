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

    // Criação da tabela 'usuario'
    const sqlUsuario = `
  CREATE TABLE IF NOT EXISTS usuario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(50) NOT NULL,
    sobrenome VARCHAR(50),
    email VARCHAR(255) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`;


    // Criação da tabela 'profissional'
    var sqlProfissional = `
    CREATE TABLE IF NOT EXISTS profissional (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nome VARCHAR(50) NOT NULL,
        sobrenome VARCHAR(50),
        email VARCHAR(255) NOT NULL UNIQUE,
        senha VARCHAR(255) NOT NULL,
        especialidade VARCHAR(50) NOT NULL,
        outra_especialidade VARCHAR(100),
        registro_profissional VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`;

    con.query(sqlUsuario, function (err, result) {
        if (err) throw err;
        console.log("Tabela 'usuario' criada!");
    });

    con.query(sqlProfissional, function (err, result) {
        if (err) throw err;
        console.log("Tabela 'profissional' criada!");
    });

    

    // Encerra a conexão após a execução
    con.end()
});
