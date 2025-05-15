var mysql = require('mysql');

var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: ""
});


// Criação do banco de dados com IF NOT EXISTS
con.connect(function (err) {
    if (err) throw err;
    console.log("Conectado!");
    
    var sql = "CREATE DATABASE IF NOT EXISTS ConectGine";
    con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("Banco de dados 'ConectGine' criado (ou já existia)");
        con.end();
    });
});


