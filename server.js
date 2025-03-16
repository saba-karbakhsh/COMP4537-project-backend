const http = require('http');
const db = require('mysql2');
const url = require('url');
const messages = require('./messages');
const crypto = require('crypto');

require('dotenv').config();
const connectionString = process.env.DB_CONNECTION_STRING;
const con = db.createConnection(connectionString);

con.connect(function (err) {
    if (err) throw err;
    console.log("Connected!");
});

con.query("CREATE DATABASE IF NOT EXISTS DB", function (err, result) {
    if (err) throw err;
    console.log("Database created");
});
con.query("USE DB", function (err, result) {
        con.query("CREATE TABLE IF NOT EXISTS Users (userID INT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(100) NOT NULL UNIQUE,password VARCHAR(255) NOT NULL,role VARCHAR(100) DEFAULT 'user',apiCounter INT DEFAULT 20)ENGINE=InnoDB", function (err, result) {
            if (err) throw err;
            console.log("Table created");
        });
    });
let userEmails = [];
    con.query("SELECT email FROM Users", function (err, result) {
        if (err) throw err;
        for (let i = 0; i < result.length; i++) {
            userEmails.push(result[i].email);
        }
    }); 
http.createServer(function (req, res) {

    let q = url.parse(req.url, true);
    if (req.method === "POST" && q.pathname === "/signup") {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            let userData = JSON.parse(body);
            if (userEmails.includes(userData.email)) {
                  res.end(messages.userMessages.userExists);
                return;
            }else{
            let hashedPassword = crypto.createHash('sha256').update(userData.password).digest('hex');
            userData.password = hashedPassword;
            let sql = "INSERT INTO Users (email, password) VALUES ?";
            let values = [[userData.email, userData.password]];
            con.query(sql, [values], function (err, result) {
                if (err) throw err;
                userEmails.push(userData.email);
                res.end(messages.userMessages.userInserted);
            });
            }
        });
    } else if (req.method === "POST" && q.pathname === "/login") {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            let userData = JSON.parse(body);
            let hashedPassword = crypto.createHash('sha256').update(userData.password).digest('hex');
            userData.password = hashedPassword;
            let sql = "SELECT * FROM Users WHERE email = ? AND password = ?";
            let values = [userData.email, userData.password];
            con.query(sql, values, function (err, result) {
                if (err) throw err;
                if (result.length > 0) {
                    let data;
                    if (result[0].role === "admin") {
                        let sqlAdmin = "SELECT * FROM Users";
                        con.query(sqlAdmin, function (err, queryResult) {
                            if (err) throw err;
                            data = {
                                email: result[0].email,
                                role: result[0].role,
                                apiCounter: result[0].apiCounter,
                                usersData: queryResult
                            };
                            
                            res.end(JSON.stringify(data));
                        });
                    }
                    else {
                        data = {
                            email: result[0].email,
                            role: result[0].role,
                            apiCounter: result[0].apiCounter
                        };
                        res.end(JSON.stringify(data));
                    }
                } else {
                    res.end(messages.userMessages.userNotFound);
                }
            });
        });
    }
}).listen(8080);
