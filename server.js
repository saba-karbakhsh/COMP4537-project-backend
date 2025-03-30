const http = require('http');
const db = require('mysql2');
const url = require('url');
const messages = require('./messages');
const crypto = require('crypto');

require('dotenv').config();
const connectionString = process.env.DB_CONNECTION_STRING;
const con = db.createConnection(connectionString);
let userEmails = [];
con.connect(err => {
        if (err) throw err;
        console.log("Connected!");
    
        con.query("CREATE DATABASE IF NOT EXISTS DB", (err) => {
            if (err) throw err;
            console.log("Database created");
    
            con.query("USE DB", (err) => {
                if (err) throw err;
    
                const userTable = `CREATE TABLE IF NOT EXISTS Users (
                    userID INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(100) DEFAULT 'user',
                    salt VARCHAR(255)
                ) ENGINE=InnoDB`;
    
                const apiTable = `CREATE TABLE IF NOT EXISTS API (
                    apiID INT AUTO_INCREMENT PRIMARY KEY,
                    userID INT,
                    apiCounter INT DEFAULT 20,
                    FOREIGN KEY (userID) REFERENCES Users(userID)
                ) ENGINE=InnoDB`;
    
                const sessionTable = `CREATE TABLE IF NOT EXISTS Sessions (
                    token VARCHAR(255) PRIMARY KEY,
                    userID INT,
                    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB`;
    
                con.query(userTable, (err) => {
                    if (err) throw err;
                    con.query(apiTable, (err) => {
                        if (err) throw err;
                        con.query(sessionTable, (err) => {
                            if (err) throw err;
                            console.log("All tables ensured.");
                            con.query("SELECT email FROM Users", function (err, result) {
                                if (err) throw err;
                                userEmails = result.map(row => row.email);
                            });
                        });
                    });
                });
            });
        });
    });
    
    let postCounter = 0;
    let getCounter = 0;
    
http.createServer(function (req, res) {

    let q = url.parse(req.url, true);
    console.log("Request received:", q.pathname, "Method:", req.method);
    if (req.method === "POST" && q.pathname === "/signup") {
        postCounter++;
        console.log("POST request received");
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
           
            let salt = crypto.randomBytes(16).toString('hex');
            let hashedPassword = crypto.pbkdf2Sync(userData.password, salt, 100000, 64, 'sha512').toString('hex');
            userData.password = hashedPassword;
            con.query("INSERT INTO Users (email, password, salt) VALUES (?, ?, ?)", [userData.email, userData.password, salt], function (err, result) {
                if (err) throw err;
                let sqlApi = "INSERT INTO API (userID) VALUES (?)";
                let values = [result.insertId];
                con.query(sqlApi, values, function (err, result) {
                    if (err) throw err;
                });
                userEmails.push(userData.email);
                res.end(messages.userMessages.userInserted);
            });
           
            }
        });
    } else if (req.method === "POST" && q.pathname === "/login") {
        postCounter++;
        postCounter++;
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            const userData = JSON.parse(body);
            const sql = "SELECT * FROM Users WHERE email = ?";

            con.query(sql, [userData.email], (err, result) => {
                if (err) throw err;
                if (result.length === 0) return res.end(messages.userMessages.userNotFound);

                const user = result[0];
                crypto.pbkdf2(userData.password, user.salt, 100000, 64, 'sha512', (err, derivedKey) => {
                    if (err) throw err;
                    if (derivedKey.toString('hex') !== user.password) {
                        return res.end(messages.userMessages.userNotFound);
                    }

                    const sessionToken = crypto.randomBytes(64).toString('hex');
                    const maxAge = 60;
                    const allowedOrigin = req.headers.origin;

                    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
                    res.setHeader('Access-Control-Allow-Credentials', 'true');
                    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
                    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

                    const checkSessionSql = "SELECT * FROM Sessions WHERE userID = ?";
                    con.query(checkSessionSql, [user.userID], (err, sessionResult) => {
                        if (err) throw err;
                        const sessionSQL = sessionResult.length > 0
                            ? "UPDATE Sessions SET token = ? WHERE userID = ?"
                            : "INSERT INTO Sessions (token, userID) VALUES (?, ?)";
                        con.query(sessionSQL, [sessionToken, user.userID], (err) => {
                            if (err) throw err;                            
                        });
                    });
                    res.writeHead(200, {
                        'Set-Cookie': `token=${sessionToken}; HttpOnly; Max-Age=${maxAge}; SameSite=Lax`,
                        'Content-Type': 'text/plain'
                    });


                    res.end("Login successful");

                });
            });
        });
       
    }else if(req.method === "GET" && q.pathname === "/index") {
        getCounter++;
        res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');

        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Credentials': 'true'
        });
    
        const token = req.headers.cookie ? req.headers.cookie.split('; ').find(row => row.startsWith('token=')).split('=')[1] : null;
       
        if (!token) {
            console.log("No token provided");
            return res.end(JSON.stringify({ error: "No token provided" }));
        }       
    
        const sessionSql = `
        SELECT Users.userID, Users.email, Users.role
        FROM Sessions
        JOIN Users ON Sessions.userID = Users.userID
        WHERE Sessions.token = ?
    `;

    con.query(sessionSql, [token], (err, result) => {
        if (err) throw err;

        if (result.length === 0) {
            return res.end(JSON.stringify({ error: "Invalid token" }));
        }

        const user = result[0];

        console.log("User found:", user);
        if (user.role === 'admin') {
            // Admin: get all users and their API counters
            const allUsersSql = `
                SELECT Users.userID, Users.email, Users.role, API.apiCounter
                FROM Users
                LEFT JOIN API ON Users.userID = API.userID
            `;

            con.query(allUsersSql, (err, allResults) => {
                if (err) throw err;

                console.log("Admin data sent:", allResults);
                return res.end(JSON.stringify({
                    role: 'admin',
                    usersData: allResults
                }));
            });

        } else {
            // Regular user: get their API counter
            const userApiSql = `
                SELECT apiCounter FROM API WHERE userID = ?
            `;
            con.query(userApiSql, [user.userID], (err, apiResult) => {
                if (err) throw err;

                const apiCounter = apiResult.length > 0 ? apiResult[0].apiCounter : 0;

                const userData = {
                    email: user.email,
                    role: user.role,
                    userID: user.userID,
                    apiCounter: apiCounter
                };

                console.log("User data sent to GET:", userData);
                return res.end(JSON.stringify(userData));
            });
        }
    });
    
    }
}).listen(8080);


// let data;
//      if (user.role === "admin") {
//     let sqlAdmin = "SELECT * FROM Users JOIN API ON Users.userID = API.userID";
//     con.query(sqlAdmin, function (err, queryResult) {
//         if (err) throw err;
//         data = {
//             email: user.email,
//             role: user.role,
//             apiCounter: user.apiCounter,
//             usersData: queryResult
//         };
//         console.log("Data sent to admin:", data);
//         res.end(JSON.stringify(data));
//     });
// }
// else {
//     let sqlClient = "SELECT apiCounter FROM API WHERE userID = ?";
//     con.query(sqlClient, [user.userID], function (err, queryResult) {
//         if (err) throw err;
//         user.apiCounter = queryResult[0]?.apiCounter || 0;
//         data = {
//             email: user.email,
//             role: user.role,
//             apiCounter: user.apiCounter
//         };
//         console.log("Data sent to client:", data);
//         res.end(JSON.stringify(data));
//     });
    
// }
        



















// const http = require('http');
// const db = require('mysql2');
// const url = require('url');
// const crypto = require('crypto');
// require('dotenv').config();

// const connectionString = process.env.DB_CONNECTION_STRING;
// const con = db.createConnection(connectionString);
// let userEmails = [];

// 
// http.createServer((req, res) => {
//     const q = url.parse(req.url, true);

//    
//  else if (req.method === "POST" && q.pathname === "/login") {
//         

//     }  else if (req.method === "GET" && q.pathname === "/index") {
//             getCounter++;
//             console.log("GET request received");
//             console.log("GET counter: ", req.headers.cookie);
        
//             // console.log("cook ", req.headers.cookie);
//             // console.log("req ", req.headers);
//             res.writeHead(200, {
//                 'Content-Type': 'application/json',
//                 'Access-Control-Allow-Origin': req.headers.origin || 'http://localhost:8080',
//                 'Access-Control-Allow-Credentials': 'true'
//             });
        
//             const token = getCookies(req).token;
//             if (!token) {
//                 console.log("No token provided");
//                 return res.end(JSON.stringify({ error: "No token provided" }));
//             }
        
//             const sessionSql = `
//                 SELECT Users.email, Users.role, Users.userID
//                 FROM Sessions
//                 JOIN Users ON Sessions.userID = Users.userID
//                 WHERE Sessions.token = ?
//             `;
        
//             con.query(sessionSql, [token], (err, result) => {
//                 if (err) throw err;
//                 if (result.length === 0)
//                     return res.end(JSON.stringify({ error: "no token" }));
        
//                 const user = result[0];
//                 console.log("User found:", user);
//                 const userData = {
//                     email: user.email,
//                     role: user.role,
//                     userID: user.userID
//                 };
//                 console.log("User data sent to GET:", userData);
//                 res.end(JSON.stringify(userData));
//             });
        
//         } else {
//         console.log("Unknown endpoint");
//         res.writeHead(404, { 'Content-Type': 'text/plain' });
//         res.end("Endpoint not found");
//     }
// }).listen(8080);

// function getCookies(req) {
//     const cookies = {};
//     const rawCookies = req.headers.cookie;
//     // console.log("Raw Cookies:", rawCookies);
//     // console.log("Cookies:", req.headers);
//     if (!rawCookies) return cookies;
//     rawCookies.split(';').forEach(cookie => {
//         const parts = cookie.split('=');
//         cookies[parts[0].trim()] = decodeURIComponent(parts[1]);
//     });
//     return cookies;
// }






// // if (user.role === "admin") {
// //     con.query("SELECT * FROM Users", (err, usersResult) => {
// //         if (err) throw err;
// //         con.query("SELECT * FROM API", (err, apiResult) => {
// //             if (err) throw err;
// //             const data = {
// //                 email: user.email,
// //                 role: user.role,
// //                 userApiCounters: apiResult,
// //                 usersData: usersResult
// //             };
// //             console.log("Data sent to admin:", data);
// //             res.end(JSON.stringify(data));
// //         });
// //     });
// // } else {
// //     con.query("SELECT apiCounter FROM API WHERE userID = ?", [user.userID], (err, apiResult) => {
// //         if (err) throw err;
// //         const apiCounter = apiResult[0]?.apiCounter || 0;
// //         const data = {
// //             email: user.email,
// //             role: user.role,
// //             apiCounter: apiCounter
// //         };
// //         console.log("Data sent to client:", data);
// //         res.end(JSON.stringify(data));
// //     });
// // }