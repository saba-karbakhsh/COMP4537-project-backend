const http = require('http');
const fs = require('fs');
const db = require('mysql2');
const url = require('url');
const messages = require('./messages');
const crypto = require('crypto');
const Mailjet = require('node-mailjet');
require('dotenv').config();
const mailjet = Mailjet.apiConnect(
    process.env.MJ_APIKEY_PUBLIC,
    process.env.MJ_APIKEY_PRIVATE
);

const httpProxy = require('http-proxy');
// Create a proxy server instance pointing to the Flask server
const proxy = httpProxy.createProxyServer({target: 'https://comp4537g2.loca.lt', secure: false, timeout: 10000});

proxy.on('error', (err, req, res) => {
    console.error('Proxy error:', err);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Proxy error occurred');
});

// Add CORS headers to all proxied responses
proxy.on('proxyRes', (proxyRes, req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'https://nice-flower-0dc97321e.6.azurestaticapps.net');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, bypass-tunnel-reminder');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
});

const con = db.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        ca: fs.readFileSync('./ca-certificate.crt')
    }
});

const SESSION_EXPIRY_MS = 60 * 60 * 1000; // 1 hour in milliseconds

const maxApiCalls = 20; // Maximum API calls allowed

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
                    apiCounter INT DEFAULT 0,
                    FOREIGN KEY (userID) REFERENCES Users(userID) ON DELETE CASCADE
                ) ENGINE=InnoDB`;

            const sessionTable = `CREATE TABLE IF NOT EXISTS Sessions (
                    token VARCHAR(255) PRIMARY KEY,
                    userID INT,
                    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB`;

            const resetTokenTable = `CREATE TABLE IF NOT EXISTS ResetTokens (
                id INT AUTO_INCREMENT PRIMARY KEY,    
                email VARCHAR(100) UNIQUE,
                     token VARCHAR(255),
                     expiresAt DATETIME
                ) ENGINE=InnoDB;`
            con.query(userTable, (err) => {
                if (err) throw err;
                con.query(apiTable, (err) => {
                    if (err) throw err;
                    con.query(sessionTable, (err) => {
                        if (err) throw err;
                        console.log("All tables ensured.");
                        con.query(resetTokenTable, (err) => {
                            if (err) throw err;
                            console.log("ResetTokens table ensured.");
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
});

let postCounter = 0;
let getCounter = 0;
let deleteCounter = 0;
let putCounter = 0;

http.createServer(function (req, res) {

    let q = url.parse(req.url, true);
    console.log("Request received:", req.method, q.pathname);
    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, bypass-tunnel-reminder',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE, PUT'
        });
        return res.end(JSON.stringify({ message:  messages.userMessages.CORS }));
    }
    console.log("Request received:", req.method, q.pathname);

    // Define endpoints to proxy (for tracking usage)
    const proxiedEndpoints = ['/drone/v1/toggle-face-tracking', '/drone/v1/toggle-face-detection'];
 
    // Check if the request should be proxied
    if (proxiedEndpoints.includes(q.pathname)) {
        // // Optional: Add authentication check
        // const authToken = req.headers['authorization'];
        // if (!authToken) {
        //     res.writeHead(401, { 'Content-Type': 'text/plain' });
        //     res.end('Unauthorized');
        //     return;
        // }
        // // Placeholder: Replace with your actual token validation logic
        // if (authToken !== 'valid-token') {
        //     res.writeHead(401, { 'Content-Type': 'text/plain' });
        //     res.end('Invalid token');
        //     return;
        // }
        // // Track usage (e.g., log the request)
        // console.log(`Proxying request to ${q.pathname} for user with token ${authToken}`);
        // increment api counter
        incrementApiCounter(userID);
        // Forward the request to the Flask server
        proxy.web(req, res);
    
    } else if (req.method === "POST" && q.pathname === "/api/v1/signup") {
        postCounter++;
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            let userData = JSON.parse(body);
            incrementApiCounter(userData.userID);
            if (userEmails.includes(userData.email)) {
                res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                res.end(JSON.stringify({ error: messages.userMessages.userExists }));
                return;
            } else {

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
                    res.end(JSON.stringify({ message: messages.userMessages.userCreated }));
                });

            }
        });
    } else if (req.method === "POST" && q.pathname === "/api/v1/login") {
        
        postCounter++;
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            const userData = JSON.parse(body);
            const sql = "SELECT * FROM Users WHERE email = ?";

            con.query(sql, [userData.email], (err, result) => {
                setCORSHeaders(res);

                res.setHeader('Content-Type', 'application/json');
                
                if (err) throw err;
                if (result.length === 0){
                    res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                    return res.end(JSON.stringify({ error: messages.userMessages.userNotFound }));
                } 

                const user = result[0];
                crypto.pbkdf2(userData.password, user.salt, 100000, 64, 'sha512', (err, derivedKey) => {
                    if (err) throw err;
                    if (derivedKey.toString('hex') !== user.password) {
                        res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                        return res.end(JSON.stringify({ error: messages.userMessages.userNotFound }));
                    }

                    const sessionToken = crypto.randomBytes(64).toString('hex');
                    const maxAge = SESSION_EXPIRY_MS / 1000; // Convert to seconds


                    const checkSessionSql = "SELECT * FROM Sessions WHERE userID = ?";
                    con.query(checkSessionSql, [user.userID], (err, sessionResult) => {
                        if (err) throw err;
                        const sessionSQL = sessionResult.length > 0
                            ? "UPDATE Sessions SET token = ? WHERE userID = ?"
                            : "INSERT INTO Sessions (token, userID) VALUES (?, ?)";
                        con.query(sessionSQL, [sessionToken, user.userID], (err) => {
                            if (err) throw err;

                            res.writeHead(200, {
                                'Set-Cookie': `token=${sessionToken}; HttpOnly; Max-Age=${maxAge};SameSite=None; Secure`,
                                'Content-Type': 'application/json',
                            });

                            incrementApiCounter(user.userID);

                            res.end(JSON.stringify({ message: messages.userMessages.userLogin, userID: user.userID }));
                        });
                    });
                });
            });
        });

    } else if (req.method === "GET" && q.pathname === "/api/v1/index") {
        getCounter++;
        let query = url.parse(req.url, true).query;
        let userID = query.userID;
        let error = null;
        incrementApiCounter(userID);

        const allowedOrigin = req.headers.origin;
        setCORSHeaders(res);

        res.setHeader('Content-Type', 'application/json');
        
        const token = req.headers.cookie?.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
            return res.end(JSON.stringify({ error: messages.userMessages.noToken }));
        }
        con.query("SELECT * FROM Sessions", (err, result) => {
            if (err) throw err;

            if (result.length === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.noSession }));
            }
        });

        const sessionSql = `
            SELECT Users.email, Users.role, Users.userID
            FROM Sessions   
            JOIN Users ON Sessions.userID = Users.userID
            WHERE Sessions.token = ?
        `;

        con.query(sessionSql, [token], (err, result) => {
            if (err) throw err;

            // console.log("Session result:", result);
            if (result.length === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.invalidToken }));
            }

            const session = result[0];
            const now = new Date();
            const createdAt = new Date(session.createdAt);
            const ageInMs = now - createdAt;

            // Invalidate if older than 1 minute (60,000 ms)
            if (ageInMs > SESSION_EXPIRY_MS) {

                con.query("DELETE FROM Sessions WHERE token = ?", [token], (err) => {
                    if (err) console.error("Failed to delete expired session:", err);
                });
                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.sessionExpired }));
            }

            const user = session;

            if (user.role === 'admin') {
                const allUsersSql = `
                    SELECT Users.userID, Users.email, Users.role, API.apiCounter
                    FROM Users
                    LEFT JOIN API ON Users.userID = API.userID
                `;

                con.query(allUsersSql, (err, allResults) => {
                    allResults = allResults.filter(user => user.role !== 'admin');
                    if (err) throw err;
                    
                    return res.end(JSON.stringify({
                        role: 'admin',
                        email: user.email,
                        userID: user.userID,
                        putCounter: putCounter,
                        postCounter: postCounter,
                        getCounter: getCounter,
                        deleteCounter: deleteCounter,
                        usersData: allResults
                    }));
                });

            } else {
                const userApiSql = `SELECT apiCounter FROM API WHERE userID = ?`;

                con.query(userApiSql, [user.userID], (err, apiResult) => {
                    if (err) throw err;

                    const apiCounter = apiResult.length > 0 ? apiResult[0].apiCounter : 0;

                    const userData = {
                        email: user.email,
                        role: user.role,
                        userID: user.userID,
                        apiCounter: apiCounter
                    };

                    return res.end(JSON.stringify(userData));
                });
            }
        });

    }
    else if (req.method === "DELETE" && q.pathname === "/api/v1/deleteUser") {
        deleteCounter++;

        setCORSHeaders(res);

        res.setHeader('Content-Type', 'application/json');

        let query = url.parse(req.url, true).query;
        let userID = query.userID;
        incrementApiCounter(userID);
        const token = req.headers.cookie?.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
            return res.end(JSON.stringify({ error: messages.userMessages.noToken }));
        }
        con.query("SELECT * FROM Sessions", (err, result) => {
            if (err) throw err;

            if (result.length === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.noSession }));
            }
        });

        const sessionSql = `
            SELECT Users.email, Users.role, Users.userID
            FROM Sessions   
            JOIN Users ON Sessions.userID = Users.userID
            WHERE Sessions.token = ?
        `;

        con.query(sessionSql, [token], (err, result) => {
            if (err) throw err;

            // console.log("Session result:", result);
            if (result.length === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.invalidToken }));
            }

            const session = result[0];
            const now = new Date();
            const createdAt = new Date(session.createdAt);
            const ageInMs = now - createdAt;

            // Invalidate if older than 1 minute (60,000 ms)
            if (ageInMs > SESSION_EXPIRY_MS) {

                con.query("DELETE FROM Sessions WHERE token = ?", [token], (err) => {
                    if (err) console.error("Failed to delete expired session:", err);
                });

                res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.sessionExpired }));
            }


            
                const userEmail = query.email;
                console.log("User ID:", userID);
                con.query("SELECT * FROM Users WHERE userID = ?", [userID], (err, result) => {
                    if (err) throw err;
                    console.log("User data:", result);
                    if (result.length === 0) return res.end(JSON.stringify({ error: messages.userMessages.userNotFound }));
                    if (result[0].role !== "admin"){
                        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                        return res.end(JSON.stringify({ error: messages.userMessages.notAuthorizedForDeleting }));
                    } 

                    const sql = "DELETE FROM Users WHERE email = ?";
                    con.query(sql, [userEmail], (err, result) => {

                        if (err) throw err;
                        console.log("Deleted user:", result);
                        if (result.affectedRows === 0){
                            res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                            return res.end(JSON.stringify({ error: messages.userMessages.userNotFound }));
                        } 
                        userEmails = userEmails.filter(email => email !== userEmail);
                        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net' , 'Access-Control-Allow-Credentials': 'true' });
                        res.end(JSON.stringify({ message: messages.userMessages.userDeleted }));
                    });
                });
            });
 
    } else if (req.method === "PUT" && q.pathname === "/api/v1/resetPassword") {
        console.log("Reset password request received");
        setCORSHeaders(res);
        res.setHeader('Content-Type', 'application/json');
        
        let query = url.parse(req.url, true).query;
        let userID = query.userID;
        putCounter++;
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            const { email } = JSON.parse(body);
            if (!email) {
                res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.EmailRequired }));
            }
        

        incrementApiCounter(userID);
        // Check if email exists
        con.query("SELECT * FROM Users WHERE email = ?", [email], (err, result) => {
            if (err) throw err;
            if (result.length === 0) {
                res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net', 'Access-Control-Allow-Credentials': 'true' });
                return res.end(JSON.stringify({ error: messages.userMessages.userNotFound }));
            }

            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 3600000); // 1 hour expiry

            con.query("INSERT INTO ResetTokens (email, token, expiresAt) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token=?, expiresAt=?",
                [email, token, expiresAt, token, expiresAt], (err) => {
                    if (err) throw err;

                    // Send Mailjet email

                    const resetUrl = `https://nice-flower-0dc97321e.6.azurestaticapps.net/reset.html?token=${token}&email=${encodeURIComponent(email)}`;

                    const request = mailjet.post("send", { 'version': 'v3.1' }).request({
                        "Messages": [{
                            "From": { "Email": "saba.karbakhsh@gmail.com", "Name": "COMP4537" },
                            "To": [{ "Email": email }],
                            "Subject": "Password Reset Request",
                            "TextPart": `Click this link to reset your password: ${resetUrl}`,
                            "HTMLPart": `<h3>Password Reset</h3><p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`
                        }]
                    });

                    request
                        .then(result => {
                            res.end(JSON.stringify({ message: messages.userMessages.emailSent }));
                        })
                        .catch(err => {

                            res.end(JSON.stringify({ error: messages.userMessages.emailNotSent }));
                        });
                });
            
        });
    });
    
    } else if (req.method === "PUT" && q.pathname === "/api/v1/updatePassword") {
        setCORSHeaders(res);

        
        res.setHeader('Content-Type', 'application/json');
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            const { email, token, newPassword } = JSON.parse(body);
            con.query("SELECT * FROM Users WHERE email = ?", [email], (err, result) => {
                if (err) throw err;
                userID = result[0].userID;
                incrementApiCounter(userID);
                if (!email || !token || !newPassword) {
                    res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net' })
                    return res.end(JSON.stringify({ error: messages.userMessages.invalidReq }));
                }

                con.query("SELECT * FROM ResetTokens WHERE email = ? AND token = ?", [email, token], (err, result) => {
                    if (err) throw err;
                    if (result.length === 0 || new Date(result[0].expiresAt) < new Date()) {
                        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': 'https://nice-flower-0dc97321e.6.azurestaticapps.net' })
                        return res.end(JSON.stringify({ error: messages.userMessages.invalidToken }));
                    }

                    // Hash new password
                    const salt = crypto.randomBytes(16).toString('hex');
                    const hashedPassword = crypto.pbkdf2Sync(newPassword, salt, 100000, 64, 'sha512').toString('hex');

                    con.query("UPDATE Users SET password = ?, salt = ? WHERE email = ?", [hashedPassword, salt, email], (err) => {
                        if (err) throw err;

                        con.query("DELETE FROM ResetTokens WHERE email = ?", [email]);
                        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin':'https://nice-flower-0dc97321e.6.azurestaticapps.net' });
                        res.end(JSON.stringify({ message: messages.userMessages.passwordUpdated }));
                    });
                });
            });
        });

    } else if (req.method === "DELETE" && q.pathname === "/api/v1/logout") {
        res.setHeader('Set-Cookie', 'token=; HttpOnly; Max-Age=0; SameSite=None; Secure');
        setCORSHeaders(res);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: messages.userMessages.logout }));
    }

}).listen(8080);


function incrementApiCounter(userID) {
    con.query("UPDATE API SET apiCounter = apiCounter + 1 WHERE userID = ?", [userID], (err, result) => {
        if (err) throw err;
    });
}

function setCORSHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', 'https://nice-flower-0dc97321e.6.azurestaticapps.net');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, bypass-tunnel-reminder');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
}
