const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const snarkjs = require("snarkjs");
const cors = require('cors');

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const vkey = require('./verification_key_register_new.json');  // The verification key generated during the setup
const vkeyLogin = require('./verification_key_login_new.json');  // The verification key generated during the setup
const vkeyChangePass = require('./verification_key_change_pass.json');  // The verification key generated during the setup
const NodeCache = require("node-cache");

const nonceCache = new NodeCache();
const NONCE_CACHE_TTL = 5; // sec
var nonce = 0;

const app = express();
const PORT = 3000;
app.use(cors());

// Middleware
app.use(bodyParser.json());

// JWT Secret
const JWT_SECRET = "f0234klfa1jdkf098adsfmasdf,2138asdf08adf"; 
const JWT_SECRET_TMP = "fjl908asdkfnmaf454fasdf98ashjdfjkasdfhjkasdfnamsas.fiasdfj.,2138asdf08adf"; 

// MySQL Database Connection
const db = mysql.createConnection({
    host: "192.168.1.111",
    user: "root", // Replace with your MySQL username
    password: "sa123456", // Replace with your MySQL password
    database: "zkp",
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error("Error connecting to MySQL:", err.message);
        process.exit(1);
    } else {
        console.log("Connected to MySQL database.");
    }
});

function validateUsername(username, minLength = 5, maxLength = 20){
    const regex = /^[a-zA-Z0-9]+$/;
    if (username.length < minLength) {
        return false;
    } else if (username.length > maxLength) {
        return false;
    } else if(!regex.test(username)){
        return false;
    } else {
        return true;
    }
}

function queryAsync(sql, params) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
}

// Register Endpoint
app.post("/register", async (req, res) => {
    const { username, proof, hashedPassword } = req.body;

    console.log(req.body);

    if (!username || !proof || !hashedPassword) {
        return res.status(400).json({ message: "Username, proof and hashedPassword are required." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length > 0) {
            return res.status(400).json({ message: "Username already exists." });
        }
        console.log({vkey, hashedPassword, proof});
        const result = await snarkjs.groth16.verify(vkey, hashedPassword, proof);
        if (result === true) {
            console.log("Proof is valid!");
            await queryAsync("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
            res.status(201).json({ message: "User registered successfully." });
        } else {
            console.log("Proof is not valid.");
            return res.status(400).json({ message: "Proof is not valid." });
        }
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Login Endpoint
app.post("/login", async (req, res) => {
    const { username, proof, public } = req.body;

    console.log("Receive login request: " + {username, proof, public});
    console.log(username);
    console.log(proof);
    console.log(public);

    if (!username || !proof || !public) {
        return res.status(400).json({ message: "Username, proof and public are required." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        const user = results[0];
        let userNonce = nonceCache.get(username) ?? 0;
        const publicSignals = [user.password, public, userNonce];
        console.log(publicSignals);

        const result = await snarkjs.groth16.verify(vkeyLogin, publicSignals, proof);
        if (!result) {
            return res.status(400).json({ message: "Invalid proof." });
        }
        nonceCache.del(username);
        if(user.enable_fa2 === 1){
            const token = jwt.sign({ username: user.username }, JWT_SECRET_TMP, { expiresIn: "1m" });
            res.status(209).json({ message: "2 factor authentication required", token});
        } else {
            const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
            res.status(200).json({ message: "Login successful.", token });
        }
    } catch(err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});


// Get nonce Endpoint
app.post("/get-nonce", async (req, res) => {
    const { username } = req.body;

    console.log("Receive get-nonce request");

    if (!username) {
        return res.status(400).json({ message: "Username are required." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        nonce = (nonce + 1000000001) % 1000000000;
        nonceCache.set(username, nonce, NONCE_CACHE_TTL);
        res.status(200).json({ nonce });
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Change pass endpoint
app.post("/change-pass", async (req, res) => {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }
    let username = "";
    try {
        const user = jwt.verify(token, JWT_SECRET);
        username = user.username;
    } catch (err) {
        return res.status(403).json({ message: "Invalid token." });
    }

    const { proof, hashedPassword } = req.body;

    console.log("Receive change pass request: " + {proof, hashedPassword});

    if (!proof || !hashedPassword) {
        return res.status(400).json({ message: "Proof and hashedPassword are required." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        const user = results[0];
        const publicSignals = [user.password, hashedPassword];
        console.log(publicSignals);
        const result = await snarkjs.groth16.verify(vkeyChangePass, publicSignals, proof);
        if (!result) {
            return res.status(400).json({ message: "Invalid proof." });
        }
        await queryAsync("UPDATE users SET password = ? WHERE username = ?", [hashedPassword, username]);
        res.status(200).json({ message: "Password change successful."});
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});


app.post('/enable-2fa', async (req, res) => {
    console.log("Receive enable 2FA request");
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }
    let username = "";
    try {
        const user = jwt.verify(token, JWT_SECRET);
        username = user.username;
    } catch (err) {
        return res.status(403).json({ message: "Invalid token." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }

        const user = results[0];
        if(user.enable_fa2 === 1){
            console.log("FA2 has been enabled");
            return res.status(210).json({ message: "FA2 has been enabled." });
        }

        const secret = speakeasy.generateSecret({ name: "Crypto.ZKP" });
        await queryAsync("UPDATE users SET fa2_secret = ? WHERE username = ?", [secret.base32, username]);

        QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
            if (err) {
                return res.status(500).json({ message: "Error generating QR code" });
            }
            res.status(200).json({message: "2FA enabled successfully", qrCode: data_url});
        });    
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.post('/disable-2fa', async (req, res) => {
    console.log("Receive disable 2FA request");
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }
    let username = "";
    try {
        const user = jwt.verify(token, JWT_SECRET);
        username = user.username;
    } catch (err) {
        return res.status(403).json({ message: "Invalid token." });
    }


    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        const user = results[0];
        if(user.enable_fa2 !== 1){
            console.log("2FA is not enabled");
            return res.status(210).json({ message: "2FA is not enabled." });
        }
        await queryAsync("UPDATE users SET enable_fa2 = 0 WHERE username = ?", [username]);
        res.status(200).json({message: "2FA disabled successfully"});
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.post('/verify-2fa', async (req, res) => {
    console.log("Receive verify 2FA request");
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }
    let username = "";
    try {
        const user = jwt.verify(token, JWT_SECRET);
        username = user.username;
    } catch (err) {
        return res.status(403).json({ message: "Invalid token." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }
    
    const { pin } = req.body;

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        const user = results[0];
        if(user.enable_fa2 === 1){
            return res.status(210).json({ message: "FA2 has been enabled." });
        }
        const verified = speakeasy.totp.verify({
            secret: user.fa2_secret,
            encoding: 'base32',
            token: pin,
        });

        if (verified) {
            await queryAsync("UPDATE users SET enable_fa2 = 1 WHERE username = ?", [username]);
            res.status(200).json({ message: "2FA verification successful" });
        } else {
            res.status(402).json({ message: "Invalid 2FA pin" });
        }
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

app.post('/login/verify-2fa', async (req, res) => {
    console.log("Receive verify login 2FA request");
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Token required." });
    }
    let username = "";

    try {
        const user = jwt.verify(token, JWT_SECRET_TMP);
        username = user.username;
    } catch (err) {
        return res.status(403).json({ message: "Invalid token." });
    }

    if(!validateUsername(username)){
        return res.status(400).json({ message: "Username is not valid." });
    }
    
    const { pin } = req.body;

    try {
        let results = await queryAsync("SELECT * FROM users WHERE username = ?", [username]);
        if (results.length === 0) {
            return res.status(400).json({ message: "Invalid username." });
        }
        const user = results[0];
        if(user.enable_fa2 !== 1){
            return res.status(400).json({ message: "Account does not have 2-step verification enabled." });
        }
        const verified = speakeasy.totp.verify({
            secret: user.fa2_secret,
            encoding: 'base32',
            token: pin,
        });
        if (verified) {
            const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
            res.status(200).json({ message: "Login successful.", token });
        } else {
            res.status(402).json({ message: "Invalid 2FA pin" });
        }
    } catch (err){
        console.log(err);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Protected Endpoint
app.get("/protected", (req, res) => {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Invalid token." });
        }

        res.status(200).json({ message: `Hello, ${user.username}. Welcome to the protected route!` });
    });
});

// Start Server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
