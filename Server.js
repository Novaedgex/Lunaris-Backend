import express from "express";
import cors from "cors";
import bcrypt from "bcrypt"
import crypto from "crypto"
import Database from "better-sqlite3";
import os from "os";
import blacklist from "the-big-username-blacklist"

const db = new Database("./Lunaris.db");

const allowedOrigins = [
    "http://localhost:5173",
    "https://lunarisvps.vercel.app"
]

const app = express();
app.use(cors({origin: allowedOrigins}));
app.use(express.json()); 

app.post("/user/create", (req, res) => {
    const {username, email, password} = req.body
    const HashedPass = bcrypt.hashSync(password, 15)
    const uuid = crypto.randomUUID()
    const EmailPrefix = email.split("@")[0]
    // Check if email or username is already in use
    const checkEmail = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    const checkUsername = db.prepare("SELECT * FROM users WHERE username = ?").get(username)
    // Validation checks
    if(blacklist.validate(EmailPrefix)) return res.json({status: "error", message: "Email is not allowed"})
    if(checkEmail) return res.json({status: "error", message: "Email already in use"})
    if(checkUsername) return res.json({status: "error", message: "Username already in use"})
    if(blacklist.validate(username)) return res.json({status: "error", message: "Username is not allowed"})

    db.prepare("INSERT INTO users (uuid, username, email, password) VALUES (?, ?, ?, ?)").run(uuid, username, email, HashedPass)
    return res.json({status: "success", user: {uuid, username, email}})
})

app.post("/user/login", (req, res) => {
    const {email, password} = req.body
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    if(!user) return res.json({status: "error", message: "Invalid email or password"})
    const isValidPass = bcrypt.compareSync(password, user.password)
    if(!isValidPass) return res.json({status: "error", message: "Invalid email or password"})
    return res.json({status: "success", user: {uuid: user.uuid, username: user.username, email: user.email}})
})