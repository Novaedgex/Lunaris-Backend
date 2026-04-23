import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import supabase from "./Supabase.js";

const allowedOrigins = [
    "http://localhost:5173",
    "https://lunarisvps.vercel.app"
];

const app = express();

// Use a function for CORS to be more resilient with Vercel's edge
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());

app.get("/", (req, res) => {
    res.send({ status: "online" });
});

app.post("/user/create", async (req, res) => {
    const { username, email, password } = req.body;
    const BlackList = ["admin", "root", "support", "help", "contact", "info", "sysadmin", "administrator", "hostmaster", "webmaster", "postmaster", "abuse", "security", "ssladmin", "ssladministrator", "sslwebmaster"];
    if (BlackList.includes(username.toLowerCase())) {return res.json({ status: "error", message: "Username is not allowed" });}
    const {data: userData, error: userError} = await supabase.auth.signUp({email, password})
    if (userError) {return res.json({ status: "error", message: userError.message });}
    const {data: insertData, error: insertError} = await supabase.from("Accounts").insert({uuid: userData.user.id, username})
    if (insertError) {return res.json({ status: "error", message: insertError.message });}
    return res.json({ status: "success", message: "Account created successfully" });
    
});

app.post("/user/login", async (req, res) => {
    const {email, password} = req.body
    const {data: tokenData, error: tokenError} = await supabase.auth.signInWithPassword({email, password})
    if(tokenError) return res.json({status: "error", message: "Invalid token"})
    const user = await supabase.from("Accounts").select("*").eq("UUID", tokenData.user.id)
    return res.json({status: "success", user: {uuid: user.data[0].uuid, email: email, username: user.data[0].username}, token: tokenData.session.access_token})
})

app.post("/user/verify", async (req, res) => {
    const {email, password} = req.body
    const {data: tokenData, error: tokenError} = await supabase.auth.signInWithPassword({email, password})
    if(tokenError) return res.json({status: "error", message: "Invalid token"})
    const user = await supabase.from("Accounts").select("*").eq("UUID", tokenData.user.id)
    return res.json({status: "success", user: {uuid: user.data[0].uuid, email: email, username: user.data[0].username}, token: tokenData.session.access_token})

    
})

export default app;