import express from "express";
import cors from "cors";
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
    const {data: insertData, error: insertError} = await supabase.from("Accounts").insert({UUID : userData.user.id, username: username})
    if (insertError) {return res.json({ status: "error", message: insertError.message });}
    return res.json({ status: "success", message: "Account created successfully" });
    
});

app.post("/user/login", async (req, res) => {
    const {email, password} = req.body
    const {data: tokenData, error: tokenError} = await supabase.auth.signInWithPassword({email, password})
    if(tokenError) return res.json({status: "error", message: "Invalid token"})
    const user = await supabase.from("Accounts").select("*").eq("UUID", tokenData.user.uuid)
    return res.json({status: "success", user: {uuid: user.data[0].UUID, email: email, username: user.data[0].username}, token: tokenData.session.access_token})
})

app.post("/user/verify", async (req, res) => {
    const {email , token} = req.body
    const {data: VerifyOtpData, error: VerifyOtpError} = await supabase.auth.verifyOtp({email : email, token : token, type : "signup"})
    if(VerifyOtpError) return res.json({status: "error", message: "Invalid token"})
    return res.json({status: "success", message: "Account verified successfully"})
})

app.post("/user/check", async (req, res) => {
    const {UUID} = req.body
    const {data: userData, error: userError} = await supabase.auth.admin.getUserById(UUID)
    if (userError) {return res.json({status: "error", message: userError.message})}
    if (userData.user?.email_confirmed_at) {return res.json({status: "success", message: "Email is verified"})}
    else {return res.json({status: "error", message: "Email is not verified"})}
})

export default app;