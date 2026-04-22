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

    // Use a slightly lower salt round (10-12) for serverless performance
    const HashedPass = bcrypt.hashSync(password, 10);
    const EmailPrefix = email.split("@")[0];
    const BlackList = ["admin", "root", "support", "help", "contact", "info", "sysadmin", "administrator", "hostmaster", "webmaster", "postmaster", "abuse", "security", "ssladmin", "ssladministrator", "sslwebmaster"];

    // 1. Validation logic
    for (const word of BlackList) {
        if (username.toLowerCase().includes(word)) {
            return res.json({ status: "error", message: "Username cannot contain reserved words" });
        }
        if (EmailPrefix.toLowerCase().includes(word)) {
            return res.json({ status: "error", message: "Email prefix cannot contain reserved words" });
        }
    }

    // 2. Check duplicates (Supabase returns {data, error})
    const { data: emailData } = await supabase.from("Accounts").select("*").eq("email", email);
    if (emailData && emailData.length > 0) return res.json({ status: "error", message: "Email is already in use" });

    const { data: usernameData } = await supabase.from("Accounts").select("*").eq("username", username);
    if (usernameData && usernameData.length > 0) return res.json({ status: "error", message: "Username is already in use" });

    // 3. Create auth user
    const { data: SuData, error: SuError } = await supabase.auth.signUp({ email, password });
    if (SuError) return res.json({ status: "error", message: SuError.message });

    // 4. Insert account row
    const { error: AcError } = await supabase.from("Accounts").insert({
        username,
        email,
        password: HashedPass,
        UUID: SuData.user.id 
    });

    if (AcError) return res.json({ status: "error", message: AcError.message });

    return res.json({ status: "success", message: "Account created successfully" });
});

app.post("/user/login", async (req, res) => {
    const { email, password } = req.body;

    // FIX: Must use 'await' and destructure { data }
    const { data: userData, error: userError } = await supabase.from("Accounts").select("*").eq("email", email);
    
    if (userError || !userData || userData.length === 0) {
        return res.json({ status: "error", message: "Invalid email or password" });
    }

    const user = userData[0];

    // FIX: bcrypt.compareSync requires a string password
    const validPass = bcrypt.compareSync(password, user.password);
    if (!validPass) return res.json({ status: "error", message: "Invalid email or password" });

    // FIX: Must use 'await' for sign in
    const { data: tokenData, error: tokenError } = await supabase.auth.signInWithPassword({ email, password });
    
    if (tokenError) return res.json({ status: "error", message: "An error occurred while logging in" });

    return res.json({ 
        status: "success", 
        user: { uuid: user.UUID, email: user.email, username: user.username }, 
        token: tokenData.session.access_token 
    });
});

export default app;