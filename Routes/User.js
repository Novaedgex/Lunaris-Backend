import express from 'express';
import supabase from '../lib/Supabase.js';
const router = express.Router();

const BLACKLIST = ["admin", "root", "support", "help", "contact", "info", "sysadmin", "administrator", "hostmaster", "webmaster", "postmaster", "abuse", "security", "ssladmin", "ssladministrator", "sslwebmaster"];

const validateInput = (email, password, username = null) => {
    if (!email || !password) {
        return "Email and password are required";
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return "Invalid email format";
    }
    if (password.length < 8) {
        return "Password must be at least 8 characters";
    }
    if (username && username.length < 3) {
        return "Username must be at least 3 characters";
    }
    return null;
};

router.post("/create", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validation
        const validationError = validateInput(email, password, username);
        if (validationError) {
            return res.status(400).json({ status: "error", message: validationError });
        }

        if (BLACKLIST.includes(username.toLowerCase())) {
            return res.status(400).json({ status: "error", message: "Username is not allowed" });
        }

        // Sign up
        const { data: userData, error: userError } = await supabase.auth.signUp({ email, password });
        if (userError) {
            return res.status(400).json({ status: "error", message: userError.message });
        }

        // Insert into database
        const { data: insertData, error: insertError } = await supabase
            .from("Accounts")
            .insert({ UUID: userData.user.id, username: username });
        
        if (insertError) {
            // If insert fails, delete the auth user to keep things consistent
            await supabase.auth.admin.deleteUser(userData.user.id);
            return res.status(400).json({ status: "error", message: insertError.message });
        }

        return res.status(201).json({ status: "success", message: "Account created successfully" });
    } catch (error) {
        console.error("Create account error:", error);
        return res.status(500).json({ status: "error", message: "Server error" });
    }
}); 

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const validationError = validateInput(email, password);
        if (validationError) {
            return res.status(400).json({ status: "error", message: validationError });
        }

        const { data: tokenData, error: tokenError } = await supabase.auth.signInWithPassword({ email, password });
        if (tokenError) {
            return res.status(401).json({ status: "error", message: tokenError.message });
        }

        const { data: userData, error: userError } = await supabase
            .from("Accounts")
            .select("username, type, balance, reputation")
            .eq("UUID", tokenData.user.id)
            .single();

        if (userError || !userData) {
            return res.status(404).json({ status: "error", message: "User account not found" });
        }

        return res.json({
            status: "success",
            user: {
                uuid: tokenData.user.id,
                email: email,
                username: userData.username,
                type: userData.type,
                balance: userData.balance,
                reputation: userData.reputation,
            },
            token: tokenData.session.access_token
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ status: "error", message: "Server error" });
    }
});

router.post("/verify", async (req, res) => {
    try {
        const { email, token } = req.body;

        if (!email || !token) {
            return res.status(400).json({ status: "error", message: "Email and token are required" });
        }

        const { data: verifyData, error: verifyError } = await supabase.auth.verifyOtp({
            email: email,
            token: token,
            type: "signup"
        });

        if (verifyError) {
            return res.status(400).json({ status: "error", message: "Invalid or expired token" });
        }

        return res.json({ status: "success", message: "Account verified successfully" });
    } catch (error) {
        console.error("Verify error:", error);
        return res.status(500).json({ status: "error", message: "Server error" });
    }
});

router.post("/password-reset", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ status: "error", message: "Valid email is required" });
        }

        const { data: resetData, error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: "https://lunarisvps.vercel.app/reset-password"
        });

        if (resetError) {
            return res.status(400).json({ status: "error", message: resetError.message });
        }

        // Don't reveal if email exists or not (security best practice)
        return res.json({ status: "success", message: "If the email exists, a reset link has been sent" });
    } catch (error) {
        console.error("Password reset error:", error);
        return res.status(500).json({ status: "error", message: "Server error" });
    }
});

export default router;