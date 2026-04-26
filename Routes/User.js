import express from 'express';
import supabase from '../Supabase';
const router = express.Router();

router.post("/create", async (req, res) => {
    const { username, email, password } = req.body;
    const BlackList = ["admin", "root", "support", "help", "contact", "info", "sysadmin", "administrator", "hostmaster", "webmaster", "postmaster", "abuse", "security", "ssladmin", "ssladministrator", "sslwebmaster"];
    if (BlackList.includes(username.toLowerCase())) {return res.json({ status: "error", message: "Username is not allowed" });}
    const {data: userData, error: userError} = await supabase.auth.signUp({email, password})
    if (userError) {return res.json({ status: "error", message: userError.message });}
    const {data: insertData, error: insertError} = await supabase.from("Accounts").insert({UUID : userData.user.id, username: username})
    if (insertError) {return res.json({ status: "error", message: insertError.message });}
    return res.json({ status: "success", message: "Account created successfully" });
    
});

router.post("/login", async (req, res) => {
    const {email, password} = req.body
    const {data: tokenData, error: tokenError} = await supabase.auth.signInWithPassword({email, password})
    if(tokenError) return res.json({status: "error", message: tokenError.message})
    const user = await supabase.from("Accounts").select("*").eq("UUID", tokenData.user.id)
    return res.json({status: "success", user: {uuid: tokenData.user.id, email: email, username: user.data[0].username, type: user.data[0].type}, token: tokenData.session.access_token})
})

router.post("/verify", async (req, res) => {
    const {email , token} = req.body
    const {data: VerifyOtpData, error: VerifyOtpError} = await supabase.auth.verifyOtp({email : email, token : token, type : "signup"})
    if(VerifyOtpError) return res.json({status: "error", message: "Invalid token"})
    return res.json({status: "success", message: "Account verified successfully"})
})

router.post("/password-reset", async (req, res) => {
    const {email} = req.body
    const {data: resetData, error: resetError} = await supabase.auth.resetPasswordForEmail(email, {redirectTo: "https://lunarisvps.vercel.app/reset-password"})
    if(resetError) return res.json({status: "error", message: resetError.message})
    return res.json({status: "success", message: "Password reset email sent successfully"})
})

export default router;