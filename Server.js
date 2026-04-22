import express from "express";
import cors from "cors";
import bcrypt from "bcrypt"
import blacklist from "the-big-username-blacklist"
import supabase from "./Supabase.js";

const allowedOrigins = [
    "http://localhost:5173",
    "https://lunarisvps.vercel.app"
]

const app = express();
app.use(cors({origin: allowedOrigins}));
app.use(express.json()); 

app.get("/", (req, res) => {
    res.send({status: "online"});
});



app.post("/user/create", async (req, res) => {
  const { username, email, password } = req.body

  const HashedPass = bcrypt.hashSync(password, 15)
  const EmailPrefix = email.split("@")[0]

  // check duplicates
  const { data: emailData } = await supabase.from("Accounts").select("*").eq("email", email)
  if (emailData.length > 0) return res.json({ status: "error", message: "Email is already in use" })

  const { data: usernameData } = await supabase.from("Accounts").select("*").eq("username", username)
  if (usernameData.length > 0) return res.json({ status: "error", message: "Username is already in use" })

  // validation
  if (blacklist.validate(EmailPrefix)) return res.json({ status: "error", message: "Email is not allowed" })
  if (blacklist.validate(username)) return res.json({ status: "error", message: "Username is not allowed" })

  // create auth user
  const { data: SuData, error: SuError } = await supabase.auth.signUp({ email, password })
  if (SuError) return res.json({ status: "error", message: SuError.message })

  // insert account row using the uuid from auth
  const { error: AcError } = await supabase.from("Accounts").insert({
    username,
    email,
    password: HashedPass,
    UUID: SuData.user.id  // use the auth uuid
  })

  if (AcError) return res.json({ status: "error", message: AcError.message })

  return res.json({ status: "success", message: "Account created successfully" })
})

app.post("/user/login", (req, res) => {
    const {email, password} = req.body
    const user = supabase.from("Accounts").select("*").eq("email", email)
    if(user.data.length === 0) return res.json({status: "error", message: "Invalid email or password"})
    const validPass = bcrypt.compareSync(password, user.data[0].password)
    if(!validPass) return res.json({status: "error", message: "Invalid email or password"})
    const {data: tokenData, error: tokenError} = supabase.auth.signInWithPassword({email, password})
    if(tokenError) return res.json({status: "error", message: "An error occurred while logging in"})
    return res.json({status: "success", user: {uuid: user.data[0].uuid, email: user.data[0].email, username: user.data[0].username}, token: tokenData.session.access_token})
    
})