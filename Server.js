import express from "express";
import cors from "cors";
import supabase from "./Supabase.js";
import userRoutes from "./Routes/User.js";
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
app.use("/user", userRoutes);
app.use(express.json());

app.get("/", (req, res) => {
    res.send({ status: "online" });
});



export default app;