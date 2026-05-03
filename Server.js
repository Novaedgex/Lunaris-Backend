import express from "express";
import cors from "cors";
import userRoutes from "./Routes/User.js";
import itemRouter from "./Routes/Items.js"

// const port = 3000;
const allowedOrigins = [
    "http://localhost:5173",
    "https://lunarisvps.vercel.app"
];

const app = express();

// Middleware order matters! Parse JSON FIRST
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data too

// Then CORS
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

// Then routes
app.use("/user", userRoutes);
app.use("/item", itemRouter)

app.get("/", (req, res) => {
    res.json({ status: "online" }); // Use .json() for consistency
});

// app.listen(port, () => {
//     console.log(`API listening at http://localhost:${port}`);
// });

export default app;