import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import authRoutes from "./routes/auth.js";
import cors from "cors";

dotenv.config();

const app = express();
connectDB();

app.use(cors({ origin: "*" }));
// Middleware
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
