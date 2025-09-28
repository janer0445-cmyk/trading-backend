const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

// --- Database connection ---
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// --- Root route (so Render doesn’t show “Cannot GET /”) ---
app.get("/", (req, res) => {
  res.send("✅ Trading Backend is running! Use /signup, /login, /balance, /deposit, /withdraw");
});

// --- Signup ---
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      "INSERT INTO users (email, password, balance) VALUES ($1, $2, $3) RETURNING id",
      [email, hashedPassword, 1000] // default balance
    );
    res.json({ message: "User created", userId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });
  const user = result.rows[0];

  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ message: "Login successful", token });
});

// --- Balance ---
app.get("/balance", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query("SELECT balance FROM users WHERE id=$1", [decoded.id]);
    res.json({ balance: result.rows[0].balance });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// --- Deposit ---
app.post("/deposit", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { amount } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await pool.query("UPDATE users SET balance = balance + $1 WHERE id=$2", [amount, decoded.id]);
    res.json({ message: "Deposit successful" });
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
});

// --- Withdraw ---
app.post("/withdraw", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const { amount } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await pool.query("UPDATE users SET balance = balance - $1 WHERE id=$2", [amount, decoded.id]);
    res.json({ message: "Withdraw successful" });
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Trading backend running on port ${PORT} 🚀`);
});
