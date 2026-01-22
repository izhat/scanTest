/**
 * Intentionally vulnerable sample for testing GitHub security scanning.
 * DO NOT deploy. Use only in a private repo for tooling validation.
 */

const express = require("express");
const crypto = require("crypto");
const child_process = require("child_process");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- 1) Hardcoded secret (Secret Scanning should flag this) ---
const STRIPE_API_KEY = "sk_test_51HARD_CODED_EXAMPLE_KEY_DO_NOT_USE";

// --- 2) Weak / insecure crypto (CodeQL may flag md5 for passwords) ---
function weakHashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// --- 3) In-memory SQLite DB for demo ---
const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)");
  db.run("INSERT INTO users (username, password_hash) VALUES ('admin', ?)", [
    weakHashPassword("admin123"),
  ]);
});

// --- 4) Reflected XSS pattern (unsafely reflecting user input into HTML) ---
app.get("/hello", (req, res) => {
  const name = req.query.name || "friend";
  // Intentionally unsafe: no output encoding
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<h1>Hello ${name}</h1>`);
});

// --- 5) SQL Injection pattern (string concatenation in query) ---
app.get("/user", (req, res) => {
  const username = req.query.username || "";
  const sql = "SELECT id, username FROM users WHERE username = '" + username + "'"; // intentionally unsafe
  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: "db error" });
    res.json({ rows });
  });
});

// --- 6) Command injection pattern (building shell command from input) ---
app.get("/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  // Intentionally unsafe: shell=true and user-controlled input
  child_process.exec(`ping -c 1 ${host}`, { timeout: 2000 }, (err, stdout, stderr) => {
    res.type("text/plain").send(stdout || stderr || String(err));
  });
});

// --- 7) Dangerous eval (code injection / arbitrary code execution risk) ---
app.post("/calc", (req, res) => {
  const expr = String(req.body.expr || "");
  // Intentionally unsafe: NEVER eval user input
  const result = eval(expr);
  res.json({ result });
});

// --- 8) Insecure authentication example (no rate limit; trivial comparison) ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const pwHash = weakHashPassword(String(password || ""));
  db.get(
    "SELECT id, username FROM users WHERE username = ? AND password_hash = ?",
    [String(username || ""), pwHash],
    (err, row) => {
      if (row) return res.json({ ok: true, user: row });
      return res.status(401).json({ ok: false });
    }
  );
});

// --- 9) Missing security headers (Helmet not used) ---
app.get("/", (req, res) => res.send("Vulnerable demo app (for scanning only)."));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on http://localhost:${port}`));
