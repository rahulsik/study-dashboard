require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");

const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_FILE || "study.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, pass TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS otps(id TEXT PRIMARY KEY, code TEXT NOT NULL, pass TEXT NOT NULL, exp INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, user TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, subject TEXT NOT NULL, minutes INTEGER NOT NULL, day TEXT NOT NULL);
`);

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const isGmail = (s) => /^[a-z0-9._%+-]+@gmail\.com$/.test(s);
const isPhone = (s) => /^[6-9]\d{9}$/.test(s);
function norm(v) {
  v = String(v || "").trim().toLowerCase();
  const d = v.replace(/[\s-]/g, "");
  if (isPhone(d)) return d;
  const m = d.match(/^(?:\+91|91)([6-9]\d{9})$/);
  return m ? m[1] : v;
}

// Simple in-memory rate limiter
const hits = new Map();
function limit(key, max, ms) {
  const now = Date.now();
  const a = (hits.get(key) || []).filter((t) => now - t < ms);
  if (a.length >= max) return false;
  a.push(now);
  hits.set(key, a);
  return true;
}

// OTP sending: Gmail -> email (SMTP), number -> SMS (Twilio).
// Agar keys nahi hain to OTP server console mein print hota hai (test ke liye).
const mailer = process.env.SMTP_USER
  ? nodemailer.createTransport({ service: "gmail", auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } })
  : null;

async function sendOtp(id, code) {
  const text = `Study Dashboard OTP: ${code}. Ye 10 minute mein expire ho jayega.`;
  if (isGmail(id)) {
    if (process.env.MAIL_URL) {
      // Google Apps Script ke raaste email (HTTPS, free hosting par bhi chalta hai)
      const r = await fetch(process.env.MAIL_URL, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({ key: process.env.MAIL_KEY, to: id, subject: "Study Dashboard OTP", text }),
      });
      const t = (await r.text()).trim();
      if (t !== "ok") throw new Error("Mail script ne ok nahi diya: " + t.slice(0, 80));
      return;
    }
    if (!mailer) return console.log(`[TEST] OTP for ${id}: ${code}`);
    await mailer.sendMail({ from: process.env.SMTP_USER, to: id, subject: "Study Dashboard OTP", text });
  } else {
    const { TWILIO_SID: sid, TWILIO_TOKEN: tok, TWILIO_FROM: from } = process.env;
    if (!sid) return console.log(`[TEST] OTP for ${id}: ${code}`);
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: "POST",
      headers: {
        Authorization: "Basic " + Buffer.from(sid + ":" + tok).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ To: "+91" + id, From: from, Body: text }),
    });
    if (!r.ok) throw new Error("SMS failed: " + r.status);
  }
}

// Login session cookie
function getToken(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)sd=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
function startSession(res, user) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO tokens VALUES(?,?,?)").run(token, user, Date.now() + 30 * 864e5);
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `sd=${token}; HttpOnly; Path=/; Max-Age=${30 * 86400}; SameSite=Lax${secure}`);
}
function auth(req, res, next) {
  const t = getToken(req);
  const row = t && db.prepare("SELECT user FROM tokens WHERE token=? AND exp>?").get(t, Date.now());
  if (!row) return res.status(401).json({ error: "Pehle login karo." });
  req.user = row.user;
  req.token = t;
  next();
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.post("/api/signup/start", async (req, res) => {
  const id = norm(req.body.id);
  const pw = String(req.body.password || "");
  if (!isGmail(id) && !isPhone(id)) return res.status(400).json({ error: "Sirf Gmail ya 10 digit mobile number chalega." });
  if (pw.length < 6) return res.status(400).json({ error: "Password kam se kam 6 akshar ka rakho." });
  if (db.prepare("SELECT 1 FROM users WHERE id=?").get(id)) return res.status(409).json({ error: "Is Gmail ya number se account pehle se hai. Login karo." });
  if (!limit("otp:" + id, 3, 3600e3) || !limit("ip:" + req.ip, 20, 3600e3))
    return res.status(429).json({ error: "Bahut baar try kiya. Thodi der baad dobara karo." });
  const code = String(crypto.randomInt(100000, 1000000));
  db.prepare("REPLACE INTO otps VALUES(?,?,?,?,0)").run(id, sha(code), bcrypt.hashSync(pw, 10), Date.now() + 600e3);
  try {
    await sendOtp(id, code);
  } catch (e) {
    console.error(e.message);
    return res.status(502).json({ error: "OTP bhej nahi paye. Thodi der baad try karo." });
  }
  res.json({ ok: true });
});

app.post("/api/signup/verify", (req, res) => {
  const id = norm(req.body.id);
  const code = String(req.body.otp || "").trim();
  const row = db.prepare("SELECT * FROM otps WHERE id=?").get(id);
  if (!row || row.exp < Date.now()) return res.status(400).json({ error: "OTP expire ho gaya. Dobara bhejo." });
  if (row.tries >= 5) {
    db.prepare("DELETE FROM otps WHERE id=?").run(id);
    return res.status(429).json({ error: "Bahut galat OTP. Naya OTP mangao." });
  }
  if (sha(code) !== row.code) {
    db.prepare("UPDATE otps SET tries=tries+1 WHERE id=?").run(id);
    return res.status(400).json({ error: "OTP galat hai." });
  }
  db.prepare("INSERT OR IGNORE INTO users VALUES(?,?,?)").run(id, row.pass, Date.now());
  db.prepare("DELETE FROM otps WHERE id=?").run(id);
  startSession(res, id);
  res.json({ ok: true, user: id });
});

app.post("/api/login", (req, res) => {
  const id = norm(req.body.id);
  const pw = String(req.body.password || "");
  if (!limit("login:" + id, 8, 15 * 60e3)) return res.status(429).json({ error: "Bahut baar try kiya. 15 minute baad dobara karo." });
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if (!u || !bcrypt.compareSync(pw, u.pass)) return res.status(401).json({ error: "Gmail/number ya password galat hai." });
  startSession(res, id);
  res.json({ ok: true, user: id });
});

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

app.post("/api/logout", auth, (req, res) => {
  db.prepare("DELETE FROM tokens WHERE token=?").run(req.token);
  res.setHeader("Set-Cookie", "sd=; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/sessions", auth, (req, res) =>
  res.json(db.prepare("SELECT id, subject AS s, minutes AS m, day AS d FROM sessions WHERE user=?").all(req.user))
);

app.post("/api/sessions", auth, (req, res) => {
  const s = String(req.body.s || "").trim().slice(0, 30);
  const m = parseInt(req.body.m, 10);
  const d = String(req.body.d || "");
  if (!s || !(m >= 1 && m <= 720) || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return res.status(400).json({ error: "Session ki details galat hain." });
  const r = db.prepare("INSERT INTO sessions(user,subject,minutes,day) VALUES(?,?,?,?)").run(req.user, s, m, d);
  res.json({ id: Number(r.lastInsertRowid), s, m, d });
});

app.delete("/api/sessions/:id", auth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE id=? AND user=?").run(req.params.id, req.user);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log("Server chal raha hai: http://localhost:" + PORT));
