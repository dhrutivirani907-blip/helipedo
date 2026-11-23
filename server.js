const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable is required");
if (!ADMIN_PASSWORD) throw new Error("ADMIN_PASSWORD environment variable is required");
if (!SESSION_SECRET) throw new Error("SESSION_SECRET environment variable is required");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: "20kb" }));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", generalLimiter);

const COOKIE_NAME = "job_account_session";

function normalizeName(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function validName(name) {
  return name.length >= 2 && name.length <= 40 && /^[\p{L}\p{N} ._-]+$/u.test(name);
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function makeToken(accountId) {
  const payload = `${accountId}.${Date.now()}`;
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  try {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [accountId, issuedAt, signature] = parts;
    if (!/^\d+$/.test(accountId) || !/^\d+$/.test(issuedAt)) return null;

    // Session lifetime: 180 days.
    if (Date.now() - Number(issuedAt) > 180 * 24 * 60 * 60 * 1000) return null;

    const expected = sign(`${accountId}.${issuedAt}`);
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;

    return Number(accountId);
  } catch {
    return null;
  }
}

function setSessionCookie(res, accountId) {
  res.cookie(COOKIE_NAME, makeToken(accountId), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 180 * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

function getAccountId(req) {
  return verifyToken(req.headers["x-account-token"]) ||
    verifyToken(req.cookies?.[COOKIE_NAME]);
}

async function requireAccount(req, res, next) {
  const accountId = getAccountId(req);
  if (!accountId) return res.status(401).json({ ok: false, error: "Account session expired. Please enter your name again." });

  try {
    const result = await pool.query(
      "SELECT id, name, ads_count FROM job_accounts WHERE id = $1 AND is_active = TRUE",
      [accountId]
    );
    if (!result.rows[0]) {
      clearSessionCookie(res);
      return res.status(401).json({ ok: false, error: "Account not found." });
    }
    req.account = result.rows[0];
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Server error." });
  }
}

function requireAdmin(req, res, next) {
  const token = String(req.headers["x-admin-token"] || "");
  if (!token || token.length < 20) return res.status(401).json({ ok: false, error: "Admin authentication required." });

  const expected = sign("admin:" + ADMIN_PASSWORD);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
      return res.status(401).json({ ok: false, error: "Invalid admin session." });
    }
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid admin session." });
  }
  next();
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS job_accounts (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(40) NOT NULL,
      name_key VARCHAR(40) NOT NULL UNIQUE,
      ads_count BIGINT NOT NULL DEFAULT 0 CHECK (ads_count >= 0),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS job_accounts_created_idx
    ON job_accounts(created_at DESC);
  `);
}

app.get("/", (req, res) => {
  res.json({
    status: "Active",
    app: "Ad Tracker Backend",
    database: "Connected API",
    version: "2.0.0"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, status: "healthy" });
  } catch {
    res.status(503).json({ ok: false, status: "database_unavailable" });
  }
});

// Tells the frontend whether this browser already has a backend session.
// No user data is stored in localStorage.
app.get("/api/session", async (req, res) => {
  const accountId = getAccountId(req);
  if (!accountId) return res.json({ ok: true, hasSession: false });

  try {
    const result = await pool.query(
      "SELECT id, name, ads_count FROM job_accounts WHERE id = $1 AND is_active = TRUE",
      [accountId]
    );
    if (!result.rows[0]) {
      clearSessionCookie(res);
      return res.json({ ok: true, hasSession: false });
    }
    res.json({ ok: true, hasSession: true });
  } catch {
    res.status(500).json({ ok: false, error: "Server error." });
  }
});

// First-time account creation.
app.post("/api/account", async (req, res) => {
  const name = normalizeName(req.body?.name);
  if (!validName(name)) {
    return res.status(400).json({
      ok: false,
      error: "Please enter a valid name (2-40 characters)."
    });
  }

  const nameKey = name.toLocaleLowerCase("en-US");

  try {
    const existing = await pool.query(
      "SELECT id FROM job_accounts WHERE name_key = $1",
      [nameKey]
    );

    if (existing.rows[0]) {
      return res.status(409).json({
        ok: false,
        error: "This name already has an account. Please use Check Account."
      });
    }

    const created = await pool.query(
      `INSERT INTO job_accounts (name, name_key)
       VALUES ($1, $2)
       RETURNING id, name, ads_count`,
      [name, nameKey]
    );

    const account = created.rows[0];
    setSessionCookie(res, account.id);

    res.status(201).json({
      ok: true,
      account: {
        id: account.id,
        name: account.name,
        adsCount: Number(account.ads_count)
      }
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ ok: false, error: "This name already has an account." });
    }
    console.error(err);
    res.status(500).json({ ok: false, error: "Could not create account." });
  }
});

// Returning user checks their name. The backend account is opened only if it exists.
app.post("/api/account/check", async (req, res) => {
  const name = normalizeName(req.body?.name);
  if (!validName(name)) {
    return res.status(400).json({ ok: false, error: "Please enter a valid name." });
  }

  const nameKey = name.toLocaleLowerCase("en-US");

  try {
    const result = await pool.query(
      `SELECT id, name, ads_count
       FROM job_accounts
       WHERE name_key = $1 AND is_active = TRUE`,
      [nameKey]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        ok: false,
        error: "No account was found with this name."
      });
    }

    const account = result.rows[0];
    setSessionCookie(res, account.id);

    res.json({
      ok: true,
      account: {
        id: account.id,
        name: account.name,
        adsCount: Number(account.ads_count)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Could not check account." });
  }
});

app.get("/api/account/me", requireAccount, (req, res) => {
  res.json({
    ok: true,
    account: {
      id: req.account.id,
      name: req.account.name,
      adsCount: Number(req.account.ads_count)
    }
  });
});

// The client calls this only after the 8-second ad-return check succeeds.
app.post("/api/account/me/increment-ad", requireAccount, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE job_accounts
       SET ads_count = ads_count + 1, updated_at = NOW()
       WHERE id = $1 AND is_active = TRUE
       RETURNING id, name, ads_count`,
      [req.account.id]
    );

    const account = result.rows[0];
    res.json({
      ok: true,
      account: {
        id: account.id,
        name: account.name,
        adsCount: Number(account.ads_count)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Could not update ad count." });
  }
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// Admin password is NEVER placed in index.html.
// The frontend receives only a short-lived signed admin token after this check.
app.post("/api/admin/login", adminLimiter, (req, res) => {
  const password = String(req.body?.password || "");
  if (!password) return res.status(400).json({ ok: false, error: "Password is required." });

  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ ok: false, error: "Incorrect admin password." });
  }

  const token = sign("admin:" + ADMIN_PASSWORD);
  res.json({ ok: true, adminToken: token });
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, ads_count, created_at, updated_at
      FROM job_accounts
      WHERE is_active = TRUE
      ORDER BY created_at DESC
    `);

    res.json({
      ok: true,
      users: result.rows.map(row => ({
        id: row.id,
        name: row.name,
        adsCount: Number(row.ads_count),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Could not load users." });
  }
});

app.post("/api/admin/users/:id/reset", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, error: "Invalid user ID." });
  }

  try {
    const result = await pool.query(
      `UPDATE job_accounts
       SET ads_count = 0, updated_at = NOW()
       WHERE id = $1 AND is_active = TRUE
       RETURNING id, name, ads_count`,
      [id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ ok: false, error: "User not found." });
    }

    res.json({
      ok: true,
      message: "Ad count reset successfully.",
      account: {
        id: result.rows[0].id,
        name: result.rows[0].name,
        adsCount: Number(result.rows[0].ads_count)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Could not reset user." });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: "Unexpected server error." });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Ad Tracker backend running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
