const express = require("express");
const cookieSession = require("cookie-session");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, "register-data.json");

const PRODUCTS = {
  wine_half: { name: "Wine (Half)", priceCents: 400 },
  wine_full: { name: "Wine (Full)", priceCents: 900 },
  water: { name: "Water", priceCents: 500 },
  chips: { name: "Chips", priceCents: 700 },
  candy: { name: "Candy", priceCents: 2000 }
};

const ACCOUNT_CONFIG = {
  owen448: { role: "customer", passwordEnv: "OWEN448_PASSWORD" },
  colton448: { role: "customer", passwordEnv: "COLTON448_PASSWORD" },
  bar388: { role: "bartender", passwordEnv: "BAR388_PASSWORD" }
};

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET in your environment to a random string at least 32 characters long.");
  process.exit(1);
}

for (const [username, config] of Object.entries(ACCOUNT_CONFIG)) {
  if (!process.env[config.passwordEnv]) {
    console.error(`Missing required environment variable: ${config.passwordEnv}`);
    process.exit(1);
  }
}

function freshData() {
  return {
    accounts: {
      owen448: { balanceCents: 10000, shiftStartedAt: null },
      colton448: { balanceCents: 10000, shiftStartedAt: null }
    },
    ratings: [],
    nextRatingId: 1,
    purchases: []
  };
}

function loadData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    const initial = freshData();
    parsed.accounts ||= initial.accounts;
    parsed.ratings ||= [];
    parsed.purchases ||= [];
    parsed.nextRatingId ||= 1;
    for (const username of ["owen448", "colton448"]) {
      parsed.accounts[username] ||= initial.accounts[username];
      if (!Number.isInteger(parsed.accounts[username].balanceCents)) {
        parsed.accounts[username].balanceCents = 10000;
      }
      if (parsed.accounts[username].shiftStartedAt === undefined) {
        parsed.accounts[username].shiftStartedAt = null;
      }
    }
    return parsed;
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error("Could not read register data:", error);
      throw error;
    }
    const initial = freshData();
    saveData(initial);
    return initial;
  }
}

let data = loadData();

function saveData(nextData = data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tempFile = DATA_FILE + ".tmp";
  fs.writeFileSync(tempFile, JSON.stringify(nextData, null, 2), { mode: 0o600 });
  fs.renameSync(tempFile, DATA_FILE);
}

function getAccountBalanceCents(account) {
  if (account.shiftStartedAt === null) return account.balanceCents;
  const elapsedMs = Math.max(0, Date.now() - account.shiftStartedAt);
  const earned = Math.floor(elapsedMs * 500 / 60000); // $5.00 per minute
  return account.balanceCents + earned;
}

function settleShift(account) {
  account.balanceCents = getAccountBalanceCents(account);
  account.shiftStartedAt = null;
}

function publicCustomerState(username) {
  const account = data.accounts[username];
  return {
    username,
    balanceCents: getAccountBalanceCents(account),
    onShift: account.shiftStartedAt !== null
  };
}

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));
  return aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf);
}

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use(express.json({ limit: "10kb" }));
app.use(cookieSession({
  name: "bar_register_session",
  keys: [process.env.SESSION_SECRET],
  httpOnly: true,
  sameSite: "lax",
  secure: IS_PRODUCTION,
  maxAge: 8 * 60 * 60 * 1000
}));

// Basic in-memory login throttling. Render restarts clear this counter.
const loginAttempts = new Map();
app.post("/api/login", (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const config = ACCOUNT_CONFIG[username];

  const now = Date.now();
  const attempts = loginAttempts.get(username);
  if (attempts && attempts.count >= 8 && now - attempts.startedAt < 10 * 60 * 1000) {
    return res.status(429).json({ error: "Too many login attempts. Try again in 10 minutes." });
  }

  if (!config || !safeEqual(password, process.env[config.passwordEnv])) {
    const current = attempts && now - attempts.startedAt < 10 * 60 * 1000
      ? attempts
      : { count: 0, startedAt: now };
    current.count += 1;
    loginAttempts.set(username, current);
    return res.status(401).json({ error: "Incorrect username or password." });
  }

  loginAttempts.delete(username);
  req.session = { username, role: config.role };
  res.json({ user: { username, role: config.role } });
});

app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

function requireLogin(req, res, next) {
  if (!req.session || !ACCOUNT_CONFIG[req.session.username]) {
    return res.status(401).json({ error: "Please log in." });
  }
  next();
}

function requireBartender(req, res, next) {
  if (req.session?.role !== "bartender" || req.session.username !== "bar388") {
    return res.status(403).json({ error: "Bartender access only." });
  }
  next();
}

app.get("/api/me", (req, res) => {
  if (!req.session || !ACCOUNT_CONFIG[req.session.username]) {
    return res.json({ user: null });
  }
  res.json({ user: { username: req.session.username, role: req.session.role } });
});

app.get("/api/customer/state", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({ error: "Customer account required." });
  }
  res.json({ customer: publicCustomerState(req.session.username) });
});

app.post("/api/customer/shift", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({ error: "Customer account required." });
  }
  const account = data.accounts[req.session.username];
  if (account.shiftStartedAt === null) {
    account.shiftStartedAt = Date.now();
  } else {
    settleShift(account);
  }
  saveData();
  res.json({ customer: publicCustomerState(req.session.username) });
});

app.get("/api/customer/ratings/pending", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({ error: "Customer account required." });
  }
  const username = req.session.username;
  const pending = data.ratings.filter(r => r.customer === username && r.rating === null);
  res.json({ ratings: pending });
});

app.post("/api/customer/ratings/:id", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({ error: "Customer account required." });
  }
  const id = Number(req.params.id);
  const ratingValue = Number(req.body?.rating);
  if (!Number.isInteger(ratingValue) || ratingValue < 1 || ratingValue > 5) {
    return res.status(400).json({ error: "Choose a rating from 1 to 5." });
  }
  const rating = data.ratings.find(
    r => r.id === id && r.customer === req.session.username && r.rating === null
  );
  if (!rating) return res.status(404).json({ error: "Rating request not found." });

  rating.rating = ratingValue;
  rating.ratedAt = Date.now();
  saveData();
  res.json({ ok: true });
});

app.get("/api/bartender/dashboard", requireLogin, requireBartender, (req, res) => {
  const customers = ["owen448", "colton448"].map(publicCustomerState);
  const ratings = data.ratings
    .filter(r => r.rating !== null)
    .slice(-30)
    .reverse();
  res.json({ customers, products: PRODUCTS, ratings });
});

app.post("/api/bartender/purchase", requireLogin, requireBartender, (req, res) => {
  const customer = String(req.body?.customer || "").toLowerCase();
  const productId = String(req.body?.productId || "");
  if (!["owen448", "colton448"].includes(customer)) {
    return res.status(400).json({ error: "Choose a valid customer account." });
  }
  const product = PRODUCTS[productId];
  if (!product) return res.status(400).json({ error: "Choose a valid menu item." });

  const account = data.accounts[customer];
  if (account.shiftStartedAt !== null) {
    return res.status(409).json({ error: "That customer is on shift and cannot make purchases." });
  }
  if (account.balanceCents < product.priceCents) {
    return res.status(400).json({ error: `${customer} does not have enough money.` });
  }

  account.balanceCents -= product.priceCents;
  const purchase = {
    customer,
    productId,
    itemName: product.name,
    priceCents: product.priceCents,
    bartender: "bar388",
    purchasedAt: Date.now()
  };
  data.purchases.push(purchase);
  data.ratings.push({
    id: data.nextRatingId++,
    customer,
    itemName: product.name,
    bartender: "bar388",
    rating: null,
    createdAt: Date.now(),
    ratedAt: null
  });
  saveData();

  res.json({
    message: `Bought ${product.name} for ${customer}.`,
    customer: publicCustomerState(customer)
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bar register listening on port ${PORT}`);
  console.log(`Register data file: ${DATA_FILE}`);
});
