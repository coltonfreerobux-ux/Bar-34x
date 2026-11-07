"use strict";

const express = require("express");
const cookieSession = require("cookie-session");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";

// ======================================================
// MENU
// ======================================================

const PRODUCTS = {
  wine_half: { name: "Wine (Half)", priceCents: 400 },
  wine_full: { name: "Wine (Full)", priceCents: 900 },
  water: { name: "Water", priceCents: 500 },
  chips: { name: "Chips", priceCents: 700 },
  candy: { name: "Candy", priceCents: 2000 }
};

// ======================================================
// ACCOUNTS
// ======================================================

const ACCOUNT_CONFIG = {
  owen448: { role: "customer", password: "owen448" },
  colton448: { role: "customer", password: "colton448" },
  bar388: { role: "bartender", password: "bar388" }
};

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET to a random string at least 32 characters long.");
  process.exit(1);
}

// ======================================================
// PERSISTENT DATA
// ======================================================

const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, "bar-register-data.json");

function freshData() {
  return {
    accounts: {
      owen448: { balanceCents: 10000, shiftStartedAt: null },
      colton448: { balanceCents: 10000, shiftStartedAt: null }
    },
    ratings: [],
    nextRatingId: 1,
    purchases: [],
    nextPurchaseId: 1,

    // Bartender accountability system
    bartenderDisappointedCount: 0,
    bartenderRemoved: false,
    bartenderNotifications: []
  };
}

function loadData() {
  const defaults = freshData();

  try {
    if (!fs.existsSync(DATA_FILE)) return defaults;

    const saved = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    const loaded = {
      ...defaults,
      ...saved,
      accounts: {
        ...defaults.accounts,
        ...(saved.accounts || {})
      },
      ratings: Array.isArray(saved.ratings) ? saved.ratings : [],
      purchases: Array.isArray(saved.purchases) ? saved.purchases : [],
      bartenderNotifications: Array.isArray(saved.bartenderNotifications)
        ? saved.bartenderNotifications
        : []
    };

    for (const username of Object.keys(defaults.accounts)) {
      const account = loaded.accounts[username] || defaults.accounts[username];

      loaded.accounts[username] = {
        balanceCents: Number.isInteger(account.balanceCents)
          ? account.balanceCents
          : defaults.accounts[username].balanceCents,

        shiftStartedAt: Number.isFinite(account.shiftStartedAt)
          ? account.shiftStartedAt
          : null
      };
    }

    if (!Number.isInteger(loaded.nextRatingId) || loaded.nextRatingId < 1) {
      loaded.nextRatingId = 1;
    }

    if (!Number.isInteger(loaded.nextPurchaseId) || loaded.nextPurchaseId < 1) {
      loaded.nextPurchaseId = 1;
    }

    if (!Number.isInteger(loaded.bartenderDisappointedCount)) {
      loaded.bartenderDisappointedCount = 0;
    }

    loaded.bartenderRemoved = Boolean(loaded.bartenderRemoved);

    return loaded;
  } catch (error) {
    console.error("Could not load saved register data:", error);
    throw error;
  }
}

let data = loadData();

function saveData() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });

    const temporaryFile = DATA_FILE + ".tmp";

    fs.writeFileSync(
      temporaryFile,
      JSON.stringify(data, null, 2),
      "utf8"
    );

    fs.renameSync(temporaryFile, DATA_FILE);
  } catch (error) {
    console.error("Could not save register data:", error);
    throw error;
  }
}

// ======================================================
// BALANCE AND SHIFT FUNCTIONS
// ======================================================

function getAccountBalanceCents(account) {
  if (account.shiftStartedAt === null) {
    return account.balanceCents;
  }

  const elapsedMs = Math.max(0, Date.now() - account.shiftStartedAt);
  const earned = Math.floor(elapsedMs * 500 / 60000);

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

// ======================================================
// PASSWORD COMPARISON
// ======================================================

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));

  return aBuf.length === bBuf.length &&
    crypto.timingSafeEqual(aBuf, bBuf);
}

// ======================================================
// MIDDLEWARE
// ======================================================

app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
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

// ======================================================
// BARTENDER NOTIFICATIONS
// ======================================================

function addBartenderNotification(message, type = "warning") {
  data.bartenderNotifications.push({
    id: crypto.randomUUID(),
    message,
    type,
    createdAt: Date.now(),
    read: false
  });

  // Keep the latest 50 notifications.
  data.bartenderNotifications =
    data.bartenderNotifications.slice(-50);

  saveData();
}

// ======================================================
// LOGIN
// ======================================================

const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;

app.post("/api/login", (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  const config = ACCOUNT_CONFIG[username];
  const now = Date.now();
  const attempts = loginAttempts.get(username);

  if (attempts && now - attempts.startedAt >= LOGIN_WINDOW_MS) {
    loginAttempts.delete(username);
  } else if (attempts && attempts.count >= MAX_LOGIN_ATTEMPTS) {
    return res.status(429).json({
      error: "Too many login attempts. Try again in 10 minutes."
    });
  }

  if (!config || !safeEqual(password, config.password)) {
    const current = loginAttempts.get(username);

    if (!current || now - current.startedAt >= LOGIN_WINDOW_MS) {
      loginAttempts.set(username, {
        count: 1,
        startedAt: now
      });
    } else {
      current.count++;
    }

    return res.status(401).json({
      error: "Incorrect username or password."
    });
  }

  // Check whether bartender has been removed.
  if (username === "bar388" && data.bartenderRemoved) {
    return res.status(403).json({
      error: "Your bartender account has been removed after three customer disappointments."
    });
  }

  loginAttempts.delete(username);

  req.session = {
    username,
    role: config.role
  };

  return res.json({
    user: {
      username,
      role: config.role
    }
  });
});

// ======================================================
// LOGOUT
// ======================================================

app.post("/api/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// ======================================================
// AUTHENTICATION CHECKS
// ======================================================

function requireLogin(req, res, next) {
  const config = req.session &&
    ACCOUNT_CONFIG[req.session.username];

  if (!config || req.session.role !== config.role) {
    return res.status(401).json({
      error: "Please log in."
    });
  }

  if (
    req.session.username === "bar388" &&
    data.bartenderRemoved
  ) {
    req.session = null;

    return res.status(403).json({
      error: "Your bartender account has been removed."
    });
  }

  next();
}

function requireBartender(req, res, next) {
  if (
    req.session?.role !== "bartender" ||
    req.session.username !== "bar388"
  ) {
    return res.status(403).json({
      error: "Bartender access only."
    });
  }

  if (data.bartenderRemoved) {
    req.session = null;

    return res.status(403).json({
      error: "You have been removed from the bartender system."
    });
  }

  next();
}

// ======================================================
// CHECK CURRENT LOGIN
// ======================================================

app.get("/api/me", (req, res) => {
  const config = req.session &&
    ACCOUNT_CONFIG[req.session.username];

  if (!config || req.session.role !== config.role) {
    return res.json({ user: null });
  }

  if (
    req.session.username === "bar388" &&
    data.bartenderRemoved
  ) {
    req.session = null;
    return res.json({ user: null });
  }

  return res.json({
    user: {
      username: req.session.username,
      role: config.role
    }
  });
});

// ======================================================
// CUSTOMER ACCOUNT STATE
// ======================================================

app.get("/api/customer/state", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  return res.json({
    customer: publicCustomerState(req.session.username)
  });
});

// ======================================================
// CUSTOMER SHIFT
// ======================================================

app.post("/api/customer/shift", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const account = data.accounts[req.session.username];

  if (account.shiftStartedAt === null) {
    account.shiftStartedAt = Date.now();
  } else {
    settleShift(account);
  }

  saveData();

  return res.json({
    customer: publicCustomerState(req.session.username)
  });
});

// ======================================================
// CUSTOMER PENDING RATINGS
// ======================================================

app.get("/api/customer/ratings/pending", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const pending = data.ratings.filter(rating =>
    rating.customer === req.session.username &&
    rating.rating === null
  );

  return res.json({ ratings: pending });
});

// ======================================================
// CUSTOMER SUBMITS RATING
// ======================================================

app.post("/api/customer/ratings/:id", requireLogin, (req, res) => {
  if (req.session.role !== "customer") {
    return res.status(403).json({
      error: "Customer account required."
    });
  }

  const id = Number(req.params.id);
  const ratingValue = Number(req.body?.rating);

  if (
    !Number.isInteger(ratingValue) ||
    ratingValue < 1 ||
    ratingValue > 5
  ) {
    return res.status(400).json({
      error: "Choose a rating from 1 to 5."
    });
  }

  const rating = data.ratings.find(item =>
    item.id === id &&
    item.customer === req.session.username &&
    item.rating === null
  );

  if (!rating) {
    return res.status(404).json({
      error: "Rating request not found."
    });
  }

  // Save the customer's rating.
  rating.rating = ratingValue;
  rating.ratedAt = Date.now();

  // ==================================================
  // ONE-STAR REFUND AND BARTENDER WARNING SYSTEM
  // ==================================================

  if (ratingValue === 1) {
    let purchase = null;

    // Find the exact purchase connected to this rating.
    if (rating.purchaseId) {
      purchase = data.purchases.find(item =>
        item.id === rating.purchaseId &&
        item.customer === rating.customer
      );
    }

    // Backward compatibility for older saved ratings.
    if (!purchase) {
      purchase = [...data.purchases].reverse().find(item =>
        item.customer === rating.customer &&
        item.itemName === rating.itemName &&
        !item.refunded
      );
    }

    let refundAmount = 0;

    // Refund only if this purchase has not already been refunded.
    if (purchase && !purchase.refunded) {
      const account = data.accounts[rating.customer];

      // Settle any active shift before applying the refund.
      if (account.shiftStartedAt !== null) {
        settleShift(account);
      }

      refundAmount = purchase.priceCents;
      account.balanceCents += refundAmount;

      purchase.refunded = true;
      purchase.refundedAt = Date.now();

      rating.refunded = true;
      rating.refundCents = refundAmount;
    } else {
      rating.refunded = false;
      rating.refundCents = 0;
    }

    // Increase bartender disappointment count.
    data.bartenderDisappointedCount++;

    const count = data.bartenderDisappointedCount;

    // First and second disappointment warnings.
    if (count < 3) {
      addBartenderNotification(
        `A customer was disappointed. If this happens three times, you will be removed. (${count}/3)`,
        "warning"
      );
    }

    // Third disappointment: remove bartender.
    if (count >= 3) {
      data.bartenderRemoved = true;

      addBartenderNotification(
        "You have been removed from the bartender system after three customer disappointments.",
        "removed"
      );
    }

    saveData();

    return res.json({
      ok: true,
      rating: ratingValue,
      refunded: Boolean(refundAmount),
      refundCents: refundAmount,
      disappointmentCount: count,
      bartenderRemoved: data.bartenderRemoved,
      message: refundAmount
        ? `You received a full refund of $${(refundAmount / 100).toFixed(2)}.`
        : "Your rating was recorded. A refund could not be matched to this purchase."
    });
  }

  saveData();

  return res.json({
    ok: true,
    rating: ratingValue,
    refunded: false,
    message: "Thank you for rating your bartender."
  });
});

// ======================================================
// BARTENDER NOTIFICATIONS
// ======================================================

app.get(
  "/api/bartender/notifications",
  requireLogin,
  requireBartender,
  (req, res) => {
    return res.json({
      notifications: data.bartenderNotifications,
      disappointmentCount: data.bartenderDisappointedCount,
      removalThreshold: 3,
      removed: data.bartenderRemoved
    });
  }
);

app.post(
  "/api/bartender/notifications/read",
  requireLogin,
  requireBartender,
  (req, res) => {
    for (const notification of data.bartenderNotifications) {
      notification.read = true;
    }

    saveData();

    return res.json({ ok: true });
  }
);

// ======================================================
// BARTENDER DASHBOARD
// ======================================================

app.get(
  "/api/bartender/dashboard",
  requireLogin,
  requireBartender,
  (req, res) => {
    const customers = [
      "owen448",
      "colton448"
    ].map(publicCustomerState);

    const ratings = data.ratings
      .filter(rating => rating.rating !== null)
      .slice(-30)
      .reverse();

    return res.json({
      customers,
      products: PRODUCTS,
      ratings,

      // Notification and warning information.
      notifications: data.bartenderNotifications,
      disappointmentCount: data.bartenderDisappointedCount,
      removalThreshold: 3,
      bartenderRemoved: data.bartenderRemoved
    });
  }
);

// ======================================================
// BARTENDER PURCHASE
// ======================================================

app.post(
  "/api/bartender/purchase",
  requireLogin,
  requireBartender,
  (req, res) => {
    const customer = String(req.body?.customer || "").toLowerCase();
    const productId = String(req.body?.productId || "");

    if (!["owen448", "colton448"].includes(customer)) {
      return res.status(400).json({
        error: "Choose a valid customer account."
      });
    }

    const product = PRODUCTS[productId];

    if (!product) {
      return res.status(400).json({
        error: "Choose a valid menu item."
      });
    }

    const account = data.accounts[customer];

    if (account.shiftStartedAt !== null) {
      return res.status(409).json({
        error: "That customer is on shift and cannot make purchases."
      });
    }

    if (account.balanceCents < product.priceCents) {
      return res.status(400).json({
        error: `${customer} does not have enough money.`
      });
    }

    // Charge customer.
    account.balanceCents -= product.priceCents;

    // Create a unique purchase record.
    const purchaseId = data.nextPurchaseId++;

    data.purchases.push({
      id: purchaseId,
      customer,
      productId,
      itemName: product.name,
      priceCents: product.priceCents,
      bartender: "bar388",
      purchasedAt: Date.now(),
      refunded: false,
      refundedAt: null
    });

    // Create rating request connected to exact purchase.
    data.ratings.push({
      id: data.nextRatingId++,
      purchaseId,
      customer,
      itemName: product.name,
      bartender: "bar388",
      rating: null,
      createdAt: Date.now(),
      ratedAt: null,
      refunded: false,
      refundCents: 0
    });

    saveData();

    return res.json({
      message: `Bought ${product.name} for ${customer}.`,
      customer: publicCustomerState(customer)
    });
  }
);

// ======================================================
// SERVE WEBSITE AND HEALTH CHECK
// ======================================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "Bar Register"
  });
});

// ======================================================
// ERROR HANDLING
// ======================================================

app.use((err, req, res, next) => {
  console.error("Request failed:", err);

  if (res.headersSent) {
    return next(err);
  }

  if (req.path.startsWith("/api/")) {
    const status =
      Number.isInteger(err.status) &&
      err.status >= 400 &&
      err.status < 600
        ? err.status
        : 500;

    const message = status === 400
      ? "Invalid request. Please check the submitted data."
      : "The server could not complete the request. Check the server logs.";

    return res.status(status).json({
      error: message
    });
  }

  return res.status(500).send("Internal server error.");
});

// ======================================================
// START SERVER
// ======================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bar register listening on port ${PORT}`);
});
