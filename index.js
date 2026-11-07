
"use strict";

const express = require("express");
const cookieSession = require("cookie-session");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const PRODUCTS = {
    wine_half: {
        name: "Wine (Half)",
        priceCents: 400
    },
    wine_full: {
        name: "Wine (Full)",
        priceCents: 900
    },
    water: {
        name: "Water",
        priceCents: 500
    },
    chips: {
        name: "Chips",
        priceCents: 700
    },
    candy: {
        name: "Candy",
        priceCents: 2000
    }
};

const ACCOUNTS = {
    owen448: {
        role: "customer",
        passwordEnv: "OWEN448_PASSWORD"
    },
    colton448: {
        role: "customer",
        passwordEnv: "COLTON448_PASSWORD"
    },
    bar388: {
        role: "bartender",
        passwordEnv: "BAR388_PASSWORD"
    }
};

// SECURITY SETTINGS

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
    console.error("SESSION_SECRET must be at least 32 characters.");
    process.exit(1);
}

for (const account of Object.values(ACCOUNTS)) {
    if (!process.env[account.passwordEnv]) {
        console.error(
            "Missing environment variable: " + account.passwordEnv
        );
        process.exit(1);
    }
}

// TEMPORARY MEMORY STORAGE
// Everything resets when Render restarts.

function freshData() {
    return {
        accounts: {
            owen448: {
                balanceCents: 10000,
                shiftStartedAt: null
            },
            colton448: {
                balanceCents: 10000,
                shiftStartedAt: null
            }
        },
        ratings: [],
        purchases: [],
        nextRatingId: 1
    };
}

let data = freshData();

// HELPERS

function money(cents) {
    return "$" + (cents / 100).toFixed(2);
}

function getBalance(account) {
    if (account.shiftStartedAt === null) {
        return account.balanceCents;
    }

    const elapsed = Math.max(
        0,
        Date.now() - account.shiftStartedAt
    );

    const earned = Math.floor(
        elapsed * 500 / 60000
    );

    return account.balanceCents + earned;
}

function settleShift(account) {
    account.balanceCents = getBalance(account);
    account.shiftStartedAt = null;
}

function publicCustomer(username) {
    const account = data.accounts[username];

    return {
        username,
        balanceCents: getBalance(account),
        onShift: account.shiftStartedAt !== null
    };
}

function safeEqual(a, b) {
    const first = Buffer.from(String(a));
    const second = Buffer.from(String(b));

    return first.length === second.length &&
        crypto.timingSafeEqual(first, second);
}

// MIDDLEWARE

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
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
}));

// LOGIN ATTEMPT LIMIT

const loginAttempts = new Map();

app.post("/api/login", (req, res) => {
    const username = String(
        req.body?.username || ""
    ).trim().toLowerCase();

    const password = String(
        req.body?.password || ""
    );

    const config = ACCOUNTS[username];

    const now = Date.now();
    const attempts = loginAttempts.get(username);

    if (
        attempts &&
        attempts.count >= 8 &&
        now - attempts.startedAt < 600000
    ) {
        return res.status(429).json({
            error: "Too many login attempts. Try again later."
        });
    }

    if (
        !config ||
        !safeEqual(
            password,
            process.env[config.passwordEnv]
        )
    ) {
        const current =
            attempts && now - attempts.startedAt < 600000
                ? attempts
                : { count: 0, startedAt: now };

        current.count++;

        loginAttempts.set(username, current);

        return res.status(401).json({
            error: "Incorrect username or password."
        });
    }

    loginAttempts.delete(username);

    req.session = {
        username,
        role: config.role
    };

    res.json({
        user: {
            username,
            role: config.role
        }
    });
});

// LOGOUT

app.post("/api/logout", (req, res) => {
    req.session = null;

    res.json({ ok: true });
});

// AUTHENTICATION

function requireLogin(req, res, next) {
    if (
        !req.session ||
        !ACCOUNTS[req.session.username]
    ) {
        return res.status(401).json({
            error: "Please log in."
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

    next();
}

// CURRENT USER

app.get("/api/me", (req, res) => {
    if (
        !req.session ||
        !ACCOUNTS[req.session.username]
    ) {
        return res.json({ user: null });
    }

    res.json({
        user: {
            username: req.session.username,
            role: req.session.role
        }
    });
});

// CUSTOMER ACCOUNT

app.get(
    "/api/customer/state",
    requireLogin,
    (req, res) => {
        if (req.session.role !== "customer") {
            return res.status(403).json({
                error: "Customer account required."
            });
        }

        res.json({
            customer: publicCustomer(
                req.session.username
            )
        });
    }
);

// GO ON SHIFT / OFF SHIFT

app.post(
    "/api/customer/shift",
    requireLogin,
    (req, res) => {
        if (req.session.role !== "customer") {
            return res.status(403).json({
                error: "Customer account required."
            });
        }

        const account =
            data.accounts[req.session.username];

        if (account.shiftStartedAt === null) {
            account.shiftStartedAt = Date.now();
        } else {
            settleShift(account);
        }

        res.json({
            customer: publicCustomer(
                req.session.username
            )
        });
    }
);

// PENDING CUSTOMER RATINGS

app.get(
    "/api/customer/ratings/pending",
    requireLogin,
    (req, res) => {
        if (req.session.role !== "customer") {
            return res.status(403).json({
                error: "Customer account required."
            });
        }

        const ratings = data.ratings.filter(r =>
            r.customer === req.session.username &&
            r.rating === null
        );

        res.json({ ratings });
    }
);

// SUBMIT CUSTOMER RATING

app.post(
    "/api/customer/ratings/:id",
    requireLogin,
    (req, res) => {
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

        const rating = data.ratings.find(r =>
            r.id === id &&
            r.customer === req.session.username &&
            r.rating === null
        );

        if (!rating) {
            return res.status(404).json({
                error: "Rating request not found."
            });
        }

        rating.rating = ratingValue;
        rating.ratedAt = Date.now();

        res.json({ ok: true });
    }
);

// BARTENDER DASHBOARD

app.get(
    "/api/bartender/dashboard",
    requireLogin,
    requireBartender,
    (req, res) => {
        const customers = [
            publicCustomer("owen448"),
            publicCustomer("colton448")
        ];

        const ratings = data.ratings
            .filter(r => r.rating !== null)
            .slice(-30)
            .reverse();

        res.json({
            customers,
            products: PRODUCTS,
            ratings
        });
    }
);

// BARTENDER PURCHASE SYSTEM

app.post(
    "/api/bartender/purchase",
    requireLogin,
    requireBartender,
    (req, res) => {
        const customer = String(
            req.body?.customer || ""
        ).toLowerCase();

        const productId = String(
            req.body?.productId || ""
        );

        if (
            !["owen448", "colton448"].includes(customer)
        ) {
            return res.status(400).json({
                error: "Choose a valid customer."
            });
        }

        const product = PRODUCTS[productId];

        if (!product) {
            return res.status(400).json({
                error: "Invalid menu item."
            });
        }

        const account = data.accounts[customer];

        if (account.shiftStartedAt !== null) {
            return res.status(409).json({
                error: "Customer is on shift and cannot buy anything."
            });
        }

        if (account.balanceCents < product.priceCents) {
            return res.status(400).json({
                error: "Customer does not have enough money."
            });
        }

        // SUBTRACT PRICE

        account.balanceCents -= product.priceCents;

        // RECORD PURCHASE

        data.purchases.push({
            customer,
            productId,
            itemName: product.name,
            priceCents: product.priceCents,
            bartender: "bar388",
            purchasedAt: Date.now()
        });

        // CREATE RATING REQUEST

        data.ratings.push({
            id: data.nextRatingId++,
            customer,
            itemName: product.name,
            bartender: "bar388",
            rating: null,
            createdAt: Date.now(),
            ratedAt: null
        });

        res.json({
            message:
                "Bought " + product.name +
                " for " + customer + ".",

            customer: publicCustomer(customer)
        });
    }
);

// WEBSITE

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "index.html")
    );
});

// HEALTH CHECK

app.get("/health", (req, res) => {
    res.json({ ok: true });
});

// START SERVER

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        "Bar Register running on port " + PORT
    );

    console.log(
        "Memory-only storage enabled. Data resets on restart."
    );
});
