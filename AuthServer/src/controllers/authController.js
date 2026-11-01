
const crypto = require("node:crypto");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const { z } = require("zod");

const Admin = require("../models/Admin");
const { redisClient } = require("../config/redis");

const SESSION_TTL = 15 * 60;
const COOKIE_NAME = "JWT-cookie";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/",
};

const loginSchema = z.object({
  email: z.email().max(254)
    .transform((value) => value.trim().toLowerCase()),

  password: z.string().min(1).max(128),
}).strict();

async function login(req, res) {
  let redisKey = null;
  let sessionCreated = false;

  try {
    // Step 1: Validate incoming JSON.
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: "Invalid login data",
      });
    }

    const { email, password } = parsed.data;

    // Step 2: Find the admin in MongoDB.
    const admin = await Admin.findOne({
      email,
    }).select("+passwordHash");

    if (!admin || !admin.isActive) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Step 3: Verify Argon2 password.
    const validPassword = await argon2.verify(
      admin.passwordHash,
      password
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (admin.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }

    // Step 4: Check Redis availability.
    if (!redisClient.isReady) {
      return res.status(503).json({
        success: false,
        message: "Authentication service unavailable",
      });
    }

    // Step 5: Generate session ID and signed JWT.
    const sessionId = crypto.randomUUID();

    const token = jwt.sign(
      { role: admin.role },
      process.env.JWT_SECRET,
      {
        subject: String(admin._id),
        jwtid: sessionId,
        expiresIn: SESSION_TTL,
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        algorithm: "HS256",
      }
    );

    // Step 6: Store session in Redis.
    redisKey = `session:${sessionId}`;

    const stored = await redisClient.set(
      redisKey,
      String(admin._id),
      {
        EX: SESSION_TTL,
        NX: true,
      }
    );

    if (stored !== "OK") {
      return res.status(503).json({
        success: false,
        message: "Unable to establish session",
      });
    }

    sessionCreated = true;

    // Step 7: Update login timestamp.
    await Admin.updateOne(
      { _id: admin._id },
      { $set: { lastLoginAt: new Date() } }
    );

    // Step 8: Set JWT in HttpOnly cookie.
    res.cookie(COOKIE_NAME, token, {
      ...cookieOptions,
      maxAge: SESSION_TTL * 1000,
    });

    // Step 9: Return successful authentication.
    return res.status(200).json({
      success: true,
      message: "Login successful",
      admin: {
        id: String(admin._id),
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });

  } catch (error) {
    console.error("Login error:", error.message);

    // Clean up a session if a later step failed.
    if (sessionCreated && redisKey) {
      try {
        await redisClient.del(redisKey);
      } catch (cleanupError) {
        console.error(
          "Session cleanup failed:",
          cleanupError.message
        );
      }
    }

    return res.status(503).json({
      success: false,
      message: "Authentication service unavailable",
    });
  }
}

module.exports = {
  login,
  COOKIE_NAME,
  cookieOptions,
};
