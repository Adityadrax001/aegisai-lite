
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const Admin = require("../models/Admin");
const { redisClient } = require("../config/redis");
const {COOKIE_NAME} = require("../controllers/authController.js")
async function authenticate(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });
  }

  let payload;

  try {
    payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session",
    });
  }

  if (
    typeof payload !== "object" ||
    typeof payload.sub !== "string" ||
    !mongoose.isValidObjectId(payload.sub) ||
    typeof payload.jti !== "string" ||
    !/^[0-9a-f-]{36}$/i.test(payload.jti)
  ) {
    return res.status(401).json({
      success: false,
      message: "Invalid session",
    });
  }

  if (!redisClient.isReady) {
    return res.status(503).json({
      success: false,
      message: "Authentication service unavailable",
    });
  }

  try {
    const storedAdminId = await redisClient.get(
      `session:${payload.jti}`
    );

    if (
      !storedAdminId ||
      storedAdminId !== payload.sub
    ) {
      return res.status(401).json({
        success: false,
        message: "Session expired or revoked",
      });
    }

    const admin = await Admin.findById(payload.sub);

    if (
      !admin ||
      !admin.isActive ||
      admin.role !== "admin" ||
      payload.role !== admin.role
    ) {
      return res.status(401).json({
        success: false,
        message: "Administrator access denied",
      });
    }

    req.admin = admin;
    req.auth = {
      sessionId: payload.jti,
      adminId: payload.sub,
    };

    return next();
  } catch (error) {
    console.error(
      "Session verification error:",
      error.message
    );

    return res.status(503).json({
      success: false,
      message: "Authentication service unavailable",
    });
  }
}

module.exports = authenticate;
