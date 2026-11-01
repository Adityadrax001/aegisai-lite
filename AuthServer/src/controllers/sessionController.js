
const { redisClient } = require("../config/redis");

const {
  COOKIE_NAME,
  cookieOptions,
} = require("./authController");

// GET /api/auth/me
function getCurrentAdmin(req, res) {
  const admin = req.admin;

  return res.status(200).json({
    success: true,
    admin: {
      id: String(admin._id),
      name: admin.name,
      email: admin.email,
      role: admin.role,
      isActive: admin.isActive,
      lastLoginAt: admin.lastLoginAt,
    },
  });
}

// POST /api/auth/logout
async function logout(req, res) {
  if (!redisClient.isReady) {
    return res.status(503).json({
      success: false,
      message: "Authentication service unavailable",
    });
  }

  try {
    const deleted = await redisClient.del(
      `session:${req.auth.sessionId}`
    );

    if (deleted !== 1) {
      return res.status(401).json({
        success: false,
        message: "Session already expired or revoked",
      });
    }

    res.clearCookie(COOKIE_NAME, cookieOptions);

    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error.message);

    return res.status(503).json({
      success: false,
      message: "Unable to complete logout",
    });
  }
}

module.exports = {
  getCurrentAdmin,
  logout,
};
