
const express = require("express");
const crypto = require("node:crypto");
const argon2 = require("argon2");
const { z } = require("zod");
const Admin = require("../models/Admin");
const { login } = require("../controllers/authController");
const authenticate = require("../middleware/authenticate");
const {
  loginRateLimiter,
} = require("../middleware/rateLimiter");
const {
  getCurrentAdmin,
  logout,
} = require("../controllers/sessionController");
const adminSchema = z.object({
  name: z.string().trim().min(2).max(100),

  email: z.email().max(254)
    .transform((value) => value.toLowerCase()),

  password: z.string()
    .min(5)
    .max(128),
}).strict();


const router = express.Router();
function validBootstrapSecret(provided) {
  const expected = process.env.ADMIN_BOOTSTRAP_SECRET;

  if (!expected || typeof provided !== "string") {
    return false;
  }

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

// One-time first-admin provisioning.
// Never expose this route as public registration.
router.post("/bootstrap", async (req, res) => {
  try {

    if (process.env.ENABLE_ADMIN_BOOTSTRAP !== "true") {
      return res.status(404).json({
        message: "Route not found",
      });
    }


//     console.log("Bootstrap debug:", {
//   envSecretConfigured: Boolean(process.env.ADMIN_BOOTSTRAP_SECRET),
//   headerReceived: Boolean(req.get("x-bootstrap-secret")),
//   envSecretLength: process.env.ADMIN_BOOTSTRAP_SECRET?.length,
//   headerLength: req.get("x-bootstrap-secret")?.length,
// });

    if (!validBootstrapSecret(req.get("x-bootstrap-secret"))) {
      return res.status(403).json({
        message: "Bootstrap authorization failed",
      });
    }

    const parsed = adminSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Invalid admin details",
        errors: z.flattenError(parsed.error).fieldErrors,
      });
    }

    // Ensure the unique email index has been created.
    await Admin.init();

    // Only allow first-admin provisioning.
    if (await Admin.exists({})) {
      return res.status(403).json({
        message: "Initial admin already exists",
      });
    }

    const { name, email, password } = parsed.data;

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
    });

    const admin = await Admin.create({
      name,
      email,
      passwordHash,
      role: "admin",
      isActive: true,
    });

    return res.status(201).json({
      success: true,
      message: "Admin created successfully",
      admin: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });

  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Duplicate admin account",
      });
    }

    console.error("Admin bootstrap failed:", error.message);

    return res.status(500).json({
      message: "Unable to create admin",
    });
  }
});
//login api 
router.post("/login",loginRateLimiter,login);
//authenticate admin
router.get("/me", authenticate, getCurrentAdmin);
//logout the admin
router.post("/logout", authenticate, logout);

module.exports = router;

