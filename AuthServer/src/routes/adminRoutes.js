
const express = require("express");

const authenticate = require("../middleware/authenticate");
const { createAdmin, getAdmins } = require("../controllers/adminController");

const router = express.Router();

function requireAdmin(req, res, next) {
  if (req.admin?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator privileges required",
    });
  }

  next();
}

// Get all admins
router.get("/", authenticate, requireAdmin, getAdmins);

// Create a new admin
router.post("/", authenticate, requireAdmin, createAdmin);

module.exports = router;
