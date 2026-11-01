
const argon2 = require("argon2");
const { z } = require("zod");

const Admin = require("../models/Admin");

const createAdminSchema = z.object({
  name: z.string()
    .trim()
    .min(2)
    .max(100),

  email: z.email()
    .max(254)
    .transform((email) => email.trim().toLowerCase()),

  password: z.string()
    .min(12)
    .max(128),
}).strict();

async function createAdmin(req, res) {
  try {
    const parsed = createAdminSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: "Invalid administrator details",
        errors: z.flattenError(parsed.error).fieldErrors,
      });
    }

    const { name, email, password } = parsed.data;

    // Ensure the unique email index exists.
    await Admin.init();

    const existingAdmin = await Admin.exists({ email });

    if (existingAdmin) {
      return res.status(409).json({
        success: false,
        message: "An administrator with this email already exists",
      });
    }

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
        id: String(admin._id),
        name: admin.name,
        email: admin.email,
        role: admin.role,
        isActive: admin.isActive,
      },
    });
  } catch (error) {
    // The unique database index handles concurrent requests.
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An administrator with this email already exists",
      });
    }

    console.error("Create admin error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to create administrator",
    });
  }
}

async function getAdmins(req, res) {
  try {
    const admins = await Admin.find({})
      .select("name email role isActive createdAt lastLoginAt")
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      success: true,
      count: admins.length,
      admins: admins.map((admin) => ({
        id: String(admin._id),
        name: admin.name,
        email: admin.email,
        role: admin.role,
        isActive: admin.isActive,
        lastLoginAt: admin.lastLoginAt,
      })),
    });
  } catch (error) {
    console.error("Fetch admins failed:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch administrators",
    });
  }
}

module.exports = { createAdmin,getAdmins};
