
require("dotenv").config();

const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const mongoose = require("mongoose");
const argon2 = require("argon2");

const connectDB = require("../src/config/db");
const Admin = require("../src/models/Admin");

async function main() {
  // The script must be launched from a terminal.
  if (!stdin.isTTY) {
    throw new Error("Run this script in an interactive terminal.");
  }

  const rl = readline.createInterface({
    input: stdin,
    output: stdout,
  });

  let name;
  let email;
  let password;

  try {
    name = (await rl.question("Admin name: ")).trim();

    email = (await rl.question("Admin email: "))
      .trim()
      .toLowerCase();

    // Do not echo the password into terminal history.
    // For this initial script, retrieve it from a protected
    // environment variable rather than an echoed prompt.
    if (name.length < 2 || name.length > 100) {
      throw new Error("Name must contain 2–100 characters.");
    }

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      throw new Error("Invalid email address.");
    }

    password = process.env.ADMIN_BOOTSTRAP_PASSWORD;

    if (!password || password.length < 12) {
      throw new Error(
        "Set ADMIN_BOOTSTRAP_PASSWORD to a strong password " +
        "of at least 12 characters."
      );
    }

    await connectDB();

    // Make sure the unique email index exists.
    await Admin.init();

    const existing = await Admin.exists({ email });

    if (existing) {
      throw new Error("An admin with this email already exists.");
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

    console.log("Admin account created successfully.");
    console.log("Admin ID:", admin.id);
    console.log("Email:", admin.email);
  } finally {
    password = undefined;
    await rl.close();
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  console.error(
    error.code === 11000
      ? "An admin with this email already exists."
      : error.message
  );
  process.exitCode = 1;
});
