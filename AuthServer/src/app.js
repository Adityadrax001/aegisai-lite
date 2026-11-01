require("dotenv").config();
const authRoutes = require("./routes/authRoutes");
const { connectRedis } = require("./config/redis");

const express = require("express");
const helmet = require("helmet");
const mongoose = require("mongoose");
const connectDB = require("./config/db");
const cookieParser = require('cookie-parser')
const app = express();
const PORT = Number(process.env.PORT) || 8081;

const adminRoutes = require("./routes/adminRoutes");
 const adminRateLimiter = require("./middleware/adminRateLimiter");
 const csrfProtection = require("./middleware/csrfProtection");
const authenticate = require("./middleware/authenticate");



// Basic security configuration
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());

app.use("/api/auth", authRoutes);

// Health check endpoint
app.get("/api/health", (req, res) => {
  const isConnected = mongoose.connection.readyState === 1;

  res.status(isConnected ? 200 : 503).json({
    service: "AegisAI Authentication Server",
    status: isConnected ? "healthy" : "unavailable",
    database: isConnected ? "connected" : "disconnected",
  });
});
app.use("/api/auth", authRoutes);


app.use(
  "/api/admins",
   csrfProtection,
  authenticate,
   adminRateLimiter,
  adminRoutes
);

// Handle unknown routes
app.use((req, res) => {
  res.status(404).json({
    message: "Route not found",
  });
});

// Start the server only after MongoDB connects

function startServer() {
  Promise.all([
    connectDB().then(() => {
      console.log("MongoDB connected successfully");
    }),

    connectRedis().then(() => {
      console.log("Redis connected successfully");
    }),
  ])
    .then(() => {
      console.log("All database connections established");

      app.listen(PORT, () => {
        console.log(
          `AuthServer is listening at Port:${PORT}`
        );
      });
    })
    .catch((error) => {
      console.error("Server startup failed:", error.message);
      process.exit(1);
    });
}

startServer();

