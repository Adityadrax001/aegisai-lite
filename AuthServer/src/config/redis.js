
const { createClient } = require("redis");

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    connectTimeout: 10000,
    reconnectStrategy: (retries) =>
      retries >= 5 ? false : Math.min(retries * 200, 2000),
  },
});

redisClient.on("error", (error) => {
  console.error("Redis connection error:", error.message);
});

redisClient.on("ready", () => {
  console.log("Redis connection ready");
});

async function connectRedis() {
  if (!process.env.REDIS_URL) {
    throw new Error("REDIS_URL is missing");
  }

  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
}

module.exports = {
  redisClient,
  connectRedis,
};
