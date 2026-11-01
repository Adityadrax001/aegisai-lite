
const crypto = require("node:crypto");
const { redisClient } = require("../config/redis");

// One-hour rolling window.
const WINDOW_SECONDS = 60 * 60;
const MAX_LOGIN_REQUESTS = 10;

// Redis executes this entire script atomically.
const SLIDING_WINDOW_SCRIPT = `
  local key = KEYS[1]
  local maxRequests = tonumber(ARGV[1])
  local windowMs = tonumber(ARGV[2])
  local member = ARGV[3]

  -- Use Redis server time, not application server time.
  local time = redis.call("TIME")
  local now = time[1] * 1000
    + math.floor(time[2] / 1000)

  local cutoff = now - windowMs

  -- Remove expired request timestamps.
  redis.call(
    "ZREMRANGEBYSCORE",
    key,
    "-inf",
    cutoff
  )

  local count = redis.call("ZCARD", key)

  if count < maxRequests then
    redis.call("ZADD", key, now, member)
    redis.call("PEXPIRE", key, windowMs)

    return {
      1,
      maxRequests - count - 1,
      0
    }
  end

  -- Find when the oldest request expires.
  local oldest = redis.call(
    "ZRANGE", key, 0, 0, "WITHSCORES"
  )

  local retryMs = windowMs

  if oldest[2] then
    retryMs = math.max(
      1,
      math.floor(
        tonumber(oldest[2]) + windowMs - now + 1
      )
    )
  end

  return { 0, 0, retryMs }
`;

async function loginRateLimiter(req, res, next) {
  if (!redisClient.isReady) {
    return res.status(503).json({
      success: false,
      message: "Rate limiting service unavailable",
    });
  }

  try {
    // req.ip comes from Express.
    // Only trust proxy headers when your proxy is configured
    // explicitly and securely.
    const clientIP = req.ip || req.socket.remoteAddress;

    const ipHash = crypto
      .createHash("sha256")
      .update(clientIP || "unknown")
      .digest("hex");

    const key = `rate:login:ip:${ipHash}`;

    // Unique member avoids collisions for simultaneous requests.
    const requestId = crypto.randomUUID();

    const result = await redisClient.eval(
      SLIDING_WINDOW_SCRIPT,
      {
        keys: [key],
        arguments: [
          String(MAX_LOGIN_REQUESTS),
          String(WINDOW_SECONDS * 1000),
          requestId,
        ],
      }
    );

    const [allowed, remaining, retryMs] =
      result.map(Number);

    res.setHeader("X-RateLimit-Limit", MAX_LOGIN_REQUESTS);
    res.setHeader("X-RateLimit-Remaining", remaining);

    if (allowed !== 1) {
      const retryAfter = Math.max(
        1,
        Math.ceil(retryMs / 1000)
      );

      res.setHeader("Retry-After", retryAfter);

      return res.status(429).json({
        success: false,
        message:
          "Too many login requests. Please try again later.",
        retryAfterSeconds: retryAfter,
      });
    }

    return next();
  } catch (error) {
    console.error("Rate limiter error:", error.message);

    // Authentication must not bypass rate limiting
    // when Redis is unavailable or returns an error.
    return res.status(503).json({
      success: false,
      message: "Rate limiting service unavailable",
    });
  }
}

module.exports = {
  loginRateLimiter,
};
