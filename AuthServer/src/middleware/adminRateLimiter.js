
const crypto = require("node:crypto");

const MAX_REQUESTS =300;
const WINDOW_SECONDS = 60 * 60;

// Redis Lua script: check and increment atomically.
const RATE_LIMIT_SCRIPT = `
  local key = KEYS[1]
  local limit = tonumber(ARGV[1])
  local window = tonumber(ARGV[2])
  local member = ARGV[3]

  local now = redis.call("TIME")
  local nowMs = tonumber(now[1]) * 1000
                + math.floor(tonumber(now[2]) / 1000)
  local windowMs = window * 1000

  redis.call("ZREMRANGEBYSCORE", key, "-inf", nowMs - windowMs)

  local count = redis.call("ZCARD", key)

  if count >= limit then
    local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
    local retryMs = windowMs

    if #oldest > 0 then
      retryMs = math.max(
        1000,
        tonumber(oldest[2]) + windowMs - nowMs
      )
    end

    return {0, count, math.ceil(retryMs / 1000)}
  end

  redis.call("ZADD", key, nowMs, member)
  redis.call("PEXPIRE", key, windowMs)

  return {1, count + 1, 0}
`;

// Pass your existing connected Redis client to this factory.
function createAdminRateLimiter(redisClient) {
  return async function adminRateLimiter(req, res, next) {
    const adminId = req.admin?.id || req.admin?._id;

    if (!adminId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    if (!redisClient?.isReady) {
      return res.status(503).json({
        success: false,
        message: "Rate limiting service unavailable",
      });
    }

    const key = `ratelimit:admin:${String(adminId)}`;

    try {
      const result = await redisClient.eval(RATE_LIMIT_SCRIPT, {
        keys: [key],
        arguments: [
          String(MAX_REQUESTS),
          String(WINDOW_SECONDS),
          crypto.randomUUID(),
        ],
      });

      const [allowed, used, retryAfter] = result.map(Number);

      res.setHeader("X-RateLimit-Limit", MAX_REQUESTS);
      res.setHeader(
        "X-RateLimit-Remaining",
        Math.max(0, MAX_REQUESTS - used)
      );

      if (!allowed) {
        res.setHeader("Retry-After", retryAfter);

        return res.status(429).json({
          success: false,
          message: "Too many admin API requests",
          retryAfterSeconds: retryAfter,
        });
      }

      next();
    } catch (error) {
      console.error("Admin rate limiter error:", error.message);

      return res.status(503).json({
        success: false,
        message: "Rate limiting service unavailable",
      });
    }
  };
}

module.exports = createAdminRateLimiter;
