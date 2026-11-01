
function csrfProtection(req, res, next) {
  // GET requests should only read data.
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const allowedOrigin = process.env.FRONTEND_ORIGIN;

  if (!allowedOrigin) {
    return res.status(503).json({
      success: false,
      message: "CSRF protection is not configured",
    });
  }

  const origin = req.get("Origin");
  const customHeader = req.get("X-Aegis-Request");

  // Check that request came from our frontend.
  if (origin !== allowedOrigin) {
    return res.status(403).json({
      success: false,
      message: "CSRF protection: Invalid origin",
    });
  }

  // Require a custom header on state-changing requests.
  if (customHeader !== "browser") {
    return res.status(403).json({
      success: false,
      message: "CSRF protection: Missing security header",
    });
  }

  next();
}

module.exports = csrfProtection;
