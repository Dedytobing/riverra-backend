const jwt = require("jsonwebtoken");

const env = require("../../config/env");

function authMiddleware(req, res, next) {
  try {
    let token;

    // ambil token dari cookie
    if (req.cookies?.access_token) {
      token = req.cookies.access_token;
    }

    // fallback Authorization Header
    else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,

        message: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, env.JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,

      message: "Invalid or expired token",
    });
  }
}

module.exports = authMiddleware;
