const rateLimit = require("express-rate-limit");

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  max: 200,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    success: false,

    message: "Too many requests, try again later",
  },
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,

  max: 10,

  message: {
    success: false,

    message: "Too many login attempts",
  },
});

module.exports = {
  globalLimiter,

  loginLimiter,
};
