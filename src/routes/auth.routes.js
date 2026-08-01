const express = require("express");

const router = express.Router();

const authController = require("../controllers/auth.controller");

const { loginLimiter } = require("../middleware/rateLimit.middleware");

// POST /api/auth/login

router.post(
  "/login",

  loginLimiter,

  authController.login
);

// POST /api/auth/refresh

router.post(
  "/refresh",

  authController.refreshToken
);

// POST /api/auth/logout

router.post(
  "/logout",

  authController.logout
);

module.exports = router;
