const jwt = require("jsonwebtoken");

const env = require("../config/env");

function generateAccessToken(payload) {
  return jwt.sign(
    payload,

    env.JWT_SECRET,

    {
      expiresIn: "15m",
    }
  );
}

function generateRefreshToken(payload) {
  return jwt.sign(
    payload,

    env.JWT_SECRET,

    {
      expiresIn: env.JWT_EXPIRE,
    }
  );
}

function verifyToken(token) {
  return jwt.verify(
    token,

    env.JWT_SECRET
  );
}

module.exports = {
  generateAccessToken,

  generateRefreshToken,

  verifyToken,
};
