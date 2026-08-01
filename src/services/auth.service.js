const db = require("../config/database");

const {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
} = require("../utils/jwt");

const {
  setAuthCookies,
  clearAuthCookies,
  getRefreshToken,
} = require("../utils/cookie");

async function login(email, password, res) {
  const user = await db.findOne("users", {
    email,
  });

  if (!user) {
    throw new Error("User not found");
  }

  /*
        Password validation
        sesuaikan dengan
        bcrypt di project lama
    */

  if (user.password !== password) {
    throw new Error("Invalid password");
  }

  const payload = {
    id: user.id,

    email: user.email,

    role: user.role,
  };

  const accessToken = generateAccessToken(payload);

  const refreshToken = generateRefreshToken(payload);

  await db.insert(
    "sessions",

    {
      user_id: user.id,

      refresh_token: refreshToken,
    }
  );

  setAuthCookies(
    res,

    accessToken,

    refreshToken
  );

  return user;
}

async function refreshToken(req, res) {
  const token = getRefreshToken(req);

  if (!token) {
    throw new Error("Refresh token missing");
  }

  const decoded = verifyToken(token);

  const accessToken = generateAccessToken({
    id: decoded.id,

    email: decoded.email,

    role: decoded.role,
  });

  setAuthCookies(
    res,

    accessToken,

    token
  );

  return true;
}

async function logout(req, res) {
  const token = getRefreshToken(req);

  if (token) {
    await db.remove(
      "sessions",

      {
        refresh_token: token,
      }
    );
  }

  clearAuthCookies(res);

  return true;
}

module.exports = {
  login,

  refreshToken,

  logout,
};
