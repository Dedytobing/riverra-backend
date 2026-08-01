const authService = require("../services/auth.service");

const { success, error } = require("../utils/response");

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const user = await authService.login(
      email,

      password,

      res
    );

    return success(
      res,

      user,

      "Login successful"
    );
  } catch (err) {
    next(err);
  }
}

async function refreshToken(req, res, next) {
  try {
    await authService.refreshToken(
      req,

      res
    );

    return success(
      res,

      null,

      "Token refreshed"
    );
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    await authService.logout(
      req,

      res
    );

    return success(
      res,

      null,

      "Logout successful"
    );
  } catch (err) {
    next(err);
  }
}

module.exports = {
  login,

  refreshToken,

  logout,
};
