const env = require("../config/env");

function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie(
    "access_token",

    accessToken,

    {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: 15 * 60 * 1000,
    }
  );

  res.cookie(
    env.COOKIE_NAME,

    refreshToken,

    {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    }
  );
}

function clearAuthCookies(res) {
  res.clearCookie("access_token");

  res.clearCookie(env.COOKIE_NAME);
}

function getRefreshToken(req) {
  return req.cookies?.[env.COOKIE_NAME];
}

module.exports = {
  setAuthCookies,

  clearAuthCookies,

  getRefreshToken,
};
