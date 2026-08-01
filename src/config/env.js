require("dotenv").config();

const env = {
  PORT: process.env.PORT || 3000,

  NODE_ENV: process.env.NODE_ENV || "development",

  SUPABASE_URL: process.env.SUPABASE_URL,

  SUPABASE_KEY: process.env.SUPABASE_KEY,

  JWT_SECRET: process.env.JWT_SECRET,

  JWT_EXPIRE: process.env.JWT_EXPIRE || "7d",

  COOKIE_NAME: process.env.COOKIE_NAME || "refresh_token",

  DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID,

  DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET,

  DISCORD_REDIRECT_URI: process.env.DISCORD_REDIRECT_URI,
};

const required = ["SUPABASE_URL", "SUPABASE_KEY", "JWT_SECRET"];

required.forEach((key) => {
  if (!env[key]) {
    throw new Error(`Missing environment variable: ${key}`);
  }
});

module.exports = env;
