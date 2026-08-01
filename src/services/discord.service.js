const axios = require("axios");

const env = require("../config/env");

async function getDiscordUser(accessToken) {
  const response = await axios.get(
    "https://discord.com/api/users/@me",

    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  return response.data;
}

async function sendNotification(message) {
  if (!env.DISCORD_WEBHOOK) {
    return;
  }

  await axios.post(
    env.DISCORD_WEBHOOK,

    {
      content: message,
    }
  );
}

module.exports = {
  getDiscordUser,

  sendNotification,
};
