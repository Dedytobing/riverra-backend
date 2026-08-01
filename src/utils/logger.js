const env = require("../config/env");

function info(message, data = {}) {
  console.log(
    `[INFO] ${new Date().toISOString()}`,

    message,

    data
  );
}

function error(message, err = {}) {
  console.error(
    `[ERROR] ${new Date().toISOString()}`,

    message,

    err
  );
}

function debug(message, data = {}) {
  if (env.NODE_ENV !== "production") {
    console.log(
      `[DEBUG]`,

      message,

      data
    );
  }
}

module.exports = {
  info,

  error,

  debug,
};
