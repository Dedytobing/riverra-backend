const db = require("../config/database");

async function createLog({
  userId,

  action,

  module,

  detail,
}) {
  return await db.insert(
    "audit_logs",

    {
      user_id: userId,

      action,

      module,

      detail,

      created_at: new Date(),
    }
  );
}

async function getLogs() {
  return await db.findAll("audit_logs");
}

module.exports = {
  createLog,

  getLogs,
};
