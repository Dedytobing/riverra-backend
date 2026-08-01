const db = require("../config/database");

async function createBackup(name) {
  return await db.insert(
    "backups",

    {
      name,

      status: "completed",

      created_at: new Date(),
    }
  );
}

async function getBackups() {
  return await db.findAll("backups");
}

async function deleteBackup(id) {
  return await db.remove(
    "backups",

    {
      id,
    }
  );
}

module.exports = {
  createBackup,

  getBackups,

  deleteBackup,
};
