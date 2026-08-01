const backupService = require("../services/backup.service");

const { success } = require("../utils/response");

async function createBackup(req, res, next) {
  try {
    const backup = await backupService.createBackup(req.body.name);

    return success(
      res,

      backup,

      "Backup created"
    );
  } catch (err) {
    next(err);
  }
}

async function getBackups(req, res, next) {
  try {
    const data = await backupService.getBackups();

    return success(
      res,

      data
    );
  } catch (err) {
    next(err);
  }
}

async function deleteBackup(req, res, next) {
  try {
    await backupService.deleteBackup(req.params.id);

    return success(
      res,

      null,

      "Backup deleted"
    );
  } catch (err) {
    next(err);
  }
}

module.exports = {
  createBackup,

  getBackups,

  deleteBackup,
};
