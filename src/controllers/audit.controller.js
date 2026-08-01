const auditService = require("../services/audit.service");

const { success } = require("../utils/response");

async function getLogs(req, res, next) {
  try {
    const logs = await auditService.getLogs();

    return success(
      res,

      logs
    );
  } catch (err) {
    next(err);
  }
}

async function createLog(req, res, next) {
  try {
    const log = await auditService.createLog({
      userId: req.user.id,

      action: req.body.action,

      module: req.body.module,

      detail: req.body.detail,
    });

    return success(
      res,

      log,

      "Audit created"
    );
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getLogs,

  createLog,
};
