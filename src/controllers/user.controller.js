const userService = require("../services/user.service");

const { success } = require("../utils/response");

async function getUsers(req, res, next) {
  try {
    const users = await userService.getUsers();

    return success(
      res,

      users
    );
  } catch (err) {
    next(err);
  }
}

async function getUserById(req, res, next) {
  try {
    const user = await userService.getUserById(req.params.id);

    return success(
      res,

      user
    );
  } catch (err) {
    next(err);
  }
}

async function updateUser(req, res, next) {
  try {
    const user = await userService.updateUser(
      req.params.id,

      req.body
    );

    return success(
      res,

      user,

      "User updated"
    );
  } catch (err) {
    next(err);
  }
}

async function deleteUser(req, res, next) {
  try {
    await userService.deleteUser(req.params.id);

    return success(
      res,

      null,

      "User deleted"
    );
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getUsers,

  getUserById,

  updateUser,

  deleteUser,
};
