const db = require("../config/database");

async function getUserById(id) {
  return await db.findOne(
    "users",

    {
      id,
    }
  );
}

async function getUsers() {
  return await db.findAll("users");
}

async function updateUser(
  id,

  payload
) {
  return await db.update(
    "users",

    {
      id,
    },

    payload
  );
}

async function deleteUser(id) {
  return await db.remove(
    "users",

    {
      id,
    }
  );
}

module.exports = {
  getUserById,

  getUsers,

  updateUser,

  deleteUser,
};
