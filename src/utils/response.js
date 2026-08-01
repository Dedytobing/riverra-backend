function success(
  res,

  data,

  message = "Success",

  statusCode = 200
) {
  return res.status(statusCode).json({
    success: true,

    message,

    data,
  });
}

function error(
  res,

  message = "Error",

  statusCode = 500,

  errors = null
) {
  return res.status(statusCode).json({
    success: false,

    message,

    errors,
  });
}

module.exports = {
  success,

  error,
};
