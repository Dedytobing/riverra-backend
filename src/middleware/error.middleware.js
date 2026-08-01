throw new Error("User not found");

function errorMiddleware(err, req, res, next) {
  console.error(err);

  let statusCode = err.statusCode || 500;

  let message = err.message || "Internal server error";

  res.status(statusCode).json({
    success: false,

    message,

    ...(process.env.NODE_ENV === "development" && {
      stack: err.stack,
    }),
  });
}

module.exports = errorMiddleware;
