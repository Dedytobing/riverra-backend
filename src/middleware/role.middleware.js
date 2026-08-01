router.get("/admin", authMiddleware, roleMiddleware("admin"), controller);

function roleMiddleware(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,

        message: "Unauthorized",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,

        message: "Access forbidden",
      });
    }

    next();
  };
}

module.exports = roleMiddleware;
