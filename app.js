const { globalLimiter } = require("./src/middleware/rateLimit.middleware");

app.use(globalLimiter);

app.use(errorMiddleware);
