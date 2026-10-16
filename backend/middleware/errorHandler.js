/**
 * SafeBrowse Global Error Handling Middleware
 * Prevents information leakage and stack trace exposure while logging securely.
 */

function errorHandler(err, req, res, next) {
  // If response has already started streaming, delegate to default Express handler
  if (res.headersSent) {
    return next(err);
  }

  const isProduction = process.env.NODE_ENV === "production";

  // Log error internally without exposing sensitive values
  console.error(`[SafeBrowse Server Error] ${req.method} ${req.url}:`, err.message);

  const status = err.status || err.statusCode || 500;
  const message = (isProduction && status === 500)
    ? "An unexpected internal server error occurred."
    : err.message || "An unexpected error occurred.";

  res.status(status).json({
    error: message,
    statusCode: status
  });
}

module.exports = {
  errorHandler
};
