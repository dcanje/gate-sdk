var middleware = require('./src/middleware');
var GateClient = require('./src/client');

module.exports = {
  createGateMiddleware: middleware.createGateMiddleware,
  requireRole: middleware.requireRole,
  requirePermission: middleware.requirePermission,
  clearValidationCache: middleware.clearValidationCache,
  GateClient: GateClient
};
