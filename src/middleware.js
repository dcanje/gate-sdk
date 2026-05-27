const jwt = require('jsonwebtoken');
const axios = require('axios');

// Cache de validacion: email:tokenVersion -> { timestamp, valid }
var validationCache = new Map();
var DEFAULT_CACHE_TTL = 60 * 1000; // 60 segundos

function createGateMiddleware(options) {
  var appId = options.appId;
  var gateUrl = options.gateUrl;
  var publicKey = options.publicKey;
  var validateWithGate = options.validateWithGate !== false; // default true
  var cacheTtl = options.cacheTtl != null ? options.cacheTtl : DEFAULT_CACHE_TTL;
  // Seguro por default: si Gate no responde, NO dejamos pasar (anula token versioning).
  // Las apps que prioricen disponibilidad sobre seguridad pueden opt-in con true.
  var failOpenOnNetworkError = options.failOpenOnNetworkError === true;

  return function gateAuth(req, res, next) {
    // 1. Buscar token en header o query param
    var token = null;
    var authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.query.gate_token) {
      token = req.query.gate_token;
    }

    // 2. Sin token — redirigir a Gate login
    if (!token) {
      var callbackUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
      return res.redirect(gateUrl + '/login?app=' + appId + '&callback=' + encodeURIComponent(callbackUrl));
    }

    // 3. Verificar firma del token
    var decoded;
    try {
      decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.redirect(gateUrl + '/login?app=' + appId);
      }
      return res.status(401).json({ error: 'Token invalido' });
    }

    // 4. Verificar que el token es para esta app (root pasa siempre)
    if (!decoded.isRoot && decoded.appId && decoded.appId !== appId) {
      return res.status(403).json({ error: 'Token no valido para esta aplicacion' });
    }

    // 5. Validar contra Gate (invalidacion inmediata)
    if (!validateWithGate) {
      req.user = decoded;
      return next();
    }

    var cacheKey = decoded.email + ':' + (decoded.tokenVersion || 0);
    var cached = validationCache.get(cacheKey);
    var now = Date.now();

    if (cached && (now - cached.timestamp) < cacheTtl) {
      if (!cached.valid) {
        return res.status(401).json({ error: 'Token invalidado' });
      }
      req.user = decoded;
      return next();
    }

    // Consultar a Gate
    axios.get(gateUrl + '/auth/validate', {
      headers: { Authorization: 'Bearer ' + token },
      timeout: 3000
    }).then(function (response) {
      if (response.data && response.data.valid) {
        validationCache.set(cacheKey, { timestamp: now, valid: true });
        req.user = decoded;
        next();
      } else {
        validationCache.set(cacheKey, { timestamp: now, valid: false });
        res.status(401).json({ error: 'Token invalidado' });
      }
    }).catch(function (err) {
      // 401 del endpoint validate = token invalidado
      if (err.response && err.response.status === 401) {
        validationCache.set(cacheKey, { timestamp: now, valid: false });
        return res.status(401).json({ error: 'Token invalidado' });
      }
      // Error de red/timeout. Comportamiento por default: FAIL-CLOSED (503).
      // Esto preserva la garantia de revocacion inmediata via tokenVersion.
      if (failOpenOnNetworkError) {
        req.user = decoded;
        return next();
      }
      return res.status(503).json({
        error: 'Servicio de autenticacion no disponible. Intenta nuevamente en unos segundos.'
      });
    });
  };
}

function requireRole() {
  var roles = Array.prototype.slice.call(arguments);
  return function (req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: 'No autenticado' });
    }
    if (req.user.isRoot) return next();
    if (roles.indexOf(req.user.role) !== -1) return next();
    return res.status(403).json({ error: 'Sin permisos' });
  };
}

function requirePermission() {
  var requiredPerms = Array.prototype.slice.call(arguments);
  return function (req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: 'No autenticado' });
    }
    if (req.user.isRoot) return next();
    var userPerms = req.user.permissions || [];
    var hasAll = requiredPerms.every(function (p) {
      return userPerms.indexOf(p) !== -1;
    });
    if (hasAll) return next();
    return res.status(403).json({ error: 'Sin permisos para esta accion' });
  };
}

function clearValidationCache() {
  validationCache.clear();
}

module.exports = {
  createGateMiddleware: createGateMiddleware,
  requireRole: requireRole,
  requirePermission: requirePermission,
  clearValidationCache: clearValidationCache
};
