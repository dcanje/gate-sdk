const jwt = require('jsonwebtoken');
const axios = require('axios');

// Cache de validacion: email:tokenVersion -> { timestamp, valid }
var validationCache = new Map();
var DEFAULT_CACHE_TTL = 60 * 1000; // 60 segundos
var PUBLIC_KEY_TIMEOUT_MS = 5000;

async function descargarPublicKey(gateUrl) {
  var url = gateUrl.replace(/\/+$/, '') + '/auth/public-key';
  var res = await axios.get(url, { timeout: PUBLIC_KEY_TIMEOUT_MS });
  if (!res.data || !res.data.publicKey) {
    throw new Error('GATE /auth/public-key no devolvio un campo publicKey');
  }
  return res.data.publicKey;
}

function crearMiddlewareBypass() {
  return function gateAuthBypass(req, _res, next) {
    req.user = {
      email: '_local',
      name: 'Local Bypass',
      isRoot: true,
      role: 'admin',
      permissions: [],
      appId: '_local',
    };
    next();
  };
}

async function createGateMiddleware(options) {
  options = options || {};

  // Bypass opt-in explicito para desarrollo o ambientes sin GATE.
  if (options.bypass === true) {
    return crearMiddlewareBypass();
  }

  var appId = options.appId;
  var gateUrl = options.gateUrl;
  var publicKey = options.publicKey;

  // Fail-fast: no servir trafico sin auth cuando el deploy olvido configurar GATE.
  if (!appId || !gateUrl) {
    throw new Error(
      'createGateMiddleware: appId y gateUrl son requeridos. Para bypass de desarrollo, pasar { bypass: true }.'
    );
  }

  // Descargar public key si no se proveyo. Si falla, el server no arranca.
  if (!publicKey) {
    publicKey = await descargarPublicKey(gateUrl);
  }

  var validateWithGate = options.validateWithGate !== false;
  var cacheTtl = options.cacheTtl != null ? options.cacheTtl : DEFAULT_CACHE_TTL;
  // Seguro por default: si Gate no responde, NO dejamos pasar (preserva token versioning).
  var failOpenOnNetworkError = options.failOpenOnNetworkError === true;

  return function gateAuth(req, res, next) {
    // 0. Si GATE redirige al callback con ?gate_token=..., guardamos el token
    //    en una cookie httpOnly y redirigimos al mismo path SIN el query. Asi
    //    el JWT no queda en barra de direcciones, history del browser, logs
    //    de proxy ni en el header Referer de recursos externos.
    if (req.query && req.query.gate_token) {
      setearCookieToken(res, req.query.gate_token, esConexionSegura(req));
      var cleanQuery = Object.assign({}, req.query);
      delete cleanQuery.gate_token;
      var qs = new URLSearchParams(cleanQuery).toString();
      // Forzar el path a empezar con UN solo "/", evitando open redirect via
      // protocol-relative URL ("//evil.com/...") o backslash injection.
      var basePathRaw = (req.originalUrl || req.url || '/').split('?')[0];
      var pathSeguro = '/' + basePathRaw.replace(/^[\/\\]+/, '');
      var cleanUrl = pathSeguro + (qs ? '?' + qs : '');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Referrer-Policy', 'no-referrer');
      return res.redirect(cleanUrl);
    }

    // 1. Buscar token: header Authorization Bearer, o cookie gate_token.
    var token = null;
    var authHeader = req.headers.authorization;
    if (authHeader && authHeader.indexOf('Bearer ') === 0) {
      token = authHeader.substring(7);
    } else {
      var cookieToken = leerCookie(req, 'gate_token');
      if (cookieToken) token = cookieToken;
    }

    // 2. Sin token: HTML pide redirect a GATE, fetch/curl pide 401 JSON.
    if (!token) {
      var callbackUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
      var loginUrl = gateUrl + '/login?app=' + appId + '&callback=' + encodeURIComponent(callbackUrl);
      if (!aceptaHtml(req)) {
        return res.status(401).json({ error: 'No autenticado', loginUrl: loginUrl });
      }
      return res.redirect(loginUrl);
    }

    // 3. Verificar firma del token
    var decoded;
    try {
      decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        var loginUrlExp = gateUrl + '/login?app=' + appId;
        if (!aceptaHtml(req)) {
          return res.status(401).json({ error: 'Token expirado', loginUrl: loginUrlExp });
        }
        return res.redirect(loginUrlExp);
      }
      return res.status(401).json({ error: 'Token invalido' });
    }

    // 4. Verificar que el token es para esta app (root pasa siempre)
    if (!decoded.isRoot && decoded.appId && decoded.appId !== appId) {
      return res.status(403).json({ error: 'Token no valido para esta aplicacion' });
    }

    // 5. Validar contra Gate (invalidacion inmediata via tokenVersion)
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
      // 401 del endpoint validate = token invalidado.
      if (err.response && err.response.status === 401) {
        validationCache.set(cacheKey, { timestamp: now, valid: false });
        return res.status(401).json({ error: 'Token invalidado' });
      }
      // Error de red/timeout. Default fail-closed (preserva revocacion).
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

function leerCookie(req, nombre) {
  var cookies = (req.headers && req.headers.cookie) || '';
  var partes = cookies.split(';');
  for (var i = 0; i < partes.length; i++) {
    var c = partes[i];
    var idxIgual = c.indexOf('=');
    if (idxIgual < 0) continue;
    var k = c.substring(0, idxIgual).trim();
    if (k === nombre) {
      return decodeURIComponent(c.substring(idxIgual + 1).trim());
    }
  }
  return null;
}

function setearCookieToken(res, token, secure) {
  var flags = ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=14400'];
  if (secure) flags.push('Secure');
  res.setHeader('Set-Cookie', 'gate_token=' + encodeURIComponent(token) + '; ' + flags.join('; '));
}

function esConexionSegura(req) {
  if (req.protocol === 'https') return true;
  var xfp = req.headers && req.headers['x-forwarded-proto'];
  return xfp === 'https' || xfp === 'wss';
}

function aceptaHtml(req) {
  return ((req.headers && req.headers.accept) || '').indexOf('text/html') !== -1;
}

module.exports = {
  createGateMiddleware: createGateMiddleware,
  requireRole: requireRole,
  requirePermission: requirePermission,
  clearValidationCache: clearValidationCache,
  descargarPublicKey: descargarPublicKey,
};
