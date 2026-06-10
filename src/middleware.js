const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const axios = require('axios');

// Cache de validacion: email:tokenVersion -> { timestamp, valid }
var validationCache = new Map();
var DEFAULT_CACHE_TTL = 60 * 1000;          // 60 segundos
var PUBLIC_KEY_TIMEOUT_MS = 5000;
var STATE_TTL_SECONDS = 600;                // 10 minutos para completar el login
var EXCHANGE_TIMEOUT_MS = 5000;
var CODE_FORMAT = /^[a-f0-9]{64}$/;
var STATE_FORMAT = /^[a-f0-9]{64}$/;

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
  var appSecret = options.appSecret;
  var publicKey = options.publicKey;

  // Fail-fast: no servir trafico sin auth cuando el deploy olvido configurar GATE.
  // appSecret es necesario para el intercambio server-to-server del code por el JWT.
  if (!appId || !gateUrl || !appSecret) {
    throw new Error(
      'createGateMiddleware: appId, gateUrl y appSecret son requeridos. Para bypass de desarrollo, pasar { bypass: true }.'
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
    // 0. ¿Es el callback de GATE? Detectamos por presencia de ?code= y ?state=.
    //    En ese caso validamos state, intercambiamos code por JWT via POST
    //    server-to-server y seteamos cookie con el JWT recibido en el body.
    //    El JWT nunca aparece en una URL en este flow.
    if (req.query && req.query.code && req.query.state) {
      return manejarCallbackCode(req, res, next, {
        gateUrl: gateUrl,
        appId: appId,
        appSecret: appSecret,
      });
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

    // 2. Sin token: generamos state CSRF, lo guardamos en cookie httpOnly y
    //    redirigimos a /login con state en query. Si Accept no es text/html,
    //    respondemos 401 JSON con loginUrl (la cookie state igual queda
    //    seteada para que la SPA pueda hacer location.href al loginUrl).
    if (!token) {
      var state = crypto.randomBytes(32).toString('hex');
      setearCookieState(res, state, esConexionSegura(req));
      var callbackUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
      var loginUrl = gateUrl.replace(/\/+$/, '')
        + '/login?app=' + encodeURIComponent(appId)
        + '&callback=' + encodeURIComponent(callbackUrl)
        + '&state=' + encodeURIComponent(state);
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
        // Token expirado: arrancar otro flow de login (con state nuevo).
        var newState = crypto.randomBytes(32).toString('hex');
        setearCookieState(res, newState, esConexionSegura(req));
        var callbackExp = req.protocol + '://' + req.get('host') + req.originalUrl;
        var loginUrlExp = gateUrl.replace(/\/+$/, '')
          + '/login?app=' + encodeURIComponent(appId)
          + '&callback=' + encodeURIComponent(callbackExp)
          + '&state=' + encodeURIComponent(newState);
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

    axios.get(gateUrl.replace(/\/+$/, '') + '/auth/validate', {
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
      if (err.response && err.response.status === 401) {
        validationCache.set(cacheKey, { timestamp: now, valid: false });
        return res.status(401).json({ error: 'Token invalidado' });
      }
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

// Maneja el callback OAuth: ?code=&state= en la URL.
// 1) valida formato y state CSRF, 2) intercambia code por JWT server-to-server,
// 3) setea cookie con JWT, borra cookie state, redirige limpio.
function manejarCallbackCode(req, res, _next, opts) {
  var code = req.query.code;
  var state = req.query.state;

  if (typeof code !== 'string' || !CODE_FORMAT.test(code)) {
    return res.status(400).json({ error: 'code con formato invalido' });
  }
  if (typeof state !== 'string' || !STATE_FORMAT.test(state)) {
    return res.status(400).json({ error: 'state con formato invalido' });
  }

  // El state debe coincidir con la cookie que seteamos antes del redirect al
  // login. Sin esto: session fixation con JWT firmado por GATE pero emitido
  // para el atacante (este pasa el codigo a la victima).
  var cookieState = leerCookie(req, 'gate_state');
  if (!cookieState) {
    return recuperarCallbackObsoleto(req, res, 'state CSRF: cookie ausente');
  }
  var a = Buffer.from(state);
  var b = Buffer.from(cookieState);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return recuperarCallbackObsoleto(req, res, 'state CSRF: mismatch');
  }

  // Intercambiar code por JWT server-to-server. El secret NUNCA viaja por el
  // browser del usuario; solo el server de la app lo conoce.
  axios.post(
    opts.gateUrl.replace(/\/+$/, '') + '/auth/exchange-code',
    { code: code, app: opts.appId, secret: opts.appSecret },
    { timeout: EXCHANGE_TIMEOUT_MS }
  ).then(function (response) {
    var token = response.data && response.data.token;
    var expiresIn = response.data && response.data.expiresIn;
    if (!token) {
      return res.status(502).json({ error: 'GATE no devolvio token al exchange' });
    }
    setearCookieToken(res, token, esConexionSegura(req), expiresIn);
    borrarCookieState(res, esConexionSegura(req));

    // Headers anti-leak: el redirect 302 a la URL limpia evita que el browser
    // guarde la URL con ?code= en history; no-store frena caches intermedias
    // y no-referrer corta el header Referer hacia recursos externos.
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');

    return res.redirect(urlBaseLimpia(req));
  }).catch(function (err) {
    var status = (err.response && err.response.status) || 502;
    var message = (err.response && err.response.data && err.response.data.error)
      || 'Error al intercambiar code con GATE';
    return res.status(status).json({ error: message });
  });
}

function requireRole() {
  var roles = Array.prototype.slice.call(arguments);
  return function (req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'No autenticado' });
    if (req.user.isRoot) return next();
    if (roles.indexOf(req.user.role) !== -1) return next();
    return res.status(403).json({ error: 'Sin permisos' });
  };
}

function requirePermission() {
  var requiredPerms = Array.prototype.slice.call(arguments);
  return function (req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'No autenticado' });
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

function setearCookieToken(res, token, secure, expiresInSeconds) {
  var maxAge = Number.isFinite(expiresInSeconds) && expiresInSeconds > 0
    ? expiresInSeconds
    : 14400; // 4 horas por default
  var flags = ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=' + maxAge];
  if (secure) flags.push('Secure');
  appendSetCookie(res, 'gate_token=' + encodeURIComponent(token) + '; ' + flags.join('; '));
}

function setearCookieState(res, state, secure) {
  var flags = ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=' + STATE_TTL_SECONDS];
  if (secure) flags.push('Secure');
  appendSetCookie(res, 'gate_state=' + encodeURIComponent(state) + '; ' + flags.join('; '));
}

function borrarCookieState(res, secure) {
  var flags = ['HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0'];
  if (secure) flags.push('Secure');
  appendSetCookie(res, 'gate_state=; ' + flags.join('; '));
}

// Cookies multiples requieren un array en Set-Cookie. Si ya hay una, lo
// convertimos para no pisarla.
function appendSetCookie(res, cookieValue) {
  var existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', cookieValue);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', existing.concat([cookieValue]));
    return;
  }
  res.setHeader('Set-Cookie', [existing, cookieValue]);
}

function esConexionSegura(req) {
  if (req.protocol === 'https') return true;
  var xfp = req.headers && req.headers['x-forwarded-proto'];
  return xfp === 'https' || xfp === 'wss';
}

function aceptaHtml(req) {
  return ((req.headers && req.headers.accept) || '').indexOf('text/html') !== -1;
}

// URL base del request sin los parametros code/state del callback OAuth.
// Normaliza el path para evitar open-redirect (// -> /). La usan tanto el
// callback exitoso como la recuperacion de callbacks obsoletos.
function urlBaseLimpia(req) {
  var cleanQuery = Object.assign({}, req.query);
  delete cleanQuery.code;
  delete cleanQuery.state;
  var qs = new URLSearchParams(cleanQuery).toString();
  var basePathRaw = (req.originalUrl || req.url || '/').split('?')[0];
  var pathSeguro = '/' + basePathRaw.replace(/^[\/\\]+/, '');
  return pathSeguro + (qs ? '?' + qs : '');
}

// Callback OAuth obsoleto: el state no calza con la cookie (mismatch) o la
// cookie ya no esta (caducada o pisada por otra pestaña/poll). En navegacion
// de browser, en vez de un JSON 400 sin salida, borramos la cookie state stale
// y redirigimos a la URL base limpia: el proximo request sin code/state arranca
// un login fresco. Es seguro: al no canjear el code no hay session fixation.
// Para peticiones no-HTML (API/SPA) mantenemos el 400 JSON (contrato intacto).
function recuperarCallbackObsoleto(req, res, errorMsg) {
  if (aceptaHtml(req)) {
    borrarCookieState(res, esConexionSegura(req));
    return res.redirect(urlBaseLimpia(req));
  }
  return res.status(400).json({ error: errorMsg });
}

module.exports = {
  createGateMiddleware: createGateMiddleware,
  requireRole: requireRole,
  requirePermission: requirePermission,
  clearValidationCache: clearValidationCache,
  descargarPublicKey: descargarPublicKey,
};
