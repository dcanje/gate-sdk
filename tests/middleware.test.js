const { generateKeyPairSync } = require('crypto');
const jwt = require('jsonwebtoken');
const {
  createGateMiddleware,
  requireRole,
  requirePermission,
  clearValidationCache,
} = require('../index');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const APP_ID = 'mi-app';
const GATE_URL = 'http://localhost:3001';
const APP_SECRET = 'sdk-test-secret-' + 'a'.repeat(48);

function mockReqRes(opts) {
  opts = opts || {};
  var headers = Object.assign({ accept: 'text/html' }, opts.headers || {});
  var setHeaders = {};
  var setCookies = [];
  var redirectArg = null;
  var statusCode = 200;
  var jsonBody = null;
  var nextCalled = false;
  var nextErr = null;

  var req = {
    headers: headers,
    query: opts.query || {},
    protocol: opts.protocol || 'http',
    originalUrl: opts.originalUrl || '/',
    url: opts.url || opts.originalUrl || '/',
    get: function (h) {
      if (h === 'host') return opts.host || 'localhost:3000';
      return undefined;
    },
  };
  var res = {
    status: jest.fn(function (c) { statusCode = c; return res; }),
    json: jest.fn(function (b) { jsonBody = b; return res; }),
    redirect: jest.fn(function (url) { redirectArg = url; return res; }),
    setHeader: jest.fn(function (name, value) {
      setHeaders[name] = value;
      if (name === 'Set-Cookie') {
        setCookies = Array.isArray(value) ? value.slice() : [value];
      }
    }),
    getHeader: jest.fn(function (name) {
      return setHeaders[name];
    }),
  };
  var next = jest.fn(function (err) { nextCalled = true; nextErr = err; });
  return {
    req: req,
    res: res,
    next: next,
    get setHeaders() { return setHeaders; },
    get setCookies() { return setCookies; },
    get redirectArg() { return redirectArg; },
    get statusCode() { return statusCode; },
    get jsonBody() { return jsonBody; },
    get nextCalled() { return nextCalled; },
    get nextErr() { return nextErr; },
  };
}

describe('createGateMiddleware: validacion de inputs', () => {
  test('lanza si falta appId', async () => {
    await expect(createGateMiddleware({
      gateUrl: GATE_URL, appSecret: APP_SECRET, publicKey: publicKey,
    })).rejects.toThrow(/appId.*gateUrl.*appSecret/);
  });

  test('lanza si falta gateUrl', async () => {
    await expect(createGateMiddleware({
      appId: APP_ID, appSecret: APP_SECRET, publicKey: publicKey,
    })).rejects.toThrow(/appId.*gateUrl.*appSecret/);
  });

  test('lanza si falta appSecret', async () => {
    await expect(createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, publicKey: publicKey,
    })).rejects.toThrow(/appId.*gateUrl.*appSecret/);
  });

  test('bypass:true retorna middleware noop con req.user isRoot', async () => {
    const mw = await createGateMiddleware({ bypass: true });
    const m = mockReqRes();
    mw(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
    expect(m.req.user.isRoot).toBe(true);
    expect(m.req.user.email).toBe('_local');
  });

  test('bypass:true tiene precedencia sobre vars faltantes', async () => {
    const mw = await createGateMiddleware({ bypass: true, appId: '', gateUrl: '', appSecret: '' });
    const m = mockReqRes();
    mw(m.req, m.res, m.next);
    expect(m.req.user.isRoot).toBe(true);
  });

  test('bypass expone req.user.scopes = []', async () => {
    const mw = await createGateMiddleware({ bypass: true });
    const m = mockReqRes();
    mw(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
    expect(m.req.user.scopes).toEqual([]);
  });
});

describe('createGateMiddleware: verificacion de tokens', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: APP_ID,
      gateUrl: GATE_URL,
      appSecret: APP_SECRET,
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  test('pasa con token valido para la app correcta', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: APP_ID },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
    expect(m.req.user.email).toBe('user@apprecio.com');
  });

  test('rechaza token para otra app', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'otra-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });

  test('acepta token de root sin importar appId', () => {
    const token = jwt.sign(
      { email: 'root@apprecio.com', role: 'root', isRoot: true },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('retorna 401 con token invalido', () => {
    const m = mockReqRes({ headers: { authorization: 'Bearer token-basura' } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
  });

  test('lee token desde cookie gate_token si no hay header', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', appId: APP_ID },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { cookie: 'gate_token=' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('cookie con percent-encoding malformado no crashea (DoS fix)', () => {
    const m = mockReqRes({ headers: { cookie: 'gate_token=%ZZ' } });
    middleware(m.req, m.res, m.next);
    // Debe redirigir al login o dar 401, nunca lanzar excepcion
    expect(m.nextCalled).toBe(false);
    const respondio = m.redirectArg !== null || m.statusCode !== 200;
    expect(respondio).toBe(true);
  });

  test('JWT de panel admin (sin appId) es rechazado en app consumidora', () => {
    // El panel admin emite JWTs sin appId; no deben ser validos en apps consumidoras
    const adminPanelToken = jwt.sign(
      { email: 'admin@apprecio.com', name: 'Admin', isRoot: false, tokenVersion: 1 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + adminPanelToken } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
    expect(m.nextCalled).toBe(false);
  });
});

describe('createGateMiddleware: sin token genera state y redirige a /login', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: APP_ID,
      gateUrl: GATE_URL,
      appSecret: APP_SECRET,
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  test('HTML sin token → setea cookie gate_state httpOnly + redirect a /login?...&state=<hex>', () => {
    const m = mockReqRes({ headers: { accept: 'text/html' }, originalUrl: '/dashboard' });
    middleware(m.req, m.res, m.next);
    // Cookie state seteada
    const stateCookie = m.setCookies.find(c => c.startsWith('gate_state='));
    expect(stateCookie).toBeDefined();
    expect(stateCookie).toMatch(/HttpOnly/);
    expect(stateCookie).toMatch(/SameSite=Lax/);
    expect(stateCookie).toMatch(/Max-Age=600/);
    // El valor de la cookie debe ser hex de 64 chars
    const stateValue = decodeURIComponent(stateCookie.split('=')[1].split(';')[0]);
    expect(stateValue).toMatch(/^[a-f0-9]{64}$/);
    // Redirect a /login con app, callback y state
    expect(m.redirectArg).toMatch(new RegExp('^' + GATE_URL + '/login\\?'));
    expect(m.redirectArg).toContain('app=' + APP_ID);
    expect(m.redirectArg).toContain('callback=');
    expect(m.redirectArg).toContain('state=' + encodeURIComponent(stateValue));
  });

  test('JSON sin token → 401 con loginUrl + cookie state igualmente seteada', () => {
    const m = mockReqRes({ headers: { accept: 'application/json' } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
    expect(m.jsonBody.error).toMatch(/No autenticado/i);
    expect(m.jsonBody.loginUrl).toMatch(/state=/);
    const stateCookie = m.setCookies.find(c => c.startsWith('gate_state='));
    expect(stateCookie).toBeDefined();
  });

  test('cookie state tiene Secure cuando X-Forwarded-Proto: https', () => {
    const m = mockReqRes({ headers: { accept: 'text/html', 'x-forwarded-proto': 'https' } });
    middleware(m.req, m.res, m.next);
    const stateCookie = m.setCookies.find(c => c.startsWith('gate_state='));
    expect(stateCookie).toMatch(/Secure/);
  });
});

describe('createGateMiddleware: callback con ?code=&state=', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: APP_ID,
      gateUrl: GATE_URL,
      appSecret: APP_SECRET,
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  const validCode = 'a'.repeat(64);
  const validState = 'b'.repeat(64);

  test('rechaza con 400 si code tiene formato invalido', () => {
    const m = mockReqRes({
      query: { code: 'not-hex', state: validState },
      originalUrl: '/cb?code=not-hex&state=' + validState,
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(400);
    expect(m.jsonBody.error).toMatch(/code/i);
  });

  test('rechaza con 400 si state tiene formato invalido', () => {
    const m = mockReqRes({
      query: { code: validCode, state: 'not-hex' },
      originalUrl: '/cb',
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(400);
    expect(m.jsonBody.error).toMatch(/state/i);
  });

  // --- Cookie state ausente ---
  // Caso tipico: el callback quedo obsoleto (la cookie state caduco o fue
  // pisada por otra pestaña). En navegacion de browser recuperamos el login
  // limpio en vez de mostrar un JSON sin salida (Nivel B). Para API/SPA
  // mantenemos el 400 JSON (contrato intacto).

  test('navegacion browser con cookie state ausente → redirige a URL base limpia y borra cookie state', () => {
    const m = mockReqRes({
      headers: { accept: 'text/html' },
      query: { code: validCode, state: validState },
      originalUrl: '/dashboard?code=' + validCode + '&state=' + validState,
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg).toBe('/dashboard');
    const stateClear = m.setCookies.find(c => c.startsWith('gate_state=;'));
    expect(stateClear).toBeDefined();
    expect(stateClear).toMatch(/Max-Age=0/);
  });

  test('peticion no-HTML con cookie state ausente → 400 JSON', () => {
    const m = mockReqRes({
      headers: { accept: 'application/json' },
      query: { code: validCode, state: validState },
      originalUrl: '/cb',
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(400);
    expect(m.jsonBody.error).toMatch(/state CSRF: cookie ausente/i);
  });

  // --- State mismatch (CSRF / callback superado) ---

  test('navegacion browser con state mismatch → redirige a URL base limpia (Nivel B)', () => {
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + 'c'.repeat(64), accept: 'text/html' },
      query: { code: validCode, state: validState },
      originalUrl: '/panel?code=' + validCode + '&state=' + validState,
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg).toBe('/panel');
  });

  test('peticion no-HTML con state mismatch → 400 JSON (CSRF defense)', () => {
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + 'c'.repeat(64), accept: 'application/json' },
      query: { code: validCode, state: validState },
      originalUrl: '/cb',
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(400);
    expect(m.jsonBody.error).toMatch(/state CSRF: mismatch/i);
  });

  test('state de distinta longitud que la cookie se trata como mismatch (no-HTML → 400)', () => {
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + 'a'.repeat(64), accept: 'application/json' },
      query: { code: validCode, state: 'a'.repeat(32) },
      originalUrl: '/cb',
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(400);
  });

  test('recuperacion Nivel B normaliza open-redirect (//evil.com → /evil.com)', () => {
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + 'c'.repeat(64), accept: 'text/html' },
      query: { code: validCode, state: validState },
      originalUrl: '//evil.com/path?code=' + validCode + '&state=' + validState,
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg.startsWith('/')).toBe(true);
    expect(m.redirectArg.startsWith('//')).toBe(false);
  });
});

describe('requireRole', () => {
  test('pasa con rol correcto', () => {
    const m = mockReqRes();
    m.req.user = { email: 'u@apprecio.com', role: 'vendedor' };
    requireRole('vendedor', 'admin')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza rol incorrecto', () => {
    const m = mockReqRes();
    m.req.user = { email: 'u@apprecio.com', role: 'vendedor' };
    requireRole('admin')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });

  test('root pasa siempre', () => {
    const m = mockReqRes();
    m.req.user = { email: 'r@apprecio.com', role: 'root', isRoot: true };
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('retorna 401 si no hay usuario', () => {
    const m = mockReqRes();
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
  });
});

describe('requirePermission', () => {
  test('pasa si tiene el permiso', () => {
    const m = mockReqRes();
    m.req.user = { email: 'u@apprecio.com', permissions: ['view:dashboard'] };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza si falta un permiso', () => {
    const m = mockReqRes();
    m.req.user = { email: 'u@apprecio.com', permissions: ['view:dashboard'] };
    requirePermission('view:dashboard', 'edit:ventas')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });

  test('root pasa siempre sin importar permisos', () => {
    const m = mockReqRes();
    m.req.user = { email: 'r@apprecio.com', isRoot: true, permissions: [] };
    requirePermission('manage:usuarios')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('retorna 401 si no hay usuario', () => {
    const m = mockReqRes();
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
  });

  test('rechaza si usuario sin permisos definidos', () => {
    const m = mockReqRes();
    m.req.user = { email: 'u@apprecio.com' };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });
});

jest.mock('axios');
const axios = require('axios');

describe('validateWithGate (token versioning)', () => {
  beforeEach(() => {
    axios.get.mockReset();
    axios.post.mockReset();
    clearValidationCache();
  });

  test('consulta a Gate y pasa si valido', async () => {
    axios.get.mockResolvedValue({ data: { valid: true, tokenVersion: 2 } });
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'u@apprecio.com', role: 'vendedor', appId: APP_ID, tokenVersion: 2 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(axios.get).toHaveBeenCalledWith(GATE_URL + '/auth/validate', expect.any(Object));
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza 401 si Gate devuelve 401', async () => {
    const err = new Error('Unauthorized');
    err.response = { status: 401 };
    axios.get.mockRejectedValue(err);
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'u@apprecio.com', appId: APP_ID, tokenVersion: 1 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.statusCode).toBe(401);
  });

  test('fail-closed por default: 503 si Gate esta caido', async () => {
    axios.get.mockRejectedValue(new Error('ECONNREFUSED'));
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'u@apprecio.com', appId: APP_ID, tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.statusCode).toBe(503);
  });

  test('fail-open explicito permite pasar si failOpenOnNetworkError=true', async () => {
    axios.get.mockRejectedValue(new Error('ECONNREFUSED'));
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: true, failOpenOnNetworkError: true,
    });
    const token = jwt.sign(
      { email: 'u@apprecio.com', appId: APP_ID, tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.nextCalled).toBe(true);
  });
});

describe('callback con ?code=&state=: exchange exitoso', () => {
  beforeEach(() => {
    axios.get.mockReset();
    axios.post.mockReset();
  });

  test('valida state + POST /auth/exchange-code + setea cookie + redirect limpio', async () => {
    const validCode = 'd'.repeat(64);
    const validState = 'e'.repeat(64);
    const tokenJwt = jwt.sign(
      { email: 'u@apprecio.com', appId: APP_ID },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    axios.post.mockResolvedValue({ data: { token: tokenJwt, expiresIn: 14400 } });

    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: false,
    });
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + validState, accept: 'text/html' },
      query: { code: validCode, state: validState },
      originalUrl: '/dashboard?code=' + validCode + '&state=' + validState,
    });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 30));

    expect(axios.post).toHaveBeenCalledWith(
      GATE_URL + '/auth/exchange-code',
      { code: validCode, app: APP_ID, secret: APP_SECRET },
      expect.any(Object)
    );
    // Cookie gate_token con el JWT recibido
    const tokenCookie = m.setCookies.find(c => c.startsWith('gate_token='));
    expect(tokenCookie).toBeDefined();
    expect(tokenCookie).toMatch(/HttpOnly/);
    // Cookie gate_state borrada (Max-Age=0)
    const stateClear = m.setCookies.find(c => c.startsWith('gate_state=;') || c.startsWith('gate_state=;'));
    expect(stateClear).toBeDefined();
    expect(stateClear).toMatch(/Max-Age=0/);
    // Headers anti-leak
    expect(m.setHeaders['Cache-Control']).toBe('no-store');
    expect(m.setHeaders['Referrer-Policy']).toBe('no-referrer');
    // Redirect limpio: sin code ni state
    expect(m.redirectArg).toBe('/dashboard');
  });

  test('exchange fallido (401 desde GATE) devuelve el mismo status', async () => {
    const err = new Error('Unauthorized');
    err.response = { status: 401, data: { error: 'Code invalido o expirado' } };
    axios.post.mockRejectedValue(err);

    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: false,
    });
    const validCode = 'f'.repeat(64);
    const validState = 'a'.repeat(64);
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + validState },
      query: { code: validCode, state: validState },
      originalUrl: '/cb',
    });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 30));

    expect(m.statusCode).toBe(401);
  });

  test('exchange con response sin token devuelve 502', async () => {
    axios.post.mockResolvedValue({ data: {} });
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: false,
    });
    const validCode = '1'.repeat(64);
    const validState = '2'.repeat(64);
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + validState },
      query: { code: validCode, state: validState },
      originalUrl: '/cb',
    });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 30));

    expect(m.statusCode).toBe(502);
  });

  test('open redirect protection: //evil.com en originalUrl se normaliza', async () => {
    const tokenJwt = jwt.sign({ email: 'u@apprecio.com', appId: APP_ID }, privateKey, { algorithm: 'RS256' });
    axios.post.mockResolvedValue({ data: { token: tokenJwt, expiresIn: 14400 } });
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
      publicKey: publicKey, validateWithGate: false,
    });
    const validCode = 'a'.repeat(64);
    const validState = 'b'.repeat(64);
    const m = mockReqRes({
      headers: { cookie: 'gate_state=' + validState },
      query: { code: validCode, state: validState },
      originalUrl: '//evil.com/path?code=' + validCode + '&state=' + validState,
    });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 30));

    expect(m.redirectArg).toBeTruthy();
    expect(m.redirectArg.startsWith('/')).toBe(true);
    expect(m.redirectArg.startsWith('//')).toBe(false);
  });
});

describe('createGateMiddleware: descarga automatica de publicKey', () => {
  beforeEach(() => {
    axios.get.mockReset();
    axios.post.mockReset();
  });

  test('si no se pasa publicKey, la descarga al boot', async () => {
    const dummyKey = '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----';
    axios.get.mockResolvedValueOnce({ data: { publicKey: dummyKey } });
    const mw = await createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET, validateWithGate: false,
    });
    expect(axios.get).toHaveBeenCalledWith(GATE_URL + '/auth/public-key', expect.any(Object));
    expect(typeof mw).toBe('function');
  });

  test('si la descarga falla, lanza', async () => {
    axios.get.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
    await expect(createGateMiddleware({
      appId: APP_ID, gateUrl: GATE_URL, appSecret: APP_SECRET,
    })).rejects.toThrow();
  });
});
