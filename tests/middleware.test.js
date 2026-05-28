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

function mockReqRes(opts) {
  opts = opts || {};
  var headers = Object.assign({ accept: 'text/html' }, opts.headers || {});
  var setHeaders = {};
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
    setHeader: jest.fn(function (name, value) { setHeaders[name] = value; }),
  };
  var next = jest.fn(function (err) { nextCalled = true; nextErr = err; });
  return {
    req: req,
    res: res,
    next: next,
    get setHeaders() { return setHeaders; },
    get redirectArg() { return redirectArg; },
    get statusCode() { return statusCode; },
    get jsonBody() { return jsonBody; },
    get nextCalled() { return nextCalled; },
    get nextErr() { return nextErr; },
  };
}

describe('createGateMiddleware: validación de inputs', () => {
  test('lanza si falta appId', async () => {
    await expect(createGateMiddleware({
      gateUrl: 'http://localhost:3001', publicKey: publicKey,
    })).rejects.toThrow(/appId y gateUrl son requeridos/);
  });

  test('lanza si falta gateUrl', async () => {
    await expect(createGateMiddleware({
      appId: 'mi-app', publicKey: publicKey,
    })).rejects.toThrow(/appId y gateUrl son requeridos/);
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
    const mw = await createGateMiddleware({ bypass: true, appId: '', gateUrl: '' });
    const m = mockReqRes();
    mw(m.req, m.res, m.next);
    expect(m.req.user.isRoot).toBe(true);
  });
});

describe('createGateMiddleware: verificación de tokens', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://localhost:3001',
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  test('pasa con token valido para la app correcta', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
    expect(m.req.user.email).toBe('user@apprecio.com');
    expect(m.req.user.role).toBe('vendedor');
  });

  test('rechaza token para otra app', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'otra-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
    expect(m.nextCalled).toBe(false);
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
    const m = mockReqRes({ headers: { authorization: 'Bearer token-basura-invalido' } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
    expect(m.nextCalled).toBe(false);
  });
});

describe('createGateMiddleware: sin token (HTML vs no-HTML)', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://localhost:3001',
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  test('cliente HTML sin token → redirect a GATE login', () => {
    const m = mockReqRes({ headers: { accept: 'text/html' } });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg).toMatch(/\/login\?app=mi-app/);
    expect(m.nextCalled).toBe(false);
  });

  test('cliente JSON (fetch/curl) sin token → 401 JSON con loginUrl', () => {
    const m = mockReqRes({ headers: { accept: 'application/json' } });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
    expect(m.jsonBody).toMatchObject({ error: expect.stringMatching(/No autenticado/i) });
    expect(m.jsonBody.loginUrl).toMatch(/\/login\?app=mi-app/);
  });

  test('cliente HTML con token expirado → redirect a GATE', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '0s' }
    );
    const m = mockReqRes({
      headers: { accept: 'text/html', authorization: 'Bearer ' + token },
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg).toMatch(/\/login\?app=mi-app/);
  });
});

describe('createGateMiddleware: manejo del callback ?gate_token=...', () => {
  let middleware;
  beforeAll(async () => {
    middleware = await createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://localhost:3001',
      publicKey: publicKey,
      validateWithGate: false,
    });
  });

  function validToken(extra) {
    return jwt.sign(
      Object.assign({ email: 'u@apprecio.com', role: 'admin', appId: 'mi-app' }, extra || {}),
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
  }

  test('rechaza con 401 si el gate_token del query tiene firma inválida (anti session fixation)', () => {
    const m = mockReqRes({
      headers: { accept: 'text/html' },
      query: { gate_token: 'eyJ.fake.token' },
      originalUrl: '/dashboard?gate_token=eyJ.fake.token',
    });
    middleware(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
    expect(m.setHeaders['Set-Cookie']).toBeUndefined();
    expect(m.redirectArg).toBeNull();
  });

  test('JWT válido: extrae gate_token a cookie httpOnly y redirige a path limpio', () => {
    const tok = validToken();
    const m = mockReqRes({
      headers: { accept: 'text/html' },
      query: { gate_token: tok },
      originalUrl: '/dashboard?gate_token=' + tok,
    });
    middleware(m.req, m.res, m.next);
    expect(m.setHeaders['Set-Cookie']).toMatch(/^gate_token=/);
    expect(m.setHeaders['Set-Cookie']).toMatch(/HttpOnly/);
    expect(m.setHeaders['Set-Cookie']).toMatch(/SameSite=Lax/);
    expect(m.setHeaders['Set-Cookie']).not.toMatch(/Secure/);
    expect(m.setHeaders['Cache-Control']).toBe('no-store');
    expect(m.setHeaders['Referrer-Policy']).toBe('no-referrer');
    expect(m.redirectArg).toBe('/dashboard');
  });

  test('JWT válido + X-Forwarded-Proto: https → cookie con Secure', () => {
    const tok = validToken();
    const m = mockReqRes({
      headers: { accept: 'text/html', 'x-forwarded-proto': 'https' },
      query: { gate_token: tok },
      originalUrl: '/?gate_token=' + tok,
    });
    middleware(m.req, m.res, m.next);
    expect(m.setHeaders['Set-Cookie']).toMatch(/Secure/);
  });

  test('preserva los otros query params al limpiar gate_token', () => {
    const tok = validToken();
    const m = mockReqRes({
      query: { gate_token: tok, from: '2026-01-01', to: '2026-12-31' },
      originalUrl: '/reportes?gate_token=' + tok + '&from=2026-01-01&to=2026-12-31',
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg).not.toMatch(/gate_token/);
    expect(m.redirectArg).toMatch(/from=2026-01-01/);
    expect(m.redirectArg).toMatch(/to=2026-12-31/);
  });

  test('open redirect protection: //evil.com en originalUrl se normaliza a un solo /', () => {
    const tok = validToken();
    const m = mockReqRes({
      query: { gate_token: tok },
      originalUrl: '//evil.com/path?gate_token=' + tok,
    });
    middleware(m.req, m.res, m.next);
    expect(m.redirectArg.startsWith('/')).toBe(true);
    expect(m.redirectArg.startsWith('//')).toBe(false);
  });

  test('después del redirect-limpio, la siguiente request (con cookie) pasa', () => {
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({
      headers: { accept: 'text/html', cookie: 'gate_token=' + token },
    });
    middleware(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
    expect(m.req.user.email).toBe('user@apprecio.com');
  });
});

describe('requireRole', () => {
  test('pasa con rol correcto', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', role: 'vendedor' };
    requireRole('vendedor', 'admin')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza rol incorrecto', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', role: 'vendedor' };
    requireRole('admin')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });

  test('root pasa siempre', () => {
    const m = mockReqRes();
    m.req.user = { email: 'root@apprecio.com', role: 'root', isRoot: true };
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('retorna 401 si no hay usuario autenticado', () => {
    const m = mockReqRes();
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
    expect(m.nextCalled).toBe(false);
  });
});

describe('requirePermission', () => {
  test('pasa si tiene el permiso requerido', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard', 'edit:ventas'] };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('pasa si tiene todos los permisos requeridos', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard', 'edit:ventas'] };
    requirePermission('view:dashboard', 'edit:ventas')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza si falta un permiso', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard'] };
    requirePermission('view:dashboard', 'edit:ventas')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
    expect(m.nextCalled).toBe(false);
  });

  test('root pasa siempre sin importar permisos', () => {
    const m = mockReqRes();
    m.req.user = { email: 'root@apprecio.com', isRoot: true, permissions: [] };
    requirePermission('manage:usuarios')(m.req, m.res, m.next);
    expect(m.nextCalled).toBe(true);
  });

  test('retorna 401 si no hay usuario', () => {
    const m = mockReqRes();
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(401);
  });

  test('rechaza si usuario no tiene permisos definidos', () => {
    const m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com' };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.statusCode).toBe(403);
  });
});

jest.mock('axios');
const axios = require('axios');

describe('validateWithGate (token versioning)', () => {
  beforeEach(() => {
    axios.get.mockReset();
    clearValidationCache();
  });

  test('consulta a Gate y pasa si token es valido', async () => {
    axios.get.mockResolvedValue({ data: { valid: true, tokenVersion: 2 } });
    const mw = await createGateMiddleware({
      appId: 'mi-app', gateUrl: 'http://gate.test',
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 2 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(axios.get).toHaveBeenCalledWith('http://gate.test/auth/validate', expect.any(Object));
    expect(m.nextCalled).toBe(true);
  });

  test('rechaza con 401 si Gate devuelve 401 (token invalidado)', async () => {
    const err = new Error('Unauthorized');
    err.response = { status: 401 };
    axios.get.mockRejectedValue(err);
    const mw = await createGateMiddleware({
      appId: 'mi-app', gateUrl: 'http://gate.test',
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 1 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.statusCode).toBe(401);
    expect(m.nextCalled).toBe(false);
  });

  test('fail-closed por default: 503 si Gate esta caido', async () => {
    const err = new Error('ECONNREFUSED');
    axios.get.mockRejectedValue(err);
    const mw = await createGateMiddleware({
      appId: 'mi-app', gateUrl: 'http://gate.test',
      publicKey: publicKey, validateWithGate: true,
    });
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.statusCode).toBe(503);
    expect(m.nextCalled).toBe(false);
  });

  test('fail-open explicito: pasa si failOpenOnNetworkError=true', async () => {
    const err = new Error('ECONNREFUSED');
    axios.get.mockRejectedValue(err);
    const mw = await createGateMiddleware({
      appId: 'mi-app', gateUrl: 'http://gate.test',
      publicKey: publicKey, validateWithGate: true, failOpenOnNetworkError: true,
    });
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(m.nextCalled).toBe(true);
  });

  test('cacheTtl:0 consulta siempre a Gate', async () => {
    axios.get.mockResolvedValue({ data: { valid: true, tokenVersion: 0 } });
    const mw = await createGateMiddleware({
      appId: 'mi-app', gateUrl: 'http://gate.test',
      publicKey: publicKey, validateWithGate: true, cacheTtl: 0,
    });
    const token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    const m1 = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    const m2 = mockReqRes({ headers: { authorization: 'Bearer ' + token } });
    mw(m1.req, m1.res, m1.next);
    await new Promise(resolve => setTimeout(resolve, 30));
    mw(m2.req, m2.res, m2.next);
    await new Promise(resolve => setTimeout(resolve, 30));
    expect(axios.get).toHaveBeenCalledTimes(2);
  });
});

describe('createGateMiddleware: descarga automatica de publicKey', () => {
  beforeEach(() => {
    axios.get.mockReset();
  });

  test('si no se pasa publicKey, la descarga de {gateUrl}/auth/public-key', async () => {
    const dummyKey = '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----';
    axios.get.mockResolvedValueOnce({ data: { publicKey: dummyKey } });
    const mw = await createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      // publicKey omitido
      validateWithGate: false,
    });
    expect(axios.get).toHaveBeenCalledWith(
      'http://gate.test/auth/public-key',
      expect.any(Object)
    );
    expect(typeof mw).toBe('function');
  });

  test('si la descarga falla, lanza error (no arranca el server)', async () => {
    axios.get.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
    await expect(createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
    })).rejects.toThrow();
  });
});
