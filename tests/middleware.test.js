const { generateKeyPairSync } = require('crypto');
const jwt = require('jsonwebtoken');
const { createGateMiddleware, requireRole, requirePermission } = require('../index');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Tests usan validateWithGate:false para testear solo verificacion de firma
// sin consultar a Gate. La validacion periodica se testea por separado.
const middleware = createGateMiddleware({
  appId: 'mi-app',
  gateUrl: 'http://localhost:3001',
  publicKey: publicKey,
  validateWithGate: false
});

function mockReqRes(headers) {
  headers = headers || {};
  return {
    req: { headers: headers, query: {}, protocol: 'http', get: function() { return 'localhost'; }, originalUrl: '/' },
    res: {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      redirect: jest.fn()
    },
    next: jest.fn()
  };
}

describe('gate-sdk middleware', () => {
  test('pasa con token valido para la app correcta', () => {
    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });
    middleware(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
    expect(m.req.user.email).toBe('user@apprecio.com');
    expect(m.req.user.role).toBe('vendedor');
  });

  test('rechaza token para otra app', () => {
    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'otra-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });
    middleware(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(403);
    expect(m.next).not.toHaveBeenCalled();
  });

  test('redirige sin token', () => {
    var m = mockReqRes({});
    middleware(m.req, m.res, m.next);
    expect(m.res.redirect).toHaveBeenCalled();
    expect(m.next).not.toHaveBeenCalled();
  });

  test('acepta token de root sin importar appId', () => {
    var token = jwt.sign(
      { email: 'root@apprecio.com', role: 'root', isRoot: true },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });
    middleware(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });
});

describe('requireRole', () => {
  test('pasa con rol correcto', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', role: 'vendedor' };
    requireRole('vendedor', 'admin')(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });

  test('rechaza rol incorrecto', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', role: 'vendedor' };
    requireRole('admin')(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(403);
  });

  test('root pasa siempre', () => {
    var m = mockReqRes();
    m.req.user = { email: 'root@apprecio.com', role: 'root', isRoot: true };
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });

  test('retorna 401 si no hay usuario autenticado', () => {
    var m = mockReqRes();
    requireRole('vendedor')(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(401);
    expect(m.next).not.toHaveBeenCalled();
  });
});

describe('gate-sdk middleware - edge cases', () => {
  test('acepta token desde query param gate_token', () => {
    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({});
    m.req.query = { gate_token: token };
    middleware(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
    expect(m.req.user.email).toBe('user@apprecio.com');
  });

  test('redirige con token expirado', () => {
    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app' },
      privateKey, { algorithm: 'RS256', expiresIn: '0s' }
    );
    // Pequeña espera para que expire
    var m = mockReqRes({ authorization: 'Bearer ' + token });
    middleware(m.req, m.res, m.next);
    expect(m.res.redirect).toHaveBeenCalled();
    expect(m.next).not.toHaveBeenCalled();
  });

  test('retorna 401 con token invalido', () => {
    var m = mockReqRes({ authorization: 'Bearer token-basura-invalido' });
    middleware(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(401);
    expect(m.next).not.toHaveBeenCalled();
  });
});

describe('requirePermission', () => {
  test('pasa si tiene el permiso requerido', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard', 'edit:ventas'] };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });

  test('pasa si tiene todos los permisos requeridos', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard', 'edit:ventas'] };
    requirePermission('view:dashboard', 'edit:ventas')(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });

  test('rechaza si falta un permiso', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com', permissions: ['view:dashboard'] };
    requirePermission('view:dashboard', 'edit:ventas')(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(403);
    expect(m.next).not.toHaveBeenCalled();
  });

  test('root pasa siempre sin importar permisos', () => {
    var m = mockReqRes();
    m.req.user = { email: 'root@apprecio.com', isRoot: true, permissions: [] };
    requirePermission('manage:usuarios')(m.req, m.res, m.next);
    expect(m.next).toHaveBeenCalled();
  });

  test('retorna 401 si no hay usuario', () => {
    var m = mockReqRes();
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(401);
  });

  test('rechaza si usuario no tiene permisos definidos', () => {
    var m = mockReqRes();
    m.req.user = { email: 'user@apprecio.com' };
    requirePermission('view:dashboard')(m.req, m.res, m.next);
    expect(m.res.status).toHaveBeenCalledWith(403);
  });
});

jest.mock('axios');
const axios = require('axios');

describe('validateWithGate (token versioning)', () => {
  const { clearValidationCache } = require('../index');

  beforeEach(() => {
    axios.get.mockReset();
    clearValidationCache();
  });

  test('consulta a Gate y pasa si token es valido', async () => {
    axios.get.mockResolvedValue({ data: { valid: true, tokenVersion: 2 } });

    const mw = createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      publicKey: publicKey,
      validateWithGate: true
    });

    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 2 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(axios.get).toHaveBeenCalledWith('http://gate.test/auth/validate', expect.any(Object));
    expect(m.next).toHaveBeenCalled();
  });

  test('rechaza con 401 si Gate devuelve 401 (token invalidado)', async () => {
    const err = new Error('Unauthorized');
    err.response = { status: 401 };
    axios.get.mockRejectedValue(err);

    const mw = createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      publicKey: publicKey,
      validateWithGate: true
    });

    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 1 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(m.res.status).toHaveBeenCalledWith(401);
    expect(m.next).not.toHaveBeenCalled();
  });

  test('fail-closed por default: devuelve 503 si Gate esta caido', async () => {
    const err = new Error('ECONNREFUSED');
    axios.get.mockRejectedValue(err);

    const mw = createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      publicKey: publicKey,
      validateWithGate: true
    });

    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(m.res.status).toHaveBeenCalledWith(503);
    expect(m.next).not.toHaveBeenCalled();
  });

  test('fail-open explicito: permite pasar si Gate esta caido y failOpenOnNetworkError=true', async () => {
    const err = new Error('ECONNREFUSED');
    axios.get.mockRejectedValue(err);

    const mw = createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      publicKey: publicKey,
      validateWithGate: true,
      failOpenOnNetworkError: true
    });

    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m = mockReqRes({ authorization: 'Bearer ' + token });

    mw(m.req, m.res, m.next);
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(m.next).toHaveBeenCalled();
  });

  test('cacheTtl:0 consulta siempre a Gate (no es sobrescrito por default)', async () => {
    axios.get.mockResolvedValue({ data: { valid: true, tokenVersion: 0 } });

    const mw = createGateMiddleware({
      appId: 'mi-app',
      gateUrl: 'http://gate.test',
      publicKey: publicKey,
      validateWithGate: true,
      cacheTtl: 0
    });

    var token = jwt.sign(
      { email: 'user@apprecio.com', role: 'vendedor', appId: 'mi-app', tokenVersion: 0 },
      privateKey, { algorithm: 'RS256', expiresIn: '1h' }
    );
    var m1 = mockReqRes({ authorization: 'Bearer ' + token });
    var m2 = mockReqRes({ authorization: 'Bearer ' + token });

    mw(m1.req, m1.res, m1.next);
    await new Promise(resolve => setTimeout(resolve, 30));
    mw(m2.req, m2.res, m2.next);
    await new Promise(resolve => setTimeout(resolve, 30));

    // Con cacheTtl:0, cada request consulta a Gate
    expect(axios.get).toHaveBeenCalledTimes(2);
  });
});
