const axios = require('axios');
const GateClient = require('../src/client');

jest.mock('axios');

describe('GateClient', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('constructor inicializa gateUrl y publicKey null', () => {
    const client = new GateClient('http://localhost:3001');
    expect(client.gateUrl).toBe('http://localhost:3001');
    expect(client.publicKey).toBeNull();
  });

  test('fetchPublicKey obtiene la clave del servidor', async () => {
    const fakePem = '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----';
    axios.get.mockResolvedValue({ data: { publicKey: fakePem } });

    const client = new GateClient('http://localhost:3001');
    const key = await client.fetchPublicKey();

    expect(key).toBe(fakePem);
    expect(axios.get).toHaveBeenCalledWith('http://localhost:3001/auth/public-key');
    expect(client.publicKey).toBe(fakePem);
  });

  test('fetchPublicKey usa cache en la segunda llamada', async () => {
    const fakePem = '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----';
    axios.get.mockResolvedValue({ data: { publicKey: fakePem } });

    const client = new GateClient('http://localhost:3001');
    await client.fetchPublicKey();
    await client.fetchPublicKey();

    expect(axios.get).toHaveBeenCalledTimes(1);
  });

  test('fetchPublicKey propaga error de red', async () => {
    axios.get.mockRejectedValue(new Error('ECONNREFUSED'));

    const client = new GateClient('http://localhost:3001');
    await expect(client.fetchPublicKey()).rejects.toThrow('ECONNREFUSED');
    expect(client.publicKey).toBeNull();
  });
});
