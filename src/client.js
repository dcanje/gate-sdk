const axios = require('axios');

class GateClient {
  constructor(gateUrl) {
    this.gateUrl = gateUrl;
    this.publicKey = null;
  }

  async fetchPublicKey() {
    if (this.publicKey) return this.publicKey;
    var res = await axios.get(this.gateUrl + '/auth/public-key');
    this.publicKey = res.data.publicKey;
    return this.publicKey;
  }
}

module.exports = GateClient;
