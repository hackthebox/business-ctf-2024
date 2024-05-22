const { Curl } = require('node-libcurl');

class CurlWrapper {
  constructor() {
    this.curl = new Curl();
  }

  head(url, options = {}) {
    return this._request('HEAD', url, options);
  }

  get(url, options = {}) {
    return this._request('GET', url, options);
  }

  post(url, data = {}, options = {}) {
    return this._request('POST', url, { ...options, data });
  }

  _request(method, url, options) {
    return new Promise((resolve, reject) => {
      const curl = new Curl();

      curl.setOpt(Curl.option.URL, url);
      curl.setOpt(Curl.option.CUSTOMREQUEST, method);
      curl.setOpt(Curl.option.FOLLOWLOCATION, true);

      if (method === 'HEAD') {
        curl.setOpt(Curl.option.NOBODY, true);
      } else if (method === 'POST') {
        curl.setOpt(Curl.option.POSTFIELDS, JSON.stringify(options.data));
        curl.setOpt(Curl.option.HTTPHEADER, [
          'Content-Type: application/json'
        ]);
      }

      if (options.headers) {
        curl.setOpt(Curl.option.HTTPHEADER, options.headers);
      }

      curl.on('end', (statusCode, body, headers) => {
        resolve({
          statusCode,
          body,
          headers: this._parseHeaders(headers)
        });
        curl.close();
      });

      curl.on('error', (err) => {
        reject(err);
        curl.close();
      });

      curl.perform();
    });
  }

  _parseHeaders(headerArray) {
    const headers = new Map();
    const headerObject = headerArray[0];

    for (const [key, value] of Object.entries(headerObject)) {
      if (key !== 'result') {
        headers.set(key, value);
      }
    }

    return headers;
  }
}

module.exports = CurlWrapper;