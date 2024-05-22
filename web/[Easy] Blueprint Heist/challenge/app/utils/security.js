const URL = require("url").URL;

function detectSqli (query) {
    const pattern = /^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]/
    return pattern.test(query)
}

function checkInternal(req) {
    const address = req.socket.remoteAddress.replace(/^.*:/, '')
    return address === "127.0.0.1"
}

function isUrl(url) {
    try {
      new URL(url);
      return true;
    } catch (err) {
      return false;
    }
  };

module.exports = { detectSqli, checkInternal, isUrl }