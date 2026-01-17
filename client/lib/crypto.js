const crypto = require("crypto");

function hkdfExpand(ikm, salt, infoStr, length) {
  return new Promise((resolve, reject) => {
    crypto.hkdf(
      "sha256",
      ikm,
      salt,
      Buffer.from(infoStr),
      length,
      (err, key) => {
        if (err) reject(err);
        else resolve(Buffer.from(key));
      },
    );
  });
}

module.exports = { hkdfExpand };
