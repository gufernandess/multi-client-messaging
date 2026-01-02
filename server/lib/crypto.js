const crypto = require("crypto");

function generateIdentity() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const serverCert = publicKey.export({ type: "pkcs1", format: "pem" });
  return { privateKey, publicKey, serverCert };
}

function hkdfExpand(ikm, salt, infoStr, length) {
  return new Promise((resolve, reject) => {
    crypto.hkdf(
      "sha256",
      ikm,
      salt,
      Buffer.from(infoStr),
      length,
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      },
    );
  });
}

module.exports = { generateIdentity, hkdfExpand };
