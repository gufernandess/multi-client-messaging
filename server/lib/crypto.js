const crypto = require("crypto");

function generateIdentity() {
  // Gera um par de chaves RSA de 2048 bits de forma síncrona.
  // A chave privada (privateKey) fica APENAS na memória do servidor.
  // Ela será usada para assinar digitalmente o handshake.
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // Exporta a chave pública em formato PEM.
  // Serve para que ele possa validar nossa assinatura.
  const serverCert = publicKey.export({ type: "pkcs1", format: "pem" });

  return { privateKey, publicKey, serverCert };
}

function hkdfExpand(ikm, salt, infoStr, length) {
  return new Promise((resolve, reject) => {
    // O HKDF é crucial, pegando o segredo compartilhado que veio do ECDH
    // e o mistura com um Salt aleatório para gerar chaves fortes e uniformes.
    crypto.hkdf(
      "sha256", // Algoritmo de hash base (HMAC-SHA256)
      ikm, // O segredo "Z" resultante do ECDH
      salt, // Salt aleatório gerado no handshake (garante entropia)
      Buffer.from(infoStr), // Contexto para gerar chaves diferentes
      length, // Tamanho da chave de saída (16 bytes para AES-128)
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      },
    );
  });
}

module.exports = { generateIdentity, hkdfExpand };
