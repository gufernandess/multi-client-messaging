const crypto = require("crypto");
const { hkdfExpand } = require("./crypto");

class ClientProtocol {
  constructor(myId, targetId) {
    this.myId = myId;
    this.targetId = targetId;

    // Estado da Criptografia
    this.ecdh = crypto.createECDH("prime256v1");
    this.ecdh.generateKeys();
    this.clientPublicKey = this.ecdh.getPublicKey();

    this.keys = null; // { key_c2s, key_s2c }
    this.seq_send = 1n;
    this.seq_recv = 0n;
    this.handshakeDone = false;
  }

  getPublicKeyPayload() {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(this.clientPublicKey.length);
    return Buffer.concat([lenBuf, this.clientPublicKey, this.myId]);
  }

  async processHandshake(packetBuffer) {
    const buf = packetBuffer.buffer;
    let cursor = 0;

    // Helper interno para leitura segura
    const readCheck = (n) => {
      if (cursor + n > buf.length) throw new Error("WAIT");
      const data = buf.subarray(cursor, cursor + n);
      cursor += n;
      return data;
    };
    const readInt = () => {
      if (cursor + 4 > buf.length) throw new Error("WAIT");
      const val = buf.readUInt32BE(cursor);
      cursor += 4;
      return val;
    };

    // Parsing
    const lenCert = readInt();
    const serverCert = readCheck(lenCert);
    const lenSig = readInt();
    const signature = readCheck(lenSig);
    const lenPkS = readInt();
    const pkS = readCheck(lenPkS);
    const salt = readCheck(16);

    // Consome o buffer real apenas se tudo acima funcionou
    packetBuffer.read(cursor);

    // 1. Validar Assinatura RSA
    const dataToVerify = Buffer.concat([
      pkS,
      this.myId,
      this.clientPublicKey,
      salt,
    ]);
    const isVerified = crypto.verify(
      "sha256",
      dataToVerify,
      serverCert,
      signature,
    );

    if (!isVerified) throw new Error("Assinatura do servidor INVÁLIDA");

    // 2. Derivar Chaves
    const sharedSecretZ = this.ecdh.computeSecret(pkS);
    const key_c2s = await hkdfExpand(sharedSecretZ, salt, "c2s", 16);
    const key_s2c = await hkdfExpand(sharedSecretZ, salt, "s2c", 16);

    this.keys = { key_c2s, key_s2c };
    this.handshakeDone = true;
    return true;
  }

  encryptMessage(text) {
    const plaintext = Buffer.from(text, "utf-8");
    const nonce = crypto.randomBytes(12);

    const seqBuffer = Buffer.alloc(8);
    seqBuffer.writeBigUInt64BE(this.seq_send);
    this.seq_send += 1n;

    const cipher = crypto.createCipheriv(
      "aes-128-gcm",
      this.keys.key_c2s,
      nonce,
    );
    const aad = Buffer.concat([this.myId, this.targetId, seqBuffer]);
    cipher.setAAD(aad);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const finalPayload = Buffer.concat([encrypted, tag]);

    const header = Buffer.alloc(56);
    nonce.copy(header, 0);
    this.myId.copy(header, 12);
    this.targetId.copy(header, 28);
    seqBuffer.copy(header, 44);
    header.writeUInt32BE(finalPayload.length, 52);

    return Buffer.concat([header, finalPayload]);
  }

  decryptMessage(packetBuffer) {
    const HEADER_SIZE = 56;
    const buf = packetBuffer.buffer;

    if (buf.length < HEADER_SIZE) return null;

    const lenCipher = buf.readUInt32BE(52);
    if (buf.length < HEADER_SIZE + lenCipher) return null;

    const header = packetBuffer.read(HEADER_SIZE);
    const ciphertextTag = packetBuffer.read(lenCipher);

    const nonce = header.subarray(0, 12);
    const senderId = header.subarray(12, 28);
    const recipientId = header.subarray(28, 44);
    const seqNoBuf = header.subarray(44, 52);
    const seqNo = seqNoBuf.readBigUInt64BE();

    if (seqNo <= this.seq_recv) {
      console.warn(`[REPLAY] Seq ${seqNo} ignorado.`);
      return "REPLAY_DETECTED";
    }
    this.seq_recv = seqNo;

    const decipher = crypto.createDecipheriv(
      "aes-128-gcm",
      this.keys.key_s2c,
      nonce,
    );
    const aad = Buffer.concat([senderId, recipientId, seqNoBuf]);
    decipher.setAAD(aad);

    const tagLength = 16;
    const authTag = ciphertextTag.subarray(ciphertextTag.length - tagLength);
    const cipherData = ciphertextTag.subarray(
      0,
      ciphertextTag.length - tagLength,
    );

    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(cipherData), decipher.final()]);
  }
}

module.exports = ClientProtocol;
