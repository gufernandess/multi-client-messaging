const crypto = require("crypto");
const { uInt32ToBuffer } = require("./utils");
const { hkdfExpand } = require("./crypto");
const sessions = require("./sessions");

class ProtocolHandler {
  constructor(identity) {
    this.rsaKeys = {
      privateKey: identity.privateKey,
      publicKey: identity.publicKey,
    };
    this.serverCert = identity.serverCert;
  }

  async processHandshake(sock, buf) {
    if (buf.length < 4) return null;

    const lenPkC = buf.buffer.readUInt32BE(0);
    const totalHandshakeSize = 4 + lenPkC + 16;

    if (buf.length < totalHandshakeSize) return null;

    buf.read(4);
    const pkC_bytes = buf.read(lenPkC);
    const cId = buf.read(16);

    const ecdhServer = crypto.createECDH("prime256v1");
    ecdhServer.generateKeys();
    const pkS_bytes = ecdhServer.getPublicKey();

    const sharedSecretZ = ecdhServer.computeSecret(pkC_bytes);
    const salt = crypto.randomBytes(16);

    const key_c2s = await hkdfExpand(sharedSecretZ, salt, "c2s", 16);
    const key_s2c = await hkdfExpand(sharedSecretZ, salt, "s2c", 16);

    const dataToSign = Buffer.concat([pkS_bytes, cId, pkC_bytes, salt]);
    const signature = crypto.sign(
      "sha256",
      dataToSign,
      this.rsaKeys.privateKey,
    );

    const certBuffer = Buffer.from(this.serverCert);

    const response = Buffer.concat([
      uInt32ToBuffer(certBuffer.length),
      certBuffer,
      uInt32ToBuffer(signature.length),
      signature,
      uInt32ToBuffer(pkS_bytes.length),
      pkS_bytes,
      salt,
    ]);

    sock.write(response);

    sessions.set(cId.toString("hex"), {
      socket: sock,
      key_c2s,
      key_s2c,
      seq_recv: 0n,
      seq_send: 1n,
      clientId: cId,
    });

    return cId;
  }

  processMessage(buf, currentClientId) {
    while (true) {
      const HEADER_SIZE = 56;
      if (buf.length < HEADER_SIZE) break;

      const lenCipher = buf.buffer.readUInt32BE(52);
      if (buf.length < HEADER_SIZE + lenCipher) break;

      const header = buf.read(HEADER_SIZE);
      const ciphertextTag = buf.read(lenCipher);

      const nonce = header.subarray(0, 12);
      const senderId = header.subarray(12, 28);
      const recipientId = header.subarray(28, 44);
      const seqNoBuffer = header.subarray(44, 52);
      const seqNo = seqNoBuffer.readBigUInt64BE();

      const cIdHex = currentClientId.toString("hex");

      if (!senderId.equals(currentClientId))
        throw new Error("Sender ID forjado.");

      const session = sessions.get(cIdHex);
      if (!session) throw new Error("Sessão não encontrada.");

      if (seqNo <= session.seq_recv) throw new Error(`${seqNo}`);
      session.seq_recv = seqNo;

      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        session.key_c2s,
        nonce,
      );
      const aad = Buffer.concat([senderId, recipientId, seqNoBuffer]);
      decipher.setAAD(aad);

      const authTagLength = 16;
      const actualCiphertext = ciphertextTag.subarray(
        0,
        ciphertextTag.length - authTagLength,
      );
      const authTag = ciphertextTag.subarray(
        ciphertextTag.length - authTagLength,
      );

      decipher.setAuthTag(authTag);

      let plaintext;
      try {
        plaintext = Buffer.concat([
          decipher.update(actualCiphertext),
          decipher.final(),
        ]);
        console.log(
          `De ${senderId.toString("hex")} para ${recipientId.toString("hex")}`,
        );
      } catch (e) {
        throw new Error("Falha na decifragem ou integridade.");
      }

      this.forwardMessage(plaintext, senderId, recipientId);
    }
  }

  forwardMessage(plaintext, senderId, recipientId) {
    const recipientHex = recipientId.toString("hex");
    const targetSession = sessions.get(recipientHex);

    if (!targetSession) {
      console.log(`Destinatário ${recipientHex} offline.`);
      return;
    }

    const keyS2C = targetSession.key_s2c;
    const targetSeq = targetSession.seq_send;
    targetSession.seq_send += 1n;

    const newNonce = crypto.randomBytes(12);
    const targetSeqBuffer = Buffer.alloc(8);
    targetSeqBuffer.writeBigUInt64BE(targetSeq);

    const aad = Buffer.concat([senderId, recipientId, targetSeqBuffer]);

    const cipher = crypto.createCipheriv("aes-128-gcm", keyS2C, newNonce);
    cipher.setAAD(aad);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const finalPayload = Buffer.concat([encrypted, tag]);

    const header = Buffer.alloc(56);
    newNonce.copy(header, 0);
    senderId.copy(header, 12);
    recipientId.copy(header, 28);
    targetSeqBuffer.copy(header, 44);
    header.writeUInt32BE(finalPayload.length, 52);

    targetSession.socket.write(Buffer.concat([header, finalPayload]));
    console.log(`Encaminhada para ${recipientHex}`);
  }
}

module.exports = ProtocolHandler;
