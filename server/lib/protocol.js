const crypto = require("crypto");
const { uInt32ToBuffer } = require("./utils");
const { hkdfExpand } = require("./crypto");
const sessions = require("./sessions");

class ProtocolHandler {
  constructor(identity) {
    // Carrega a identidade RSA gerada na inicialização.
    // Necessária para assinar o handshake.
    this.rsaKeys = {
      privateKey: identity.privateKey,
      publicKey: identity.publicKey,
    };
    this.serverCert = identity.serverCert;
  }

  async processHandshake(sock, buf) {
    // Verificação básica de tamanho de buffer (header)
    if (buf.length < 4) return null;

    const lenPkC = buf.buffer.readUInt32BE(0);
    const totalHandshakeSize = 4 + lenPkC + 16;

    // Espera ter o pacote completo antes de processar
    if (buf.length < totalHandshakeSize) return null;

    // Consome os dados do buffer
    buf.read(4);
    const pkC_bytes = buf.read(lenPkC); // Chave pública efêmera do Cliente
    const cId = buf.read(16); // ID do Cliente

    // Gera par efêmero do Servidor (Curva P-256)
    const ecdhServer = crypto.createECDH("prime256v1");
    ecdhServer.generateKeys();
    const pkS_bytes = ecdhServer.getPublicKey();

    // Calcula o segredo compartilhado (Z)
    const sharedSecretZ = ecdhServer.computeSecret(pkC_bytes);

    // Gera Salt aleatório para o HKDF
    const salt = crypto.randomBytes(16);

    // Usa HKDF para expandir o segredo em duas chaves distintas
    // Isso isola criptograficamente os canais de envio e recebimento.
    const key_c2s = await hkdfExpand(sharedSecretZ, salt, "c2s", 16);
    const key_s2c = await hkdfExpand(sharedSecretZ, salt, "s2c", 16);

    // Assina os parâmetros da troca com a Chave Privada RSA.
    const dataToSign = Buffer.concat([pkS_bytes, cId, pkC_bytes, salt]);
    const signature = crypto.sign(
      "sha256",
      dataToSign,
      this.rsaKeys.privateKey,
    );

    const certBuffer = Buffer.from(this.serverCert);

    // Monta o pacote de resposta
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

    // Registra o estado seguro na memória
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
    // Loop 'while' para lidar com 'TCP Coalescing'
    while (true) {
      const HEADER_SIZE = 56;
      if (buf.length < HEADER_SIZE) break;

      // Lê o tamanho do ciphertext para saber se tem o pacote todo
      const lenCipher = buf.buffer.readUInt32BE(52);
      if (buf.length < HEADER_SIZE + lenCipher) break;

      // Extrai cabeçalho e corpo
      const header = buf.read(HEADER_SIZE);
      const ciphertextTag = buf.read(lenCipher);

      // Parsing dos campos do header
      const nonce = header.subarray(0, 12);
      const senderId = header.subarray(12, 28);
      const recipientId = header.subarray(28, 44);
      const seqNoBuffer = header.subarray(44, 52);
      const seqNo = seqNoBuffer.readBigUInt64BE();

      const cIdHex = currentClientId.toString("hex");

      // Verifica se o remetente é dono do socket
      if (!senderId.equals(currentClientId))
        throw new Error("Sender ID forjado.");

      const session = sessions.get(cIdHex);
      if (!session) throw new Error("Sessão não encontrada.");

      // O número de sequência deve ser estritamente crescente
      if (seqNo <= session.seq_recv)
        throw new Error(`Replay Attack: Seq ${seqNo}`);
      session.seq_recv = seqNo;

      // Prepara decifragem AES-GCM
      const decipher = crypto.createDecipheriv(
        "aes-128-gcm",
        session.key_c2s,
        nonce,
      );

      // Garante que o cabeçalho (IDs + Seq) não foi adulterado, mesmo estando em texto plano.
      const aad = Buffer.concat([senderId, recipientId, seqNoBuffer]);
      decipher.setAAD(aad);

      // Separa Ciphertext da Tag de Autenticação (últimos 16 bytes)
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
        // Se a tag não bater, final() lança exceção.
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

      // Roteia a mensagem decifrada para o destino
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

    // Pega as chaves da sessão do DESTINATÁRIO
    const keyS2C = targetSession.key_s2c;
    const targetSeq = targetSession.seq_send;
    targetSession.seq_send += 1n; // Incrementa contador do servidor

    // Gera novo Nonce para este salto da viagem
    const newNonce = crypto.randomBytes(12);
    const targetSeqBuffer = Buffer.alloc(8);
    targetSeqBuffer.writeBigUInt64BE(targetSeq);

    const aad = Buffer.concat([senderId, recipientId, targetSeqBuffer]);

    // Cifra novamente, agora com a chave do destinatário
    const cipher = crypto.createCipheriv("aes-128-gcm", keyS2C, newNonce);
    cipher.setAAD(aad);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const finalPayload = Buffer.concat([encrypted, tag]);

    // Monta novo Header
    const header = Buffer.alloc(56);
    newNonce.copy(header, 0);
    senderId.copy(header, 12);
    recipientId.copy(header, 28);
    targetSeqBuffer.copy(header, 44);
    header.writeUInt32BE(finalPayload.length, 52);

    // Envia para o socket de destino
    targetSession.socket.write(Buffer.concat([header, finalPayload]));
    console.log(`Encaminhada para ${recipientHex}`);
  }
}

module.exports = ProtocolHandler;
