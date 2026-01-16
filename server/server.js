require("dotenv").config();
const net = require("net");
const { PacketBuffer } = require("./lib/utils");
const { generateIdentity } = require("./lib/crypto");
const sessions = require("./lib/sessions");
const ProtocolHandler = require("./lib/protocol");

const PORT = process.env.SERVER_PORT;
const HOST = process.env.SERVER_HOST;

class SecureServer {
  constructor() {
    this.identity = null;
    this.protocol = null;
  }

  start() {
    console.log("Gerando identidade...");

    // Gera o par RSA 2048-bit e o Certificado Autoassinado na memória.
    // Isso garante a autenticidade do servidor no Handshake.
    this.identity = generateIdentity();

    // Inicializa o manipulador do protocolo com a identidade gerada
    this.protocol = new ProtocolHandler(this.identity);
    console.log("Identidade pronta.");

    // Cria o servidor TCP puro (camada de transporte)
    const server = net.createServer((socket) => this.handleConnection(socket));

    server.listen(PORT, HOST, () => {
      console.log(`=== SERVIDOR RODANDO EM ${HOST}:${PORT} ===`);
    });
  }

  async handleConnection(socket) {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`Novo cliente: ${addr}`);

    // Utilitário para lidar com a fragmentação de pacotes TCP
    const packetBuffer = new PacketBuffer();

    // Flags de estado da sessão local
    let handshakeDone = false;
    let clientId = null;

    socket.on("data", async (chunk) => {
      packetBuffer.add(chunk); // Acumula bytes até ter um pacote completo

      if (!handshakeDone) {
        try {
          // Processa troca de chaves ECDHE + Assinatura RSA
          const resultId = await this.protocol.processHandshake(
            socket,
            packetBuffer,
          );

          // Se retornou ID, o handshake foi seguro e completo
          if (resultId) {
            clientId = resultId;
            handshakeDone = true;
            console.log(`Sucesso com ${clientId.toString("hex")}`);
          }
        } catch (err) {
          // Se falhar a criptografia ou assinatura, desconecta imediatamente
          console.error(`Erro Handshake: ${err.message}`);
          socket.end();
        }
      } else {
        try {
          // Processa, decifra (AES-GCM), valida Anti-Replay e encaminha
          this.protocol.processMessage(packetBuffer, clientId);
        } catch (err) {
          // Se houver erro de integridade (TAG inválida) ou Replay,
          // a conexão é destruída para evitar ataques.
          console.error(`Erro Msg: ${err.message}`);
          socket.destroy();
        }
      }
    });
    socket.on("end", () => {
      console.log(`Desconectado: ${addr}`);
      // Remove da tabela de sessões para liberar memória e evitar envio para socket morto
      if (clientId) sessions.delete(clientId.toString("hex"));
    });

    socket.on("error", (err) => console.log(`Erro Socket: ${err.message}`));
  }
}

new SecureServer().start();
