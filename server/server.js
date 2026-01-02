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
    this.identity = generateIdentity();
    this.protocol = new ProtocolHandler(this.identity);
    console.log("Identidade pronta.");

    const server = net.createServer((socket) => this.handleConnection(socket));

    server.listen(PORT, HOST, () => {
      console.log(`=== SERVIDOR RODANDO EM ${HOST}:${PORT} ===`);
    });
  }

  async handleConnection(socket) {
    const addr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`Novo cliente: ${addr}`);

    const packetBuffer = new PacketBuffer();
    let handshakeDone = false;
    let clientId = null;

    socket.on("data", async (chunk) => {
      packetBuffer.add(chunk);

      if (!handshakeDone) {
        try {
          const resultId = await this.protocol.processHandshake(
            socket,
            packetBuffer,
          );
          if (resultId) {
            clientId = resultId;
            handshakeDone = true;
            console.log(`Sucesso com ${clientId.toString("hex")}`);
          }
        } catch (err) {
          console.error(`${err.message}`);
          socket.end();
        }
      } else {
        try {
          this.protocol.processMessage(packetBuffer, clientId);
        } catch (err) {
          console.error(`${err.message}`);
          socket.destroy();
        }
      }
    });

    socket.on("end", () => {
      console.log(`Desconectado: ${addr}`);
      if (clientId) sessions.delete(clientId.toString("hex"));
    });

    socket.on("error", (err) => console.log(`${err.message}`));
  }
}

new SecureServer().start();
