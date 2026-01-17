require("dotenv").config();

const net = require("net");
const readline = require("readline");
const { PacketBuffer, formatId } = require("./lib/utils");
const ClientProtocol = require("./lib/protocol");

const PORT = process.env.SERVER_PORT;
const HOST = process.env.SERVER_HOST;

const myIdStr = process.argv[2];
const targetIdStr = process.argv[3];

if (!myIdStr || !targetIdStr) {
  process.exit(1);
}

const protocol = new ClientProtocol(formatId(myIdStr), formatId(targetIdStr));
const packetBuffer = new PacketBuffer();

const socket = new net.Socket();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: `[${myIdStr}]> `,
});

socket.connect(PORT, HOST, () => {
  console.log(`[CONEXÃO] Conectado a ${HOST}:${PORT}`);

  // 1. Inicia Handshake
  const handshakePayload = protocol.getPublicKeyPayload();
  socket.write(handshakePayload);
  console.log("[HANDSHAKE] Chave pública enviada.");
});

socket.on("data", async (chunk) => {
  packetBuffer.add(chunk);

  if (!protocol.handshakeDone) {
    try {
      const success = await protocol.processHandshake(packetBuffer);
      if (success) {
        console.log("[SEGURANÇA] Servidor Autenticado. Canal Seguro.");
        console.log(`--- Chat com ${targetIdStr} iniciado ---`);
        rl.prompt();
      }
    } catch (e) {
      if (e.message !== "WAIT") {
        console.error(`[ERRO FATAL] ${e.message}`);
        process.exit(1);
      }
    }
  } else {
    // Processa mensagens em loop
    while (true) {
      try {
        const result = protocol.decryptMessage(packetBuffer);

        if (result === null) break; // Esperar mais dados
        if (result === "REPLAY_DETECTED") continue;

        // Limpa linha e exibe mensagem
        readline.clearLine(process.stdout, 0);
        readline.cursorTo(process.stdout, 0);
        console.log(`[${targetIdStr}]: ${result.toString()}`);
        rl.prompt();
      } catch (e) {
        console.error("[ERRO INTEGRIDADE] Mensagem corrompida.");
        break;
      }
    }
  }
});

socket.on("close", () => {
  console.log("\n[DESCONECTADO]");
  process.exit(0);
});

socket.on("error", (err) => console.error(`[ERRO SOCKET] ${err.message}`));

rl.on("line", (line) => {
  if (line.trim() && protocol.handshakeDone) {
    const packet = protocol.encryptMessage(line);
    socket.write(packet);
  }
  rl.prompt();
});
