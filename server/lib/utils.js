const Buffer = require("buffer").Buffer;

class PacketBuffer {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  // O TCP é um protocolo de "stream", não de mensagens.
  // Isso significa que uma mensagem pode chegar picotada em vários pedaços.
  // Este método acumula tudo o que chega no socket em um único buffer.
  add(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  // Tenta consumir 'length' bytes do buffer acumulado.
  read(length) {
    // Se ainda não temos bytes suficientes para ler o que precisamos,
    // retornamos null. Isso avisa o servidor para "esperar mais dados".
    if (this.buffer.length < length) return null;

    // Se temos dados suficientes, cortamos a fatia que nos interessa.
    const chunk = this.buffer.subarray(0, length);

    // 2. Removemos essa fatia do buffer principal.
    this.buffer = this.buffer.subarray(length);

    return chunk;
  }

  get length() {
    return this.buffer.length;
  }
}

function uInt32ToBuffer(num) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(num);
  return buf;
}

module.exports = { PacketBuffer, uInt32ToBuffer };
