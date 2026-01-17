const Buffer = require("buffer").Buffer;

class PacketBuffer {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  add(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  // Lê sem consumir
  peek(length) {
    if (this.buffer.length < length) return null;
    return this.buffer.subarray(0, length);
  }

  // Lê e consome
  read(length) {
    if (this.buffer.length < length) return null;
    const chunk = this.buffer.subarray(0, length);
    this.buffer = this.buffer.subarray(length);
    return chunk;
  }

  get length() {
    return this.buffer.length;
  }
}

// Garante ID com 16 bytes
function formatId(idStr) {
  const buf = Buffer.alloc(16);
  buf.write(idStr.substring(0, 16), 0);
  return buf;
}

module.exports = { PacketBuffer, formatId };
