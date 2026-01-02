const Buffer = require("buffer").Buffer;

class PacketBuffer {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  add(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

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

function uInt32ToBuffer(num) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(num);
  return buf;
}

module.exports = { PacketBuffer, uInt32ToBuffer };
