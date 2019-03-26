import { Buffer } from 'buffer';

export const binaryStringToArrayBuffer = (str) => {
    const len = str.length;
    const uint8Array = new Uint8Array(len);

    for (let i = 0; i < len; i += 1) {
        uint8Array[i] = str.charCodeAt(i);
    }

    return uint8Array.buffer;
};

export const arrayBufferToBinaryString = (arrayBuffer) =>
    String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));

export const hexStringToArrayBuffer = (str) =>
    new Uint8Array(str.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))).buffer;

export const arrayBufferToHexString = (arrayBuffer) =>
    Array.prototype.map.call(new Uint8Array(arrayBuffer), (x) => (`00${x.toString(16)}`).slice(-2)).join('');

export const nodeBufferToArrayBuffer = (buffer) =>
    buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);

export const arrayBufferToNodeBuffer = (arrayBuffer) => Buffer.from(arrayBuffer);

export const bnToArrayBuffer = (bn) => {
    const numArray = bn.toArray();

    /* eslint-disable no-bitwise */
    // Remove useless sign
    if (!bn.negative && numArray[0] & 0x80) {
        numArray.unshift(0);
    }
    /* eslint-enable no-bitwise */

    return Uint8Array.from(numArray).buffer;
};

export const integerFromArrayBuffer = (arrayBuffer) => {
    if (arrayBuffer.byteLength > 32) {
        throw new Error('Only 32 byte integers is supported');
    }

    const uint8Array = new Uint8Array(arrayBuffer);
    let integer = 0;
    let byteCount = 0;

    do {
        /* eslint-disable no-bitwise */
        integer = (integer << 8) + uint8Array[byteCount];
        /* eslint-enable no-bitwise */
        byteCount += 1;
    } while (arrayBuffer.byteLength > byteCount);

    return integer;
};

