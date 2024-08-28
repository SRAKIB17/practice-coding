const ROTR = (n: number, x: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
const SHR = (n: number, x: number) => (x >>> n) >>> 0;

const Σ0 = (x: number) => (ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x)) >>> 0;
const Σ1 = (x: number) => (ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x)) >>> 0;
const σ0 = (x: number) => (ROTR(1, x) ^ ROTR(8, x) ^ SHR(7, x)) >>> 0;
const σ1 = (x: number) => (ROTR(19, x) ^ ROTR(61, x) ^ SHR(6, x)) >>> 0;

const H: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

const K: number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f,
    0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
    0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4,
    0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c
];

function padMessage(message: Uint8Array): Uint8Array {
    const originalBitLength = message.length * 8;
    const originalLengthBytes = new Uint8Array(8);
    new DataView(originalLengthBytes.buffer).setBigUint64(0, BigInt(originalBitLength), true);

    const paddingLength = (128 - ((message.length + 16) % 128)) % 128;
    const paddedMessage = new Uint8Array(message.length + paddingLength + 16);

    paddedMessage.set(message);
    paddedMessage[message.length] = 0x80;
    paddedMessage.set(originalLengthBytes, paddedMessage.length - 8);

    return paddedMessage;
}

export function sha512(message: string, salt: string): string {
    const saltedMessage = new TextEncoder().encode(salt + message);
    const paddedMessage = padMessage(saltedMessage);

    const W = new Array(80).fill(0);
    let [a, b, c, d, e, f, g, h] = H;

    for (let i = 0; i < paddedMessage.length; i += 128) {
        for (let t = 0; t < 16; ++t) {
            W[t] = (paddedMessage[i + t * 8] << 24) |
                (paddedMessage[i + t * 8 + 1] << 16) |
                (paddedMessage[i + t * 8 + 2] << 8) |
                paddedMessage[i + t * 8 + 3];
        }

        for (let t = 16; t < 80; ++t) {
            W[t] = (σ1(W[t - 2]) + W[t - 7] + σ0(W[t - 15]) + W[t - 16]) >>> 0;
        }

        let [A, B, C, D, E, F, G, H] = [a, b, c, d, e, f, g, h];

        for (let t = 0; t < 80; ++t) {
            const T1 = (H + Σ1(E) + ((E & F) ^ (~E & G)) + K[t] + W[t]) >>> 0;
            const T2 = (Σ0(A) + ((A & B) ^ (A & C) ^ (B & C))) >>> 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) >>> 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) >>> 0;
        }

        a = (a + A) >>> 0;
        b = (b + B) >>> 0;
        c = (c + C) >>> 0;
        d = (d + D) >>> 0;
        e = (e + E) >>> 0;
        f = (f + F) >>> 0;
        g = (g + G) >>> 0;
        h = (h + H) >>> 0;
    }

    const hashBytes = new Uint8Array(64);

    const toBytes = (num: number) => [
        (num >> 24) & 0xff,
        (num >> 16) & 0xff,
        (num >> 8) & 0xff,
        num & 0xff
    ];

    for (let i = 0; i < 8; ++i) {
        hashBytes.set(toBytes(a), i * 8);
    }

    return Array.from(hashBytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}


