function rightRotate(n: number, x: number): number {
    return (x >>> n) | (x << (32 - n));
}

export function sha256WithSalt(message: string, salt: string): string {
    const maxWord = Math.pow(2, 32);
    let result = '';

    // Combine the message and salt
    let ascii = message + salt;
    const words: number[] = [];
    const asciiBitLength = ascii.length * 8;

    let hash: number[] = [];
    let k: number[] = [];
    let primeCounter = k.length;

    const isComposite: { [key: number]: boolean } = {};

    for (let candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (let i = 0; i < 313; i += candidate) {
                isComposite[i] = true;
            }
            hash[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0;
            k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
        }
    }

    ascii += '\x80';

    while ((ascii.length % 64) - 56) ascii += '\x00';

    for (let i = 0; i < ascii.length; i++) {
        const j = ascii.charCodeAt(i);
        if (j >> 8) return ''; // Ensures each character is within the byte range.
        words[i >> 2] |= j << (((3 - i) % 4) * 8);
    }

    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;

    for (let j = 0; j < words.length;) {
        const w: number[] = words.slice(j, (j += 16));
        const oldHash = hash.slice(0);

        for (let i = 0; i < 64; i++) {
            const w15 = w[i - 15], w2 = w[i - 2];

            const a = hash[0], e = hash[4];
            const temp1 = hash[7] +
                (rightRotate(6, e) ^ rightRotate(11, e) ^ rightRotate(25, e)) +
                ((e & hash[5]) ^ (~e & hash[6])) +
                k[i] +
                (w[i] = (i < 16 ? w[i] : (w[i - 16] +
                    (rightRotate(7, w15) ^ rightRotate(18, w15) ^ (w15 >>> 3)) +
                    w[i - 7] +
                    (rightRotate(17, w2) ^ rightRotate(19, w2) ^ (w2 >>> 10))) | 0));

            const temp2 = (rightRotate(2, a) ^ rightRotate(13, a) ^ rightRotate(22, a)) +
                ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
        }

        for (let i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    for (let i = 0; i < 8; i++) {
        for (let j = 3; j + 1; j--) {
            const b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? '0' : '') + b.toString(16);
        }
    }
    return result;
}

// Example usage:
const message = "hello world";
const salt = "random_salt_value";
const hashWithSalt = sha256WithSalt(message, salt);
console.log("SHA-256 Hash with Salt:", hashWithSalt);
