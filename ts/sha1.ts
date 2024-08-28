// Basic SHA-1 implementation in pure JavaScript.
function sha1(message: any) {
    function rotateLeft(n: any, s: any) {
        return (n << s) | (n >>> (32 - s));
    }

    function cvtHex(val: any) {
        let str = "";
        for (let i = 7; i >= 0; i--) {
            let v = (val >>> (i * 4)) & 0x0f;
            str += v.toString(16);
        }
        return str;
    }

    function utf8Encode(string: any) {
        return decodeURIComponent(encodeURIComponent(string));
    }

    let blockstart;
    let i, j;
    let W = new Array(80);
    let H0 = 0x67452301;
    let H1 = 0xefcdab89;
    let H2 = 0x98badcfe;
    let H3 = 0x10325476;
    let H4 = 0xc3d2e1f0;
    let A, B, C, D, E;
    let temp;

    message = utf8Encode(message);
    let msgLen = message.length;

    let wordArray = [];
    for (i = 0; i < msgLen - 3; i += 4) {
        j =
            (message.charCodeAt(i) << 24) |
            (message.charCodeAt(i + 1) << 16) |
            (message.charCodeAt(i + 2) << 8) |
            message.charCodeAt(i + 3);
        wordArray.push(j);
    }

    switch (msgLen % 4) {
        case 0:
            i = 0x080000000;
            break;
        case 1:
            i = (message.charCodeAt(msgLen - 1) << 24) | 0x0800000;
            break;
        case 2:
            i =
                (message.charCodeAt(msgLen - 2) << 24) |
                (message.charCodeAt(msgLen - 1) << 16) |
                0x08000;
            break;
        case 3:
            i =
                (message.charCodeAt(msgLen - 3) << 24) |
                (message.charCodeAt(msgLen - 2) << 16) |
                (message.charCodeAt(msgLen - 1) << 8) |
                0x80;
            break;
    }

    wordArray.push(i);
    while (wordArray.length % 16 != 14) wordArray.push(0);
    wordArray.push(msgLen >>> 29);
    wordArray.push((msgLen << 3) & 0x0ffffffff);

    for (blockstart = 0; blockstart < wordArray.length; blockstart += 16) {
        for (i = 0; i < 16; i++) W[i] = wordArray[blockstart + i];
        for (i = 16; i <= 79; i++)
            W[i] = rotateLeft(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;

        for (i = 0; i <= 19; i++) {
            temp =
                (rotateLeft(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5a827999) &
                0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (i = 20; i <= 39; i++) {
            temp =
                (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ed9eba1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (i = 40; i <= 59; i++) {
            temp =
                (rotateLeft(A, 5) +
                    ((B & C) | (B & D) | (C & D)) +
                    E +
                    W[i] +
                    0x8f1bbcdc) &
                0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        for (i = 60; i <= 79; i++) {
            temp =
                (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0xca62c1d6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
        }

        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }

    let tempValue =
        cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4);
    return tempValue.toLowerCase();
}

// HMAC function using SHA-1
function hmacSHA1(key: string, message: string) {
    const blockSize = 64; // Block size for SHA-1
    if (key.length > blockSize) {
        key = sha1(key); // Hash the key if it is longer than block size
    }
    if (key.length < blockSize) {
        key = key.padEnd(blockSize, String.fromCharCode(0)); // Pad key to block size
    }

    const oKeyPad = Array.from(key, (char: string) =>
        String.fromCharCode(char.charCodeAt(0) ^ 0x5c)
    ).join("");
    const iKeyPad = Array.from(key, (char: string) =>
        String.fromCharCode(char.charCodeAt(0) ^ 0x36)
    ).join("");

    return sha1(oKeyPad + sha1(iKeyPad + message));
}

// Function to generate a random hex string of a given length
function generateRandomHex(length: number) {
    const characters = "0123456789abcdef";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters[Math.floor(Math.random() * characters.length)];
    }
    return result;
}

const length = 16;

export default function wrappedCryptoToken({
    salt = generateRandomHex(length),
    wrappedCryptoString = "",
}) {
    try {
        // Generate HMAC-SHA1 hash using our custom implementation
        const hash = hmacSHA1(salt, wrappedCryptoString);
        return {
            salt: salt,
            success: true,
            hash: Buffer.from(hash, "hex").toString("base64"),
        };
    } catch (err: any) {
        return {
            success: false,
            salt: null,
            hash: null,
            message: err.message,
        };
    }
}
