import crypto from "crypto";

function generateSalt(length = 16): string {
    return crypto.randomBytes(length).toString("hex");
}

function customHash(password: string, salt: string, iterations = 100000): string {
    let hash = salt + password;

    for (let i = 0; i < iterations; i++) {
        hash = crypto.createHash("sha256").update(hash).digest("base64");
    }

    return hash;
}

function hashPassword(password: string): { salt: string; hash: string } {
    const salt = generateSalt();
    const hashedPassword = customHash(password, salt);
    return { salt, hash: hashedPassword };
}

function verifyPassword(password: string, salt: string, hashedPassword: string): boolean {
    return customHash(password, salt) === hashedPassword;
}

// Example Usage
const password = "mySecurePassword";
const { salt, hash } = hashPassword(password);
console.log("Salt:", salt);
console.log("Hashed Password:", hash);

const isMatch = verifyPassword(password, salt, hash);
console.log("Password Match:", isMatch); // Should return true
