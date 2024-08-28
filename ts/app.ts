import wrappedCryptoToken from "./sha1";
import { sha256WithSalt } from "./sha256";
import { sha512 } from "./sha512";
const x: any = wrappedCryptoToken({ wrappedCryptoString: "SFSDF" })
const test = wrappedCryptoToken({ salt: x?.salt, wrappedCryptoString: "SFSDF" })
console.log(test)

const message = "hello world";
const hashWithSalt = sha256WithSalt(message, x?.salt);
console.log(sha256WithSalt(message, x?.salt) == hashWithSalt)
console.log("SHA-256 Hash with Salt:", hashWithSalt);

// Example usage
const salt = 'random_salt';
// Example usage
const hash = sha512(message, salt);
console.log(`SHA-512 Hash: ${hash}`);