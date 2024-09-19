import wrappedCryptoToken from "./sha1";

const x: any = wrappedCryptoToken({ wrappedCryptoString: "ccccc" })
const test = wrappedCryptoToken({ salt: "6f27a28e58f950b1", wrappedCryptoString: "ccccc" })
console.log(x, test)

// const message = "hello world";
// const hashWithSalt = sha256WithSalt(message, x?.salt);
// console.log(sha256WithSalt(message, x?.salt) == hashWithSalt)
// console.log("SHA-256 Hash with Salt:", hashWithSalt);

// // Example usage
// const salt = 'random_salt';
// // Example usage
// const hash = sha512(message, salt);
// console.log(`SHA-512 Hash: ${hash}`);