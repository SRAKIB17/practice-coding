import wrappedCryptoToken from "./test";

const x: any = wrappedCryptoToken({ wrappedCryptoString: "SFSDF" })
console.log(x)
const test = wrappedCryptoToken({ salt: x?.salt, wrappedCryptoString: "SFSDF" })
console.log(test)