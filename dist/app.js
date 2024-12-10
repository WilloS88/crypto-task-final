"use strict";
// Function greatest common divisor
function gcd(a, b) {
    while (b !== BigInt(0)) {
        const temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
// Function modular multiplicative inverse using the Extended Euclidean Algorithm
function modInverse(e, phi) {
    let [old_r, r] = [phi, e];
    let [old_s, s] = [BigInt(0), BigInt(1)];
    while (r !== BigInt(0)) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    if (old_s < BigInt(0)) {
        old_s += phi;
    }
    return old_s;
}
// Function modular exponentiation
function modPow(base, exponent, modulus) {
    if (modulus === BigInt(1))
        return BigInt(0);
    let result = BigInt(1);
    base = base % modulus;
    while (exponent > BigInt(0)) {
        if (exponent % BigInt(2) === BigInt(1)) {
            result = (result * base) % modulus;
        }
        exponent = exponent / BigInt(2);
        base = (base * base) % modulus;
    }
    return result;
}
// Miller-Rabin
function isProbablyPrime(n, k = 5) {
    if (n === BigInt(2) || n === BigInt(3))
        return true;
    if (n <= BigInt(1) || n % BigInt(2) === BigInt(0))
        return false;
    let s = BigInt(0);
    let d = n - BigInt(1);
    while (d % BigInt(2) === BigInt(0)) {
        d /= BigInt(2);
        s += BigInt(1);
    }
    WitnessLoop: for (let i = 0; i < k; i++) {
        const a = BigInt(2) + BigInt(Math.floor(Math.random() * Number(n - BigInt(4))));
        let x = modPow(a, d, n);
        if (x === BigInt(1) || x === n - BigInt(1))
            continue;
        for (let r = BigInt(1); r < s; r++) {
            x = modPow(x, BigInt(2), n);
            if (x === BigInt(1))
                return false;
            if (x === n - BigInt(1))
                continue WitnessLoop;
        }
        return false;
    }
    return true;
}
// Function to generate a random prime number with y digits
function generateRandomPrime(y) {
    const min = BigInt("1" + "0".repeat(y - 1));
    const max = BigInt("9".repeat(y));
    let p;
    // Generate radom num with "min" "max"
    do {
        const range = max - min + BigInt(1);
        const randBytes = new Uint8Array(range.toString().length);
        crypto.getRandomValues(randBytes);
        const randNum = Array.from(randBytes).reduce((acc, byte) => (acc << BigInt(8)) + BigInt(byte), BigInt(0));
        p = min + (randNum % range);
        if (p % BigInt(2) === BigInt(0))
            p += BigInt(1);
        while (p <= max && !isProbablyPrime(p)) {
            p += BigInt(2);
        }
    } while (p > max);
    return p;
}
// Key Generation
function generateKeys(y) {
    const p = generateRandomPrime(y);
    let q;
    do {
        q = generateRandomPrime(y);
    } while (q === p);
    const n = p * q;
    const phi = (p - BigInt(1)) * (q - BigInt(1));
    let e = BigInt(65537);
    if (gcd(e, phi) !== BigInt(1)) {
        e = BigInt(3);
        while (e < phi && gcd(e, phi) !== BigInt(1)) {
            e += BigInt(2);
        }
    }
    const d = modInverse(e, phi);
    const publicKey = { n, e };
    const privateKey = { n, d };
    return { publicKey, privateKey };
}
;
let currentPrivateKey = null;
let currentPublicKey = null;
let fileToSign = null;
let hashBytesGlobal = null;
// Function for file details
function displayFileDetails(file) {
    detailsList.innerHTML = "";
    const lastModifiedDate = new Date(file.lastModified).toLocaleString();
    const details = [
        "File Details:",
        `File name: ${file.name}`,
        `Type: ${file.type || "Unknown"}`,
        `Size: ${(file.size / 1024).toFixed(2)} KB`,
        `Date of last modification: ${lastModifiedDate}`,
    ];
    details.forEach((detail) => {
        const listItem = document.createElement("p");
        listItem.textContent = detail;
        detailsList.appendChild(listItem);
    });
}
// Export keys
function exportKeysToFiles() {
    if (!currentPrivateKey || !currentPublicKey) {
        alert("Please generate keys first.");
        return;
    }
    const privateKeyString = "RSA " +
        btoa(JSON.stringify({
            n: currentPrivateKey.n.toString(),
            d: currentPrivateKey.d.toString(),
        }));
    const publicKeyString = "RSA " +
        btoa(JSON.stringify({
            n: currentPublicKey.n.toString(),
            e: currentPublicKey.e.toString(),
        }));
    const privBlob = new Blob([privateKeyString], {
        type: "text/plain;charset=utf-8",
    });
    const pubBlob = new Blob([publicKeyString], {
        type: "text/plain;charset=utf-8",
    });
    const privURL = URL.createObjectURL(privBlob);
    const pubURL = URL.createObjectURL(pubBlob);
    const privLink = document.createElement("a");
    privLink.href = privURL;
    privLink.download = "key.priv";
    privLink.click();
    const pubLink = document.createElement("a");
    pubLink.href = pubURL;
    pubLink.download = "key.pub";
    pubLink.click();
}
// Load public key
function loadPublicKeyFromFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            if (typeof reader.result === "string") {
                const content = reader.result.trim();
                if (!content.startsWith("RSA ")) {
                    return reject("Invalid public key format");
                }
                const base64Part = content.slice(4);
                try {
                    const jsonStr = atob(base64Part);
                    const keyObj = JSON.parse(jsonStr);
                    if (!keyObj.n || !keyObj.e) {
                    }
                    resolve({ n: BigInt(keyObj.n), e: BigInt(keyObj.e) });
                }
                catch (error) {
                    reject("Could not parse public key");
                }
            }
            else {
                reject("Could not read public key file");
            }
        };
        reader.onerror = (err) => {
            reject(err);
        };
        reader.readAsText(file);
    });
}
// Hash file with SHA3-256
function hashFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            if (reader.result instanceof ArrayBuffer) {
                const bytes = new Uint8Array(reader.result);
                const hashHex = sha3_256(bytes);
                const hashBytes = new Uint8Array(hashHex.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
                resolve(hashBytes);
            }
            else {
                reject("Failed to read file for hashing.");
            }
        };
        reader.onerror = (err) => {
            reject(err);
        };
        reader.readAsArrayBuffer(file);
    });
}
function bigintFromBytes(bytes) {
    let result = BigInt(0);
    for (const b of bytes) {
        result = (result << BigInt(8)) + BigInt(b);
    }
    return result;
}
function bigIntToBytes(num) {
    let hex = num.toString(16);
    if (hex.length % 2)
        hex = "0" + hex;
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(String.fromCharCode(parseInt(hex.slice(i, i + 2), 16)));
    }
    return bytes.join("");
}
function signHash(hashBytes, privateKey) {
    const hashBigInt = bigintFromBytes(hashBytes);
    const signatureBigInt = modPow(hashBigInt, privateKey.d, privateKey.n);
    const signatureBase64 = btoa(bigIntToBytes(signatureBigInt));
    return "RSA_SHA3-256 " + signatureBase64;
}
function verifySignature(hashBytes, signature, publicKey) {
    if (!signature.startsWith("RSA_SHA3-256 ")) {
        return false;
    }
    const base64Signature = signature.replace("RSA_SHA3-256 ", "").trim();
    const signatureBytesStr = atob(base64Signature);
    const signatureBytes = new Uint8Array(signatureBytesStr.split("").map((c) => c.charCodeAt(0)));
    const signatureBigInt = bigintFromBytes(signatureBytes);
    const decryptedHashBigInt = modPow(signatureBigInt, publicKey.e, publicKey.n);
    const decryptedHashBytes = new Uint8Array(hexToBytes(bigIntToHex(decryptedHashBigInt)));
    const result = compareUint8Arrays(hashBytes, decryptedHashBytes);
    return result;
}
function compareUint8Arrays(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}
function bigIntToHex(num) {
    let hex = num.toString(16);
    if (hex.length % 2 !== 0) {
        hex = "0" + hex;
    }
    return hex;
}
function hexToBytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substring(c, c + 2), 16));
    }
    return bytes;
}
function fileToArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            if (reader.result instanceof ArrayBuffer) {
                resolve(reader.result);
            }
            else {
                reject("Could not read file to ArrayBuffer");
            }
        };
        reader.onerror = (err) => {
            reject(err);
        };
        reader.readAsArrayBuffer(file);
    });
}
async function createSignedZip(originalFile, signature) {
    const zip = new JSZip();
    const origData = await fileToArrayBuffer(originalFile);
    zip.file(originalFile.name, origData);
    zip.file(originalFile.name + ".sign", signature);
    const blob = await zip.generateAsync({ type: "blob" });
    return blob;
}
async function verifyFromZip(zipFile, publicKey) {
    const data = await fileToArrayBuffer(zipFile);
    const zip = await JSZip.loadAsync(data);
    let originalFileName;
    let signFileName;
    for (const fileName of Object.keys(zip.files)) {
        if (fileName.endsWith(".sign")) {
            signFileName = fileName;
            originalFileName = fileName.slice(0, -5);
        }
    }
    if (!originalFileName || !signFileName) {
        throw new Error("The ZIP does not contain a .sign file or the original file.");
    }
    const originalData = new Uint8Array(await zip.file(originalFileName).async("arraybuffer"));
    const signatureStr = await zip.file(signFileName).async("text");
    // Recompute hash of original data
    const hashHex = sha3_256(originalData);
    const hashBytes = new Uint8Array(hashHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
    const verificationResult = verifySignature(hashBytes, signatureStr, publicKey);
    return verificationResult;
}
// DOM Elements
const generateKeysButton = document.getElementById("generate-keys");
const publicKeyDisplay = document.getElementById("public-key");
const privateKeyDisplay = document.getElementById("private-key");
const exportKeysButton = document.getElementById("export-keys");
const inputFile = document.getElementById("input-file");
const pubKeyFileInput = document.getElementById("pub-key-file");
const zipFileInput = document.getElementById("zip-file");
const encryptHashButton = document.getElementById("encrypt-hash");
const createSignedZipButton = document.getElementById("create-signed-zip");
const verifySigButton = document.getElementById("verify-signature");
const detailsList = document.getElementById("detailsList");
// Event listeners
inputFile.addEventListener("change", () => {
    const files = inputFile.files;
    if (files && files.length > 0) {
        fileToSign = files[0];
        displayFileDetails(fileToSign);
    }
    else {
        detailsList.innerHTML = "<p>No file chosen</p>";
    }
});
generateKeysButton.addEventListener("click", () => {
    const keySize = 60;
    const { publicKey, privateKey } = generateKeys(keySize);
    currentPublicKey = publicKey;
    currentPrivateKey = privateKey;
    publicKeyDisplay.textContent = `(${publicKey.n}, ${publicKey.e})`;
    privateKeyDisplay.textContent = `(${privateKey.n}, ${privateKey.d})`;
});
exportKeysButton.addEventListener("click", () => {
    exportKeysToFiles();
});
encryptHashButton.addEventListener("click", async () => {
    if (!fileToSign) {
        alert("Please choose a file first.");
        return;
    }
    hashBytesGlobal = await hashFile(fileToSign);
    alert("File hashed successfully. You can now sign it by creating a signed ZIP.");
});
createSignedZipButton.addEventListener("click", async () => {
    if (!fileToSign) {
        alert("Please choose a file first.");
        return;
    }
    if (!currentPrivateKey) {
        alert("Please generate keys first or ensure private key is available.");
        return;
    }
    if (!hashBytesGlobal) {
        hashBytesGlobal = await hashFile(fileToSign);
    }
    const signature = signHash(hashBytesGlobal, currentPrivateKey);
    const zipBlob = await createSignedZip(fileToSign, signature);
    const url = URL.createObjectURL(zipBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileToSign.name + ".zip";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    alert("ZIP with signed file created and downloaded.");
});
verifySigButton.addEventListener("click", async () => {
    const pubFiles = pubKeyFileInput.files;
    const zipFiles = zipFileInput.files;
    if (!pubFiles || pubFiles.length === 0) {
        alert("Please choose a public key (.pub) file.");
        return;
    }
    if (!zipFiles || zipFiles.length === 0) {
        alert("Please choose a ZIP file to verify.");
        return;
    }
    try {
        const publicKey = await loadPublicKeyFromFile(pubFiles[0]);
        const result = await verifyFromZip(zipFiles[0], publicKey);
        if (result) {
            alert("The signature is valid!");
        }
        else {
            alert("The signature is invalid!");
        }
    }
    catch (error) {
        alert("Error during verification: " + error);
    }
});
