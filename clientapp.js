const http = require("http");
const crypto = require("crypto");

// Step 1: Student object
class Student {
  constructor(id, name, gpa) {
    this.id = id;
    this.name = name;
    this.gpa = gpa;
    this.timestamp = new Date().toISOString();
  }
}

const student = new Student(1, "Alice Johnson", 2.00);
const payloadJsonString = JSON.stringify(student);

// Step 5: Generate AES symmetric key
const symmetricKey = crypto.randomBytes(32);
console.log("Client Symmetric Key:", symmetricKey.toString("hex"));

// Step 4: Fetch public key
function getPublicKey(callback) {
  const options = { hostname: "localhost", port: 3000, path: "/public-key", method: "GET" };
  const req = http.request(options, (res) => {
    let keyData = "";
    res.on("data", chunk => keyData += chunk);
    res.on("end", () => callback(keyData));
  });
  req.on("error", console.error);
  req.end();
}

// Step 5: Encrypt symmetric key with RSA
function encryptSymmetricKey(publicKey, symmetricKey) {
  return crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    symmetricKey
  );
}

// Send encrypted symmetric key
function sendEncryptedKey(encryptedKey, callback) {
  const payload = JSON.stringify({ encryptedKey: encryptedKey.toString("base64") });
  const options = { hostname: "localhost", port: 3000, path: "/exchange-key", method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
  };
  const req = http.request(options, (res) => {
    let response = "";
    res.on("data", chunk => response += chunk);
    res.on("end", () => callback());
  });
  req.on("error", console.error);
  req.write(payload);
  req.end();
}

// Step 6: AES encryption
function encryptMessageAES(message, symmetricKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", symmetricKey, iv);
  let encrypted = cipher.update(message, "utf8", "base64");
  encrypted += cipher.final("base64");
  const authTag = cipher.getAuthTag();
  return { encryptedData: encrypted, iv: iv.toString("base64"), authTag: authTag.toString("base64") };
}

// Step 7: Compute HMAC
function computeHMAC(message, symmetricKey) {
  return crypto.createHmac("sha256", symmetricKey).update(message).digest("base64");
}

// Step 6–7: Send encrypted message with HMAC
function sendEncryptedMessage(encryptedPayload) {
  const hmac = computeHMAC(payloadJsonString, symmetricKey);
  const payloadToSend = { ...encryptedPayload, hmac };

  const options = { hostname: "localhost", port: 3000, path: "/message", method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(JSON.stringify(payloadToSend)) }
  };
  const req = http.request(options, (res) => {
    let response = "";
    res.on("data", chunk => response += chunk);
    res.on("end", () => console.log("Server Response:", response));
  });
  req.on("error", console.error);
  req.write(JSON.stringify(payloadToSend));
  req.end();
}

// Full sequence
getPublicKey((publicKey) => {
  const encryptedKey = encryptSymmetricKey(publicKey, symmetricKey);
  sendEncryptedKey(encryptedKey, () => {
    const encryptedPayload = encryptMessageAES(payloadJsonString, symmetricKey);
    sendEncryptedMessage(encryptedPayload);
  });
});

