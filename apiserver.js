const express = require("express");
const crypto = require("crypto");
const app = express();

app.use(express.json());

// Step 3: RSA Key Generation
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" }
});

console.log("RSA Public Key Generated:\n", publicKey);
console.log("RSA Private Key Generated:\n", privateKey);

// Store symmetric key after exchange
let symmetricKey = null;

// Step 4: Serve public key
app.get("/public-key", (req, res) => {
  res.send(publicKey);
});

// Step 5: Receive encrypted symmetric key
app.post("/exchange-key", (req, res) => {
  const encryptedKey = Buffer.from(req.body.encryptedKey, "base64");
  symmetricKey = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedKey
  );

  console.log("Server Decrypted Symmetric Key:", symmetricKey.toString("hex"));
  res.json({ status: "Symmetric key securely received" });
});

// Step 6–10: Receive encrypted message
app.post("/message", (req, res) => {
  if (!symmetricKey) {
    return res.status(400).json({ status: "Symmetric key not set yet" });
  }

  try {
    const { encryptedData, iv, authTag, hmac: receivedHMAC } = req.body;

    // Step 9: AES-GCM decryption
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      symmetricKey,
      Buffer.from(iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(authTag, "base64"));

    let decryptedMessage = decipher.update(encryptedData, "base64", "utf8");
    decryptedMessage += decipher.final("utf8");

    // Step 8: Verify HMAC
    const computedHMAC = crypto.createHmac("sha256", symmetricKey)
                               .update(decryptedMessage)
                               .digest("base64");

    if (computedHMAC !== receivedHMAC) {
      console.log("Integrity check FAILED ❌");
      return res.status(400).json({ status: "Integrity verification failed" });
    }

    console.log("Integrity verified ✅");

    // Step 10: Deserialize JSON to Student object
    const studentObj = JSON.parse(decryptedMessage);
    console.log("Deserialized Student Object:", studentObj);

    res.json({ status: "Message decrypted, integrity verified, object deserialized" });

  } catch (err) {
    console.error("Error processing message:", err);
    res.status(500).json({ status: "Server error" });
  }
});

// Optional: quick server test
app.get("/", (req, res) => res.send("Server running"));

app.listen(3000, () => console.log("Server listening on port 3000"));










