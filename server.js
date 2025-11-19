// server.js
const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const TOKEN = process.env.TOKEN;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const ACCOUNT_ID = process.env.ACCOUNT_ID;
const SCRIPT = 898;
const DEPLOY = 1;
const HTTP_METHOD = "GET";

function percentEncode(str = "") {
  return encodeURIComponent(String(str))
    .replace(/\!/g, "%21")
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
}

function generateHeader() {
  const url = `https://${ACCOUNT_ID}.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=${SCRIPT}&deploy=${DEPLOY}`;

  const nonce = crypto.randomBytes(8).toString("hex");
  const timestamp = Math.floor(Date.now() / 1000);

  const params = {
    oauth_consumer_key: CONSUMER_KEY,
    oauth_token: TOKEN,
    oauth_nonce: nonce,
    oauth_timestamp: timestamp,
    oauth_signature_method: "HMAC-SHA256",
    oauth_version: "1.0"
  };

  const baseString =
    HTTP_METHOD + "&" +
    percentEncode(url) + "&" +
    percentEncode(
      Object.keys(params)
        .sort()
        .map(k => `${percentEncode(k)}=${percentEncode(params[k])}`)
        .join("&")
    );

  const signingKey = percentEncode(CONSUMER_SECRET) + "&" + percentEncode(TOKEN_SECRET);

  const signature = crypto.createHmac("sha256", signingKey).update(baseString).digest("base64");

  return `OAuth realm="3580073",oauth_consumer_key="221f4528f81eb09a7cbac9f3e6185c4a9e9146091a8d54cb005789d0b68f1a7a",oauth_token="ba9620bc4fb9aa23e74d415f55bdaacb8cca7e23abc8fde419594b127349990e",oauth_signature_method="HMAC-SHA256",oauth_timestamp="${timestamp}",oauth_nonce="${nonce}",oauth_version="1.0",oauth_signature="${percentEncode(signature)}"`;
}

app.get("/auth-header", (req, res) => {
  const header = generateHeader();
  res.setHeader("Content-Type", "text/plain");
  res.send(header);
});

app.listen(PORT, () => {
  console.log(`Auth header server listening on port ${PORT}`);
});
