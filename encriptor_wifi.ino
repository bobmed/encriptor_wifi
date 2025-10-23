#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <Crypto.h>
#include <AES.h>
#include <CBC.h>
#include <map>
#include <set>
#include <DNSServer.h>

const byte DNS_PORT = 53;
DNSServer dnsServer;

struct UploadSession {
  //bool isFirst = true;
  unsigned long lastAccess = millis();
};

std::map<String, UploadSession> sessions;

const char* ssid = "best_project_ever";
const char* password = "bobmed";

ESP8266WebServer server(80);

AES256 aes;
CBC<AES256> cbc;

byte key[32] = { 0xF0, 0xB1, 0xB2, 0xF3, 0xA4, 0xC5, 0xD6, 0xD7, 0xA8, 0xA9, 0x2A, 0xBB, 0xC5, 0xDD, 0xEE, 0xFF, 0x00, 0x16, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xD8, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xE3, 0xFF };


const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="uk">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>File Decryption</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><text y='26' font-size='26'>❤️</text></svg>">

  <style>
    body {
      margin: 0;
      font-family: sans-serif;
      background: white;
      color: black;
      padding: 2rem;
      box-sizing: border-box;
    }
    h1 {
      font-size: calc(1.5rem + 2vw);
    }
    input, button {
      font-size: 1.2rem;
      padding: 0.5rem 1rem;
      margin-top: 1rem;
    }
    #output {
      white-space: pre-wrap;
      border: 1px solid #ccc;
      padding: 1rem;
      margin-top: 1rem;
      background: #f4f4f4;
      overflow-y: auto;
      font-size: 0.9rem;
      max-height: 33vh;
    }
    #viewButton {
      display: none;
      margin-top: 1rem;
      padding: .5rem 1rem;
    }
    #progressContainer {
      margin-top: 1rem;
      width: 100%;
      background: #ddd;
      height: 20px;
      border-radius: 10px;
      overflow: hidden;
      display: none;
    }
    #progressBar {
      width: 0%;
      height: 100%;
      background: #4caf50;
      transition: width 0.3s ease;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: -1;
      background-image: repeating-linear-gradient(
        -45deg,
        transparent,
        transparent 30px,
        rgba(255,0,0,0.1) 30px,
        rgba(255,0,0,0.1) 60px
      );
      pointer-events: none;
    }
    .bg-text {
      position: fixed;
      top: -100%;
      left: -100%;
      width: 300%;
      height: 300%;
      transform: rotate(-45deg);
      font-size: 1rem;
      line-height: 1.5rem;
      color: rgba(255, 0, 0, 0.1);
      white-space: pre;
      z-index: -2;
      font-family: monospace;
    }
  </style>
</head>
<body>
  <div class="bg-text" id="bgText"></div>
  <h1>Put the file here, dear</h1>
  <input type="file" id="fileInput" />
  <button onclick="sendFile()">Send</button>
  <div id="progressContainer"><div id="progressBar"></div></div>
  <div id="output"></div>
  <button id="viewButton" onclick="showDecrypted()">See what's in there</button>

  <script>
    let decryptedData = '';
    let sessionId = '';
    let lastIv = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);

    function generateSessionId() {
      return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
    }

    function hexToBytes(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
    }

    function bytesToHex(bytes) {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function scrollOutputToBottom() {
      const output = document.getElementById('output');
      output.scrollTop = output.scrollHeight;
    }

    function appendOutput(text) {
      const output = document.getElementById('output');
      output.textContent += text;
      scrollOutputToBottom();
    }

    function prepareChunkData(encryptedData) {
      // Combine IV and encrypted data
      const combined = new Uint8Array(16 + encryptedData.length);
      combined.set(lastIv, 0);
      combined.set(encryptedData, 16);
      return combined;
    }

    function sendFile() {
      const file = document.getElementById('fileInput').files[0];
      if (!file) {
        alert('Please select a file first');
        return;
      }

      const reader = new FileReader();

      reader.onload = function(event) {
        const text = event.target.result;
        const chunks = text.split(/\r?\n/).filter(line => line.trim().length > 0);

        let currentIndex = 0;
        sessionId = generateSessionId();
        decryptedData = '';
        // Reset IV for new session
        lastIv = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
        
        const output = document.getElementById('output');
        output.textContent = 'File transfer started...\n';
        output.textContent += `Session ID: ${sessionId}\n`;
        scrollOutputToBottom();
        document.getElementById('viewButton').style.display = 'none';
        document.getElementById('progressContainer').style.display = 'block';
        document.getElementById('progressBar').style.width = '0%';
        document.querySelector('button[onclick="sendFile()"]').disabled = true;

        function sendChunk(index, retryCount = 0) {
          if (index >= chunks.length) {
            appendOutput('\nTransfer completed!');
            document.getElementById('viewButton').style.display = 'inline-block';
            document.querySelector('button[onclick="sendFile()"]').disabled = false;
            document.getElementById('progressBar').style.width = '100%';
            return;
          }

          let hexLine = chunks[index].trim();
          let encryptedData;

          try {
            encryptedData = hexToBytes(hexLine);
          } catch (e) {
            appendOutput(`Invalid HEX at chunk ${index}, skipping...\n`);
            updateProgress(index + 1, chunks.length);
            sendChunk(index + 1);
            return;
          }

          const chunkData = prepareChunkData(encryptedData);

          const xhr = new XMLHttpRequest();
          xhr.open("POST", `/upload?sessionId=${encodeURIComponent(sessionId)}&chunkIndex=${index}`, true);
          xhr.responseType = "text";
          xhr.setRequestHeader("Content-Type", "application/octet-stream");

          xhr.onload = function () {
            if (xhr.status === 200) {
              decryptedData += xhr.responseText;
              // Update lastIv from response if provided (optional)
              if (xhr.getResponseHeader('Next-IV')) {
                const hexIv = xhr.getResponseHeader('Next-IV');
                lastIv = hexToBytes(hexIv);
              }
              appendOutput(`Chunk ${index} of ${chunks.length - 1}: received ${xhr.responseText.length} bytes\n`);
              updateProgress(index + 1, chunks.length);
              sendChunk(index + 1);
            } else if (xhr.status === 409) {
              appendOutput(`Chunk ${index} skipped (duplicate)\n`);
              updateProgress(index + 1, chunks.length);
              sendChunk(index + 1);
            } else {
              if (retryCount < 2) {
                appendOutput(`Retrying chunk ${index}, attempt ${retryCount + 1}\n`);
                sendChunk(index, retryCount + 1);
              } else {
                appendOutput(`Error: ${xhr.status} on chunk ${index}\n`);
                document.querySelector('button[onclick="sendFile()"]').disabled = false;
              }
            }
          };

          xhr.onerror = function () {
            if (retryCount < 200) {
              appendOutput(`Connection error on chunk ${index}, retrying...\n`);
              sendChunk(index, retryCount + 1);
            } else {
              appendOutput(`Connection error on chunk ${index}, giving up\n`);
              document.querySelector('button[onclick="sendFile()"]').disabled = false;
            }
          };

          xhr.send(new Blob([chunkData], {type: "application/octet-stream"}));
        }

        function updateProgress(current, total) {
          const percent = Math.round((current / total) * 100);
          document.getElementById('progressBar').style.width = percent + '%';
        }

        sendChunk(0);
      };

      reader.onerror = function() {
        alert('Error reading file');
      };

      reader.readAsText(file, 'utf-8');
    }

    function showDecrypted() {
      const w = window.open('', '_blank');
      w.document.open();
      w.document.write(decryptedData);
      w.document.close();
    }
  </script>
</body>
</html>
)rawliteral";

void cleanupSessions() {
  unsigned long now = millis();
  for (auto it = sessions.begin(); it != sessions.end(); ) {
    if (now - it->second.lastAccess > 300000) {
      it = sessions.erase(it);
    } else {
      ++it;
    }
  }
}

void handleRoot() {
  server.send_P(200, "text/html", index_html);
}

void handleNotFound() {
  server.send(404, "text/plain", "Not found");
}

void handleUpload() {
  if (!server.hasArg("sessionId") || !server.hasArg("chunkIndex")) {
    server.send(400, "text/plain", "Missing sessionId or chunkIndex");
    return;
  }

  String sessionId = server.arg("sessionId");
  size_t chunkIndex = server.arg("chunkIndex").toInt();

  if (server.args() == 0 || server.arg("plain").length() == 0) {
    server.send(400, "text/plain", "Missing or empty body");
    return;
  }

  String body = server.arg("plain");
  size_t contentLength = body.length();

  if (contentLength < 16) {
    server.send(400, "text/plain", "Data too short - must include IV");
    return;
  }

  UploadSession &session = sessions[sessionId];
  session.lastAccess = millis();

  // Extract IV from first 16 bytes
  byte iv[16];
  memcpy(iv, body.c_str(), 16);
  
  // The rest is encrypted data
  byte* encrypted = new byte[contentLength - 16];
  memcpy(encrypted, body.c_str() + 16, contentLength - 16);

  cbc.clear();
  cbc.setKey(key, sizeof(key));
  cbc.setIV(iv, sizeof(iv));

  byte* decrypted = new byte[contentLength - 16];
  cbc.decrypt(decrypted, encrypted, contentLength - 16);

  // Get the last block as IV for next chunk
  byte nextIv[16];
  if (contentLength - 16 >= 16) {
    memcpy(nextIv, encrypted + (contentLength - 16 - 16), 16);
  } else {
    memcpy(nextIv, iv, 16); // fallback if data is too short
  }
  delete[] encrypted;

  // --- PKCS7 unpad ---
  size_t decryptedLength = contentLength - 16;
  if (decryptedLength > 0) {
    byte pad = decrypted[decryptedLength - 1];
    if (pad > 0 && pad <= 16) {
      bool valid = true;
      for (size_t i = 0; i < pad; ++i) {
        if (decrypted[decryptedLength - 1 - i] != pad) {
          valid = false;
          break;
        }
      }
      if (valid) {
        decryptedLength -= pad;
      }
    }
  }

  char* tempBuf = new char[decryptedLength + 1];
  memcpy(tempBuf, decrypted, decryptedLength);
  delete[] decrypted;
  tempBuf[decryptedLength] = '\0';

  String decryptedStr = String(tempBuf);
  delete[] tempBuf;

  // Send next IV back to client for next chunk
  char nextIvHex[33];
  for (int i = 0; i < 16; i++) {
    sprintf(nextIvHex + i * 2, "%02x", nextIv[i]);
  }
  server.sendHeader("Next-IV", nextIvHex);
  server.send(200, "text/plain; charset=utf-8", decryptedStr);

  cleanupSessions();
}

void setup() {
  WiFi.softAP(ssid, password);

  dnsServer.start(DNS_PORT, "hello.there", WiFi.softAPIP());

  server.on("/", HTTP_GET, handleRoot);
  server.on("/upload", HTTP_POST, handleUpload);
  server.onNotFound(handleNotFound);

  server.begin();
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();
}
