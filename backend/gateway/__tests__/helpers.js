const express = require('express');
const http = require('http');

function createTestApp() {
  const app = express();
  app.use(express.json());
  return app;
}

function startServer(app, port = 0) {
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      const addr = server.address();
      resolve({ server, port: addr.port });
    });
  });
}

function stopServer(server) {
  return new Promise((resolve) => {
    if (server) server.close(resolve);
    else resolve();
  });
}

async function makeRequest(port, method, path, body = null, headers = {}) {
  const defaultHeaders = {
    'Content-Type': 'application/json',
    'X-Api-Key': 'test-key',
    ...headers
  };

  const options = {
    hostname: 'localhost',
    port,
    path,
    method,
    headers: defaultHeaders
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

module.exports = { createTestApp, startServer, stopServer, makeRequest };
