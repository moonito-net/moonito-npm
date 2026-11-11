const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { VisitorTrafficFiltering } = require('../dist');

const config = { isProtected: true, apiPublicKey: 'pub_123', apiSecretKey: 'sec' };
const allow = JSON.stringify({ data: { status: { need_to_block: false } } });
const PAGE = '<!DOCTYPE html><html><head><title>Shop</title></head><body><h1>Hi</h1></body></html>';

// A real Node http server, so res.write/res.end/Content-Length behave for real.
function serve(sdkConfig, handler, verdict = allow) {
  const sdk = new VisitorTrafficFiltering({ ...config, ...sdkConfig });
  sdk.requestAnalyticsAPI = async () => verdict;
  const server = http.createServer(async (req, res) => {
    await sdk.evaluateVisitor(req, res);
    if (!res.writableEnded) handler(req, res);
  });
  server.keepAliveTimeout = 1;
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function get(server, path = '/', headers = {}) {
  const { port } = server.address();
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path, agent: false, headers: { accept: 'text/html', 'x-forwarded-for': '185.137.164.30', ...headers } }, (res) => {
      let body = ''; res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
}

test('an HTML page gets the sensor once, before </head>, with a correct Content-Length', async () => {
  const server = await serve({}, (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Length', Buffer.byteLength(PAGE));
    res.end(PAGE);
  });
  const r = await get(server); server.closeAllConnections(); server.close();
  assert.equal((r.body.match(/data-guard-sensor/g) || []).length, 1);
  assert.match(r.body, /sensor@1\.1\.1\/t\.js".*data-key="pub_123".*<\/script><\/head>/);
  assert.match(r.body, /integrity="sha384-/);
  assert.equal(Number(r.headers['content-length']), Buffer.byteLength(r.body));
});

test('a page written in several chunks is still injected', async () => {
  const server = await serve({}, (req, res) => {
    res.writeHead; res.setHeader('Content-Type', 'text/html');
    res.write('<!DOCTYPE html><html><head><title>A</title>');
    res.write('</head><body>');
    res.end('x</body></html>');
  });
  const r = await get(server); server.closeAllConnections(); server.close();
  assert.equal((r.body.match(/data-guard-sensor/g) || []).length, 1);
  assert.ok(r.body.endsWith('x</body></html>'));
});

test('JSON, compressed, CSP, error and already-tagged pages are untouched', async () => {
  const cases = {
    json: (res) => { res.setHeader('Content-Type', 'application/json'); res.end('{"a":"</head>"}'); },
    gzip: (res) => { res.setHeader('Content-Type', 'text/html'); res.setHeader('Content-Encoding', 'gzip'); res.end(PAGE); },
    csp: (res) => { res.setHeader('Content-Type', 'text/html'); res.setHeader('Content-Security-Policy', "script-src 'self'"); res.end(PAGE); },
    error: (res) => { res.statusCode = 500; res.setHeader('Content-Type', 'text/html'); res.end(PAGE); },
    tagged: (res) => { res.setHeader('Content-Type', 'text/html'); res.end(PAGE.replace('</head>', '<script src="https://cdn.jsdelivr.net/gh/moonito-net/sensor@1.0.0/t.js"></script></head>')); },
    metaCsp: (res) => { res.setHeader('Content-Type', 'text/html'); res.end(PAGE.replace('<title>', '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><title>')); },
  };
  for (const [name, send] of Object.entries(cases)) {
    const server = await serve({}, (req, res) => send(res));
    const r = await get(server); server.closeAllConnections(); server.close();
    assert.equal((r.body.match(/data-guard-sensor/g) || []).length, 0, name);
  }
});

test('API calls, assets and the off switch are untouched', async () => {
  const html = (req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(PAGE); };
  let server = await serve({}, html);
  assert.ok(!(await get(server, '/', { accept: 'application/json' })).body.includes('data-guard-sensor'), 'json accept');
  assert.ok(!(await get(server, '/', { 'x-requested-with': 'XMLHttpRequest' })).body.includes('data-guard-sensor'), 'xhr');
  assert.ok(!(await get(server, '/', { 'sec-fetch-dest': 'image' })).body.includes('data-guard-sensor'), 'asset');
  server.closeAllConnections(); server.close();
  server = await serve({ injectSensor: false }, html);
  assert.ok(!(await get(server)).body.includes('data-guard-sensor'), 'off switch');
  server.closeAllConnections(); server.close();
});

test('a blocked visitor gets the blocked answer, not a sensor', async () => {
  const server = await serve({}, (req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(PAGE); },
    JSON.stringify({ data: { status: { need_to_block: true } } }));
  const r = await get(server); server.closeAllConnections(); server.close();
  assert.equal(r.status, 403);
  assert.ok(!r.body.includes('data-guard-sensor'));
});

test('when the API fails the visitor is let through and still gets the sensor', async () => {
  const sdk = new VisitorTrafficFiltering(config);
  sdk.requestAnalyticsAPI = async () => { throw new Error('down'); };
  const server = http.createServer(async (req, res) => {
    await sdk.evaluateVisitor(req, res);
    res.setHeader('Content-Type', 'text/html'); res.end(PAGE);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const r = await get(server); server.closeAllConnections(); server.close();
  assert.equal(r.status, 200);
  assert.equal((r.body.match(/data-guard-sensor/g) || []).length, 1);
});

test('Unicode pages survive byte for byte', async () => {
  const page = PAGE.replace('Hi', 'Halo 😀 dunia ñ');
  const server = await serve({}, (req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(Buffer.from(page)); });
  const r = await get(server); server.closeAllConnections(); server.close();
  assert.ok(r.body.includes('Halo 😀 dunia ñ'));
});
