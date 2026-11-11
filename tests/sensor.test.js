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
  const param = new VisitorTrafficFiltering(config).relayParam();
  assert.match(r.body, new RegExp(`src="/\\?${param}=s&amp;v=1\\.2\\.0" data-endpoint="/" data-key="pub_123" data-p="${param}" data-guard-sensor></script></head>`));
  assert.ok(!/moonito|jsdelivr/i.test(r.body), 'the page names an outside host or the service');
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
    csp: (res) => { res.setHeader('Content-Type', 'text/html'); res.setHeader('Content-Security-Policy', "script-src https://cdn.example"); res.end(PAGE); },
    cspStrict: (res) => { res.setHeader('Content-Type', 'text/html'); res.setHeader('Content-Security-Policy', "script-src 'nonce-abc' 'strict-dynamic'"); res.end(PAGE); },
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

test('the sensor\'s own requests are answered on the site, without a decision', async () => {
  const relayed = [];
  let decisions = 0;
  const sdk = new VisitorTrafficFiltering(config);
  sdk.requestAnalyticsAPI = async () => { decisions++; return allow; };
  sdk.relayBeacon = async (ip, beacon) => { relayed.push({ ip, beacon }); };
  const server = http.createServer(async (req, res) => {
    await sdk.evaluateVisitor(req, res);
    if (!res.writableEnded) { res.setHeader('Content-Type', 'text/html'); res.end(PAGE); }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const param = sdk.relayParam();

  const script = await get(server, `/shop?${param}=s&v=1.2.0`);
  assert.equal(script.status, 200);
  assert.match(script.headers['content-type'], /javascript/);
  assert.match(script.headers['cache-control'], /immutable/);
  assert.equal(script.body, require('../dist/sensor-script').SENSOR_SCRIPT);
  assert.ok(!/moonito/i.test(script.body), 'the served script names the service');

  assert.equal((await get(server, `/shop?${param}=p`)).status, 204);

  const beacon = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: `/shop?${param}=t`, method: 'POST', agent: false,
      headers: { 'content-type': 'text/plain', 'x-forwarded-for': '185.137.164.30' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.end('{"k":"pub_123"}');
  });
  assert.equal(beacon, 204);
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(relayed, [{ ip: '185.137.164.30', beacon: '{"k":"pub_123"}' }]);
  assert.equal(decisions, 0, 'a sensor request must not cost a decision');

  // Another site's parameter, or a generic one, is just a page.
  assert.equal((await get(server, '/shop?__vt=s')).status, 200);
  assert.equal(decisions, 1);
  assert.notEqual(new VisitorTrafficFiltering({ ...config, apiPublicKey: 'pub_456' }).relayParam(), param);
  server.closeAllConnections(); server.close();
});

test('a beacon is forwarded to the relay endpoint with the secret key', async () => {
  const received = [];
  const api = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => (body += c));
    req.on('end', () => { received.push({ url: req.url, secret: req.headers['x-secret-key'], body: JSON.parse(body) }); res.statusCode = 202; res.end(); });
  });
  await new Promise((r) => api.listen(0, '127.0.0.1', r));
  const sdk = new VisitorTrafficFiltering({ ...config, endpoint: `http://127.0.0.1:${api.address().port}` });
  await sdk.relayBeacon('203.0.113.9', '{"k":"pub_123"}');
  api.close();
  assert.deepEqual(received, [{ url: '/api/v2/telemetry/relay', secret: 'sec', body: { ip: '203.0.113.9', p: '{"k":"pub_123"}' } }]);
});

test('a helmet-style policy that allows self still gets the sensor, with the page path', async () => {
  const server = await serve({}, (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Security-Policy', "default-src 'self';script-src 'self';object-src 'none'");
    res.end(PAGE);
  });
  const r = await get(server, '/shop/item?id=5'); server.closeAllConnections(); server.close();
  assert.match(r.body, /src="\/shop\/item\?_[0-9a-f]{7}=s&amp;v=1\.2\.0" data-endpoint="\/shop\/item"/);
});
