const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { VisitorTrafficFiltering } = require('../dist');

const config = { isProtected: true, apiPublicKey: 'dummy-public', apiSecretKey: 'dummy-secret' };
function request(cookie = '') {
  return { headers: { host: 'example.com', cookie, 'user-agent': 'browser' },
    hostname: 'example.com', url: '/private', method: 'GET', protocol: 'https',
    socket: { remoteAddress: '185.137.164.30' }, get(name) { return this.headers[name.toLowerCase()]; } };
}
function response() {
  return { headersSent: false, statusCode: 200, headers: {},
    setHeader(n, v) { this.headers[n.toLowerCase()] = v; },
    getHeader(n) { return this.headers[n.toLowerCase()]; },
    status(n) { this.statusCode = n; return this; },
    send(v) { this.body = v; this.headersSent = true; return this; },
    end(v) { return this.send(v); }, sendStatus(n) { return this.status(n).send('status'); },
    redirect(n, v) { return this.status(n).send(v); } };
}
const verdict = (block = true, extra = {}) => JSON.stringify({ data: { status: { need_to_block: block }, ...extra } });

for (const cookie of ['', '__mo_ct=%', '__mo_pass=%E0%A4%A', '__mo_ct=' + 'a'.repeat(97), '__mo_pass=' + 'a'.repeat(1025)]) {
  test('untrusted cookie still checks and blocks: ' + cookie.slice(0, 30), async () => {
    const sdk = new VisitorTrafficFiltering(config); let calls = 0;
    sdk.httpRequest = async (_, __, payload) => {
      calls++; const body = JSON.parse(payload);
      assert.equal(body.client_token, undefined); assert.equal(body.challenge_pass, undefined);
      return verdict();
    };
    const res = response(); await sdk.evaluateVisitor(request(cookie), res);
    assert.equal(calls, 1); assert.equal(res.statusCode, 403); assert.equal(res.headersSent, true);
  });
}

test('payload limits, Unicode, cookie decoding, and credential exclusion', async () => {
  const sdk = new VisitorTrafficFiltering(config), req = request('__mo_ct=abc%3D; __mo_pass=proof%3D');
  req.url = '/' + '😀'.repeat(5000); req.method = 'A'.repeat(30);
  req.headers['user-agent'] = '😀'.repeat(2500);
  req.headers.Authorization = 'secret'; req.headers['Proxy-Authorization'] = 'secret';
  for (let i = 0; i < 100; i++) req.headers['x-test-' + i] = '😀'.repeat(3000);
  sdk.httpRequest = async (_, options, payload) => {
    const body = JSON.parse(payload);
    assert.equal(Array.from(body.path).length, 512); assert.equal(Array.from(body.events).length, 4096);
    assert.equal(Array.from(body.ua).length, 2048); assert.equal(body.method.length, 16);
    assert.equal(Object.keys(body.headers).length, 64);
    for (const [name, value] of Object.entries(body.headers)) {
      assert.ok(!['cookie', 'authorization', 'proxy-authorization'].includes(name.toLowerCase()));
      assert.ok(Array.from(value).length <= 2048);
    }
    assert.equal(body.client_token, 'abc='); assert.equal(body.challenge_pass, 'proof=');
    assert.match(options.headers['User-Agent'], /^Moonito-Node\//);
    return verdict();
  };
  const res = response(); await sdk.evaluateVisitor(req, res); assert.equal(res.statusCode, 403);
});

test('action 3 waits for replacement page before middleware may continue', async () => {
  const sdk = new VisitorTrafficFiltering({ ...config, unwantedVisitorAction: 3, unwantedVisitorTo: 'https://other.example/blocked' });
  sdk.requestAnalyticsAPI = async () => verdict(); let release;
  sdk.httpRequestWithBypass = () => new Promise(resolve => { release = resolve; });
  const res = response(); let finished = false;
  const pending = sdk.evaluateVisitor(request(), res).then(() => { finished = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(finished, false);
  release('replacement'); await pending; assert.equal(res.body, 'replacement'); assert.equal(res.headersSent, true);
  sdk.httpRequestWithBypass = async () => { throw new Error('unavailable'); };
  const failed = response(); await sdk.evaluateVisitor(request(), failed);
  assert.equal(failed.statusCode, 500); assert.equal(failed.headersSent, true);
  sdk.httpRequestWithBypass = async () => 'manual replacement';
  const manual = await sdk.evaluateVisitorManually('185.137.164.30', 'browser', '/', 'example.com');
  assert.equal(manual.content, 'manual replacement');
});

for (const existing of ['session=one', ['session=one', 'csrf=two']]) {
  test('preserves application cookies and emits context independently: ' + JSON.stringify(existing), async () => {
    const sdk = new VisitorTrafficFiltering(config); const res = response(); res.setHeader('Set-Cookie', existing);
    sdk.requestAnalyticsAPI = async () => verdict(false, { set_client_token: { value: 'identity' }, decision_id: 'did', nonce: 'proof' });
    await sdk.evaluateVisitor(request(), res);
    const cookies = res.getHeader('Set-Cookie');
    for (const cookie of [].concat(existing)) assert.ok(cookies.includes(cookie));
    assert.ok(cookies.some(c => c.startsWith('__mo_ct=identity;')));
    assert.ok(cookies.some(c => c.startsWith('__mo_cx=did%3Aproof;') && c.includes('Max-Age=120') && c.includes('Secure')));
    const second = response(); sdk.requestAnalyticsAPI = async () => verdict(false, { decision_id: 'next', nonce: 'next-proof' });
    await sdk.evaluateVisitor(request(), second);
    assert.equal(second.getHeader('Set-Cookie').length, 1);
    assert.match(second.getHeader('Set-Cookie')[0], /^__mo_cx=next%3Anext-proof;/);
    assert.equal(second.headersSent, false);
  });
}

for (const action of ['allow', 'block', 'challenge']) {
  test('challenge action ' + action, async () => {
    const sdk = new VisitorTrafficFiltering({ ...config, challengeAction: action });
    sdk.requestAnalyticsAPI = async () => verdict(false, { challenge_url: 'https://challenge.example/check' });
    const res = response(); await sdk.evaluateVisitor(request(), res);
    assert.equal(res.headersSent, action !== 'allow');
    if (action === 'block') assert.equal(res.statusCode, 403);
    if (action === 'challenge') assert.match(res.body, /sessionStorage/);
  });
}

test('real local HTTP transport reaches API and blocks; API failures retain fail-open', async t => {
  const server = http.createServer((req, res) => { let body = ''; req.on('data', chunk => body += chunk); req.on('end', () => {
    assert.equal(req.url, '/api/v2/decision'); assert.equal(JSON.parse(body).ip, '185.137.164.30'); res.end(verdict());
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => server.close());
  const sdk = new VisitorTrafficFiltering({ ...config, endpoint: `http://127.0.0.1:${server.address().port}` });
  const res = response(); await sdk.evaluateVisitor(request('__mo_ct=%'), res); assert.equal(res.statusCode, 403);
  for (const reply of ['invalid JSON', '{"error":{"message":"expired"}}']) {
    sdk.requestAnalyticsAPI = async () => reply; const open = response();
    await sdk.evaluateVisitor(request(), open); assert.equal(open.headersSent, false);
  }
  sdk.requestAnalyticsAPI = async () => { throw new Error('network'); };
  const open = response(); await sdk.evaluateVisitor(request(), open); assert.equal(open.headersSent, false);
});
