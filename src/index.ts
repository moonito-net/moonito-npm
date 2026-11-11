import * as https from 'https';
import * as http from 'http';
import * as net from 'net';
import * as querystring from 'querystring';
import * as crypto from 'crypto';
import {URL} from 'url';
import {SENSOR_SCRIPT, SENSOR_VERSION} from './sensor-script';

interface RequestContext {
    clientToken?: string;
    challengePass?: string;
    headers?: Record<string, any>;
    method?: string;
    path?: string;
}

interface Config {
    isProtected: boolean;
    endpoint?: string;
    /**
     * What to do when the engine asks for a challenge.
     *
     *   allow      treat it as an allow and log it. The default.
     *   block      treat it as a block.
     *   challenge  actually show the interstitial.
     *
     * The default is 'allow' on purpose, and matches the PHP SDK. Turning a
     * scored challenge into a real page interruption changes what a visitor
     * sees, and that is the site owner's decision, not a side effect of taking
     * an upgrade.
     */
    challengeAction?: 'allow' | 'block' | 'challenge';
    apiPublicKey: string;
    apiSecretKey: string;
    unwantedVisitorTo?: string;
    unwantedVisitorAction?: number;
    /**
     * Public proxy or load balancer addresses whose X-Forwarded-For may be
     * believed. Private addresses (nginx, Docker, a cloud load balancer) and
     * Cloudflare are recognised without being listed.
     */
    trustedProxies?: string[];
    /**
     * Add the browser sensor to HTML pages automatically, so there is no
     * second script to paste. On by default. Pages that are compressed before
     * this middleware sees them, carry a Content-Security-Policy, or already
     * have the sensor are left exactly as they are.
     */
    injectSensor?: boolean;
}

/** The browser sensor this release adds to HTML pages (same as the PHP SDK). */
const SENSOR = {
    // A sensor tag pasted by hand from the CDN; recognised so it is never doubled.
    path: '/gh/moonito-net/sensor@',
    marker: 'data-guard-sensor',
    maxBytes: 5 * 1024 * 1024,
    maxBeacon: 8192,
};

/**
 * Whether a Content-Security-Policy lets the sensor run. It is served from the
 * site itself, so 'self' for scripts and for requests is all it needs. A
 * policy built on nonces or 'strict-dynamic' is left alone.
 */
function cspAllowsSelf(header: unknown): boolean {
    if (header === undefined || header === null) {
        return true;
    }

    const directives: Record<string, string[]> = {};
    for (const part of String(Array.isArray(header) ? header.join(';') : header).split(';')) {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        const name = (tokens.shift() || '').toLowerCase();
        if (name && !(name in directives)) {
            directives[name] = tokens.map((t) => t.toLowerCase());
        }
    }

    const allows = (sources: string[] | undefined) => sources === undefined
        || (!sources.includes("'none'") && (sources.includes("'self'") || sources.includes('*')));
    const script = directives['script-src-elem'] ?? directives['script-src'] ?? directives['default-src'];
    const connect = directives['connect-src'] ?? directives['default-src'];

    return !(script && script.includes("'strict-dynamic'")) && allows(script) && allows(connect);
}

/** Cloudflare's published edge ranges. CF-Connecting-IP is only read from these. */
const CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

export class VisitorTrafficFiltering {
    private config: Config;
    public static readonly VERSION = '2.5.0';
    private static readonly IDENTITY_COOKIE = '__mo_ct';
    private static readonly PASS_COOKIE = '__mo_pass';
    private static readonly BYPASS_HEADER = 'X-VTF-Bypass';
    private static readonly BYPASS_TOKEN_HEADER = 'X-VTF-Token';
    private bypassToken: string;

    /**
     * Creates an instance of AnalyticsHandler.
     * @param config - The configuration for the handler, including protection settings and API keys.
     */
    constructor(config: Config) {
        this.config = config;
        // Generate a secure random token that changes per instance
        this.bypassToken = this.generateSecureToken();
    }

    /**
     * Generates a secure random token for bypass validation
     * @returns {string} A secure random token
     */
    private generateSecureToken(): string {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Validates if the bypass token is correct
     * @param token - The token to validate
     * @returns {boolean} True if token is valid
     */
    private isValidBypassToken(token: string | undefined): boolean {
        if (!token) return false;
        // Use timing-safe comparison to prevent timing attacks
        try {
            return crypto.timingSafeEqual(
                Buffer.from(token),
                Buffer.from(this.bypassToken)
            );
        } catch {
            return false;
        }
    }

    /**
     * Handles visitor requests by checking IP address and interacting with the analytics API.
     * This method:
     * 1. Checks if protection is enabled.
     * 2. Retrieves and validates the client's IP address and other request details.
     * 3. Makes a request to the analytics API to check if the visitor should be blocked.
     * 4. Takes action based on the API response and configuration, such as redirecting or displaying content.
     *
     * @param req - The request object, typically from an Express.js application.
     * @param res - The response object, typically from an Express.js application.
     * @returns {Promise<void>} A promise that resolves when the response is sent.
     * @throws {Error} Throws an error if there's an issue with the IP address or the API request.
     */
    public async evaluateVisitor(req: any, res: any): Promise<void> {
        if (!this.config.isProtected) {
            return;
        }

        // The browser sensor's own requests (script, timing, beacon) come to
        // this same URL with a parameter only this site uses. Answered here,
        // before any decision, so the browser only ever talks to this site.
        const relay = this.config.injectSensor === false ? null : this.relayKind(req);
        if (relay !== null) {
            this.addExpressHelpers(res);
            await this.serveRelay(relay, req, res);

            return;
        }

        // Check for valid bypass token (only for internal server-to-server requests)
        const bypassHeader = req.headers[VisitorTrafficFiltering.BYPASS_HEADER.toLowerCase()];
        const tokenHeader = req.headers[VisitorTrafficFiltering.BYPASS_TOKEN_HEADER.toLowerCase()];

        if (bypassHeader === '1' && this.isValidBypassToken(tokenHeader)) {
            return;
        }

        // Get current URL
        const currentUrl = this.getCurrentUrl(req);

        // Skip filtering if current URL matches the unwantedVisitorTo
        // This prevents loops in Action 1 (Redirect) and Action 2 (Iframe)
        if (this.config.unwantedVisitorTo && this.urlsMatch(currentUrl, this.config.unwantedVisitorTo)) {
            return;
        }

        const clientIp = this.getClientIp(req);
        const userAgent = req.headers['user-agent'] || '';
        const url = req.url;
        const domain = String(req.hostname || req.headers.host || '').toLowerCase().replace(/:\d+$/, '');

        // Fail open from here on. Anything that stops the check from running,
        // an unreadable address, an API refusal, a network fault, lets the
        // visitor through instead of throwing into the customer's app, where
        // the README's next(error) turned it into a 500 for every visitor.
        if (!this.isValidIp(clientIp)) {
            console.error('Moonito: could not determine the visitor IP, request not checked');
            return;
        }

        this.addExpressHelpers(res);

        let allowed = false;

        try {
            const response = await this.requestAnalyticsAPI(clientIp, userAgent, url, domain, {
                clientToken: this.readClientToken(req),
                challengePass: this.readChallengePass(req),
                headers: req.headers,
                method: req.method,
                path: url,
            });
            const data = JSON.parse(response);

            if (data.error) {
                console.error(`Moonito: API refused the check, visitor allowed: ${Array.isArray(data.error.message) ? data.error.message.join(', ') : data.error.message}`);
                this.startSensor(req, res);

                return;
            }

            this.writeResponseCookies(req, res, data?.data);

            if (data?.data?.status?.need_to_block) {
                await this.handleBlockedVisitor(res);

                return;
            }

            // A challenge is outranked by a block, so it is only considered
            // once the visitor was not blocked outright.
            const challengeUrl = data?.data?.challenge_url;

            if (typeof challengeUrl === 'string' && challengeUrl !== '') {
                const action = this.config.challengeAction || 'allow';

                if (action === 'challenge') {
                    this.renderChallenge(req, res, challengeUrl);
                    return;
                } else if (action === 'block') {
                    await this.handleBlockedVisitor(res);
                    return;
                }
                // 'allow' falls through: the verdict is logged server side and
                // the visitor is not interrupted.
            }

            allowed = true;
        } catch (error) {
            console.error(`Moonito: check could not run, visitor allowed: ${(error as Error).message}`);
            allowed = true;
        }

        if (allowed) {
            this.startSensor(req, res);
        }
    }

    /**
     * Add the browser sensor to the page this request is about to send.
     *
     * Wraps res.write and res.end, so it works for Express (res.send and
     * res.render end in res.end) and for plain Node http servers. Anything
     * that is not a whole HTML page is passed through byte for byte: the first
     * write decides, from the headers set by then, whether to buffer at all.
     * Must never throw and never lose a byte.
     */
    private startSensor(req: any, res: any): void {
        if (this.config.injectSensor === false || !this.config.apiPublicKey || !this.wantsPage(req)) {
            return;
        }

        if (typeof res?.write !== 'function' || typeof res?.end !== 'function' || res.headersSent) {
            return;
        }

        const write = res.write;
        const end = res.end;
        const chunks: Buffer[] = [];
        let size = 0;
        let mode: 'pending' | 'buffer' | 'pass' = 'pending';

        const restore = () => {
            res.write = write;
            res.end = end;
        };

        const decide = (): 'buffer' | 'pass' => {
            if (mode !== 'pending') {
                return mode;
            }

            try {
                const type = String(res.getHeader?.('content-type') ?? '').toLowerCase();
                const status = Number(res.statusCode ?? 200);
                const skip = res.headersSent
                    || (status < 200 || status >= 300 || status === 204)
                    || !type.includes('text/html')
                    || res.getHeader?.('content-encoding') !== undefined
                    || !cspAllowsSelf(res.getHeader?.('content-security-policy'))
                    || /attachment/i.test(String(res.getHeader?.('content-disposition') ?? ''));

                mode = skip ? 'pass' : 'buffer';
            } catch {
                mode = 'pass';
            }

            return mode;
        };

        const toBuffer = (chunk: any, encoding?: any): Buffer | null => {
            if (chunk === undefined || chunk === null || typeof chunk === 'function') {
                return null;
            }

            if (Buffer.isBuffer(chunk)) {
                return chunk;
            }

            if (chunk instanceof Uint8Array) {
                return Buffer.from(chunk);
            }

            return Buffer.from(String(chunk), typeof encoding === 'string' ? encoding as BufferEncoding : 'utf8');
        };

        const flush = (): void => {
            // Too large to hold: give back what was held, then stream as is.
            mode = 'pass';
            restore();

            if (chunks.length > 0) {
                write.call(res, Buffer.concat(chunks));
                chunks.length = 0;
            }
        };

        res.write = function (chunk: any, encoding?: any, callback?: any) {
            if (decide() === 'pass') {
                restore();

                return write.apply(res, arguments as any);
            }

            const buffer = toBuffer(chunk, encoding);

            if (buffer) {
                chunks.push(buffer);
                size += buffer.length;
            }

            if (size > SENSOR.maxBytes) {
                flush();
            }

            const done = typeof encoding === 'function' ? encoding : callback;
            if (typeof done === 'function') {
                process.nextTick(done);
            }

            return true;
        };

        const self = this;
        const path = this.pagePath(req);

        res.end = function (chunk?: any, encoding?: any, callback?: any) {
            if (decide() === 'pass') {
                restore();

                return end.apply(res, arguments as any);
            }

            restore();

            const last = toBuffer(chunk, encoding);
            if (last) {
                chunks.push(last);
            }

            const done = typeof chunk === 'function' ? chunk : typeof encoding === 'function' ? encoding : callback;
            let body = Buffer.concat(chunks);

            try {
                const html = body.toString('utf8');
                const changed = self.insertSensor(html, path);

                if (changed !== null) {
                    body = Buffer.from(changed, 'utf8');

                    if (!res.headersSent && res.getHeader?.('content-length') !== undefined) {
                        res.setHeader('Content-Length', body.length);
                    }
                }
            } catch {
                // Leave the page untouched.
            }

            return done ? end.call(res, body, done) : end.call(res, body);
        };
    }

    /**
     * res.status, res.send, res.sendStatus and res.redirect are Express. On a
     * plain Node http server they do not exist, so blocking threw and the
     * visitor was let through. Add minimal versions only where missing.
     */
    private addExpressHelpers(res: any): void {
        if (!res || typeof res.send === 'function' || typeof res.end !== 'function') {
            return;
        }

        res.status = function (code: number) { res.statusCode = code; return res; };
        res.send = function (body?: any) {
            if (!res.headersSent && res.getHeader('content-type') === undefined) {
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
            }
            res.end(body === undefined ? undefined : Buffer.isBuffer(body) ? body : String(body));
            return res;
        };
        res.sendStatus = function (code: number) { res.statusCode = code; return res.send(String(http.STATUS_CODES[code] ?? code)); };
        res.redirect = function (code: number | string, url?: string) {
            const target = typeof code === 'string' ? code : String(url);
            res.statusCode = typeof code === 'number' ? code : 302;
            res.setHeader('Location', target);
            res.end();
            return res;
        };
    }

    /**
     * The query parameter the sensor's requests use on this site. Derived from
     * the public key, so every site has its own: no URL pattern an ad blocker
     * list could match across customers, and no clash with the site's own
     * parameters. Same rule in every SDK.
     */
    public relayParam(): string {
        return '_' + crypto.createHash('sha256').update('sensor|' + String(this.config.apiPublicKey)).digest('hex').slice(0, 7);
    }

    /** 's' (script), 'p' (ping), 't' (beacon), or null for any other request. */
    private relayKind(req: any): 's' | 'p' | 't' | null {
        const url = String(req?.originalUrl || req?.url || '');
        const param = this.relayParam();
        if (url.indexOf(param + '=') === -1) {
            return null;
        }

        let kind: string | null = null;
        try {
            kind = new URL(url, 'http://localhost').searchParams.get(param);
        } catch {
            return null;
        }

        const method = String(req?.method || 'GET').toUpperCase();
        if (kind === 's' || kind === 'p') {
            return method === 'GET' || method === 'HEAD' ? kind : null;
        }

        return kind === 't' && method === 'POST' ? 't' : null;
    }

    private async serveRelay(kind: 's' | 'p' | 't', req: any, res: any): Promise<void> {
        if (kind === 's') {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            // Versioned URL, so the browser keeps it for a year.
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.end(SENSOR_SCRIPT);

            return;
        }

        const beacon = kind === 't' ? await this.readBeacon(req) : '';

        res.statusCode = 204;
        res.setHeader('Cache-Control', 'no-store, private');
        res.end();

        // After the browser has its answer: forward server to server.
        if (beacon !== '' && Buffer.byteLength(beacon) <= SENSOR.maxBeacon) {
            this.relayBeacon(this.getClientIp(req), beacon).catch(() => undefined);
        }
    }

    /** The beacon body, whether or not a body parser already read it. */
    private readBeacon(req: any): Promise<string> {
        if (typeof req?.body === 'string') {
            return Promise.resolve(req.body);
        }
        if (Buffer.isBuffer(req?.body)) {
            return Promise.resolve(req.body.toString('utf8'));
        }
        if (req?.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
            return Promise.resolve(JSON.stringify(req.body));
        }
        if (typeof req?.on !== 'function' || req.readableEnded) {
            return Promise.resolve('');
        }

        return new Promise((resolve) => {
            const chunks: Buffer[] = [];
            let size = 0;
            req.on('data', (chunk: Buffer) => {
                size += chunk.length;
                if (size <= SENSOR.maxBeacon + 1) {
                    chunks.push(Buffer.from(chunk));
                }
            });
            req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
            req.on('error', () => resolve(''));
        });
    }

    /** Forward a sensor beacon to Moonito. Two seconds at most; never throws. */
    public async relayBeacon(ip: string, beacon: string): Promise<void> {
        if (!this.isValidIp(ip) || beacon === '') {
            return;
        }

        const body = JSON.stringify({ ip, p: beacon });
        const url = new URL(this.endpoint() + '/api/v2/telemetry/relay');
        const client = url.protocol === 'http:' ? http : https;

        await new Promise<void>((resolve) => {
            const request = client.request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                    'User-Agent': `Moonito-Node/${VisitorTrafficFiltering.VERSION}`,
                    'X-Public-Key': this.config.apiPublicKey,
                    'X-Secret-Key': this.config.apiSecretKey,
                },
                timeout: 2000,
            }, (response) => {
                response.resume();
                response.on('end', () => resolve());
            });
            request.on('timeout', () => request.destroy());
            request.on('error', () => resolve());
            request.end(body);
        });
    }

    /** Whether this request is one a page is served for (not an API call or an asset). */
    private wantsPage(req: any): boolean {
        const method = String(req?.method ?? 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'POST') {
            return false;
        }

        const header = (name: string): string => String(req?.headers?.[name] ?? '').toLowerCase();

        if (header('x-requested-with') === 'xmlhttprequest') {
            return false;
        }

        const accept = header('accept');
        if (accept !== '' && !accept.includes('text/html') && !accept.includes('*/*')) {
            return false;
        }

        const dest = header('sec-fetch-dest');

        return dest === '' || dest === 'document' || dest === 'iframe';
    }

    /**
     * This page's own path, known to reach this SDK. Written into the tag so
     * the sensor always comes back to it, even on a page with a <base href> or
     * after a single-page app changes the address.
     */
    private pagePath(req: any): string {
        let path = '/';
        try {
            path = new URL(String(req?.originalUrl || req?.url || '/'), 'http://localhost').pathname;
        } catch {
            return '/';
        }

        return /^\/[^\s"<>\\]{0,2047}$/.test(path) ? path : '/';
    }

    /** The page with the sensor tag added, or null when it should be left alone. */
    public insertSensor(html: string, path = ''): string | null {
        if (html === '' || html.includes(SENSOR.path) || html.includes(SENSOR.marker)) {
            return null;
        }

        // A policy in a meta tag cannot be checked from here; stay out.
        if (/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy/i.test(html)) {
            return null;
        }

        const key = String(this.config.apiPublicKey).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
        const param = this.relayParam();
        // Served by this SDK from the page's own URL (serveRelay): no other
        // host, nothing that names the service.
        const at = path.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
        const tag = `<script defer src="${at}?${param}=s&amp;v=${SENSOR_VERSION}"${at ? ` data-endpoint="${at}"` : ''}`
            + ` data-key="${key}" data-p="${param}" ${SENSOR.marker}></script>`;

        const head = html.search(/<\/head>/i);
        if (head !== -1) {
            return html.slice(0, head) + tag + html.slice(head);
        }

        const body = /<body\b[^>]*>/i.exec(html);
        if (body) {
            const at = body.index + body[0].length;

            return html.slice(0, at) + tag + html.slice(at);
        }

        return null;
    }

    /**
     * Manually handles visitor data using provided IP address, user agent, and event.
     *
     * @param ip - The IP address of the visitor.
     * @param userAgent - The user agent string of the visitor.
     * @param event - The event associated with the visitor.
     * @param domain - The domain to be sent to the analytics API.
     * @returns {Promise<string>} The response content for blocked visitors.
     * @throws {Error} Throws an error if there's an issue with the IP address or the API request.
     */
    public async evaluateVisitorManually(ip: string, userAgent: string, event: string, domain: string): Promise<any> {
        if (!this.config.isProtected) {
            return { need_to_block: false, detect_activity: null, content: null };
        }

        // Skip filtering if event path matches the unwantedVisitorTo
        // Construct full URL from domain and event path for comparison
        if (this.config.unwantedVisitorTo) {
            let currentUrl: string;
            if (event.startsWith('http://') || event.startsWith('https://')) {
                // Event is already a full URL
                currentUrl = event;
            } else {
                // Event is a path - normalize it (add leading slash if missing)
                const normalizedPath = event.startsWith('/') ? event : `/${event}`;
                currentUrl = `https://${domain}${normalizedPath}`;
            }

            if (this.urlsMatch(currentUrl, this.config.unwantedVisitorTo)) {
                return { need_to_block: false, detect_activity: null, content: null };
            }
        }

        const allowed = { need_to_block: false, detect_activity: null, content: null };

        if (!this.isValidIp(ip)) {
            console.error('Moonito: invalid IP address, request not checked');
            return allowed;
        }

        try {
            const response = await this.requestAnalyticsAPI(ip, userAgent, event, domain);
            const data = JSON.parse(response);

            if (data.error) {
                console.error(`Moonito: API refused the check, visitor allowed: ${Array.isArray(data.error.message) ? data.error.message.join(', ') : data.error.message}`);
                return allowed;
            }

            const needToBlock = data?.data?.status?.need_to_block;
            const detectActivity = data?.data?.status?.detect_activity;

            if (needToBlock) {
                return { need_to_block: true, detect_activity: detectActivity, content: await this.getBlockedContent() };
            }

            return { need_to_block: false, detect_activity: detectActivity, content: null };
        } catch (error) {
            console.error(`Moonito: check could not run, visitor allowed: ${(error as Error).message}`);
            return allowed;
        }
    }

    /**
     * Makes a request to the analytics API.
     * @param ip - The IP address to query.
     * @param userAgent - The user agent to send.
     * @param event - The event to query.
     * @param domain - The domain to send.
     * @returns {Promise<string>} The response body from the API.
     */
    private async requestAnalyticsAPI(
        ip: string,
        userAgent: string,
        event: string,
        domain: string,
        extra: RequestContext = {}
    ): Promise<string> {
        /*
         * v2 rather than v1, because v1 has no way to say "challenge".
         *
         * The two endpoints are metered the same and return the same body; v2
         * adds challenge_url, decision_id and nonce. On v1 a challenge verdict
         * collapses to allow before it reaches the caller, since the server
         * will not hand back an instruction the client cannot carry out. So a
         * v1 SDK lets a suspected rotating proxy through and logs it as
         * challenged, which reads like the visitor was stopped when they were
         * not. Speaking v2 is what makes the verdict real.
         */
        const body: Record<string, any> = {
            ip,
            ua: this.bounded(userAgent, 2048),
            events: this.bounded(event, 4096),
            domain,
            sdk: `node/${VisitorTrafficFiltering.VERSION}`,
        };

        if (extra.method) {
            body.method = this.bounded(extra.method, 16);
        }

        if (extra.path) {
            body.path = this.bounded(extra.path, 512);
        }

        /*
         * The header set and the visitor's token are what let the rotation
         * detectors work at all. Without them the API can only judge a request
         * on its own address and user agent, which is exactly what a rotating
         * residential pool is built to defeat.
         */
        if (extra.clientToken) {
            body.client_token = extra.clientToken;
        }

        // Proof that this visitor already solved a challenge. Without it they
        // would be asked again on the very next request, which is a loop.
        if (extra.challengePass) {
            body.challenge_pass = extra.challengePass;
        }

        if (extra.headers) {
            const headers: Record<string, string> = {};

            for (const [name, value] of Object.entries(extra.headers)) {
                // Cookie and Authorization are never forwarded. They carry the
                // visitor's session on the customer's own site and the API has
                // no use for either.
                if (['cookie', 'authorization', 'proxy-authorization'].includes(name.toLowerCase())) {
                    continue;
                }

                if (typeof value === 'string') {
                    headers[name] = this.bounded(value, 2048);
                    if (Object.keys(headers).length >= 64) break;
                }
            }

            if (Object.keys(headers).length > 0) {
                body.headers = headers;
            }
        }

        const payload = JSON.stringify(body);
        const url = new URL(`${this.endpoint()}/api/v2/decision`);

        const options: https.RequestOptions = {
            method: 'POST',
            headers: {
                'User-Agent': `Moonito-Node/${VisitorTrafficFiltering.VERSION}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload).toString(),
                'Accept': 'application/json',
                'X-Public-Key': this.config.apiPublicKey,
                'X-Secret-Key': this.config.apiSecretKey,
            },
        };

        return this.httpRequest(url, options, payload);
    }

    private endpoint(): string {
        const configured = (this.config as any).endpoint;

        return typeof configured === 'string' && configured !== ''
            ? configured.replace(/\/+$/, '')
            : 'https://moonito.net';
    }

    /**
     * The proof that this visitor already passed a challenge.
     *
     * Read and forwarded without validation. The SDK cannot check it: the pass
     * is signed with the domain secret and verifying it here would mean
     * reimplementing the MAC in every language. The server checks it, and a
     * forged one simply fails there.
     */
    private readChallengePass(req: any): string | undefined {
        return this.readCookie(req, VisitorTrafficFiltering.PASS_COOKIE, 1024);
    }

    private readCookie(req: any, name: string, limit: number): string | undefined {
        const header = req.headers?.cookie;

        if (typeof header !== 'string' || header === '') {
            return undefined;
        }

        for (const part of header.split(';')) {
            const eq = part.indexOf('=');

            if (eq < 0) {
                continue;
            }

            if (part.slice(0, eq).trim() === name) {
                const value = part.slice(eq + 1).trim();

                try {
                    const decoded = decodeURIComponent(value);
                    return decoded !== '' && decoded.length <= limit ? decoded : undefined;
                } catch {
                    return undefined;
                }
            }
        }

        return undefined;
    }

    private readClientToken(req: any): string | undefined {
        return this.readCookie(req, VisitorTrafficFiltering.IDENTITY_COOKIE, 96);
    }

    private bounded(value: string, limit: number): string {
        return Array.from(value || '').slice(0, limit).join('');
    }

    /** Append our cookies without discarding the application's session cookies. */
    private writeResponseCookies(req: any, res: any, data: any): void {
        if (typeof res?.setHeader !== 'function' || res.headersSent) return;
        const secure = req.secure || req.protocol === 'https' ? '; Secure' : '';
        const cookies: string[] = [];
        const descriptor = data?.set_client_token;
        if (descriptor?.value) {
            cookies.push(`${VisitorTrafficFiltering.IDENTITY_COOKIE}=${encodeURIComponent(descriptor.value)}`
                + `; Path=/; Max-Age=${Number(descriptor.max_age) || 7776000}; SameSite=Lax${secure}`);
        }
        if (data?.decision_id && data?.nonce) {
            cookies.push(`__mo_cx=${encodeURIComponent(data.decision_id + ':' + data.nonce)}`
                + `; Path=/; Max-Age=120; SameSite=Lax${secure}`);
        }
        if (cookies.length === 0) return;
        const existing = res.getHeader?.('Set-Cookie');
        res.setHeader('Set-Cookie', [...(Array.isArray(existing) ? existing : existing ? [existing] : []), ...cookies]);
    }

    /**
     * Handles blocked visitors based on the configured action.
     * @param res - The response object.
     */
    /**
     * Send the visitor to the challenge, keeping their request intact.
     *
     * A redirect would be simpler and would lose every POST. Somebody halfway
     * through a checkout or a long form would come back to an empty page and
     * blame the site, so the form body is stashed in sessionStorage on the
     * customer's own origin first and replayed when the challenge sends them
     * back.
     *
     * The stash is same origin and short lived. What it cannot preserve is a
     * file input, because script cannot put a file back into a form. That is
     * said plainly on the page rather than silently dropped.
     */
    private renderChallenge(req: any, res: any, challengeUrl: string): void {
        if (res.headersSent) {
            // The page is already going out. Printing an interstitial on top of
            // a half rendered response produces something worse than letting it
            // finish.
            return;
        }

        const method = String(req.method || 'GET').toUpperCase();
        const fields = method === 'POST' ? this.flattenBody(req.body) : {};
        const hasUpload = method === 'POST'
            && typeof req.headers?.['content-type'] === 'string'
            && req.headers['content-type'].indexOf('multipart/form-data') === 0;

        const stash = JSON.stringify({
            u: String(req.originalUrl || req.url || '/'),
            m: method,
            f: fields,
        });

        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, private');
        res.setHeader('X-Robots-Tag', 'noindex, nofollow');
        res.setHeader('Referrer-Policy', 'no-referrer');

        res.end(this.challengeHtml(challengeUrl, stash, hasUpload));
    }

    private challengeHtml(challengeUrl: string, stash: string, hasUpload: boolean): string {
        const note = hasUpload
            ? '<p>You will need to choose your file again after this check.</p>'
            : '';

        // JSON.stringify twice: once for the value, once so the result is a
        // JavaScript string literal that cannot terminate the script element.
        const payload = JSON.stringify(stash).replace(/</g, '\\u003c');
        const target = JSON.stringify(challengeUrl).replace(/</g, '\\u003c');

        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            + '<meta name="viewport" content="width=device-width, initial-scale=1">'
            + '<meta name="robots" content="noindex, nofollow">'
            + '<title>Checking your browser</title></head>'
            + '<body><p>Checking your browser before you continue.</p>' + note
            + '<script>(function(){try{sessionStorage.setItem("__mo_resume",'
            + payload + ');}catch(e){}location.replace(' + target + ');})();</script>'
            + '<noscript><p>JavaScript is required to continue.</p></noscript>'
            + '</body></html>';
    }

    /**
     * Flatten a parsed body into name/value pairs a form can be rebuilt from.
     *
     * Capped, because a body large enough to fill sessionStorage would break
     * the resume rather than help it. Anything past the cap is dropped and the
     * visitor retypes it, which beats a page that silently fails to load.
     */
    private flattenBody(body: any, prefix = ''): Record<string, string> {
        const out: Record<string, string> = {};

        if (!body || typeof body !== 'object') {
            return out;
        }

        for (const [key, value] of Object.entries(body)) {
            if (Object.keys(out).length >= 200) {
                break;
            }

            const name = prefix === '' ? key : `${prefix}[${key}]`;

            if (value !== null && typeof value === 'object') {
                Object.assign(out, this.flattenBody(value, name));
                continue;
            }

            const text = String(value);

            if (text.length <= 8192) {
                out[name] = text;
            }
        }

        return out;
    }

    private async handleBlockedVisitor(res: any): Promise<void> {
        if (this.config.unwantedVisitorTo) {
            const statusCode = Number(this.config.unwantedVisitorTo);
            if (!isNaN(statusCode)) {
                if (statusCode >= 100 && statusCode <= 599) {
                    return res.sendStatus(statusCode);
                }

                return res.sendStatus(500);
            }

            if (this.config.unwantedVisitorAction === 2) {
                res.send(`<iframe src="${this.config.unwantedVisitorTo}" width="100%" height="100%" align="left"></iframe>
                    <style>body { padding: 0; margin: 0; } iframe { margin: 0; padding: 0; border: 0; }</style>`);
            } else if (this.config.unwantedVisitorAction === 3) {
                try {
                    res.send(await this.httpRequestWithBypass(new URL(this.config.unwantedVisitorTo)));
                } catch (fetchError) {
                        console.error(`Fetching unwanted content error: ${(fetchError as Error).message}`);
                        res.status(500).send('Error fetching unwanted content.');
                }
            } else {
                res.redirect(302, this.config.unwantedVisitorTo);
            }
        } else {
            res.status(403).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <title>Access Denied</title>
                    <style>.sep { border-bottom: 5px black dotted; }</style>
                </head>
                <body>
                    <div><b>Access Denied!</b></div>
                </body>
                </html>
            `);
        }
    }

    /**
     * Returns content for blocked visitors based on the configured action.
     * @returns {Promise<string>} The response content for blocked visitors.
     */
    private async getBlockedContent(): Promise<number | string> {
        if (this.config.unwantedVisitorTo) {
            const statusCode = Number(this.config.unwantedVisitorTo);
            if (!isNaN(statusCode)) {
                if (statusCode >= 100 && statusCode <= 599) {
                    return statusCode;
                }

                return 500;
            }

            if (this.config.unwantedVisitorAction === 2) {
                // Return an iframe with the URL
                return `<iframe src="${this.config.unwantedVisitorTo}" width="100%" height="100%" align="left"></iframe>
                    <style>body { padding: 0; margin: 0; } iframe { margin: 0; padding: 0; border: 0; }</style>`;
            } else if (this.config.unwantedVisitorAction === 3) {
                // Return the content fetched from the URL
                try {
                    return await this.httpRequestWithBypass(new URL(this.config.unwantedVisitorTo));
                } catch (error) {
                    console.error('Error fetching content:', error);
                    return '<p>Content not available</p>'; // Fallback content in case of error
                }
            } else {
                // Return HTML with JavaScript redirection
                return `
                <p>Redirecting to <a href="${this.config.unwantedVisitorTo}">${this.config.unwantedVisitorTo}</a></p>
                <script>
                    setTimeout(function() {
                        window.location.href = "${this.config.unwantedVisitorTo}";
                    }, 1000);
                </script>`;
            }
        }
        // Return an HTML access denied message
        return '<p>Access Denied!</p>';
    }

    /**
     * Makes an HTTP/HTTPS request with bypass header and secure token to prevent loops.
     * @param url - The URL to request.
     * @returns {Promise<string>} The response body.
     */
    private httpRequestWithBypass(url: URL): Promise<string> {
        const options: https.RequestOptions = {
            method: 'GET',
            headers: {
                [VisitorTrafficFiltering.BYPASS_HEADER]: '1',
                [VisitorTrafficFiltering.BYPASS_TOKEN_HEADER]: this.bypassToken
            }
        };

        return this.httpRequest(url, options);
    }

    /**
     * Makes an HTTPS request.
     * @param url - The URL to request.
     * @param options - The options for the request.
     * @returns {Promise<string>} The response body.
     */
    private httpRequest(url: URL, options: https.RequestOptions, body?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const client = url.protocol === 'http:' ? http : https;

            // Only reaching the server is timed. Once connected the SDK waits
            // for the decision however long it takes, because a check that
            // gives up early lets the visitor through unchecked, and blocking
            // them is the reason this library is installed.
            const req = client.request(url, options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    resolve(data);
                });
            });

            req.setTimeout(VisitorTrafficFiltering.CONNECT_TIMEOUT_MS, () => {
                req.destroy(new Error('Moonito API could not be reached'));
            });

            req.on('socket', (socket) => {
                // A kept-alive socket is already connected and never fires
                // connect again. Waiting for that event left the timer running
                // and cut a slow decision off at ten seconds.
                if (!socket.connecting) {
                    req.setTimeout(0);

                    return;
                }

                socket.once(url.protocol === 'http:' ? 'connect' : 'secureConnect', () => {
                    req.setTimeout(0);
                });
            });

            req.on('error', (e) => {
                reject(e);
            });

            if (body !== undefined) {
                req.write(body);
            }

            req.end();
        });
    }

    /**
     * Validates if an IP address is valid.
     * Uses the `net` module to check if the IP address is a valid IPv4 or IPv6 address.
     *
     * @param {string} ip - The IP address to validate.
     * @returns {boolean} True if the IP address is valid, false otherwise.
     */
    /** Milliseconds allowed to reach the API. The decision itself is never timed. */
    private static readonly CONNECT_TIMEOUT_MS = 10000;

    /**
     * The visitor's address.
     *
     * Forwarded headers are set by whoever makes the request, so they are only
     * believed when the connection came from a proxy: a private address, one
     * listed in trustedProxies, or Cloudflare for CF-Connecting-IP. Read raw,
     * a bot could claim any clean address, and a CDN's "ip, proxy" list
     * failed validation and broke the page.
     */
    private getClientIp(req: any): string {
        const remote = this.stripMapped(String(req.socket?.remoteAddress || req.connection?.remoteAddress || ''));

        if (!this.isValidIp(remote)) {
            return '';
        }

        const trusted = this.config.trustedProxies || [];
        const fromCloudflare = this.inAnyRange(remote, CLOUDFLARE_RANGES);
        const fromProxy = fromCloudflare || this.isPrivate(remote) || this.inAnyRange(remote, trusted);

        if (!fromProxy) {
            return remote;
        }

        const cf = req.headers['cf-connecting-ip'];

        if (fromCloudflare && typeof cf === 'string' && this.isValidIp(cf.trim())) {
            return cf.trim();
        }

        const xff = req.headers['x-forwarded-for'];

        if (typeof xff === 'string' && xff !== '') {
            const chain = xff.split(',').map((part) => this.stripMapped(part.trim())).reverse();

            for (const candidate of chain) {
                if (!this.isValidIp(candidate)) {
                    continue;
                }

                if (this.isPrivate(candidate) || this.inAnyRange(candidate, trusted) || this.inAnyRange(candidate, CLOUDFLARE_RANGES)) {
                    continue;
                }

                return candidate;
            }
        }

        return remote;
    }

    private stripMapped(ip: string): string {
        return ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip;
    }

    private isPrivate(ip: string): boolean {
        if (net.isIPv4(ip)) {
            return this.inAnyRange(ip, ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16']);
        }

        const lower = ip.toLowerCase();

        return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
    }

    private inAnyRange(ip: string, ranges: string[]): boolean {
        const family = net.isIPv4(ip) ? 'ipv4' : net.isIPv6(ip) ? 'ipv6' : null;

        if (family === null) {
            return false;
        }

        for (const range of ranges) {
            const [subnet, bits] = range.split('/');

            if (bits === undefined) {
                if (subnet === ip) {
                    return true;
                }

                continue;
            }

            const subnetFamily = net.isIPv4(subnet) ? 'ipv4' : net.isIPv6(subnet) ? 'ipv6' : null;

            if (subnetFamily !== family) {
                continue;
            }

            const list = new net.BlockList();
            list.addSubnet(subnet, Number(bits), family);

            if (list.check(ip, family)) {
                return true;
            }
        }

        return false;
    }

    public isValidIp(ip: string): boolean {
        return net.isIPv4(ip) || net.isIPv6(ip);
    }

    /**
     * Gets the current full URL from the request
     * @param req - The request object
     * @returns {string} The current URL
     */
    private getCurrentUrl(req: any): string {
        const protocol = req.protocol || 'http';
        // req.get is Express only; a plain Node http server has just headers.
        const host = typeof req.get === 'function' ? req.get('host') : req.headers?.host;
        const path = req.originalUrl || req.url;
        return `${protocol}://${host}${path}`;
    }

    /**
     * Compares two URLs to check if they match
     * Handles both full URLs and relative paths, ignoring protocol differences
     * @param currentUrl - The current URL
     * @param targetUrl - The target URL to compare (can be full URL or path)
     * @returns {boolean} True if URLs match
     */
    private urlsMatch(currentUrl: string, targetUrl: string): boolean {
        try {
            // If targetUrl is a full URL
            if (targetUrl.startsWith('http://') || targetUrl.startsWith('https://')) {
                const currentUrlObj = new URL(currentUrl);
                const targetUrlObj = new URL(targetUrl);

                // Compare host and path, ignoring protocol
                return currentUrlObj.host === targetUrlObj.host &&
                    currentUrlObj.pathname === targetUrlObj.pathname &&
                    currentUrlObj.search === targetUrlObj.search;
            }

            // If targetUrl is a relative path
            const currentUrlObj = new URL(currentUrl);
            const currentPath = currentUrlObj.pathname + currentUrlObj.search;

            return currentPath === targetUrl || currentUrlObj.pathname === targetUrl;
        } catch (error) {
            // Fallback to simple string comparison
            return currentUrl.includes(targetUrl);
        }
    }
}
