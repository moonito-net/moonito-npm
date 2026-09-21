import * as https from 'https';
import * as http from 'http';
import * as net from 'net';
import * as querystring from 'querystring';
import * as crypto from 'crypto';
import {URL} from 'url';

interface RequestContext {
    clientToken?: string;
    headers?: Record<string, any>;
}

interface Config {
    isProtected: boolean;
    apiPublicKey: string;
    apiSecretKey: string;
    unwantedVisitorTo?: string;
    unwantedVisitorAction?: number;
}

export class VisitorTrafficFiltering {
    private config: Config;
    public static readonly VERSION = '2.0.0';
    private static readonly IDENTITY_COOKIE = '__mo_ct';
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

        const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];
        const url = req.url;
        const domain = req.hostname.toLowerCase();

        if (!this.isValidIp(clientIp)) {
            throw new Error("Invalid IP address.");
        }

        try {
            const response = await this.requestAnalyticsAPI(clientIp, userAgent, url, domain, {
                clientToken: this.readClientToken(req),
                headers: req.headers,
            });
            const data = JSON.parse(response);

            if (data.error) {
                throw new Error(`Requesting analytics error: ${Array.isArray(data.error.message) ? data.error.message.join(', ') : data.error.message}`);
            }

            this.writeClientToken(res, data?.data?.set_client_token);

            if (data?.data?.status?.need_to_block) {
                this.handleBlockedVisitor(res);
            }
        } catch (error) {
            console.error('Error handling visitor:', error);
            throw new Error(`Error handling visitor: ${(error as Error).message}`);
        }
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

        if (!this.isValidIp(ip)) {
            throw new Error("Invalid IP address.");
        }

        try {
            const response = await this.requestAnalyticsAPI(ip, userAgent, event, domain);
            const data = JSON.parse(response);

            if (data.error) {
                throw new Error(`Requesting analytics error: ${Array.isArray(data.error.message) ? data.error.message.join(', ') : data.error.message}`);
            }

            const needToBlock = data?.data?.status?.need_to_block;
            const detectActivity = data?.data?.status?.detect_activity;

            if (needToBlock) {
                return { need_to_block: true, detect_activity: detectActivity, content: this.getBlockedContent() };
            }

            return { need_to_block: false, detect_activity: detectActivity, content: null };
        } catch (error) {
            console.error('Error handling visitor manually:', error);
            throw new Error(`Error handling visitor manually: ${(error as Error).message}`);
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
        const query: Record<string, string> = {
            ip,
            ua: encodeURIComponent(userAgent),
            events: encodeURIComponent(event),
            domain,
            sdk: `node/${VisitorTrafficFiltering.VERSION}`,
        };

        /*
         * The header set and the visitor's token are what let the rotation
         * detectors work at all. Without them the API can only judge a request
         * on its own address and user agent, which is exactly what a rotating
         * residential pool is built to defeat. Both are optional: an older
         * version of this SDK that sent neither still gets the same answer it
         * always got.
         */
        if (extra.clientToken) {
            query.client_token = extra.clientToken;
        }

        if (extra.headers) {
            for (const [name, value] of Object.entries(extra.headers)) {
                if (typeof value === 'string' && value.length <= 2048) {
                    query[`headers[${name}]`] = value;
                }
            }
        }

        const queryParams = querystring.stringify(query);
        const url = new URL(`https://moonito.net/api/v1/analytics?${queryParams}`);

        const options: https.RequestOptions = {
            method: 'GET',
            headers: {
                'User-Agent': userAgent,
                'X-Public-Key': this.config.apiPublicKey,
                'X-Secret-Key': this.config.apiSecretKey,
            },
        };

        return this.httpRequest(url, options);
    }

    /**
     * The visitor's identity token, if they are carrying one.
     *
     * Read without any attempt to validate it. The SDK cannot: the signing key
     * is server side and shipping it to every install would make it public.
     * Possessing a token confers no trust, it only tells the API whose history
     * to consult, so passing a forged one along is harmless.
     */
    private readClientToken(req: any): string | undefined {
        const raw = req.headers?.cookie;

        if (typeof raw !== 'string') {
            return undefined;
        }

        for (const part of raw.split(';')) {
            const [name, ...rest] = part.trim().split('=');

            if (name === VisitorTrafficFiltering.IDENTITY_COOKIE) {
                const value = decodeURIComponent(rest.join('='));

                return value.length > 0 && value.length <= 96 ? value : undefined;
            }
        }

        return undefined;
    }

    /** Stores the token the API handed back, so the next request carries it. */
    private writeClientToken(res: any, descriptor: any): void {
        if (!descriptor?.value || typeof res?.setHeader !== 'function' || res.headersSent) {
            return;
        }

        const maxAge = Number(descriptor.max_age) || 7776000;
        const parts = [
            `${descriptor.name || VisitorTrafficFiltering.IDENTITY_COOKIE}=${encodeURIComponent(descriptor.value)}`,
            'Path=/',
            `Max-Age=${maxAge}`,
            'SameSite=Lax',
        ];

        try {
            res.setHeader('Set-Cookie', parts.join('; '));
        } catch {
            // Headers already sent by something else. The visitor simply stays
            // anonymous for this request, which is a supported mode.
        }
    }

    /**
     * Handles blocked visitors based on the configured action.
     * @param res - The response object.
     */
    private handleBlockedVisitor(res: any): void {
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
                this.httpRequestWithBypass(new URL(this.config.unwantedVisitorTo))
                    .then(content => res.send(content))
                    .catch(fetchError => {
                        console.error(`Fetching unwanted content error: ${(fetchError as Error).message}`);
                        res.status(500).send('Error fetching unwanted content.');
                    });
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
    private httpRequest(url: URL, options: https.RequestOptions): Promise<string> {
        return new Promise((resolve, reject) => {
            const req = https.request(url, options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    resolve(data);
                });
            });

            req.on('error', (e) => {
                reject(e);
            });

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
        const host = req.get('host');
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