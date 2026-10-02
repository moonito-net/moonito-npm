# Moonito
> Real-time analytics and AI bot protection SDK for Node.js and TypeScript.

[![NPM version](https://img.shields.io/npm/v/moonito.svg)](https://npmjs.org/package/moonito)
![npm bundle size](https://img.shields.io/bundlephobia/minzip/moonito)

[Moonito](https://moonito.net) is a powerful **Node.js** and **TypeScript** module for **website security**, **traffic filtering**, and **real-time analytics**.  
It helps developers **block AI bots, web scrapers, malicious traffic, competitors, and unwanted visitors** while gaining accurate insights into genuine visitors.  
Perfect for **modern web apps**, **SaaS platforms**, and **backend applications** that need intelligent protection and analytics in one solution.

## Features

- **Traffic Filtering**: Block harmful traffic based on IP addresses, user agents, and visitor behavior
- **Bot Protection**: Shield your website from malicious bots and automated scrapers
- **Visitor Analytics**: Track and analyze your website traffic in real-time
- **Flexible Configuration**: Choose how to handle unwanted visitors (redirect, iframe, or custom content)
- **Easy Integration**: Works seamlessly with Express and other Node.js frameworks

## Install the Package

Install Moonito via npm:

```bash
npm install moonito
```

## Initialize the Client

[Sign up](https://moonito.net) for Moonito, create a project, and copy your API keys from your account dashboard. Then, create a new instance of `VisitorTrafficFiltering`.

```javascript
import { VisitorTrafficFiltering } from 'moonito';

const filter = new VisitorTrafficFiltering({
    apiPublicKey: 'YOUR_API_PUBLIC_KEY',
    apiSecretKey: 'YOUR_API_SECRET_KEY',
    isProtected: true,
    unwantedVisitorTo: 'https://example.com/blocked', // URL or HTTP status code
    unwantedVisitorAction: 1 // 1 = Redirect, 2 = Iframe, 3 = Load content
});
```

## Usage

### Method 1: Using Express Middleware (Recommended)

If you can, use middleware to track and filter incoming requests to all pages from a single place. Here's an example with Express:

```javascript
import express from 'express';
import { VisitorTrafficFiltering } from 'moonito';

const app = express();
const port = 3000;

// Configure Moonito
const filter = new VisitorTrafficFiltering({
    apiPublicKey: 'YOUR_API_PUBLIC_KEY',
    apiSecretKey: 'YOUR_API_SECRET_KEY',
    isProtected: true,
    unwantedVisitorTo: 'https://example.com/blocked', // Redirect to this URL
    unwantedVisitorAction: 1
});

// Alternative configuration with HTTP status code
// const filter = new VisitorTrafficFiltering({
//     apiPublicKey: 'YOUR_API_PUBLIC_KEY',
//     apiSecretKey: 'YOUR_API_SECRET_KEY',
//     isProtected: true,
//     unwantedVisitorTo: '403', // Return HTTP 403 Forbidden
//     unwantedVisitorAction: 1
// });

// Apply Moonito middleware
app.use(async (req, res, next) => {
    // Never throws: if the check cannot run, the visitor is let through.
    await filter.evaluateVisitor(req, res);

    // A blocked visitor has already been answered.
    if (!res.headersSent) {
        next();
    }
});

// Your routes
app.get('/', (req, res) => {
    res.send('Hello World!');
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
```

### Method 2: Manual Evaluation

For more control or custom implementations, you can manually evaluate visitors by providing IP, user agent, event, and domain information:

```javascript
import { VisitorTrafficFiltering } from 'moonito';

// Configure Moonito
const filter = new VisitorTrafficFiltering({
    apiPublicKey: 'YOUR_API_PUBLIC_KEY',
    apiSecretKey: 'YOUR_API_SECRET_KEY',
    isProtected: true,
    unwantedVisitorTo: '403', // Return HTTP 403 Forbidden
    unwantedVisitorAction: 1
});

// Visitor data
const userIP = '1.1.1.1';
const userAgent = 'Mozilla/5.0...';
const event = 'page-view';
const domain = 'example.com';

// Evaluate visitor
filter.evaluateVisitorManually(userIP, userAgent, event, domain)
    .then(result => {
        if (result.need_to_block) {
            console.log('Visitor blocked. Detect activity:', result.detect_activity);
            console.log('Block content type:', typeof result.content);

            // Handle blocked visitor based on the returned content
            if (typeof result.content === 'number') {
                // HTTP status code - return status directly
                console.log('HTTP Status Code:', result.content);
                // In your application, you might do: res.status(result.content).send()
            } else {
                // HTML content - use as response body
                console.log('HTML Content:', result.content);
                // In your application, you might do: res.send(result.content)
            }

            return;
        }
        console.log('Visitor allowed. Detect activity:', result.detect_activity);
    })
    .catch(error => {
        console.error('Error evaluating visitor:', error);
    });
```

## Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `apiPublicKey` | string | Your Moonito API public key (required) |
| `apiSecretKey` | string | Your Moonito API secret key (required) |
| `isProtected` | boolean | Enable (`true`) or disable (`false`) protection |
| `unwantedVisitorTo` | string | URL to redirect unwanted visitors or HTTP error code |
| `unwantedVisitorAction` | number | Action for unwanted visitors: `1` = Redirect, `2` = Iframe, `3` = Load content |

## Requirements

- Node.js 14 or later
- TypeScript >= 4.7 (if using TypeScript)

## Documentation

For detailed documentation, guides, and API reference, visit:
- [Usage Guides](https://moonito.net/usage-guides)
- [API Documentation](https://moonito.net/api)

## Contributing

We welcome contributions! For significant changes, please open an issue first to discuss what you would like to change. Make sure to update tests as appropriate.

## License

This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License.

## Support

Need help? Have questions or suggestions?
- Visit our [documentation](https://moonito.net/usage-guides)
- Contact support through [moonito.net](https://moonito.net)