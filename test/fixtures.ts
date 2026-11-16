/**
 * Local fixture HTTP server for the test harness. Serves canned JSON/HTML,
 * a large body, and a redirect chain — all on 127.0.0.1 (reachable only
 * when ALLOW_PRIVATE_TARGETS-style options are set).
 */
import * as http from 'node:http';

export interface Fixture {
  server: http.Server;
  port: number;
  close: () => void;
  url: (p: string) => string;
}

const JSON_BODY = JSON.stringify({
  data: { amount: 97412.34, currency: 'BTC' },
  items: [{ price: 5 }, { price: 7 }],
  ok: true,
});

const HTML_BODY = '<html><body>Price: EUR 42.50 today</body></html>';

export function startFixture(): Promise<Fixture> {
  const server = http.createServer((req, res) => {
    const p = req.url?.split('?')[0] ?? '/';
    if (p === '/json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON_BODY);
    } else if (p === '/html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(HTML_BODY);
    } else if (p === '/big') {
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': 3 * 1024 * 1024 });
      res.end('A'.repeat(3 * 1024 * 1024));
    } else if (p === '/redirect') {
      res.writeHead(302, { location: '/json' });
      res.end();
    } else if (p === '/redirect-loop') {
      res.writeHead(302, { location: '/redirect-loop' });
      res.end();
    } else {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
    }
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({
        server,
        port,
        close: () => server.close(),
        url: (p: string) => `http://127.0.0.1:${port}${p}`,
      });
    });
  });
}
