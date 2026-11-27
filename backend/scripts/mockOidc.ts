import http from 'node:http';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

export type MockOidcUser = {
  sub: string;
  username: string;
  email: string;
  groups: string[];
};

export type MockOidcServer = {
  issuerBaseUrl: string;
  close: () => Promise<void>;
};

function json(res: http.ServerResponse, body: unknown, status = 200): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

// A minimal OIDC provider for local verification: auto-approves every authorization request
// for a fixed test user and signs ID tokens with HS256 (client secret). Deliberately not
// production code - it exists so the backend's OIDC client can be exercised end to end.
export async function startMockOidc(
  options: MockOidcUser & { clientId: string; clientSecret: string }
): Promise<MockOidcServer> {
  const pendingCodes = new Map<
    string,
    { challenge: string; nonce: string; redirectUri: string }
  >();
  let issuerBaseUrl = '';

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', issuerBaseUrl);

    if (url.pathname === '/.well-known/openid-configuration') {
      json(res, {
        issuer: issuerBaseUrl,
        authorization_endpoint: `${issuerBaseUrl}/authorize`,
        token_endpoint: `${issuerBaseUrl}/token`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['HS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
        scopes_supported: ['openid', 'profile', 'email'],
        claims_supported: ['sub', 'preferred_username', 'email', 'groups', 'nonce'],
      });
      return;
    }

    if (url.pathname === '/authorize') {
      const redirectUri = url.searchParams.get('redirect_uri') ?? '';
      const state = url.searchParams.get('state') ?? '';
      const nonce = url.searchParams.get('nonce') ?? '';
      const challenge = url.searchParams.get('code_challenge') ?? '';
      const code = crypto.randomBytes(16).toString('base64url');
      pendingCodes.set(code, { challenge, nonce, redirectUri });

      const target = new URL(redirectUri);
      target.searchParams.set('code', code);
      if (state) target.searchParams.set('state', state);

      res.writeHead(302, { Location: target.toString() });
      res.end();
      return;
    }

    if (url.pathname === '/token') {
      const body = new URLSearchParams(await readBody(req));
      const clientId = body.get('client_id');
      const clientSecret = body.get('client_secret');
      const code = body.get('code') ?? '';
      const verifier = body.get('code_verifier') ?? '';
      const pending = pendingCodes.get(code);

      if (clientId !== options.clientId || clientSecret !== options.clientSecret || !pending) {
        json(res, { error: 'invalid_grant' }, 400);
        return;
      }

      const expectedChallenge = crypto.createHash('sha256').update(verifier).digest('base64url');
      if (!pending.challenge || expectedChallenge !== pending.challenge) {
        json(res, { error: 'invalid_grant', error_description: 'PKCE check failed' }, 400);
        return;
      }

      pendingCodes.delete(code);
      const now = Math.floor(Date.now() / 1000);
      const idToken = jwt.sign(
        {
          sub: options.sub,
          preferred_username: options.username,
          email: options.email,
          groups: options.groups,
          nonce: pending.nonce,
          iss: issuerBaseUrl,
          aud: options.clientId,
          iat: now,
          exp: now + 3600,
        },
        options.clientSecret,
        { algorithm: 'HS256' }
      );

      json(res, {
        access_token: crypto.randomBytes(16).toString('base64url'),
        token_type: 'Bearer',
        id_token: idToken,
        expires_in: 3600,
        scope: 'openid profile email',
      });
      return;
    }

    json(res, { error: 'not_found' }, 404);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Mock OIDC server did not bind a port');
  }
  issuerBaseUrl = `http://127.0.0.1:${address.port}`;

  return {
    issuerBaseUrl,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
