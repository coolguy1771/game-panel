import { Router, type Request, type Response } from 'express';
import { getConfig } from '../config.js';
import { generateToken } from '../utils/auth.js';
import { userRepository, ssoLoginCodeRepository } from '../database/index.js';
import { sendRouteError } from '../utils/routeErrors.js';
import { logError } from '../utils/logger.js';
import { requireBodyObject } from '../utils/httpValidation.js';
import { signSsoState, verifySsoState } from '../utils/ssoState.js';
import {
  buildSsoLoginRedirect,
  completeSsoLogin,
  SsoLoginError,
} from '../services/ssoOidc.js';
import { createRateLimiter, LOGIN_RATE_LIMITS } from '../utils/rateLimit.js';

const router = Router();
const ssoRateLimiter = createRateLimiter(LOGIN_RATE_LIMITS);

const STATE_COOKIE = 'gp_sso_state';
const STATE_COOKIE_MAX_AGE = 600; // seconds; matches the signed state TTL

function ssoDisabled(res: Response): boolean {
  if (!getConfig().sso?.enabled) {
    res.status(404).json({ error: 'SSO is not configured' });
    return true;
  }
  return false;
}

function stateCookieValue(req: Request, token: string, maxAge: number): string {
  const parts = [
    `${STATE_COOKIE}=${token}`,
    `Path=/api/auth/sso`,
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ];
  if (req.secure) parts.push('Secure');
  return parts.join('; ');
}

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

// GET /api/auth/sso/status
router.get('/status', (_req: Request, res: Response) => {
  const sso = getConfig().sso;
  res.json({
    enabled: Boolean(sso?.enabled),
    buttonLabel: sso?.buttonLabel ?? 'Sign in with SSO',
  });
});

// GET /api/auth/sso/login - starts the OIDC Authorization Code + PKCE flow.
router.get('/login', async (req: Request, res: Response) => {
  try {
    if (ssoDisabled(res)) return;
    if (!ssoRateLimiter.ensureAllowed(req, res, 'sso-login')) return;

    const redirectBase = getConfig().frontendUrl;
    const { authorizeUrl, state, nonce, verifier } = await buildSsoLoginRedirect(redirectBase);

    res.setHeader(
      'Set-Cookie',
      stateCookieValue(req, signSsoState({ state, nonce, verifier }), STATE_COOKIE_MAX_AGE)
    );
    return res.redirect(authorizeUrl.toString());
  } catch (error) {
    return sendRouteError(res, error, {
      route: 'ROUTE:AUTH:SSO_LOGIN',
      fallbackMessage: 'Failed to start SSO login',
    });
  }
});

// GET /api/auth/sso/callback - IdP redirects here; ends with a redirect back to the SPA.
router.get('/callback', async (req: Request, res: Response) => {
  const fail = (reason: string) =>
    res.redirect(`/?sso-error=${encodeURIComponent(reason)}`);

  try {
    if (ssoDisabled(res)) return;

    const cookieToken = readCookie(req, STATE_COOKIE);
    const statePayload = cookieToken ? verifySsoState(cookieToken) : null;

    // The state cookie is single-flow: clear it whatever happens next.
    res.setHeader('Set-Cookie', stateCookieValue(req, '', 0));

    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === 'string') query.set(key, value);
    }

    const { loginCode } = await completeSsoLogin({
      query,
      statePayload,
      redirectBase: getConfig().frontendUrl,
    });

    return res.redirect(`/?sso-code=${encodeURIComponent(loginCode)}`);
  } catch (error) {
    if (error instanceof SsoLoginError) {
      return fail(error.reason);
    }

    logError('ROUTE:AUTH:SSO_CALLBACK', error);
    return fail('unknown');
  }
});

// POST /api/auth/sso/exchange - trades the one-time login code for a panel JWT.
router.post('/exchange', async (req: Request, res: Response) => {
  try {
    if (ssoDisabled(res)) return;

    const body = requireBodyObject(req.body);
    const code = typeof body.code === 'string' ? body.code.trim() : '';
    if (!code) return res.status(400).json({ error: 'Missing code' });

    if (!ssoRateLimiter.ensureAllowed(req, res, 'sso-exchange')) return;

    const userId = await ssoLoginCodeRepository.consume(code);
    if (!userId) return res.status(401).json({ error: 'Invalid or expired login code' });

    const user = await userRepository.findById(userId);
    if (!user) return res.status(401).json({ error: 'Invalid or expired login code' });
    if (!user.is_enabled) return res.status(403).json({ error: 'Account disabled' });

    ssoRateLimiter.clear(req, 'sso-exchange');

    const token = generateToken({
      userId: user.id,
      username: user.username,
      isRoot: Boolean(user.is_root),
      tokenVersion: user.token_version,
    });

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        isRoot: Boolean(user.is_root),
        isEnabled: Boolean(user.is_enabled),
      },
      token,
    });
  } catch (error) {
    return sendRouteError(res, error, {
      route: 'ROUTE:AUTH:SSO_EXCHANGE',
      fallbackMessage: 'SSO exchange failed',
    });
  }
});

export default router;
