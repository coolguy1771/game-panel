import type { Request, Response } from 'express';

export function readPositiveIntEnv(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = Number(raw);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export type RateLimitConfig = {
    windowMs: number;
    maxAttempts: number;
    blockMs: number;
};

// Shared login rate-limit configuration (see LOGIN_RATE_* env vars).
export const LOGIN_RATE_LIMITS: RateLimitConfig = {
    windowMs: readPositiveIntEnv('LOGIN_RATE_WINDOW_MS', 15 * 60_000),
    maxAttempts: readPositiveIntEnv('LOGIN_RATE_MAX_ATTEMPTS', 10),
    blockMs: readPositiveIntEnv('LOGIN_RATE_BLOCK_MS', 15 * 60_000),
};

type RateBucket = {
    attempts: number[];
    blockedUntil: number;
};

function normalizeIp(value: string): string {
    const trimmed = value.trim();
    return trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
}

function getClientIp(req: Request): string {
    if (typeof req.ip === 'string' && req.ip.trim()) {
        return normalizeIp(req.ip);
    }

    if (typeof req.socket.remoteAddress === 'string' && req.socket.remoteAddress.trim()) {
        return normalizeIp(req.socket.remoteAddress);
    }

    return 'unknown';
}

function getBucket(map: Map<string, RateBucket>, key: string): RateBucket {
    let bucket = map.get(key);
    if (!bucket) {
        bucket = { attempts: [], blockedUntil: 0 };
        map.set(key, bucket);
    }
    return bucket;
}

function pruneBucket(bucket: RateBucket, now: number, windowMs: number): void {
    const minTs = now - windowMs;
    bucket.attempts = bucket.attempts.filter((ts) => ts >= minTs);
    if (bucket.blockedUntil <= now) {
        bucket.blockedUntil = 0;
    }
}

// Removes map entries whose failures have all expired and whose block has ended, so
// abandoned identifiers do not accumulate for the lifetime of the process.
function evictIfExpired(
    map: Map<string, RateBucket>,
    key: string,
    bucket: RateBucket,
    now: number,
    windowMs: number
): void {
    const hasRecentAttempts = bucket.attempts.some((ts) => ts >= now - windowMs);
    if (!hasRecentAttempts && bucket.blockedUntil <= now) {
        map.delete(key);
    }
}

export type RateLimiter = {
    // Returns false (and writes the 429 response) when the client must back off.
    ensureAllowed(req: Request, res: Response, identifier: string): boolean;
    noteFailure(req: Request, identifier: string): void;
    clear(req: Request, identifier: string): void;
};

// Sliding-window failure limiter keyed by client IP and an optional identifier (username,
// flow name). A client is blocked when either key exceeds maxAttempts inside the window.
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
    const byIp = new Map<string, RateBucket>();
    const byIdentifier = new Map<string, RateBucket>();

    const retryAfterMs = (map: Map<string, RateBucket>, key: string, now: number): number => {
        const bucket = map.get(key);
        if (!bucket) return 0;

        pruneBucket(bucket, now, config.windowMs);
        evictIfExpired(map, key, bucket, now, config.windowMs);
        return bucket.blockedUntil > now ? bucket.blockedUntil - now : 0;
    };

    const registerFailure = (map: Map<string, RateBucket>, key: string, now: number): void => {
        const bucket = getBucket(map, key);
        pruneBucket(bucket, now, config.windowMs);
        bucket.attempts.push(now);

        if (bucket.attempts.length >= config.maxAttempts) {
            bucket.blockedUntil = now + config.blockMs;
            bucket.attempts = [];
        }

        evictIfExpired(map, key, bucket, now, config.windowMs);
    };

    return {
        ensureAllowed(req, res, identifier) {
            const now = Date.now();
            const ipKey = getClientIp(req);
            const idKey = identifier.toLowerCase();

            const retryMs = Math.max(
                retryAfterMs(byIp, ipKey, now),
                retryAfterMs(byIdentifier, idKey, now)
            );

            if (retryMs <= 0) return true;

            const retryAfterSeconds = Math.max(1, Math.ceil(retryMs / 1000));
            res.setHeader('Retry-After', String(retryAfterSeconds));
            res.status(429).json({ error: 'Too many login attempts', retryAfterSeconds });
            return false;
        },

        noteFailure(req, identifier) {
            const now = Date.now();
            registerFailure(byIp, getClientIp(req), now);
            registerFailure(byIdentifier, identifier.toLowerCase(), now);
        },

        clear(req, identifier) {
            byIdentifier.delete(identifier.toLowerCase());
            byIp.delete(getClientIp(req));
        },
    };
}
