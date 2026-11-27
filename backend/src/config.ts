import path from 'node:path';
import { gamePanelImage } from './utils/images.js';

function mustEnv(name: string): string {
    const v = process.env[name];
    if (!v) throw new Error(`Missing env var: ${name}`);
    return v;
}

function envOrDefault(name: string, fallback: string): string {
    const v = process.env[name];
    if (!v || !v.trim()) return fallback;
    return v.trim();
}

function urlEnv(name: string): string | null {
    const trimmed = String(process.env[name] ?? '').trim();
    return trimmed ? trimmed.replace(/\/+$/, '') : null;
}

const CONTAINER_DATA_DIR = '/data';
// Overridable for local development and tests; deployments keep the container default.
const DATA_DIR_ENV = 'GAMEPANEL_DATA_DIR';

function boolEnv(name: string, fallback: boolean): boolean {
    const raw = process.env[name];
    if (!raw || !raw.trim()) return fallback;

    switch (raw.trim().toLowerCase()) {
        case '1':
        case 'true':
        case 'yes':
        case 'on':
            return true;
        case '0':
        case 'false':
        case 'no':
        case 'off':
            return false;
        default:
            return fallback;
    }
}

type TrustProxySetting = boolean | number | string;

function trustProxyEnv(name: string, fallback: TrustProxySetting): TrustProxySetting {
    const raw = process.env[name];
    if (!raw || !raw.trim()) return fallback;

    const normalized = raw.trim().toLowerCase();

    switch (normalized) {
        case '1':
            return 1;
        case 'true':
        case 'yes':
        case 'on':
            return true;
        case '0':
        case 'false':
        case 'no':
        case 'off':
            return false;
        default:
            if (/^\d+$/.test(raw.trim())) return Number(raw.trim());
            return raw.trim();
    }
}

type SsoConfig = {
    enabled: boolean;
    issuerUrl: string;
    clientId: string;
    clientSecret: string | null;
    scopes: string;
    groupsClaim: string;
    autoProvision: boolean;
    buttonLabel: string;
    allowInsecureRequests: boolean;
};

type AppConfig = {
    port: number;
    jwtSecret: string;
    domain: string;
    frontendUrl: string;
    trustProxy: TrustProxySetting;
    adminUsername: string;
    gamepanelServersDir: string;
    gamepanelDataDir: string;
    gamepanelAppRoot: string;
    dockerSocket: string;
    composeProjectName: string;
    gamesNetwork: string;
    updaterImage: string;
    repositoryUrl: string;
    instanceId: string | null;
    instanceSecret: string | null;
    telemetryEnabled: boolean;
    databaseApiBaseUrl: string | null;
    sso: SsoConfig | null;
};

let cached: AppConfig | null = null;

function optionalEnv(name: string): string | null {
    const trimmed = process.env[name]?.trim();
    return trimmed ? trimmed : null;
}

function readSsoConfig(): SsoConfig | null {
    const issuerUrl = optionalEnv('SSO_OIDC_ISSUER_URL');
    const clientId = optionalEnv('SSO_OIDC_CLIENT_ID');

    if (!issuerUrl || !clientId) return null;

    return {
        enabled: true,
        // Trailing slashes are stripped so the intuitive config form works; providers that
        // declare a different issuer string are handled at discovery time.
        issuerUrl: issuerUrl.replace(/\/+$/, ''),
        clientId,
        clientSecret: optionalEnv('SSO_OIDC_CLIENT_SECRET'),
        scopes: envOrDefault('SSO_OIDC_SCOPES', 'openid profile email'),
        groupsClaim: envOrDefault('SSO_OIDC_GROUPS_CLAIM', 'groups'),
        autoProvision: boolEnv('SSO_OIDC_AUTO_PROVISION', true),
        buttonLabel: envOrDefault('SSO_OIDC_BUTTON_LABEL', 'Sign in with SSO'),
        // Opt-in only: allows http:// issuers (local/test IdPs). Production IdPs are https.
        allowInsecureRequests: boolEnv('SSO_OIDC_ALLOW_INSECURE', false),
    };
}

export function getConfig(): AppConfig {
    if (cached) return cached;

    const domain = mustEnv('DOMAIN').trim();
    if (!domain) throw new Error('Missing env var: DOMAIN');

    // DOMAIN is a bare host in deployments (https is implied); an explicit scheme is
    // honored so local development can run over plain http.
    const frontendUrl = /^https?:\/\//i.test(domain)
      ? domain.replace(/\/+$/, '')
      : `https://${domain}`;

    const gamepanelAppRoot = envOrDefault('GAMEPANEL_APP_ROOT', '/opt/gamepanel');

    cached = {
        port: Number(mustEnv('PORT')),
        jwtSecret: mustEnv('JWT_SECRET'),
        domain,
        frontendUrl,
        trustProxy: trustProxyEnv('TRUST_PROXY', false),
        adminUsername: envOrDefault('ADMIN_USERNAME', 'admin'),
        gamepanelServersDir: path.posix.join(gamepanelAppRoot, 'servers'),
        gamepanelDataDir: envOrDefault(DATA_DIR_ENV, CONTAINER_DATA_DIR),
        gamepanelAppRoot,
        dockerSocket: envOrDefault('DOCKER_SOCKET', '/var/run/docker.sock'),
        composeProjectName: envOrDefault('COMPOSE_PROJECT_NAME', 'gamepanel'),
        gamesNetwork: envOrDefault('GAMEPANEL_GAMES_NETWORK', 'gamepanel-games'),
        updaterImage: envOrDefault('GAMEPANEL_UPDATER_IMAGE', gamePanelImage('gamepanel-updater')),
        repositoryUrl: envOrDefault('GAMEPANEL_REPOSITORY_URL', 'https://github.com/ovh/game-panel.git'),
        instanceId: process.env.APP_INSTANCE_ID?.trim() || null,
        instanceSecret: process.env.APP_INSTANCE_SECRET?.trim() || null,
        telemetryEnabled: boolEnv('TELEMETRY_ENABLED', true),
        databaseApiBaseUrl: urlEnv('TELEMETRY_API_BASE_URL'),
        sso: readSsoConfig(),
    };

    return cached;
}
