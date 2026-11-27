// Parses a JSON column that holds an array of permission strings. Tolerates null/blank and
// malformed content by returning an empty list (never throw) — the same policy the legacy
// per-user and per-membership permission columns used.
export function parsePermissionsJson(raw: unknown): string[] {
  if (typeof raw !== 'string' || raw.trim() === '') return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
