/**
 * Normalize URLs / hostnames so duplicates (http vs https, trailing slash, case) collapse.
 */

export function assetDedupeKey(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    const withScheme = raw.includes('://') ? raw : `https://${raw}`;
    const u = new URL(withScheme);
    const path = (u.pathname || '/').replace(/\/+$/, '') || '';
    return `${u.hostname}${path === '/' ? '' : path}`;
  } catch {
    return raw.replace(/^https?:\/\//, '').replace(/\/+$/, '').split('/')[0] || '';
  }
}

/** Dedupe string list by assetDedupeKey; keeps first original spelling. */
export function dedupeAssetsPreserveOrder(values) {
  const seen = new Set();
  const out = [];
  for (const v of values || []) {
    const s = String(v || '').trim();
    if (!s) continue;
    const k = assetDedupeKey(s);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}
