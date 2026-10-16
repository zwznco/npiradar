import { redis } from "@/lib/redis";
import { maskIp } from "@/lib/usage";

// First-class, cost-weighted rate limiting for the public API.
//
// Cost is charged per unit of work, not per request, so a 100-NPI bulk call spends 100× a single
// lookup and can't be used to dodge the limit by batching:
//   GET  /api/npi/{npi}   cost 1
//   POST /api/npi         cost = number of valid NPIs in the body (1..100)
//   GET  /api/search      cost 10  (a scan, heavier than a keyed lookup)
//
// Three budgets, checked and charged atomically (all or none):
//   1. per IP, per minute (100): one full 100-NPI bulk call a minute.
//   2. per /24 (IPv6 /48), per UTC day: per-IP limits alone are useless against a residential-proxy
//      pool that throws each IP away after a page (2026-10-10: 6,098 IPs in 1,117 /24s).
//   3. global, per UTC day, per tier: the ceiling that actually binds a pool that size.
// Tier "verified" = the request carries a valid jsgate cookie, which only a browser that passed the
// gate has (our /tools/bulk-lookup); traefik's jsgate plugin vouches with X-Jsgate-Verified and strips
// any client-sent copy. Origin/Referer can't be the signal: a scraper can send `Origin: npiradar.com`.
// The separate budget means anonymous scraping can't use up the day for the site's own bulk tool.
// Real usage when this was set (2026-10-11): 48 requests / 550 units over 10 days, so no current user
// gets near any daily cap.
//
// Traefik's edge limit for npiradar (600/min, burst 200, whole site) is the dumb backstop; this is the
// work-aware limiter and the one that emits X-RateLimit-* so clients can self-throttle.

const LIMIT = Number(process.env.API_RATE_LIMIT ?? 100); // tokens per window, per IP
const WINDOW = Number(process.env.API_RATE_WINDOW ?? 60); // seconds
const DAILY = {
  anon: {
    prefix: Number(process.env.API_DAILY_PREFIX ?? 2000),
    global: Number(process.env.API_DAILY_GLOBAL ?? 20000),
  },
  verified: {
    prefix: Number(process.env.API_DAILY_PREFIX_VERIFIED ?? 10000),
    global: Number(process.env.API_DAILY_GLOBAL_VERIFIED ?? 100000),
  },
};

// KEYS: minute, prefix-day, global-day. ARGV: minute limit, window, cost, prefix limit, global limit.
// Returns {hit, minuteRemaining, minuteTtl, dailyRemaining}; hit 0 = allowed, 1 = minute, 2 = daily.
// Minute window is anchored at its first request (INCRBY + EXPIRE on create); daily keys carry the UTC
// date in their name, so the 2-day EXPIRE is only cleanup.
const LUA = `
local cost = tonumber(ARGV[3])
local m = tonumber(redis.call('GET', KEYS[1]) or '0')
local p = tonumber(redis.call('GET', KEYS[2]) or '0')
local g = tonumber(redis.call('GET', KEYS[3]) or '0')
local ml, pl, gl = tonumber(ARGV[1]), tonumber(ARGV[4]), tonumber(ARGV[5])
local daily = math.min(pl - p, gl - g)
if m + cost > ml then return {1, ml - m, redis.call('TTL', KEYS[1]), daily} end
if p + cost > pl or g + cost > gl then return {2, ml - m, redis.call('TTL', KEYS[1]), daily} end
local n = redis.call('INCRBY', KEYS[1], cost)
if n == cost then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) end
redis.call('INCRBY', KEYS[2], cost)
redis.call('EXPIRE', KEYS[2], 172800)
redis.call('INCRBY', KEYS[3], cost)
redis.call('EXPIRE', KEYS[3], 172800)
return {0, ml - n, redis.call('TTL', KEYS[1]), daily - cost}`;

export interface RateResult {
  ok: boolean;
  scope?: "minute" | "daily"; // which budget denied it (deny path only)
  remaining: number;
  reset: number; // seconds until the denying budget resets (the minute window on the allow path)
  limit: number;
  dailyRemaining?: number;
}

function secondsToUtcMidnight(): number {
  const now = new Date();
  return Math.max(1, Math.ceil((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1) - now.getTime()) / 1000));
}

export async function rateLimit(ip: string, cost: number, verified = false): Promise<RateResult> {
  const weight = Math.max(1, Math.floor(cost));
  const tier = verified ? "verified" : "anon";
  const day = new Date().toISOString().slice(0, 10);
  try {
    const res = (await redis.eval(
      LUA,
      3,
      `rl:api:${ip}`,
      `rl:api:day:${tier}:${maskIp(ip)}:${day}`,
      `rl:api:day:${tier}:all:${day}`,
      LIMIT,
      WINDOW,
      weight,
      DAILY[tier].prefix,
      DAILY[tier].global,
    )) as [number, number, number, number];
    const [hit, remaining, ttl, dailyRemaining] = res;
    const minuteReset = ttl > 0 ? ttl : WINDOW;
    return {
      ok: hit === 0,
      scope: hit === 1 ? "minute" : hit === 2 ? "daily" : undefined,
      remaining: Math.max(0, remaining),
      reset: hit === 2 ? secondsToUtcMidnight() : minuteReset,
      limit: LIMIT,
      dailyRemaining: Math.max(0, dailyRemaining),
    };
  } catch {
    // Fail OPEN: a Redis outage must not 500 a free, public API. Traefik's edge limit is still active
    // as a backstop. Flip this to `ok: false` if starving abuse matters more than staying up.
    return { ok: true, remaining: LIMIT, reset: WINDOW, limit: LIMIT };
  }
}

// Real client IP behind Traefik. Traefik appends the peer to X-Forwarded-For; the first entry is the
// origin client. Falls back to a shared "unknown" bucket if the header is absent (direct hits).
export function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip")?.trim() || "unknown";
}

export function rateHeaders(r: RateResult): Record<string, string> {
  const h: Record<string, string> = {
    "X-RateLimit-Limit": String(r.limit),
    "X-RateLimit-Remaining": String(r.remaining),
    "X-RateLimit-Reset": String(r.reset),
  };
  if (r.dailyRemaining !== undefined) h["X-RateLimit-Daily-Remaining"] = String(r.dailyRemaining);
  if (!r.ok) h["Retry-After"] = String(r.reset);
  return h;
}
