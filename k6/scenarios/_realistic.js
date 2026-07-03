// TEMP realistic-traffic scenario — not committed.
// Zipf-ish alias popularity, bot/browser UA mix, referrer mix, random client
// IPs, HEAD/404/password/emoji traffic, normal-day -> viral-spike -> cooldown.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { createTestUrls } from '../setup.js';
import { BASE_URL } from '../lib/config.js';

const v2Human = new Counter('v2_human_hits');     // expected: recorded
const v2Bot = new Counter('v2_bot_hits');         // expected: SKIPPED (block_bots)
const v1Hits = new Counter('v1_hits');            // expected: recorded (incl. bots)
const emojiHits = new Counter('emoji_hits');      // expected: recorded
const pwHits = new Counter('password_hits');      // expected: recorded
const headHits = new Counter('head_hits');        // expected: NOT recorded
const notFound = new Counter('notfound_hits');    // expected: NOT recorded

const BROWSERS = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36',
];
const BOTS = [
  'Googlebot/2.1 (+http://www.google.com/bot.html)',
  'Twitterbot/1.0',
  'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
  'curl/8.6.0',
  'python-requests/2.32.0',
];
const REFERRERS = [
  'https://t.co/x9k2m',
  'https://www.google.com/',
  'https://discord.com/channels/123/456',
  'https://news.ycombinator.com/item?id=40000000',
  null,
  null, // ~33% direct traffic
];

function randomIp() {
  return `${1 + Math.floor(Math.random() * 222)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${1 + Math.floor(Math.random() * 253)}`;
}

export const options = {
  setupTimeout: '180s',
  scenarios: {
    day: {
      executor: 'ramping-arrival-rate',
      startRate: 120,
      timeUnit: '1s',
      preAllocatedVUs: 200,
      maxVUs: 800,
      stages: [
        { target: 120, duration: '60s' },  // normal day (~120 rps ≈ prod peak)
        { target: 450, duration: '10s' },  // something goes viral
        { target: 450, duration: '30s' },  // the burst
        { target: 120, duration: '20s' },  // cooldown
      ],
      gracefulStop: '10s',
    },
  },
  summaryTrendStats: ['med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  const urls = createTestUrls();
  // Long tail: 25 more v2 aliases
  urls.tail = [];
  for (let i = 0; i < 25; i++) {
    const alias = `k6tail${String(i).padStart(3, '0')}${Date.now().toString(36).slice(-3)}`;
    const res = http.post(
      `${BASE_URL}/api/v1/shorten`,
      JSON.stringify({ url: 'https://httpstat.us/200', alias }),
      { headers: { 'Content-Type': 'application/json' } },
    );
    if (res.status === 201) urls.tail.push(alias);
  }
  return urls;
}

function pickAlias(urls) {
  const r = Math.random();
  if (r < 0.4) return { alias: urls.v2[0], kind: 'v2' };            // THE viral link
  if (r < 0.65) return { alias: urls.v2[1 + Math.floor(Math.random() * 4)], kind: 'v2' }; // warm
  if (r < 0.85) return { alias: urls.tail[Math.floor(Math.random() * urls.tail.length)], kind: 'v2' }; // long tail
  return { alias: urls.v1[Math.floor(Math.random() * urls.v1.length)], kind: 'v1' }; // legacy
}

export default function (urls) {
  const headers = {
    'X-Forwarded-For': randomIp(),
  };
  const ref = REFERRERS[Math.floor(Math.random() * REFERRERS.length)];
  if (ref) headers['Referer'] = ref;

  const roll = Math.random();

  // 2% HEAD (link previews / unfurlers probing)
  if (roll < 0.02) {
    headers['User-Agent'] = BOTS[2]; // Discordbot unfurl
    const res = http.request('HEAD', `${BASE_URL}/${urls.v2[0]}`, null, {
      redirects: 0, responseType: 'none', headers, tags: { kind: 'head' },
    });
    check(res, { 'head 302': (x) => x.status === 302 });
    headHits.add(1);
    return;
  }
  // 2% dead links
  if (roll < 0.04) {
    headers['User-Agent'] = BROWSERS[0];
    const res = http.get(`${BASE_URL}/nope${Math.floor(Math.random() * 1e6)}`, {
      redirects: 0, responseType: 'none', headers, tags: { kind: '404' },
    });
    check(res, { 'dead 404': (x) => x.status === 404 });
    notFound.add(1);
    return;
  }
  // 3% password-protected traffic (correct password)
  if (roll < 0.07 && urls.passwordProtected) {
    headers['User-Agent'] = BROWSERS[1];
    const res = http.get(
      `${BASE_URL}/${urls.passwordProtected.alias}?password=${urls.passwordProtected.password}`,
      { redirects: 0, responseType: 'none', headers, tags: { kind: 'pw' } },
    );
    if (check(res, { 'pw 302': (x) => x.status === 302 })) pwHits.add(1);
    return;
  }
  // 5% emoji links
  if (roll < 0.12 && urls.emoji.length) {
    headers['User-Agent'] = BROWSERS[2];
    const alias = encodeURIComponent(urls.emoji[Math.floor(Math.random() * urls.emoji.length)]);
    const res = http.get(`${BASE_URL}/${alias}`, {
      redirects: 0, responseType: 'none', headers, tags: { kind: 'emoji' },
    });
    if (check(res, { 'emoji 302': (x) => x.status === 302 })) emojiHits.add(1);
    return;
  }

  // Main flow: zipf alias pick + 25% bot UA
  const { alias, kind } = pickAlias(urls);
  const isBot = Math.random() < 0.25;
  headers['User-Agent'] = isBot
    ? BOTS[Math.floor(Math.random() * BOTS.length)]
    : BROWSERS[Math.floor(Math.random() * BROWSERS.length)];

  const res = http.get(`${BASE_URL}/${alias}`, {
    redirects: 0, responseType: 'none', headers, tags: { kind, bot: String(isBot) },
  });
  if (check(res, { 'redirect 302': (x) => x.status === 302 })) {
    if (kind === 'v1') v1Hits.add(1);
    else if (isBot) v2Bot.add(1);
    else v2Human.add(1);
  }
}
