// TEMP comparative harness (inline vs stream) — not committed.
// Identical arrival-rate ramp used for both modes so summaries are comparable.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { createTestUrls } from '../setup.js';
import { BASE_URL } from '../lib/config.js';

const redirect302 = new Counter('redirect_302');
const v2Hits = new Counter('v2_redirects');
const v1Hits = new Counter('v1_redirects');

export const options = {
  setupTimeout: '120s',
  scenarios: {
    ramp: {
      executor: 'ramping-arrival-rate',
      startRate: Number(__ENV.START_RATE || 100),
      timeUnit: '1s',
      preAllocatedVUs: 300,
      maxVUs: 1200,
      stages: [
        { target: Number(__ENV.MID_RATE || 300), duration: '25s' },
        { target: Number(__ENV.MAX_RATE || 800), duration: '25s' },
        { target: Number(__ENV.MAX_RATE || 800), duration: '30s' },
      ],
      gracefulStop: '10s',
    },
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  return createTestUrls();
}

export default function (urls) {
  const r = Math.random();
  let alias, schema;
  if (r < 0.85 && urls.v2.length) {
    alias = urls.v2[Math.floor(Math.random() * urls.v2.length)];
    schema = 'v2';
  } else {
    alias = urls.v1[Math.floor(Math.random() * urls.v1.length)];
    schema = 'v1';
  }
  const res = http.get(`${BASE_URL}/${alias}`, {
    redirects: 0,
    responseType: 'none',
    tags: { schema },
    headers: {
      // Browser UA: k6's default UA is classified as a bot and the click
      // pipeline (correctly) skips analytics for bots on block_bots URLs —
      // which would bypass the very write path we're load-testing.
      'User-Agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
      Referer: 'https://t.co/loadtest',
    },
  });
  const ok = check(res, { 'is 302': (x) => x.status === 302 });
  if (ok) {
    redirect302.add(1);
    if (schema === 'v2') v2Hits.add(1);
    else v1Hits.add(1);
  }
}
