/**
 * Aegis Guard - Background Scanner Service
 *
 * Simulates continuous URL monitoring by periodically dequeuing URLs from a
 * rotating list and feeding them through the ML model via scanAndBroadcast().
 *
 * In a production deployment this queue would be populated from:
 *  - A database / Redis stream of URLs to investigate
 *  - Network proxy logs
 *  - Browser extension submissions
 *
 * For the demo / sandbox environment the scanner cycles through a curated
 * mix of safe, warning, and malicious URLs so the frontend always has live
 * data to display.
 */

"use strict";

// ---------------------------------------------------------------------------
// Demo URL queue – mix of safe, warning, and malicious links
// ---------------------------------------------------------------------------
const DEMO_QUEUE = [
  // Safe
  "https://www.google.com",
  "https://www.github.com",
  "https://www.wikipedia.org",
  "https://stackoverflow.com/questions",
  "https://www.python.org",
  // Warning
  "http://login.example-bank.com/user/verify",
  "http://update-account.info/signin?ref=email",
  "https://secure-paypal.info/account/login",
  "http://amazon-security-alert.com/verify",
  // Malicious
  "http://paypa1-secure-login.tk/account/confirm?session=abc123&verify=true",
  "http://bit.ly/3xYzAbc-limited-offer-free-prize-click-here",
  "http://appleid-account-suspended-verify.gq/login?credential=confirm",
  // Safe
  "https://www.mozilla.org",
  "https://developer.mozilla.org/en-US",
  "https://www.npmjs.com",
  // Malicious
  "http://micro50ft-account-unusual-activity-verify-now.tk/signin?token=abc",
  "http://irs-tax-refund-free-claim-now.cf/refund?ssn=enter&credential=verify",
];

// Interval between automatic scans (milliseconds)
const SCAN_INTERVAL_MS = parseInt(process.env.SCAN_INTERVAL_MS || "8000", 10);

let queueIndex = 0;
let intervalHandle = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start the background scanning loop.
 * @param {Function} scanAndBroadcast  - async (url: string) => result
 */
function start(scanAndBroadcast) {
  if (intervalHandle) {
    console.warn("[Scanner] Already running – ignoring duplicate start().");
    return;
  }

  console.log(
    `[Scanner] Background scanner started (interval: ${SCAN_INTERVAL_MS}ms).`
  );

  intervalHandle = setInterval(async () => {
    const url = DEMO_QUEUE[queueIndex % DEMO_QUEUE.length];
    queueIndex += 1;

    console.log(`[Scanner] Auto-scanning: ${url}`);
    try {
      await scanAndBroadcast(url);
    } catch (err) {
      console.error(`[Scanner] Error scanning ${url}:`, err.message);
    }
  }, SCAN_INTERVAL_MS);
}

/**
 * Stop the background scanning loop.
 */
function stop() {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
    console.log("[Scanner] Background scanner stopped.");
  }
}

/**
 * Add a URL to the front of the demo queue so it is scanned next.
 * @param {string} url
 */
function enqueue(url) {
  DEMO_QUEUE.unshift(url);
}

module.exports = { start, stop, enqueue };
