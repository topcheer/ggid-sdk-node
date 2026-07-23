/**
 * Webhook signature verification helper.
 *
 * GGID audit alerts are sent with an `X-GGID-Signature` header containing
 * `sha256=<hex HMAC-SHA256 of the raw request body>`.
 *
 * Usage (Express):
 * ```ts
 * import { verifyWebhookSignature, expressWebhook } from '@ggid/sdk';
 *
 * app.post('/webhooks/ggid', expressWebhook(process.env.GGID_WEBHOOK_SECRET), (req, res) => {
 *   // req.ggidVerified === true — signature is valid
 *   const alert = req.body;
 *   res.json({ received: true });
 * });
 * ```
 *
 * Manual usage:
 * ```ts
 * const valid = verifyWebhookSignature(rawBody, signatureHeader, secret);
 * ```
 */

import type { Request, Response, NextFunction } from 'express';
import { createHmac, timingSafeEqual } from 'crypto';

/** Default tolerance for timestamp-based replay attacks (in seconds). */
const DEFAULT_TOLERANCE = 300; // 5 minutes

export interface WebhookVerificationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Verify an X-GGID-Signature header against a raw request body.
 *
 * The signature format is: `sha256=<hex HMAC-SHA256(rawBody, secret)>`.
 *
 * @param rawBody - The raw (unparsed) request body as a Buffer or string.
 * @param signatureHeader - The value of the X-GGID-Signature header.
 * @param secret - The shared HMAC secret.
 * @returns Whether the signature is valid.
 */
export function verifyWebhookSignature(
  rawBody: Buffer | string,
  signatureHeader: string,
  secret: string,
): WebhookVerificationResult {
  if (!signatureHeader) {
    return { valid: false, reason: 'missing signature header' };
  }

  if (!signatureHeader.startsWith('sha256=')) {
    return { valid: false, reason: 'invalid signature format' };
  }

  const providedSig = signatureHeader.slice(7); // strip "sha256=" prefix

  const body = typeof rawBody === 'string' ? Buffer.from(rawBody) : rawBody;
  const expectedSig = createHmac('sha256', secret).update(body).digest('hex');

  // Constant-time comparison to prevent timing attacks.
  const providedBuf = Buffer.from(providedSig, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');

  if (providedBuf.length !== expectedBuf.length) {
    return { valid: false, reason: 'signature length mismatch' };
  }

  if (!timingSafeEqual(providedBuf, expectedBuf)) {
    return { valid: false, reason: 'signature mismatch' };
  }

  return { valid: true };
}

/**
 * Express middleware that verifies GGID webhook signatures.
 *
 * Requires `express.raw` (or equivalent) to populate `req.body` with a Buffer.
 *
 * ```ts
 * import express from 'express';
 * import { expressWebhook } from '@ggid/sdk';
 *
 * const app = express();
 * app.post('/webhooks/ggid', express.raw({ type: 'application/json' }), expressWebhook(secret), (req, res) => {
 *   const alert = JSON.parse(req.body);
 *   // process alert...
 * });
 * ```
 *
 * On success, sets `req.ggidVerified = true` and parses `req.body` as JSON.
 * On failure, returns 401 with an error message.
 */
export function expressWebhook(secret: string) {
  return (req: Request & { ggidVerified?: boolean }, res: Response, next: NextFunction) => {
    const rawBody = req.body as Buffer | string;

    // req.body must be a raw Buffer (from express.raw middleware).
    if (!rawBody || (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody))) {
      return res.status(400).json({ error: 'raw body required — use express.raw middleware' });
    }

    const signatureHeader = req.headers['x-ggid-signature'] as string;

    const result = verifyWebhookSignature(rawBody, signatureHeader, secret);

    if (!result.valid) {
      return res.status(401).json({ error: `webhook verification failed: ${result.reason}` });
    }

    req.ggidVerified = true;

    // Parse body as JSON for downstream handlers.
    try {
      req.body = JSON.parse(typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8'));
    } catch {
      // Non-JSON body — leave as parsed string.
    }

    next();
  };
}
