// Object storage: minting signed URLs, and asking storage what it actually has.
//
// Everything here is CONTROL PLANE. Not one function in this file sends or
// receives an image. The API decides whether an upload may happen and under
// what key; the bytes travel browser <-> storage directly and never enter this
// process. See THEORY.md §12.

import { randomUUID } from "node:crypto";
import {
  S3Client,
  PutObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// Fail fast at boot, exactly like db.js. A missing credential discovered at
// module load is a clear error on line one of the logs. The same credential
// discovered on first use is a confusing 500 for one unlucky user, hours later,
// on a server that has been reporting itself healthy the whole time.
const required = [
  "S3_ENDPOINT",
  "S3_REGION",
  "S3_ACCESS_KEY_ID",
  "S3_SECRET_ACCESS_KEY",
  "S3_BUCKET",
  "PUBLIC_STORAGE_URL",
];
const missing = required.filter((k) => !process.env[k]);
if (missing.length > 0) {
  throw new Error(
    `Missing storage configuration: ${missing.join(", ")}. See .env.example.`
  );
}

const BUCKET = process.env.S3_BUCKET;
const PUBLIC_BASE = process.env.PUBLIC_STORAGE_URL.replace(/\/$/, "");

// The upload limit, in one place. It has two siblings that must agree with it:
// the bucket's own size restriction, and the CHECK constraint in
// migrations/003. Three layers, because each one sees something the others
// cannot — only the bucket ever sees the actual bytes.
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

// An allowlist, not a blocklist. A blocklist has to anticipate every dangerous
// type forever; an allowlist only has to name the safe ones, and anything novel
// is rejected by default. The extension is derived from the type rather than
// taken from the uploaded filename — a filename is attacker-controlled text,
// and "cat.jpg.svg" style tricks stop existing if you never read it.
const EXTENSION_BY_TYPE = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
};

export const ALLOWED_CONTENT_TYPES = Object.keys(EXTENSION_BY_TYPE);

// How long a signed upload URL stays valid. Short on purpose: the URL IS the
// authority, so anyone who obtains the string can use it. Long enough for a
// slow phone to finish a 10 MB upload, short enough that a leaked URL is
// worthless by the time anyone finds it.
const UPLOAD_URL_TTL_SECONDS = 300;

// One client for the process, like the database pool. It holds configuration
// and connection reuse, not a live connection.
//
// forcePathStyle deserves a note. AWS's own S3 addresses buckets as a
// SUBDOMAIN — https://my-bucket.s3.eu-central-1.amazonaws.com/key — which
// requires wildcard DNS and a wildcard certificate. Most S3-compatible
// providers, Supabase included, put the bucket in the PATH instead:
// https://host/storage/v1/s3/my-bucket/key. Leaving this false against such a
// provider produces a DNS failure for a hostname that was never meant to exist.
const client = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  forcePathStyle: true,

  // Recent AWS SDK versions default to "WHEN_SUPPORTED", which adds an
  // x-amz-checksum-crc32 parameter to every request. For a PRESIGNED url that
  // is actively wrong: the checksum is computed at signing time, when there is
  // no body, so it describes an empty payload — and because it sits in the
  // query string it is covered by the signature and cannot be removed by the
  // uploader.
  //
  // Supabase ignores it. AWS S3 and Cloudflare R2 validate it, and would reject
  // every upload. Left in, this is a bug that only appears if we change
  // provider — which is exactly when we would least expect a signing failure.
  requestChecksumCalculation: "WHEN_REQUIRED",

  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
});

/**
 * Mint a one-shot upload URL.
 *
 * No network request happens here. Signing is pure computation: the SDK builds
 * a canonical description of the request and HMACs it with the secret key.
 * Supabase will independently rebuild that same description from the request it
 * receives and recompute the signature. Agreement is derived, not negotiated.
 *
 * @param {string} contentType one of ALLOWED_CONTENT_TYPES
 * @returns {Promise<{key: string, uploadUrl: string, expiresIn: number}>}
 */
export async function createUploadUrl(contentType) {
  const extension = EXTENSION_BY_TYPE[contentType];
  if (!extension) {
    // A programming error, not a user error — the route validates first.
    throw new Error(`Unsupported content type: ${contentType}`);
  }

  // The server chooses the key. Never the client.
  //
  // If the browser named the object, it could pick a key that already exists
  // and overwrite someone else's drawing with a signed URL you handed it. A
  // random UUID makes collision and targeting both impossible, and it means the
  // key carries no information about the uploader or the original filename.
  const key = `${randomUUID()}.${extension}`;

  const uploadUrl = await getSignedUrl(
    client,
    new PutObjectCommand({
      Bucket: BUCKET,
      Key: key,
      // ContentType here sets the object's stored type when the uploader does
      // not send its own content-type header.
      //
      // It does NOT pin anything, which is worth being precise about because it
      // is easy to assume otherwise. The presigner does not add `content-type`
      // to X-Amz-SignedHeaders (verified: SignedHeaders=host), so a URL signed
      // for image/png will happily accept a PUT declaring image/webp. And the
      // body is UNSIGNED-PAYLOAD, so the bytes are outside the signature
      // entirely.
      //
      // What actually enforces the type is the BUCKET's allowed-MIME-types
      // list, which returns 415 for anything not on it, regardless of how the
      // URL was signed. And even that only inspects the declared label — a
      // text file sent as image/png is stored without complaint.
      //
      // Hence statObject() below: the row records what storage reports, never
      // what the client claimed.
      ContentType: contentType,
    }),
    { expiresIn: UPLOAD_URL_TTL_SECONDS }
  );

  return { key, uploadUrl, expiresIn: UPLOAD_URL_TTL_SECONDS };
}

/**
 * Ask storage what is actually at a key.
 *
 * This is the step that closes the trust gap. The browser tells us "I uploaded
 * a 2 MB JPEG"; that is a CLAIM. HEAD asks the only party that saw the bytes.
 * It also proves the object exists at all, which is what stops us writing a row
 * that points at nothing.
 *
 * HEAD returns metadata with no body — cheap, and the bytes still never reach
 * this server.
 *
 * @returns {Promise<{contentType: string, sizeBytes: number} | null>} null if absent
 */
export async function statObject(key) {
  try {
    const head = await client.send(
      new HeadObjectCommand({ Bucket: BUCKET, Key: key })
    );
    return {
      contentType: head.ContentType,
      sizeBytes: head.ContentLength,
    };
  } catch (err) {
    // A missing object is an expected answer to this question, not a failure.
    // Anything else — bad credentials, network, bucket gone — is a real error
    // and must not be flattened into "not found".
    if (err.name === "NotFound" || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    throw err;
  }
}

/**
 * Delete an object. Used both for cleanup after a failed insert and for
 * deleting a drawing (row first, then file — see THEORY.md §12).
 *
 * S3 deletes are idempotent: deleting a key that does not exist succeeds. That
 * is a feature here, because our cleanup paths run exactly when we are least
 * sure what state things are in.
 */
export async function deleteObject(key) {
  await client.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
}

/**
 * Build the public URL for a stored object.
 *
 * The database stores the KEY. The host lives in configuration, so switching
 * provider, adding a CDN, or moving to a custom domain is an environment
 * variable rather than an UPDATE over every row ever written.
 */
export function publicUrlFor(key) {
  return `${PUBLIC_BASE}/${key}`;
}
