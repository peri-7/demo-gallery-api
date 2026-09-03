// Prove the signed-URL mechanism works, without a browser and without the API.
//
//   npm run check:storage
//
// This talks ONLY to object storage. If it passes, signing, credentials,
// endpoint style and bucket policy are all correct. If the browser then fails,
// the fault is somewhere this script cannot reach — CORS, for instance, which
// Node does not enforce.
//
// Run against whatever bucket .env points at. That is the dev bucket.

import {
  createUploadUrl,
  statObject,
  deleteObject,
  publicUrlFor,
} from "../src/storage.js";

// A genuine 1x1 PNG: small, but real bytes with real magic numbers.
const png = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64"
);

const t0 = Date.now();
const { key, uploadUrl, expiresIn } = await createUploadUrl("image/png");
console.log(`1. signed in ${Date.now() - t0}ms  <- no network call happened`);
console.log(`   key           ${key}`);
console.log(`   ttl           ${expiresIn}s`);
console.log(`   signedHeaders ${new URL(uploadUrl).searchParams.get("X-Amz-SignedHeaders")}`);
console.log(`   payload       ${new URL(uploadUrl).searchParams.get("X-Amz-Content-Sha256")}`);

// Change the object key while keeping the signature. The signature covers a
// description of the whole request, so storage rebuilds a different canonical
// string and the comparison fails.
const tampered = uploadUrl.replace(key, "hijacked-" + key);
const bad = await fetch(tampered, {
  method: "PUT",
  headers: { "content-type": "image/png" },
  body: png,
});
console.log(`2. tampered key -> HTTP ${bad.status} ${bad.status === 403 ? "(rejected)" : "(PROBLEM)"}`);

const put = await fetch(uploadUrl, {
  method: "PUT",
  headers: { "content-type": "image/png" },
  body: png,
});
console.log(`3. upload -> HTTP ${put.status}`);
if (!put.ok) {
  console.log(await put.text());
  process.exit(1);
}

// Ask the only party that saw the bytes what it actually received.
const stat = await statObject(key);
console.log(`4. HEAD -> ${stat.contentType}, ${stat.sizeBytes} bytes (sent ${png.length})`);

// A public bucket: no signature needed to read.
const pub = await fetch(publicUrlFor(key));
const bytes = Buffer.from(await pub.arrayBuffer());
console.log(`5. public GET -> HTTP ${pub.status}, ${bytes.length} bytes, identical: ${bytes.equals(png)}`);

// The limit of the protection: the bucket checks the declared type, never the
// contents. Garbage under an allowed label is stored without complaint.
const { key: k2, uploadUrl: u2 } = await createUploadUrl("image/png");
const lie = await fetch(u2, {
  method: "PUT",
  headers: { "content-type": "image/png" },
  body: Buffer.from("<script>alert(1)</script> definitely not a png"),
});
const lieStat = lie.ok ? await statObject(k2) : null;
console.log(
  `6. non-image bytes, image/png header -> HTTP ${lie.status}` +
    (lieStat ? `, stored as ${lieStat.contentType} (${lieStat.sizeBytes} bytes)` : "")
);

// A declared type the bucket does not allow, on a URL signed for one it does.
const { uploadUrl: u3 } = await createUploadUrl("image/png");
const html = await fetch(u3, {
  method: "PUT",
  headers: { "content-type": "text/html" },
  body: Buffer.from("<h1>hi</h1>"),
});
console.log(`7. text/html header -> HTTP ${html.status} ${html.status === 415 ? "(bucket rejected)" : "(PROBLEM)"}`);

// S3 deletes are idempotent, which is what makes cleanup paths safe to retry.
await deleteObject(key);
await deleteObject(k2);
await deleteObject(k2);
console.log(`8. cleaned up; gone: ${(await statObject(key)) === null}`);
