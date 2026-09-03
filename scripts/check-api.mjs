// Exercise the whole upload flow through the running API, the way a browser
// would — except that Node does not enforce CORS, so a pass here says nothing
// about whether a browser will be allowed to do the same.
//
//   npm run dev          (in one terminal)
//   npm run check:api    (in another)
//
// Point it elsewhere with:  API=https://demo-gallery-api.onrender.com npm run check:api

const API = process.env.API ?? "http://localhost:3000";

const png = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64"
);

const post = (path, body) =>
  fetch(API + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

console.log(`against ${API}\n`);

// --- step 1: ask permission. No storage call, no database write. ----------
const r1 = await post("/api/drawings/upload-url", { contentType: "image/png" });
if (!r1.ok) {
  console.error(`upload-url failed: ${r1.status} ${await r1.text()}`);
  process.exit(1);
}
const { key, uploadUrl, expiresIn, maxBytes } = await r1.json();
console.log(`1. upload-url -> ${r1.status}  ttl=${expiresIn}s  maxBytes=${maxBytes}`);

// --- step 2: the API is not involved in this at all -----------------------
const r2 = await fetch(uploadUrl, {
  method: "PUT",
  headers: { "content-type": "image/png" },
  body: png,
});
console.log(`2. PUT to storage -> ${r2.status}  <- look for this in the API log. It is not there.`);

// --- step 3: record it ----------------------------------------------------
const r3 = await post("/api/drawings", {
  title: "Check Sketch",
  artist: "check-api.mjs",
  year: 2026,
  rating: 4.25, // deliberately two decimals; numeric(2,1) keeps one
  storageKey: key,
});
const created = await r3.json();
console.log(`3. create -> ${r3.status}  location=${r3.headers.get("location")}`);
console.log(`   rating sent 4.25, stored ${created.rating}`);
console.log(`   contentType in response: ${created.contentType ?? "(absent — toApiShape does not publish it)"}`);

const img = await fetch(created.imageUrl);
console.log(`4. public image -> ${img.status}, ${(await img.arrayBuffer()).byteLength} bytes`);

// --- everything that should be refused ------------------------------------
console.log("\n--- rejections (status, and which layer caught it) ---");
const cases = [
  ["bad content type", "validation", () => post("/api/drawings/upload-url", { contentType: "image/gif" })],
  ["missing title", "validation", () => post("/api/drawings", { artist: "x", year: 2026, storageKey: key })],
  ["year as string", "validation", () => post("/api/drawings", { title: "x", artist: "y", year: "2026", storageKey: key })],
  ["path in storageKey", "validation", () => post("/api/drawings", { title: "x", artist: "y", year: 2026, storageKey: "../secrets.png" })],
  ["key never uploaded", "storage HEAD", () => post("/api/drawings", { title: "x", artist: "y", year: 2026, storageKey: "00000000-0000-0000-0000-000000000000.png" })],
  ["key already used", "database", () => post("/api/drawings", { title: "x", artist: "y", year: 2026, storageKey: key })],
];

for (const [label, layer, fn] of cases) {
  const started = Date.now();
  const res = await fn();
  const body = await res.json();
  console.log(
    `${label.padEnd(20)} ${res.status}  ${String(Date.now() - started + "ms").padEnd(7)} ${layer.padEnd(12)} ` +
      JSON.stringify(body.details ?? body.error).slice(0, 60)
  );
}

const list = await (await fetch(API + "/api/drawings")).json();
console.log(`\ntotal: ${list.drawings.length} drawings, ${list.drawings.filter((d) => d.imageUrl).length} with images`);
console.log("note: this script leaves its row and object behind on purpose — go look at them.");
