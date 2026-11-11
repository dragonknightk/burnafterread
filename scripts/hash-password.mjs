// Usage: node scripts/hash-password.mjs   (reads the password from stdin)
// Prints a value for the AUTH_PASSWORD_HASH secret.
import { pbkdf2Sync, randomBytes } from "node:crypto";

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const password = Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "").normalize("NFC");
if (!password) {
  console.error("empty password");
  process.exit(1);
}
const iterations = 100000; // Workers caps PBKDF2 at 100k iterations
const salt = randomBytes(16);
const hash = pbkdf2Sync(Buffer.from(password, "utf8"), salt, iterations, 32, "sha256");
console.log(`pbkdf2-sha256$${iterations}$${salt.toString("base64url")}$${hash.toString("base64url")}`);
