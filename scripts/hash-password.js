#!/usr/bin/env node
import { pbkdf2Sync, randomBytes } from "crypto";

const [, , email, password] = process.argv;
if (!email || !password) {
  console.error("Uso: node scripts/hash-password.js <email> <senha>");
  process.exit(1);
}

const salt = randomBytes(16).toString("hex");
const hash = pbkdf2Sync(password, salt, 100000, 32, "sha256").toString("hex");
const combined = `${salt}:${hash}`;

console.log("");
console.log("Hash gerado para:", email);
console.log("");
console.log(JSON.stringify({ email, name: email.split("@")[0], hash: combined }, null, 2));
console.log("");
console.log("Cole no env var USERS dentro do array []");