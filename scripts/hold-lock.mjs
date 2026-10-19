// Test-only helper: a separate process holds SQLite's writer lock across expiry.
import { DatabaseSync } from "node:sqlite";
const db = new DatabaseSync(process.argv[2]);
db.exec("BEGIN IMMEDIATE");
console.log("LOCKED");
setTimeout(() => {
  db.exec("COMMIT");
  db.close();
}, Number(process.argv[3]));
