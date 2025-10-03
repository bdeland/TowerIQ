// Cross-platform test preparation script
import fs from "fs";
import path from "path";

const reportsDir = path.resolve("_reports");
const junitDir = path.resolve("_reports/junit");

// Remove existing reports directory if it exists
if (fs.existsSync(reportsDir)) {
  fs.rmSync(reportsDir, { recursive: true, force: true });
}

// Create new directories
fs.mkdirSync(junitDir, { recursive: true });

console.log("Test preparation completed");
