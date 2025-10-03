// scripts/make-cursor-ndjson.mjs
// Node 18+, tiny test digest for AI agents.
// Emits:
//   - cursor_tests.ndjson  (summary + failures; minimal tokens)
//   - cursor_test_report_min.md (optional, tiny human summary)

import fs from "fs";
import { glob } from "glob";
import path from "path";
import { fileURLToPath } from "url";
import { parseStringPromise } from "xml2js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JUNITS = "_reports/junit/*.xml";
const NDJSON_OUT = path.resolve("cursor_tests.ndjson");
const MD_MIN_OUT = path.resolve("cursor_test_report_min.md");

function stripNoise(s = "") {
  let out = s
    .replace(/0x[0-9a-fA-F]+/g, "0x…") // mem addrs
    .replace(/id='[0-9]+'/g, "id='…'") // mock ids
    .replace(/[ \t]+/g, " ") // collapse spaces
    .trim();
  // single-line-ify & cap
  out = out.replace(/\s*\n\s*/g, " | ");
  if (out.length > 280) out = out.slice(0, 277) + "…";
  return out;
}

const FILE_LINE_RE =
  /([A-Za-z]:[\\/][^:\n]+\.py):(\d+)|((?:\/|\\)[^:\n]+\.py):(\d+)/i;
function firstFileLine(text = "") {
  const m = FILE_LINE_RE.exec(text);
  if (!m) return { file: null, line: null };
  if (m[1]) return { file: m[1].replace(/\\/g, "/"), line: Number(m[2]) };
  return { file: m[3].replace(/\\/g, "/"), line: Number(m[4]) };
}

function shortErr(message = "", detail = "") {
  const blob = `${message} ${detail}`;
  if (
    blob.includes(
      "coroutine' object does not support the asynchronous context manager"
    )
  ) {
    return "TypeError: async context manager misuse";
  }
  if (blob.includes("DID NOT RAISE")) return "Expected exception not raised";
  if (blob.includes("assert ") && blob.includes(" == "))
    return "AssertionError: unexpected value";
  if (
    blob.includes("AdbError") &&
    blob.includes("Direct push failed") &&
    blob.includes("Alternative method failed")
  ) {
    return "Error propagation: wrong error surfaced";
  }
  if (
    blob.includes("does not have the attribute '_download_frida_server_binary'")
  ) {
    return "AttributeError: missing expected method";
  }
  return stripNoise(message) || "Test failed";
}

function normalizeNodeId(classname = "", name = "") {
  // best-effort pytest-like nodeid from JUnit keys
  const parts = classname.split(".");
  if (parts.length > 1) {
    const className = parts.pop();
    const module = parts.join("/"); // dotted -> path-ish
    return `${module}.py::${className}::${name}`;
  }
  return `${classname}::${name}`;
}

async function parseOne(file) {
  const xml = fs.readFileSync(file, "utf8");
  const obj = await parseStringPromise(xml, {
    explicitArray: false,
    mergeAttrs: true,
  });

  // normalize to array of suites
  const suites = [];
  if (obj.testsuites?.testsuite) {
    suites.push(
      ...(Array.isArray(obj.testsuites.testsuite)
        ? obj.testsuites.testsuite
        : [obj.testsuites.testsuite])
    );
  } else if (obj.testsuite) {
    suites.push(
      ...(Array.isArray(obj.testsuite) ? obj.testsuite : [obj.testsuite])
    );
  }

  let agg = { total: 0, failed: 0, skipped: 0, duration_s: 0, failures: [] };

  for (const s of suites) {
    agg.total += Number(s.tests || 0);
    agg.failed += Number(s.failures || 0);
    agg.skipped += Number(s.skipped || 0);
    agg.duration_s += Number(s.time || 0);

    const cases = s.testcase
      ? Array.isArray(s.testcase)
        ? s.testcase
        : [s.testcase]
      : [];
    for (const tc of cases) {
      const tag = tc.failure || tc.error;
      if (!tag) continue;

      const message = tag.message || "";
      const detail = (tag._ || "").toString();
      const { file, line } = firstFileLine(detail);
      agg.failures.push({
        suite: s.name || path.basename(file || "") || "",
        nodeid: normalizeNodeId(tc.classname || "", tc.name || ""),
        file,
        line,
        err: shortErr(message, detail),
        msg: stripNoise(message),
      });
    }
  }
  return agg;
}

async function main() {
  const files = await glob(JUNITS);
  if (files.length === 0) {
    fs.writeFileSync(
      NDJSON_OUT,
      JSON.stringify({
        type: "summary",
        total: 0,
        failed: 0,
        skipped: 0,
        duration_s: 0,
      }) + "\n"
    );
    fs.writeFileSync(
      MD_MIN_OUT,
      "# Test Report (compact)\n\n_No JUnit files found._\n"
    );
    console.log("No JUnit files found; wrote empty artifacts.");
    return;
  }

  // merge all junit aggregates
  const parts = await Promise.all(files.map(parseOne));
  const summary = parts.reduce(
    (a, b) => ({
      total: a.total + b.total,
      failed: a.failed + b.failed,
      skipped: a.skipped + b.skipped,
      duration_s: Number((a.duration_s + b.duration_s).toFixed(3)),
    }),
    { total: 0, failed: 0, skipped: 0, duration_s: 0 }
  );

  const failures = parts.flatMap((p) => p.failures);

  // NDJSON: tiny + ready-to-run commands when possible
  const lines = [];
  lines.push(JSON.stringify({ type: "summary", ...summary }));
  failures.forEach((f, i) => {
    const testName = f.nodeid.split("::").pop();
    const cmd = f.file ? `pytest -q ${f.file}::${testName}` : null;
    lines.push(JSON.stringify({ type: "fail", id: i + 1, ...f, cmd }));
  });
  fs.writeFileSync(NDJSON_OUT, lines.join("\n") + "\n");

  // tiny MD (first 10 failures only)
  const md = [
    "# Test Report (compact)",
    `**Summary:** ${summary.total} total · ${summary.failed} failed · ${summary.skipped} skipped · ${summary.duration_s}s`,
  ];
  if (summary.failed === 0) {
    md.push("\n✅ All tests passed.\n");
  } else {
    md.push("\n## Failures (first 10)\n");
    failures.slice(0, 10).forEach((f, i) => {
      const loc = f.file && f.line ? `${f.file}:${f.line}` : "(file/line n/a)";
      md.push(`${i + 1}. \`${f.nodeid}\` — ${f.err}  \n   ↳ ${loc}`);
    });
    if (failures.length > 10)
      md.push(
        `\n…and ${failures.length - 10} more. See \`cursor_tests.ndjson\`.`
      );
  }
  fs.writeFileSync(MD_MIN_OUT, md.join("\n") + "\n");

  console.log(`Wrote ${NDJSON_OUT} and ${MD_MIN_OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
