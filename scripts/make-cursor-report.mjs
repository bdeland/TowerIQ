// Node 18+ (no deps)
import fs from "fs";
import path from "path";
import { parseStringPromise } from "xml2js";

const junitDir = path.resolve("_reports/junit");
const outPath = path.resolve("cursor_test_report.md");

function findFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".xml"))
    .map((f) => path.join(dir, f));
}

function firstStackLine(str = "") {
  const lines = String(str)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  // try to surface first "file:line" occurrence
  const m = lines.find((l) => /(:\d+)(?::\d+)?\)?$/.test(l)) || lines[0] || "";
  return m;
}

const files = findFiles(junitDir);
if (files.length === 0) {
  fs.writeFileSync(
    outPath,
    `# Test Report\n\n_No JUnit files found in \`${junitDir}\`._\n`
  );
  process.exit(0);
}

let total = 0,
  passed = 0,
  failed = 0,
  skipped = 0;
const failures = [];

const parseOne = async (file) => {
  const xml = fs.readFileSync(file, "utf8");
  const obj = await parseStringPromise(xml, {
    explicitArray: false,
    mergeAttrs: true,
  });

  const suites = [];
  if (obj.testsuites?.testsuite)
    suites.push(
      ...(Array.isArray(obj.testsuites.testsuite)
        ? obj.testsuites.testsuite
        : [obj.testsuites.testsuite])
    );
  else if (obj.testsuite)
    suites.push(
      ...(Array.isArray(obj.testsuite) ? obj.testsuite : [obj.testsuite])
    );

  for (const s of suites) {
    const cases = s.testcase
      ? Array.isArray(s.testcase)
        ? s.testcase
        : [s.testcase]
      : [];
    for (const tc of cases) {
      total++;
      if (tc.skipped) {
        skipped++;
        continue;
      }
      if (tc.failure || tc.error) {
        failed++;
        const failObj = tc.failure || tc.error;
        const message = (failObj?.message || "").toString();
        const detail = (failObj?._ || "").toString();
        failures.push({
          suite: s.name || path.basename(file),
          name: tc.name || "(unnamed test)",
          classname: tc.classname || "",
          fileHint: firstStackLine(detail || message),
          message: message || "(no message)",
          detail: detail,
        });
      } else {
        passed++;
      }
    }
  }
};

(async () => {
  for (const f of files) await parseOne(f);

  const header = `# Test Report

**Total:** ${total} **Passed:** ${passed} **Failed:** ${failed} **Skipped:** ${skipped}

> Source files: ${files
    .map((f) => `\`${path.relative(process.cwd(), f)}\``)
    .join(", ")}
`;

  let body = "";
  if (failed === 0) {
    body = `\n✅ All tests passed.\n`;
  } else {
    body = `\n## Failures (${failed})\n`;
    failures.forEach((x, i) => {
      body += `\n### ${i + 1}. ${x.name}\n`;
      if (x.classname) body += `- **Class:** \`${x.classname}\`\n`;
      body += `- **Suite:** \`${x.suite}\`\n`;
      if (x.fileHint) body += `- **Trace hint:** \`${x.fileHint}\`\n`;
      body += `\n**Message**\n\n${x.message}\n`;
      if (x.detail)
        body += `\n<details><summary>Stack / Details</summary>\n\n\`\`\`\n${x.detail.trim()}\n\`\`\`\n</details>\n`;
    });
  }

  fs.writeFileSync(outPath, header + body + "\n");
  console.log(`Wrote ${outPath}`);
})();
