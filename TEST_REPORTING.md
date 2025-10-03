# Test Reporting System

This project includes an automated test reporting system that generates both detailed and compact test reports for Cursor's AI agent.

## Quick Start

Run all tests and generate the report:

```bash
npm run test:all
```

This will:

1. Clean and prepare the reports directory
2. Run Python tests (pytest) with JUnit XML output
3. Run JavaScript tests (Jest) with JUnit XML output
4. Generate a detailed `cursor_test_report.md` file
5. Generate a compact `cursor_tests.ndjson` file for AI agents
6. Generate an optional `cursor_test_report_min.md` summary

## Available Commands

- `npm run test:prep` - Clean and prepare the reports directory
- `npm run test:py` - Run Python tests only
- `npm run test:js` - Run JavaScript tests only
- `npm run test:report` - Generate the detailed report from existing JUnit files
- `npm run test:report:min` - Generate the compact NDJSON report from existing JUnit files
- `npm run test:all` - Run all tests and generate both detailed and compact reports

## VS Code Integration

The following tasks are available in VS Code (Ctrl+Shift+P → "Tasks: Run Task"):

- **Tests: build Cursor report** - Run all tests and generate both detailed and compact reports
- **Tests: Python only** - Run Python tests only
- **Tests: JavaScript only** - Run JavaScript tests only
- **Tests: Generate report only** - Generate both detailed and compact reports from existing files

## Report Formats

### Detailed Report (`cursor_test_report.md`)

The detailed report contains:

- **Summary**: Total, Passed, Failed, Skipped counts
- **Source files**: List of JUnit XML files processed
- **Failures**: Detailed failure information including:
  - Test name and class
  - Suite information
  - File/line trace hints
  - Error messages
  - Full stack traces (collapsible)

### Compact Report (`cursor_tests.ndjson`)

The compact NDJSON report is optimized for AI agents with minimal token usage:

- **Summary line**: Test counts and duration
- **Failure lines**: One line per failure with:
  - Normalized test identifiers (pytest-like nodeids)
  - File/line locations
  - Shortened error messages
  - Ready-to-run pytest commands

### Minimal Summary (`cursor_test_report_min.md`)

Optional human-readable summary showing:

- Test summary statistics
- First 10 failures with locations
- Reference to full NDJSON for complete details

## Configuration

### Python Tests (pytest)

- JUnit XML output: `_reports/junit/pytest.xml`
- Configuration: `pytest.ini`

### JavaScript Tests (Jest)

- JUnit XML output: `_reports/junit/jest.xml`
- Configuration: `jest.config.js`

### Report Generation

- Detailed script: `scripts/make-cursor-report.mjs`
- Compact script: `scripts/make-cursor-ndjson.mjs`
- Outputs: `cursor_test_report.md`, `cursor_tests.ndjson`, `cursor_test_report_min.md`

## Usage with Cursor AI

### For AI Agents (Recommended)

Use the compact NDJSON format for minimal token usage:

> "Read `./cursor_tests.ndjson`. If `summary.failed == 0`, stop. Otherwise iterate failures by ascending `id`. For each failure: 1. Open `file:line` (if present). 2. Use `err` + `msg` to hypothesize the fix. 3. Run the focused test using `cmd` (if present) or `pytest -q tests -k '<test name>'`. 4. Re-run the VS Code task 'Tests: build Cursor report' to refresh artifacts. 5. Continue until `summary.failed == 0`. If you need full stacks, open `cursor_test_report.md` (detailed) as a secondary reference."

### For Human Review

Use the detailed markdown format:

> "Use `cursor_test_report.md` for the current test status. Fix failures in order. Open the file/line from each failure's 'trace hint' and run the related test file after each fix."

### Report Benefits

- **Compact format**: Token-efficient for AI agents with ready-to-run commands
- **Detailed format**: Full stack traces and comprehensive debugging information
- **Quick overview**: Test summary statistics and failure counts
- **Specific locations**: File/line references for targeted fixes
