# Dependency Management Workflow

This project uses [Poetry](https://python-poetry.org/) as the source of truth for
Python dependencies. The `poetry.lock` file captures the fully resolved dependency
graph and should be treated as canonical. When `requirements.txt` is needed (for
example, in deployment environments that rely on `pip install -r requirements.txt`),
regenerate it from the lock file instead of editing it manually.

## Generating `requirements.txt`

1. Ensure the lock file is up to date:
   ```bash
   poetry lock --no-update
   ```
2. If the `poetry-plugin-export` plugin is available, run:
   ```bash
   poetry export -f requirements.txt --without-hashes -o requirements.txt
   ```
3. In offline environments where the plugin cannot be installed, use the helper
   script committed with this repository:
   ```bash
   python tools/export_requirements.py
   ```

The generated file pins all main (runtime) dependencies and preserves platform
markers so that OS-specific wheels such as `pywin32` or the macOS `pyobjc`
family are only installed where appropriate. Review the file to confirm that:

- Only third-party packages are present (stdlib modules such as `sqlite3` should
  never appear because they are not tracked by Poetry).
- Expected runtime dependencies such as `pandas`, `aiohttp`, and `sqlcipher3-wheels`
  are listed with exact versions that match `poetry.lock`.

## Validating the Environment (Optional)

After updating `requirements.txt`, you can optionally test the result in a clean
virtual environment:

```bash
python -m venv .venv-test
source .venv-test/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python start_backend.py  # or the relevant entry point
```

This smoke test confirms that the exported requirements are sufficient to start
the backend outside of Poetry's environment.
