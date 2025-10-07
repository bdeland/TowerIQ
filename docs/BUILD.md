# Building TowerIQ

## Prerequisites

Make sure you have:

- Python 3.11+
- Node.js 18+
- Rust (for Tauri)
- Poetry (for Python dependency management)

## Build Complete Application

### Step 1: Build Backend

**Option 1: Quick Build (Recommended)**

```bash
poetry run pyinstaller build_configs/pyinstaller_production.spec --clean
```

**Option 2: Using Test Script**

```bash
python scripts/test_backend_build.py
```

This creates: `dist/toweriq-backend.exe`

⚠️ **Important:** The backend must be named `toweriq-backend.exe` (lowercase) to match Tauri's sidecar configuration.

### Step 2: Copy Backend to Sidecar Location

```bash
# Windows (PowerShell)
Copy-Item "dist\toweriq-backend.exe" -Destination "frontend\src-tauri\binaries\toweriq-backend-x86_64-pc-windows-msvc.exe" -Force

# Linux/macOS
cp dist/toweriq-backend frontend/src-tauri/binaries/toweriq-backend-x86_64-unknown-linux-gnu
```

The backend is copied with a platform-specific name that Tauri expects.

### Step 3: Build Tauri App (with embedded backend)

```bash
cd frontend
npm run tauri build
```

This creates:

- **Executable**: `src-tauri/target/release/TowerIQ.exe`
- **Installer**: `src-tauri/target/release/bundle/nsis/TowerIQ_0.1.0_x64-setup.exe`

⚠️ **Note:** The installer is in a `.gitignore`d folder (`target/`), so it won't appear in your IDE. Use File Explorer or terminal to access it.

**To open the installer folder:**

```bash
explorer frontend\src-tauri\target\release\bundle\nsis
```

The installer includes:

- ✅ Frontend (React app in WebView)
- ✅ Backend (Python FastAPI as sidecar)
- ✅ Frida server binaries (in resources)
- ✅ Auto-starts backend on app launch
- ❌ Database (NOT included - created on first run)

## Development Mode

### Terminal 1: Start Backend

```bash
python start.py
```

### Terminal 2: Start Frontend

```bash
cd frontend
npm run dev
```

## How the Sidecar Works

Per the [Tauri sidecar documentation](https://v2.tauri.app/develop/sidecar/):

1. Backend is bundled as `binaries/toweriq-backend` in `tauri.conf.json`
2. Platform-specific binary must exist: `toweriq-backend-x86_64-pc-windows-msvc.exe`
3. On app startup, Tauri automatically launches the backend sidecar
4. Backend runs in background while app is open
5. Frontend communicates with backend via HTTP (localhost:8000)

## Distribution

Distribute the NSIS installer:

```
frontend/src-tauri/target/release/bundle/nsis/TowerIQ_0.1.0_x64-setup.exe
```

Users install once, and the app:

- ✅ Runs as a single application
- ✅ Auto-starts backend on launch
- ✅ No manual backend startup needed
- ✅ Everything bundled together

## Troubleshooting

### App Stuck at Splash Screen

**Symptoms:** Application installs but stays on the "Starting TowerIQ..." splash screen indefinitely.

**Cause:** The backend sidecar isn't starting or the frontend can't connect to it.

**Common Issues:**

1. **Backend Name Mismatch**

   - Backend must be named `toweriq-backend.exe` (lowercase)
   - Platform-specific name: `toweriq-backend-x86_64-pc-windows-msvc.exe`
   - Check `frontend/src-tauri/binaries/` for the correct binary

2. **Backend Not in Binaries Folder**

   - Verify the backend exists in `frontend/src-tauri/binaries/`
   - Rebuild and copy if missing (see Step 1 & 2)

3. **Port Conflict**
   - Backend runs on port 8000 by default
   - Make sure no other service is using port 8000

**Debug Steps:**

1. Check if backend is running:

   ```bash
   netstat -ano | findstr :8000
   ```

2. Test backend directly:

   ```bash
   dist\toweriq-backend.exe
   # Then visit http://localhost:8000/api/status in browser
   ```

3. Check Tauri logs (Windows):
   ```bash
   # Logs are in: %APPDATA%\com.delan.toweriq\logs\
   ```

### Database Was Included in Build

**Issue:** Old builds accidentally included `toweriq.sqlite` database with sensitive data.

**Fix:** The configuration now excludes the database:

- `tauri.conf.json` only includes `resources: ["../../data/frida-server"]`
- Database is created fresh on first run
- Never distribute builds containing your development database

### Build Output Not Visible in IDE

**Issue:** Can't see the `target/` folder with the built installer.

**Reason:** The `target/` folder is in `.gitignore` and hidden by VS Code/Cursor.

**Solution:** Use File Explorer or terminal:

```bash
explorer frontend\src-tauri\target\release\bundle\nsis
```
