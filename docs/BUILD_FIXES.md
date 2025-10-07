# TowerIQ Build Fixes (October 7, 2025)

## Issues Identified

### 1. App Stuck at Splash Screen

**Symptom:** After installation, the application would hang indefinitely at the "Starting TowerIQ..." splash screen.

**Root Cause:** Backend sidecar binary naming mismatch

- Tauri configuration expected: `toweriq-backend` (lowercase)
- PyInstaller was building: `TowerIQ-Backend` (mixed case)
- This caused Tauri to fail silently when trying to start the backend sidecar

### 2. Database Included in Build

**Symptom:** The SQLite database (`toweriq.sqlite`) with development/sensitive data was being packaged in the installer.

**Root Cause:** Overly broad resource inclusion in `tauri.conf.json`

- Configuration included entire `data/` directory
- This pulled in `toweriq.sqlite` along with the needed Frida server binaries

### 3. Build Output Not Visible in IDE

**Symptom:** Couldn't see the `target/` folder with build artifacts in VS Code/Cursor.

**Root Cause:** The `target/` folder is in `.gitignore` and hidden by default

## Fixes Applied

### Fix 1: Backend Binary Naming

**Files Modified:**

- `build_configs/pyinstaller_production.spec`
- `build_configs/pyinstaller.spec`
- `build_configs/pyinstaller_simple.spec`
- `scripts/test_backend_build.py`

**Changes:**

```python
# Before:
name='TowerIQ-Backend',

# After:
name='toweriq-backend',
```

**Platform-Specific Naming:**

- Windows: `toweriq-backend-x86_64-pc-windows-msvc.exe`
- Linux: `toweriq-backend-x86_64-unknown-linux-gnu`
- macOS: `toweriq-backend-aarch64-apple-darwin`

### Fix 2: Database Exclusion from Build

**File Modified:** `frontend/src-tauri/tauri.conf.json`

**Changes:**

```json
// Before:
"resources": ["../../data"],

// After:
"resources": ["../../data/frida-server"],
```

**Result:**

- ✅ Frida server binaries included (needed for functionality)
- ❌ Database excluded (created fresh on first run)
- 📉 Installer size reduced from 275 MB to 220.66 MB (~54 MB smaller)

### Fix 3: Improved Build Script

**File Modified:** `scripts/test_backend_build.py`

**Improvements:**

- Automatically copies backend to `dist/toweriq-backend.exe`
- Automatically copies to Tauri binaries folder with platform-specific name
- Updated output messages to guide next steps
- Correctly references lowercase binary name

### Fix 4: Enhanced Documentation

**Files Created/Modified:**

- `docs/BUILD.md` - Comprehensive build instructions
- `docs/BUILD_FIXES.md` - This file (troubleshooting guide)

**Added Sections:**

- Prerequisites with all required tools
- Step-by-step build process
- Troubleshooting common issues
- Distribution guidelines

## Verification

### Build Size Comparison

- **Old Build:** 275.12 MB (included database)
- **New Build:** 220.66 MB (database excluded)
- **Reduction:** 54.46 MB

### Files Included in New Build

✅ Frontend (React WebView)
✅ Backend (Python FastAPI sidecar)
✅ Frida server binaries
✅ Configuration files
✅ Resource assets
❌ Development database
❌ Log files
❌ User-specific data

## Testing the Fix

### Before Installing

1. **Verify backend name:**

   ```bash
   Get-Item dist\toweriq-backend.exe
   Get-Item frontend\src-tauri\binaries\toweriq-backend-x86_64-pc-windows-msvc.exe
   ```

2. **Verify installer size:**
   ```bash
   Get-Item frontend\src-tauri\target\release\bundle\nsis\TowerIQ_0.1.0_x64-setup.exe
   # Should be ~221 MB, not ~275 MB
   ```

### After Installing

1. **Test backend starts:**

   - Install the application
   - Launch TowerIQ
   - Should pass splash screen within 3-5 seconds
   - No longer stuck indefinitely

2. **Verify backend is running:**

   ```bash
   # Check if port 8000 is in use
   netstat -ano | findstr :8000

   # Test API endpoint
   curl http://localhost:8000/api/status
   ```

3. **Verify database is NOT from development:**
   - Check application data directory
   - Database should be newly created, empty or with default data only
   - Should NOT contain your development data

## Build Process Summary

### Quick Build (Recommended)

```bash
# 1. Build backend
poetry run pyinstaller build_configs/pyinstaller_production.spec --clean

# 2. Copy to Tauri
Copy-Item dist\toweriq-backend.exe frontend\src-tauri\binaries\toweriq-backend-x86_64-pc-windows-msvc.exe -Force

# 3. Build Tauri app
cd frontend
npm run tauri build
```

### Using Build Script

```bash
# Single command that does steps 1 & 2
python scripts/test_backend_build.py

# Then build Tauri app
cd frontend
npm run tauri build
```

## Future Considerations

### For CI/CD

- Automate backend build → copy → frontend build pipeline
- Add verification step to check installer doesn't contain sensitive data
- Test backend startup in clean VM before releasing

### For Development

- Consider separating development and production databases
- Add database initialization script for first run
- Implement proper database migration system

### For Distribution

- Always test installer on a clean system
- Verify no user-specific data is included
- Check installer size as a quick validation (should be ~221 MB)
- Consider code signing for production releases

## Related Files

- [BUILD.md](BUILD.md) - Complete build instructions
- [PACKAGING.md](PACKAGING.md) - Packaging system overview (if exists)
- [GRAFANA_INTEGRATION.md](GRAFANA_INTEGRATION.md) - Grafana integration docs

## Change Log

- **2025-10-07**: Initial fixes for splash screen hang and database inclusion
  - Fixed backend binary naming mismatch
  - Excluded database from Tauri resources
  - Updated all build scripts and documentation
