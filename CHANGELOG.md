# Changelog

## [0.3.1] - 2026-01-29

### 🛠 Improvements
* **Optimization Workflow:** 
    * Automatically enables verbose output (`-v`) after optimization for a cleaner and more detailed status view.
    * Automatically filters the results to the targeted package when optimizing a specific app, eliminating noise from other packages.

## [0.3.0] - 2026-01-29

### ✨ Features
* **Optimization Flag:** Added `-o` / `--optimize` flag to trigger app-specific or system-wide dexopt.
    * Use `-o <package_name>` to clear profiles and force compile a specific app.
    * Use `-o all` to trigger the system background dexopt job (`bg-dexopt-job`).
* **Root Enforcement:** Improved root access validation for administrative commands.

### 🛠 Improvements
* **CLI Options:** Updated help menus and argument parsing to include optimization targets.
* **Version Bump:** Formalized v0.3.0 release.

---

## [0.2.0] - 2026-01-18

### 🚀 Performance
* **Native Parsing:** Replaced `aapt` subprocess calls with native Rust APK parsing using `apk-info`.
* **Speedup:** Analysis with labels (verbose mode) is now **~3x faster**.
* **Parallelism:** Parsing is fully parallelized across all available cores.

### ✨ Features
* **Robust Label Extraction:** Can now extract labels for apps where `aapt` failed or returned missing data.
* **Dependency Removal:** The tool no longer requires `aapt` to be installed. It is now self-contained.

### 🛠 Bug Fixes
* **Missing Labels:** Fixed an issue where some system apps showed no name due to `aapt` limitations.

### 🎨 Styling
* **Cyan Highlights:** Application names are highlighted for better visibility.
* **Dynamic Summary:** Summary box adjusts colors based on status.