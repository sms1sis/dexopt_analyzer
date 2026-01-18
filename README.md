# Dexter

An advanced, high-performance Android DexOpt status analyzer written in Rust. This tool replaces slow shell scripts by efficiently parsing global package status from `dumpsys` and correlating it with installed apps.

## Features

- **Blazing Fast**: Captures global state in a single pass instead of per-package lookups.
- **Robust Label Resolution**: Uses a hybrid approach (Native Parsing + `aapt` fallback) to correctly identify app names, even for split APKs.
- **Visuals**: Unicode-aware, perfectly aligned boxes that respect your terminal width.
- **Advanced Filtering**: Filter by package name or **DexOpt Status** (e.g., find all `error` or `run-from-apk` apps).
- **JSON Output**: Export structured data for automation and scripts.
- **Root Check**: Built-in validation to ensure proper privileges.

## Requirements

- **Termux** or a Linux environment on Android.
- **Root access** (`su` or `tsu`) is required.
- **aapt** (Android Asset Packaging Tool) is recommended for best results (fetching labels for system apps), but the tool works without it.
- **Rust/Cargo** (for building from source).

## Installation

1. **Install Dependencies** (Termux):
   ```bash
   pkg install rust openssl
   # Optional but recommended:
   pkg install aapt
   ```

2. **Build from Source**:
   ```bash
   git clone https://github.com/your-repo/dexter.git
   cd dexter
   # We use system OpenSSL to avoid complex cross-compilation on Android
   OPENSSL_NO_VENDOR=1 cargo build --release
   ```

The binary will be available at `target/release/dexter`.

## Usage

Run the tool with root privileges:

```bash
# Analyze User apps (default)
su -c "./target/release/dexter"

# Analyze System apps
su -c "./target/release/dexter -t system"

# Show JSON output (useful for scripts)
su -c "./target/release/dexter -j"

# Filter by Status (e.g., find unoptimized apps)
su -c "./target/release/dexter -s run-from-apk"

# Filter by Name
su -c "./target/release/dexter -f google"
```

### Options

```text
Usage: dexter [OPTIONS]

Options:
  -f, --filter <FILTER>  Filter packages by name (substring match)
  -s, --status <STATUS>  Filter by specific dexopt status (e.g., 'speed', 'verify', 'error')
  -t, --type <TYPE>      Type of applications to analyze [default: user] [possible values: user, system, all]
  -v, --verbose          Show detailed information for each package
  -j, --json             Output results as JSON
  -h, --help             Print help
  -V, --version          Print version
```

## License

MIT
