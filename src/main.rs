use apk_info::Apk;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use serde::Serialize;
use serde_json::json;
use once_cell::sync::Lazy;
use unicode_width::UnicodeWidthStr;
use terminal_size::{Width, terminal_size};

/// A tool to analyze dexopt status on Android devices.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Filter packages by name (substring match)
    #[arg(short, long)]
    filter: Option<String>,

    /// Filter by specific dexopt status (e.g., 'speed', 'verify', 'error')
    #[arg(short, long)]
    status: Option<String>,

    /// Type of applications to analyze
    #[arg(short, long, value_enum, default_value_t = AppType::User)]
    r#type: AppType,

    /// Show detailed information for each package
    #[arg(short, long)]
    verbose: bool,

    /// Output results as JSON
    #[arg(short, long)]
    json: bool,

    /// Optimize application(s). Use 'all' for background dexopt job, or specify a package name.
    #[arg(short = 'o', long = "optimize")]
    optimize: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum AppType {
    User,
    System,
    All,
}

impl fmt::Display for AppType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            AppType::User => "User",
            AppType::System => "System",
            AppType::All => "All",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, Clone, Serialize)]
struct Package {
    name: String,
    path: String,
}

impl Package {
    /// Fetches the package list using `pm list packages`.
    fn fetch_list(app_type: AppType) -> Result<Vec<Self>> {
        let filter_flag = match app_type {
            AppType::User => "-3",
            AppType::System => "-s",
            AppType::All => "",
        };

        let mut cmd = Command::new("pm");
        cmd.arg("list").arg("packages").arg("-f");
        if !filter_flag.is_empty() {
            cmd.arg(filter_flag);
        }

        let output = cmd.output()
            .with_context(|| "Failed to execute 'pm' command")?;

        let raw = String::from_utf8_lossy(&output.stdout);
        let mut list = Vec::new();

        for line in raw.lines() {
            if let Some(p) = line.trim().strip_prefix("package:") {
                if let Some((path, name)) = p.rsplit_once('=') {
                    list.push(Package {
                        name: name.trim().to_string(),
                        path: path.trim().to_string(),
                    });
                }
            }
        }

        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    /// Gets the application label from the APK file.
    fn get_label(&self) -> Option<String> {
        // 1. aapt: resolves string resources directly from the APK — most accurate
        if let Some(label) = self.get_label_from_aapt() {
            return Some(label);
        }

        // 2. apk-info native parsing: fast fallback when aapt is unavailable
        if let Ok(apk) = Apk::new(&self.path) {
            if let Some(label) = apk.get_application_label() {
                let clean = label.trim().replace(['\r', '\n'], " ");
                if !clean.is_empty() && Self::is_valid_label(&clean) {
                    return Some(clean);
                }
            }
        }

        None
    }

    /// Returns true if the string looks like a real human-readable app label.
    /// Rejects resource refs, class names, URLs, JSON blobs, and other garbage
    /// that some APKs mistakenly store in the application-label field.
    fn is_valid_label(label: &str) -> bool {
        // Resource reference e.g. "@0x1040001"
        if label.starts_with('@') {
            return false;
        }
        // URL e.g. "https://www.facebook.com/.well-known/..."
        if label.starts_with("http://") || label.starts_with("https://") {
            return false;
        }
        // JSON blob e.g. "[{ \"include\": ... }]" or "{ ... }"
        if label.starts_with('[') || label.starts_with('{') {
            return false;
        }
        // Bare package/class name e.g. "com.facebook.katana" or "com.foo.MainActivity"
        let is_class_like = label.contains('.')
            && !label.contains(' ')
            && label.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '$');
        if is_class_like {
            return false;
        }
        // Suspiciously long strings are almost certainly not a real label
        if label.len() > 64 {
            return false;
        }
        true
    }

    fn get_label_from_aapt(&self) -> Option<String> {
        let output = Command::new("aapt")
            .arg("dump")
            .arg("badging")
            .arg(&self.path)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(label) = trimmed.strip_prefix("application-label:'") {
                if let Some(end) = label.find('\'') {
                    return Some(label[..end].to_string());
                }
            }
        }
        None
    }

    fn is_aapt_available() -> bool {
        Command::new("which")
            .arg("aapt")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize)]
struct DexOptInfo {
    raw_line: String,
    status: String,
}

struct Analyzer {
    results: HashMap<String, Vec<DexOptInfo>>,
}

static STATUS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(arm64:|arm:)").expect("Invalid regex for status"));
static FILTER_EXTRACT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:status|filter)=([^\]\s]+)").expect("Invalid regex for filter extraction"));

impl Analyzer {
    fn fetch_dump() -> Result<String> {
        let output = Command::new("dumpsys")
            .arg("package")
            .arg("dexopt")
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn new(dump: &str) -> Self {
        let mut results: HashMap<String, Vec<DexOptInfo>> = HashMap::new();
        let mut current_pkg: Option<String> = None;

        for line in dump.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with('[')
                && trimmed.ends_with(']')
                && !trimmed.contains(' ')
                && !trimmed.contains('=')
            {
                current_pkg = Some(trimmed[1..trimmed.len() - 1].to_string());
            } else if let Some(ref pkg) = current_pkg {
                if STATUS_RE.is_match(trimmed) {
                    let status = FILTER_EXTRACT_RE
                        .captures(trimmed)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    results.entry(pkg.clone()).or_default().push(DexOptInfo {
                        raw_line: trimmed.to_string(),
                        status,
                    });
                }
            }
        }

        Analyzer { results }
    }

    fn get_info(&self, pkg_name: &str) -> Option<&Vec<DexOptInfo>> {
        self.results.get(pkg_name)
    }
}

struct UI;

impl UI {
    fn get_status_color(status: &str) -> Color {
        match status {
            "speed-profile" | "speed" => Color::Green,
            "verify" => Color::Yellow,
            "quicken" => Color::Blue,
            "run-from-apk" | "error" => Color::Red,
            "everything" => Color::Magenta,
            _ => Color::White,
        }
    }

    fn colorize_line(line: &str, status: &str) -> String {
        let color = Self::get_status_color(status);
        if status == "error" {
            line.color(color).bold().to_string()
        } else {
            line.color(color).to_string()
        }
    }

    fn print_header() {
        println!(
            "\n{} | {}\n",
            format!("{:<45}", "Package").bold().underline(),
            format!("{:<30}", "DexOpt Status").bold().underline()
        );
    }

    fn print_block_entry(
        stdout: &mut io::Stdout,
        pkg: &Package,
        app_label: Option<&str>,
        info_list: Option<&Vec<DexOptInfo>>,
    ) -> io::Result<()> {
        let min_width: usize = 40;

        let max_term_width = if let Some((Width(w), _)) = terminal_size() {
            (w as usize).saturating_sub(4)
        } else {
            120
        };

        // Build plain (no ANSI) display name for accurate width measurement
        let full_display_name = match app_label {
            Some(label) => format!("{} ({})", label, pkg.name),
            None => pkg.name.clone(),
        };

        // Unicode-aware truncation
        let display_name: String = if full_display_name.width() > max_term_width {
            let mut truncated = String::new();
            let mut w = 0usize;
            for c in full_display_name.chars() {
                let cw = UnicodeWidthStr::width(c.to_string().as_str());
                if w + cw > max_term_width.saturating_sub(3) {
                    truncated.push_str("...");
                    break;
                }
                truncated.push(c);
                w += cw;
            }
            truncated
        } else {
            full_display_name
        };

        // content_width = visual width of the plain text (no ANSI)
        let content_width = display_name.width();
        // box_width = number of ─ chars; actual rendered line is │ + ─*box_width + │
        let box_width = (content_width + 4).max(min_width).min(max_term_width);

        let border = "─".repeat(box_width);
        writeln!(stdout, "{}", format!("┌{}┐", border).cyan())?;

        // Padding: p_l + content_width + p_r == box_width (inner space between │ │)
        let p_space = box_width.saturating_sub(content_width);
        let p_l = p_space / 2;
        let p_r = p_space - p_l;

        // Build colorized version — ANSI bytes don't affect terminal column positions
        let inner_content = if display_name.ends_with("...") {
            display_name.bold().bright_white().to_string()
        } else {
            match app_label {
                Some(_) => {
                    let pkg_suffix = format!(" ({})", pkg.name);
                    if display_name.ends_with(&pkg_suffix) {
                        let label_part = &display_name[..display_name.len() - pkg_suffix.len()];
                        format!(
                            "{} ({})",
                            label_part.bold().cyan(),
                            pkg.name.bold().bright_white()
                        )
                    } else {
                        // Suffix was truncated — colour whole string
                        display_name.bold().bright_white().to_string()
                    }
                }
                None => display_name.bold().bright_white().to_string(),
            }
        };

        writeln!(
            stdout,
            "{}{}{}{}",
            "│".cyan(),
            " ".repeat(p_l),
            inner_content,
            format!("{}{}", " ".repeat(p_r), "│").cyan()
        )?;

        writeln!(stdout, "{}", format!("└{}┘", border).cyan())?;

        if let Some(infos) = info_list {
            let max_prefix_len = infos
                .iter()
                .filter_map(|i| i.raw_line.find(':'))
                .max()
                .unwrap_or(0);

            for info in infos {
                let raw_line = if info.raw_line.width() > max_term_width {
                    let mut s = info.raw_line.chars().take(max_term_width - 3).collect::<String>();
                    s.push_str("...");
                    s
                } else {
                    info.raw_line.clone()
                };

                let formatted = if let Some(idx) = raw_line.find(':') {
                    let (prefix, rest) = raw_line.split_at(idx);
                    format!("{:width$}{}", prefix, rest, width = max_prefix_len)
                } else {
                    raw_line
                };
                writeln!(stdout, "  {}", Self::colorize_line(&formatted, &info.status))?;
            }
        } else {
            writeln!(stdout, "  {}", "(no info found)".italic().red())?;
        }
        writeln!(stdout)?;
        Ok(())
    }

    fn print_summary(total_apps: usize, stats: &BTreeMap<String, usize>, app_type: AppType) {
        let width = 47;
        let b_blue = Color::BrightBlue;
        let b_yellow = Color::BrightYellow;

        println!("\n\n{}", format!("╔{}╗", "═".repeat(width)).color(b_blue));

        let title = "DEXOPT ANALYSIS SUMMARY";
        let p_s = (width - title.len()) / 2;
        let p_e = width - title.len() - p_s;
        println!(
            "{}{}{}{}",
            "║".color(b_blue),
            " ".repeat(p_s),
            title.bold().color(b_yellow),
            format!("{}{}", " ".repeat(p_e), "║").color(b_blue)
        );

        let mid = format!("╠{}╣", "═".repeat(width)).color(b_blue);
        println!("{}", mid);

        Self::add_summary_line("App Scope", &app_type.to_string(), Color::Cyan, Color::Magenta, width);
        Self::add_summary_line("Total Apps Checked", &total_apps.to_string(), Color::Cyan, Color::BrightGreen, width);

        println!("{}", mid);
        let sub = "Profile Breakdown";
        let p_s = (width - sub.len()) / 2;
        let p_e = width - sub.len() - p_s;
        println!(
            "{}{}{}{}",
            "║".color(b_blue),
            " ".repeat(p_s),
            sub.dimmed().bold(),
            format!("{}{}", " ".repeat(p_e), "║").color(b_blue)
        );
        println!("{}", mid);

        if stats.is_empty() {
            let msg = "No profile data found.";
            let padding = " ".repeat(width.saturating_sub(2 + msg.len()));
            println!("{}  {}{}{}", "║".color(b_blue), msg, padding, "║".color(b_blue));
        } else {
            for (profile, count) in stats {
                let color = Self::get_status_color(profile);
                Self::add_summary_line(profile, &count.to_string(), Color::Cyan, color, width);
            }
        }
        println!("{}", format!("╚{}╝", "═".repeat(width)).color(b_blue));
    }

    fn add_summary_line(label: &str, value: &str, l_col: Color, v_col: Color, width: usize) {
        let l_part = format!("{:<22}", label).bold().color(l_col);
        let v_part = value.bold().color(v_col);
        let padding = " ".repeat(width.saturating_sub(5 + 22 + value.len()));
        println!(
            "{}  {} : {}{}{}",
            "║".color(Color::BrightBlue),
            l_part,
            v_part,
            padding,
            "║".color(Color::BrightBlue)
        );
    }
}

fn check_root() -> Result<()> {
    if !nix::unistd::Uid::current().is_root() {
        eprintln!("{}", "Error: This tool requires root access (su).".red().bold());
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    check_root()?;
    let mut args = Args::parse();

    if let Some(ref target) = args.optimize {
        args.verbose = true;
        if target != "all" && args.filter.is_none() {
            args.filter = Some(target.clone());
        }
    }

    let prefix = "[-]".cyan();

    if let Some(ref target) = args.optimize {
        let msg = if target == "all" {
            "Triggering background dexopt job...".to_string().bold()
        } else {
            format!("Optimizing package: {}", target).bold()
        };
        println!("{} {}", prefix, msg);

        if target == "all" {
            let status = Command::new("su")
                .arg("-c")
                .arg("cmd package bg-dexopt-job")
                .status()
                .with_context(|| "Failed to execute background optimization")?;
            if !status.success() {
                eprintln!("{} Optimization command failed.", prefix);
            }
        } else {
            let cmd1 = format!("pm art clear-app-profiles {}", target);
            let status1 = Command::new("su")
                .arg("-c")
                .arg(&cmd1)
                .status()
                .with_context(|| "Failed to clear app profiles")?;
            if !status1.success() {
                eprintln!("{} Failed to clear app profiles for {}", prefix, target);
            }

            let cmd2 = format!("cmd package compile -m speed -f {}", target);
            let status2 = Command::new("su")
                .arg("-c")
                .arg(&cmd2)
                .status()
                .with_context(|| "Failed to compile package")?;
            if !status2.success() {
                eprintln!("{} Failed to compile {}", prefix, target);
            }
        }
    }

    if !args.json {
        println!("{} {} ({}) ...", prefix, "Fetching package list".bold(), args.r#type);
    }
    let packages = Package::fetch_list(args.r#type)?;

    if !args.json {
        println!("{} Found {} packages.", prefix, packages.len().to_string().green().bold());
        println!("{} {}", prefix, "Fetching dexopt dump...".bold());
    }
    let dump = Analyzer::fetch_dump()?;
    let analyzer = Analyzer::new(&dump);

    if !args.json && !args.verbose {
        UI::print_header();
    }

    let mut stdout = io::stdout();
    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_displayed = 0;
    let mut json_results = Vec::new();

    // Step 1: name filter (cheap string match)
    let name_filtered: Vec<&Package> = packages
        .iter()
        .filter(|pkg| args.filter.as_ref().map_or(true, |f| pkg.name.contains(f)))
        .collect();

    // Step 2: status filter (cheap lookup, no label fetching)
    let status_filtered: Vec<(&Package, Option<&Vec<DexOptInfo>>)> = name_filtered
        .iter()
        .filter_map(|pkg| {
            let info_list = analyzer.get_info(&pkg.name);
            if let Some(ref status_filter) = args.status {
                let infos = info_list?;
                if !infos.iter().any(|i| i.status.contains(status_filter)) {
                    return None;
                }
                Some((*pkg, Some(infos)))
            } else {
                Some((*pkg, info_list))
            }
        })
        .collect();

    // Step 3: fetch labels only for survivors (parallel for verbose/json)
    let display_data: Vec<(&Package, Option<String>, Option<&Vec<DexOptInfo>>)> =
        if args.verbose || args.json {
            status_filtered
                .par_iter()
                .map(|(pkg, info_list)| (*pkg, pkg.get_label(), *info_list))
                .collect()
        } else {
            status_filtered
                .iter()
                .map(|(pkg, info_list)| (*pkg, None, *info_list))
                .collect()
        };

    for (pkg, app_label, info_list) in display_data {
        total_displayed += 1;

        if let Some(infos) = info_list {
            for info in infos {
                *stats.entry(info.status.clone()).or_insert(0) += 1;
            }
        }

        if args.json {
            json_results.push(json!({
                "package": pkg.name,
                "label": app_label,
                "path": pkg.path,
                "dexopt_info": info_list
            }));
        } else if args.verbose {
            UI::print_block_entry(&mut stdout, pkg, app_label.as_deref(), info_list)?;
        } else if let Some(infos) = info_list {
            for (i, info) in infos.iter().enumerate() {
                let colored_raw = UI::colorize_line(&info.raw_line, &info.status);
                if i == 0 {
                    writeln!(stdout, "{} | {}", format!("{:<45}", pkg.name).bright_white(), colored_raw)?;
                } else {
                    writeln!(stdout, "{:<45} | {}", "", colored_raw)?;
                }
            }
            writeln!(stdout)?;
        } else {
            writeln!(
                stdout,
                "{} | {}",
                format!("{:<45}", pkg.name).bright_white(),
                "(no info found)".italic().red()
            )?;
            writeln!(stdout)?;
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&json_results)?);
    } else {
        UI::print_summary(total_displayed, &stats, args.r#type);

        if args.verbose && !Package::is_aapt_available() {
            println!();
            eprintln!("{}", "Warning: 'aapt' is not installed. Some application labels might be missing.".yellow().bold());
            eprintln!("{}", "Install it via 'pkg install aapt' for the best experience.".yellow().bold());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_parsing() {
        let sample_dump = r#"
[com.example.app]
  arm64: [status=speed-profile] [reason=bg-dexopt] [primary-abi]
[com.system.service]
  arm64: [status=verify] [reason=prebuilt]
"#;
        let analyzer = Analyzer::new(sample_dump);

        let info_app = analyzer.get_info("com.example.app").unwrap();
        assert_eq!(info_app.len(), 1);
        assert_eq!(info_app[0].status, "speed-profile");

        let info_sys = analyzer.get_info("com.system.service").unwrap();
        assert_eq!(info_sys.len(), 1);
        assert_eq!(info_sys[0].status, "verify");

        assert!(analyzer.get_info("non.existent").is_none());
    }

    #[test]
    fn test_label_heuristic_filters_class_names() {
        let cases: &[(&str, bool)] = &[
            ("com.example.SomeActivity", false),                        // class-like
            ("com.foo.bar", false),                                     // package-like
            ("@0x1040001", false),                                      // resource ref
            ("https://www.facebook.com/.well-known/assetlinks.json", false), // URL
            ("[{ \"include\": \"https://example.com\" }]", false), // JSON blob
            ("{ \"key\": \"value\" }", false),                     // JSON object
            ("a".repeat(65).as_str(), false),                           // too long
            ("My Cool App", true),                                      // real label
            ("MyApp", true),                                            // simple word
            ("Calculator", true),                                       // simple word
            ("Facebook", true),                                         // real label
        ];

        for (label, should_keep) in cases {
            assert_eq!(
                Package::is_valid_label(label),
                *should_keep,
                "Failed for label: {:?}", label
            );
        }
    }

    #[test]
    fn test_box_padding_is_exact() {
        // p_l + content_width + p_r must equal box_width exactly
        for content_len in [5, 20, 40, 60, 80] {
            let min_width: usize = 40;
            let max_term_width: usize = 120;
            let box_width = (content_len + 4).max(min_width).min(max_term_width);
            let p_space = box_width.saturating_sub(content_len);
            let p_l = p_space / 2;
            let p_r = p_space - p_l;
            assert_eq!(p_l + content_len + p_r, box_width,
                "Padding mismatch for content_len={}", content_len);
        }
    }
}
