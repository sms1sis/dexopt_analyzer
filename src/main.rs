use apk_info::Apk;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::process::Command;

/// A tool to analyze dexopt status on Android devices.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Filter packages by name (substring match)
    #[arg(short, long)]
    filter: Option<String>,

    /// Type of applications to analyze
    #[arg(short, long, value_enum, default_value_t = AppType::User)]
    r#type: AppType,

    /// Show detailed information for each package
    #[arg(short, long)]
    verbose: bool,
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

#[derive(Debug, Clone)]
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

        let cmd = format!("pm list packages -f {}", filter_flag);
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .with_context(|| format!("Failed to execute command: {}", cmd))?;

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
        // 1. Try native parsing (Fast)
        if let Ok(apk) = Apk::new(&self.path) {
            if let Some(label) = apk.get_application_label() {
                let clean = label.trim().replace(['\r', '\n'], " ");
                if !clean.is_empty() {
                    // Heuristic: Filter out internal class names
                    // If it looks like a java package/class (dots, no spaces) and isn't the package name itself
                    let is_class_name = clean.contains('.') && !clean.contains(' ') && clean != self.name;
                    // Additional check: valid class chars
                    let looks_like_class = clean.chars().all(|c: char| c.is_alphanumeric() || c == '.' || c == '_');
                    
                    if !is_class_name || !looks_like_class {
                         return Some(clean);
                    }
                }
            }
        }

        // 2. Fallback to aapt (Slow but Universal)
        // Only runs if native failed or returned a suspicious label
        self.get_label_from_aapt()
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
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct DexOptInfo {
    raw_line: String,
    status: String,
}

struct Analyzer {
    results: HashMap<String, Vec<DexOptInfo>>,
}

use once_cell::sync::Lazy;

static STATUS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(arm64:|arm:)").expect("Invalid regex for status"));
static FILTER_EXTRACT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:status|filter)=([^]\s]+)").expect("Invalid regex for filter extraction"));

impl Analyzer {
    /// Fetches the dexopt dump from `dumpsys package dexopt`.
    fn fetch_dump() -> Result<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg("dumpsys package dexopt")
            .output()?;

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Parses the dumpsys output into a structured map.
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
        let min_width = 40;
        let display_name = match app_label {
            Some(label) => format!("{} ({})", label, pkg.name),
            None => pkg.name.clone(),
        };

        let width = (display_name.len() + 4).max(min_width);
        let border = "─".repeat(width);

        writeln!(stdout, "{}", format!("┌{}┐", border).cyan())?;

        let p_space = width - display_name.len();
        let p_l = p_space / 2;
        let p_r = p_space - p_l;

        let inner_content = match app_label {
            Some(label) => format!(
                "{} ({})",
                label.bold().cyan(), 
                pkg.name.bold().bright_white()
            ),
            None => pkg.name.bold().bright_white().to_string(),
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
                let formatted = if let Some(idx) = info.raw_line.find(':') {
                    let (prefix, rest) = info.raw_line.split_at(idx);
                    format!("{:width$}{}", prefix, rest, width = max_prefix_len)
                } else {
                    info.raw_line.clone()
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

fn main() -> Result<()> {
    let args = Args::parse();
    let prefix = "[-]".cyan();

    println!("{} {} ({}) ...", prefix, "Fetching package list".bold(), args.r#type);
    let packages = Package::fetch_list(args.r#type)?;
    
    println!("{} Found {} packages.", prefix, packages.len().to_string().green().bold());
    println!("{} {}", prefix, "Fetching dexopt dump...".bold());
    let dump = Analyzer::fetch_dump()?;
    let analyzer = Analyzer::new(&dump);

    if !args.verbose {
        UI::print_header();
    }

    let mut stdout = io::stdout();
    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_displayed = 0;

    let filtered_packages: Vec<&Package> = packages
        .iter()
        .filter(|pkg| args.filter.as_ref().map_or(true, |f| pkg.name.contains(f)))
        .collect();

    let display_data: Vec<(&Package, Option<String>)> = if args.verbose {
        filtered_packages
            .par_iter()
            .map(|pkg| (*pkg, pkg.get_label()))
            .collect()
    } else {
        filtered_packages.iter().map(|pkg| (*pkg, None)).collect()
    };

    for (pkg, app_label) in display_data {
        let info_list = analyzer.get_info(&pkg.name);

        if let Some(infos) = info_list {
            total_displayed += 1;
            for info in infos {
                *stats.entry(info.status.clone()).or_insert(0) += 1;
            }
        }

        if args.verbose {
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
        }
    }

    UI::print_summary(total_displayed, &stats, args.r#type);

    if args.verbose && !Package::is_aapt_available() {
        println!();
        eprintln!(
            "{}",
            "Warning: 'aapt' is not installed. Some application labels might be missing.".yellow().bold()
        );
        eprintln!(
            "{}",
            "Install it via 'pkg install aapt' for the best experience.".yellow().bold()
        );
    }

    Ok(())
}