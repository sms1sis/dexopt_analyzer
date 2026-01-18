use clap::{Parser, ValueEnum};
use colored::*;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    filter: Option<String>,
    #[arg(short, long, value_enum, default_value_t = AppType::User)]
    r#type: AppType,
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
        match self {
            AppType::User => write!(f, "User"),
            AppType::System => write!(f, "System"),
            AppType::All => write!(f, "All"),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let prefix = "[-]".cyan();
    println!(
        "{} {} ({}) ...",
        prefix,
        "Fetching package list".bold(),
        args.r#type
    );
    let packages = get_packages(args.r#type)?;
    println!(
        "{} Found {} packages.",
        prefix,
        packages.len().to_string().green().bold()
    );
    println!(
        "{} {}",
        prefix,
        "Fetching dexopt dump...".bold()
    );
    let dump = get_dexopt_dump()?;
    let results = parse_dump(&dump);

    if !args.verbose {
        println!(
            "\n{} | {}\n",
            format!("{:<45}", "Package").bold().underline(),
            format!("{:<30}", "DexOpt Status").bold().underline()
        );
    }

    let mut stdout = io::stdout();
    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_displayed = 0;

    // Filter packages first
    let filtered_packages: Vec<&Package> = packages
        .iter()
        .filter(|pkg| {
            if let Some(ref f) = args.filter {
                pkg.name.contains(f)
            } else {
                true
            }
        })
        .collect();

    // Prepare data for printing.
    // If verbose, we fetch labels in parallel.
    // If not verbose, we just map with None labels.
    let display_data: Vec<(&Package, Option<String>)> = if args.verbose {
        filtered_packages
            .par_iter()
            .map(|pkg| {
                let label = get_app_label(&pkg.path, &pkg.name);
                (*pkg, label)
            })
            .collect()
    } else {
        filtered_packages.iter().map(|pkg| (*pkg, None)).collect()
    };

    for (pkg, app_label) in display_data {
        let info_opt = results.get(&pkg.name);

        if let Some(info_list) = info_opt {
            total_displayed += 1;
            for info in info_list {
                *stats.entry(info.status.clone()).or_insert(0) += 1;
            }
        }

        if args.verbose {
            print_block_entry(&mut stdout, pkg, app_label, info_opt)?;
        } else if let Some(info_list) = info_opt {
            for (i, info) in info_list.iter().enumerate() {
                let colored_raw = colorize_line(&info.raw_line, &info.status);
                if i == 0 {
                    writeln!(
                        stdout,
                        "{} | {}",
                        format!("{:<45}", pkg.name).bright_white(),
                        colored_raw
                    )?;
                } else {
                    writeln!(stdout, "{:<45} | {}", "", colored_raw)?;
                }
            }
            writeln!(stdout)?;
        }
    }

    print_summary(total_displayed, &stats, args.r#type);

    if args.verbose && !check_aapt_installed() {
        println!();
        eprintln!(
            "{}",
            "Warning: 'aapt' is not installed. Application labels were not displayed.".yellow().bold()
        );
        eprintln!(
            "{}",
            "Install it via 'pkg install aapt' for a better experience.".yellow().bold()
        );
    }

    Ok(())
}

fn print_block_entry(
    stdout: &mut io::Stdout,
    pkg: &Package,
    app_label: Option<String>,
    info_opt: Option<&Vec<DexOptInfo>>,
) -> io::Result<()> {
    let padding = 2;
    let min_width = 40;

    let display_name_str = if let Some(ref label) = app_label {
        format!("{} ({})", label, pkg.name)
    } else {
        pkg.name.clone()
    };

    let content_len = display_name_str.len() + (padding * 2);
    let width = if content_len > min_width {
        content_len
    } else {
        min_width
    };

    let border = "─".repeat(width);
    writeln!(stdout, "{}", format!("┌{}┐", border).cyan())?;

    let p_space = width - display_name_str.len();
    let p_l = p_space / 2;
    let p_r = p_space - p_l;

    // Construct the inner colored string manually to allow different colors for label vs package
    // App Name is highlighted in Cyan to stand out, distinct from status colors.
    let inner_content = if let Some(ref label) = app_label {
         format!(
            "{} ({})",
            label.bold().cyan(), 
            pkg.name.bold().bright_white()
        )
    } else {
        pkg.name.bold().bright_white().to_string()
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

    if let Some(info_list) = info_opt {
        let mut max_prefix_len = 0;
        for info in info_list {
            if let Some(idx) = info.raw_line.find(':') {
                if idx > max_prefix_len {
                    max_prefix_len = idx;
                }
            }
        }

        for info in info_list {
            let formatted_line = if let Some(idx) = info.raw_line.find(':') {
                let prefix = &info.raw_line[..idx];
                let rest = &info.raw_line[idx..];
                format!("{:width$}{}", prefix, rest, width = max_prefix_len)
            } else {
                info.raw_line.clone()
            };
            writeln!(stdout, "  {}", colorize_line(&formatted_line, &info.status))?;
        }
    } else {
        writeln!(stdout, "  {}", "(no info found)".italic().red())?;
    }
    writeln!(stdout)?;
    Ok(())
}

fn get_app_label(path: &str, _pkg_name: &str) -> Option<String> {
    // Primary method: aapt dump badging
    let output = Command::new("aapt")
        .arg("dump")
        .arg("badging")
        .arg(path)
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

fn get_status_color(status: &str) -> Color {
    match status {
        "speed-profile" => Color::Green,
        "speed" => Color::Green,
        "verify" => Color::Yellow,
        "quicken" => Color::Blue,
        "run-from-apk" => Color::Red,
        "error" => Color::Red,
        "everything" => Color::Magenta,
        _ => Color::White,
    }
}

fn colorize_line(line: &str, status: &str) -> String {
    let color = get_status_color(status);
    if status == "error" {
        line.color(color).bold().to_string()
    } else {
        line.color(color).to_string()
    }
}

#[derive(Debug, Clone)]
struct Package {
    name: String,
    path: String,
}

// Implement Sync for Package to allow parallel iteration (implied by default for String/String fields, but good to be aware of)
// Strings are Send + Sync, so Package is Send + Sync.

fn get_packages(app_type: AppType) -> Result<Vec<Package>, Box<dyn std::error::Error>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(match app_type {
            AppType::User => "pm list packages -f -3",
            AppType::System => "pm list packages -f -s",
            AppType::All => "pm list packages -f",
        })
        .output()?;
    let raw = String::from_utf8(output.stdout)?;
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

fn get_dexopt_dump() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("dumpsys package dexopt")
        .output()?;
    Ok(String::from_utf8(output.stdout)?)
}

struct DexOptInfo {
    raw_line: String,
    status: String,
}

fn parse_dump(dump: &str) -> HashMap<String, Vec<DexOptInfo>> {
    let mut results: HashMap<String, Vec<DexOptInfo>> = HashMap::new();
    let mut current_pkg: Option<String> = None;
    let status_re = Regex::new(r"(arm64:|arm:)").unwrap();
    let filter_extract_re = Regex::new(r"\b(?:status|filter)=([^\]\s]+)").unwrap();
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
            if status_re.is_match(trimmed) {
                let status = filter_extract_re
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
    results
}

fn print_summary(total_apps: usize, stats: &BTreeMap<String, usize>, app_type: AppType) {
    let width = 47;
    let b_blue = Color::BrightBlue;
    let b_yellow = Color::BrightYellow;
    println!("\n");
    println!("{}", format!("╔{}╗", "═".repeat(width)).color(b_blue));
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
    let mid = format!("╠{}╣", "═".repeat(width));
    println!("{}", mid.color(b_blue));
    add_summary_line(
        "App Scope",
        &app_type.to_string(),
        Color::Cyan,
        Color::Magenta,
        width,
    );
    add_summary_line(
        "Total Apps Checked",
        &total_apps.to_string(),
        Color::Cyan,
        Color::BrightGreen,
        width,
    );
    println!("{}", mid.color(b_blue));
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
    println!("{}", mid.color(b_blue));
    if stats.is_empty() {
        let msg = "No profile data found.";
        let padding = " ".repeat(width.saturating_sub(2 + msg.len()));
        println!(
            "{}  {}{}{}",
            "║".color(b_blue),
            msg,
            padding,
            "║".color(b_blue)
        );
    } else {
        for (profile, count) in stats {
            let color = get_status_color(profile);
            add_summary_line(profile, &count.to_string(), Color::Cyan, color, width);
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



fn check_aapt_installed() -> bool {

    Command::new("which")

        .arg("aapt")

        .output()

        .map(|output| output.status.success())

        .unwrap_or(false)

}


