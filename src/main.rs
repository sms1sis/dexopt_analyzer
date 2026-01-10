use clap::{Parser, ValueEnum};
use regex::Regex;
use std::collections::{HashMap, BTreeMap};
use std::process::Command;
use std::io::{self, Write};
use std::fmt;
use colored::*; 

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
enum AppType { User, System, All }

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
    println!("{} {} ({}) ...", prefix, "Fetching package list".bold(), args.r#type);
    let packages = get_packages(args.r#type)?;
    println!("{} Found {} packages.", prefix, packages.len().to_string().green().bold());
    let dump = get_dexopt_dump()?;
    let results = parse_dump(&dump);
    
    if !args.verbose {
        println!("\n{} | {}\n", format!("{:<45}", "Package").bold().underline(), format!("{:<30}", "DexOpt Status").bold().underline());
    }

    let mut stdout = io::stdout();
    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_displayed = 0;
    
    for pkg in &packages {
        if let Some(ref f) = args.filter { if !pkg.contains(f) { continue; } } 
        
        let info_opt = results.get(pkg);
        
        if let Some(info_list) = info_opt {
            total_displayed += 1;
            for info in info_list {
                *stats.entry(info.status.clone()).or_insert(0) += 1;
            }
        } 
        
        if args.verbose {
            print_block_entry(&mut stdout, pkg, info_opt)?;
        } else if let Some(info_list) = info_opt {
            for (i, info) in info_list.iter().enumerate() {
                let colored_raw = colorize_line(&info.raw_line, &info.status);
                if i == 0 { writeln!(stdout, "{} | {}", format!("{:<45}", pkg).bright_white(), colored_raw)?; } 
                else { writeln!(stdout, "{:<45} | {}", "", colored_raw)?; }
            }
            writeln!(stdout)?;
        }
    }
    print_summary(total_displayed, &stats, args.r#type);
    Ok(())
}

fn print_block_entry(stdout: &mut io::Stdout, pkg: &str, info_opt: Option<&Vec<DexOptInfo>>) -> io::Result<()> {
    let width = 60;
    let border = "─".repeat(width);
    writeln!(stdout, "{}", format!("┌{}┐", border).cyan())?;
    
    let pkg_display = if pkg.len() > width - 2 { &pkg[..width-2] } else { pkg };
    writeln!(stdout, "{} {:<w$} {}", "│".cyan(), pkg_display.bold().bright_white(), "│".cyan(), w = width - 1)?;
    
    writeln!(stdout, "{}", format!("└{}┘", border).cyan())?;
    
    if let Some(info_list) = info_opt {
        for info in info_list {
            writeln!(stdout, "  {}", colorize_line(&info.raw_line, &info.status))?;
        }
    } else {
         writeln!(stdout, "  {}", "(no info found)".italic().red())?;
    }
    writeln!(stdout)?;
    Ok(())
}

fn colorize_line(line: &str, status: &str) -> String {
    match status {
        "speed-profile" => line.green().to_string(),
        "speed" => line.bright_green().to_string(),
        "verify" => line.yellow().to_string(),
        "quicken" => line.blue().to_string(),
        "run-from-apk" => line.red().to_string(),
        "everything" => line.magenta().to_string(),
        _ => line.white().to_string(),
    }
}

fn get_packages(app_type: AppType) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new("sh").arg("-c").arg(match app_type {
        AppType::User => "pm list packages -3",
        AppType::System => "pm list packages -s",
        AppType::All => "pm list packages",
    }).output()?;
    let raw = String::from_utf8(output.stdout)?;
    let mut list = Vec::new();
    for line in raw.lines() { if let Some(p) = line.trim().strip_prefix("package:") { list.push(p.trim().to_string()); } }
    list.sort();
    Ok(list)
}

fn get_dexopt_dump() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("sh").arg("-c").arg("dumpsys package dexopt").output()?;
    Ok(String::from_utf8(output.stdout)?)
}

struct DexOptInfo { raw_line: String, status: String } 

fn parse_dump(dump: &str) -> HashMap<String, Vec<DexOptInfo>> {
    let mut results: HashMap<String, Vec<DexOptInfo>> = HashMap::new();
    let mut current_pkg: Option<String> = None;
    let status_re = Regex::new(r"(arm64:|arm:)").unwrap();
    let filter_extract_re = Regex::new(r"\^\[(?:status|filter)=([^\]]+)\^\]").unwrap();
    for line in dump.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.contains(' ') && !trimmed.contains('=') {
            current_pkg = Some(trimmed[1..trimmed.len()-1].to_string());
        } else if let Some(ref pkg) = current_pkg {
            if status_re.is_match(trimmed) {
                let status = filter_extract_re.captures(trimmed).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()).unwrap_or_else(|| "unknown".to_string());
                results.entry(pkg.clone()).or_default().push(DexOptInfo { raw_line: trimmed.to_string(), status });
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
    println!("{}{}{}{}", "║".color(b_blue), " ".repeat(p_s), title.bold().color(b_yellow), format!("{}{}", " ".repeat(p_e), "║").color(b_blue));
    let mid = format!("╠{}╣", "═".repeat(width));
    println!("{}", mid.color(b_blue));
    add_summary_line("App Scope", &app_type.to_string(), Color::Cyan, Color::Magenta, width);
    add_summary_line("Total Apps Checked", &total_apps.to_string(), Color::Cyan, Color::BrightGreen, width);
    println!("{}", mid.color(b_blue));
    let sub = "Profile Breakdown";
    let p_s = (width - sub.len()) / 2;
    let p_e = width - sub.len() - p_s;
    println!("{}{}{}{}", "║".color(b_blue), " ".repeat(p_s), sub.dimmed().bold(), format!("{}{}", " ".repeat(p_e), "║").color(b_blue));
    println!("{}", mid.color(b_blue));
    if stats.is_empty() {
        let msg = "No profile data found.";
        let padding = " ".repeat(width.saturating_sub(2 + msg.len()));
        println!("{}  {}{}{}", "║".color(b_blue), msg, padding, "║".color(b_blue));
    }
    else {
        for (profile, count) in stats {
            let color = match profile.as_str() {
                "speed-profile" => Color::Green, "speed" => Color::BrightGreen, "verify" => Color::Yellow,
                "quicken" => Color::Blue, "run-from-apk" => Color::Red, "everything" => Color::Magenta, _ => Color::White,
            };
            add_summary_line(profile, &count.to_string(), Color::Cyan, color, width);
        }
    }
    println!("{}", format!("╚{}╝", "═".repeat(width)).color(b_blue));
}

fn add_summary_line(label: &str, value: &str, l_col: Color, v_col: Color, width: usize) {
    let l_part = format!("{:<22}", label).bold().color(l_col);
    let v_part = value.bold().color(v_col);
    let padding = " ".repeat(width.saturating_sub(5 + 22 + value.len()));
    println!("{}  {} : {}{}{}", "║".color(Color::BrightBlue), l_part, v_part, padding, "║".color(Color::BrightBlue));
}