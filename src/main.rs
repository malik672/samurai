use clap::{Parser, Subcommand, ValueEnum};
use std::{path::PathBuf, process::ExitCode, time::Duration};

#[derive(Parser)]
#[command(
    name = "samurai",
    version,
    about = "Discover, inspect, validate, and record Linux tracepoints",
    arg_required_else_help = true
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FileSort {
    Total,
    Reads,
    Writes,
    Errors,
}

#[derive(Subcommand)]
enum Command {
    /// List tracepoints exposed by the running kernel.
    List {
        /// Limit discovery to one tracepoint category.
        category: Option<String>,
    },
    /// Show the kernel layout and Samurai capture interpretation.
    Inspect {
        /// Event in category:event form.
        event: String,
        /// Optional comma-separated event fields.
        #[arg(long)]
        fields: Option<String>,
    },
    /// Build and validate a capture plan without attaching BPF.
    Validate {
        /// Event in category:event form.
        event: String,
        /// Optional comma-separated event fields.
        #[arg(long)]
        fields: Option<String>,
    },
    /// Validate and summarize a completed .smr recording.
    Report {
        /// Recording produced by `samurai trace --output`.
        recording: PathBuf,
    },
    /// Stream a completed .smr recording and rank its busiest CPUs, PIDs, and field values.
    Analyze {
        /// Recording produced by `samurai trace --output`.
        recording: PathBuf,
        /// Maximum files to show in a preset-aware report.
        #[arg(long, default_value_t = 20, value_parser = parse_positive_usize)]
        top: usize,
        /// Include low-level CPU, PID, event, and field rankings.
        #[arg(long)]
        raw: bool,
        /// Include only paths beginning with this prefix.
        #[arg(long)]
        path: Option<String>,
        /// Include only files with attempted writes.
        #[arg(long)]
        writes_only: bool,
        /// Include only files with failed operations.
        #[arg(long)]
        errors_only: bool,
        /// Minimum completed I/O, for example 4096, 4KiB, or 2MiB.
        #[arg(long, value_parser = parse_byte_size)]
        min_bytes: Option<u64>,
        /// Ranking used for the file report.
        #[arg(long, value_enum, default_value_t = FileSort::Total)]
        sort: FileSort,
    },
    /// Record a useful group of related events.
    Record {
        /// Built-in event group. Currently supported: files.
        #[arg(long, value_parser = ["files"])]
        preset: String,
        /// CPUs to attach on, for example `0-3,5`; defaults to all online CPUs.
        #[arg(long)]
        cpus: Option<String>,
        /// Record this process and all descendants it creates.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        pid: Option<u32>,
        /// Launch this shell command after tracing is fully ready.
        #[arg(long, value_name = "SHELL_COMMAND", conflicts_with_all = ["pid", "count", "duration"])]
        command: Option<String>,
        /// Stop after receiving this many records.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        /// Stop after this duration, for example `10s` or `2m`.
        #[arg(long, value_parser = parse_duration)]
        duration: Option<Duration>,
        /// Binary .smr recording to create.
        #[arg(long)]
        output: PathBuf,
    },
    /// Record a tracepoint using its discovered capture plan.
    Trace {
        /// Event in category:event form.
        event: String,
        /// Optional comma-separated event fields; defaults to all event fields.
        #[arg(long)]
        fields: Option<String>,
        /// CPUs to attach on, for example `0-3,5`; defaults to all online CPUs.
        #[arg(long)]
        cpus: Option<String>,
        /// Record this process and all descendants it creates.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        pid: Option<u32>,
        /// Launch this shell command after tracing is fully ready.
        #[arg(long, value_name = "SHELL_COMMAND", conflicts_with_all = ["pid", "count", "duration"])]
        command: Option<String>,
        /// Stop after receiving this many records.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        /// Stop after this duration, for example `10s` or `2m`.
        #[arg(long, value_parser = parse_duration)]
        duration: Option<Duration>,
        /// Binary .smr recording to create.
        #[arg(long)]
        output: PathBuf,
        /// Override the embedded generic BPF object.
        #[arg(long)]
        object: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = match args.command {
        Command::List { category } => samurai::cli::run_list(category.as_deref()),
        Command::Inspect { event, fields } => split_event(&event).and_then(|(category, event)| {
            let fields = fields
                .as_deref()
                .map(samurai::cli::parse_fields)
                .transpose()?;
            samurai::cli::run_inspect(&category, &event, fields.as_deref())
        }),
        Command::Validate { event, fields } => split_event(&event).and_then(|(category, event)| {
            let fields = fields
                .as_deref()
                .map(samurai::cli::parse_fields)
                .transpose()?;
            samurai::cli::run_validate(&category, &event, fields.as_deref())
        }),
        Command::Report { recording } => samurai::smr::inspect(&recording).map(|summary| {
            println!("recording={}", recording.display());
            println!("version={}", summary.version);
            println!("events={}", summary.events.len());
            for event in &summary.events {
                println!(
                    "event={}:{} fields={}",
                    event.category,
                    event.event,
                    event
                        .fields
                        .iter()
                        .map(|field| field.name.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            println!("cpus={:?}", summary.cpus);
            println!("received={}", summary.received);
            println!("dropped={}", summary.dropped);
            println!("processes={}", summary.processes.len());
            println!("bytes={}", summary.bytes);
        }),
        Command::Analyze {
            recording,
            top,
            raw,
            path,
            writes_only,
            errors_only,
            min_bytes,
            sort,
        } => samurai::smr::analyze(&recording).map(|analysis| {
            println!("recording={}", recording.display());
            println!("events={}", analysis.summary.events.len());
            println!("received={}", analysis.summary.received);
            println!("dropped={}", analysis.summary.dropped);
            if let (Some(first), Some(last)) =
                (analysis.first_timestamp_ns, analysis.last_timestamp_ns)
            {
                let duration_ns = last.saturating_sub(first);
                println!("event_span_ns={duration_ns}");
                if duration_ns != 0 {
                    let rate =
                        analysis.summary.received as f64 * 1_000_000_000.0 / duration_ns as f64;
                    println!("event_rate_per_second={rate:.2}");
                }
            }
            if analysis.file_activity.is_none() || raw {
                print_process_tree(&analysis.summary.processes);
            }
            if let Some(files) = &analysis.file_activity {
                let mut files = files
                    .iter()
                    .filter(|file| path.as_ref().is_none_or(|prefix| file.path.starts_with(prefix)))
                    .filter(|file| !writes_only || file.write_requested != 0)
                    .filter(|file| !errors_only || file.errors != 0)
                    .filter(|file| {
                        min_bytes.is_none_or(|minimum| {
                            file.read_completed.saturating_add(file.write_completed) >= minimum
                        })
                    })
                    .collect::<Vec<_>>();
                files.sort_unstable_by(|left, right| {
                    let value = |file: &samurai::smr::FileActivity| match sort {
                        FileSort::Total => file.read_completed.saturating_add(file.write_completed),
                        FileSort::Reads => file.read_completed,
                        FileSort::Writes => file.write_completed,
                        FileSort::Errors => file.errors,
                    };
                    value(right)
                        .cmp(&value(left))
                        .then_with(|| left.path.cmp(&right.path))
                });
                println!("file_activity:");
                if files.is_empty() {
                    println!("  no files matched the requested filters");
                }
                for file in files.iter().take(top) {
                    println!(
                        "  {:?}: opens={} closes={} read={}/{} requested write={}/{} requested errors={}",
                        file.path,
                        file.opens,
                        file.closes,
                        format_bytes(file.read_completed),
                        format_bytes(file.read_requested),
                        format_bytes(file.write_completed),
                        format_bytes(file.write_requested),
                        file.errors
                    );
                }
                if files.len() > top {
                    println!("  ... {} more files; increase --top to show them", files.len() - top);
                }
            }
            if analysis.file_activity.is_none() || raw {
                println!("file_order_timestamp_regressions={}", analysis.out_of_order);
                println!("cpu_counts:");
                for (cpu, count) in &analysis.cpu_counts {
                    println!("  {cpu}: {count}");
                }
                println!("event_counts:");
                for (event, count) in &analysis.event_counts {
                    println!("  {event}: {count}");
                }
                print_ranked("pid_counts", &analysis.pid_counts);
                for field in &analysis.fields {
                    print_ranked(&format!("field.{}", field.name), &field.values);
                }
            }
        }),
        Command::Record {
            preset,
            cpus,
            pid,
            command,
            count,
            duration,
            output,
        } => match preset.as_str() {
            "files" => samurai::cli::run_files_preset(
                cpus.as_deref(),
                pid,
                command.as_deref(),
                count,
                duration,
                &output,
            ),
            _ => unreachable!("clap validates preset names"),
        },
        Command::Trace {
            event,
            fields,
            cpus,
            pid,
            command,
            count,
            duration,
            output,
            object,
        } => split_event(&event).and_then(|(category, event)| {
            let fields = fields
                .as_deref()
                .map(samurai::cli::parse_fields)
                .transpose()?;
            samurai::cli::run_trace(
                &category,
                &event,
                fields.as_deref(),
                cpus.as_deref(),
                pid,
                command.as_deref(),
                count,
                duration,
                &output,
                object.as_deref(),
            )
        }),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("samurai: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_process_tree(processes: &[samurai::smr::SmrProcess]) {
    if processes.is_empty() {
        return;
    }
    println!("process_tree:");
    for process in processes {
        let mut depth = 0usize;
        let mut parent = process.parent_pid;
        while parent != 0 && depth < processes.len() {
            let Ok(index) = processes.binary_search_by_key(&parent, |candidate| candidate.pid)
            else {
                break;
            };
            depth += 1;
            parent = processes[index].parent_pid;
        }
        println!(
            "  {}{} (PID {}, parent {})",
            "  ".repeat(depth),
            process.name(),
            process.pid,
            process.parent_pid
        );
    }
}

fn print_ranked(name: &str, values: &[samurai::smr::RankedCount]) {
    println!("{name}:");
    for value in values {
        if value.error == 0 {
            println!("  {:?}: {}", value.value, value.count);
        } else {
            println!(
                "  {:?}: <= {} (bounded estimate, error <= {})",
                value.value, value.count, value.error
            );
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0usize;
    let mut divisor = 1u64;
    while unit + 1 < UNITS.len() && bytes >= divisor.saturating_mul(1024) {
        divisor *= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{:.1} {}", bytes as f64 / divisor as f64, UNITS[unit])
    }
}

fn split_event(event: &str) -> std::io::Result<(String, String)> {
    let Some((category, name)) = event.split_once(':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "event must use category:event form",
        ));
    };
    if category.is_empty() || name.is_empty() || name.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "event must use category:event form",
        ));
    }
    Ok((category.to_owned(), name.to_owned()))
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3600),
        _ => (value, 1),
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| "duration must be an integer followed by s, m, or h".to_owned())?;
    if number == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    number
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| "duration is too large".to_owned())
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "value must be a positive integer".to_owned())?;
    if value == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(value)
}

fn parse_byte_size(value: &str) -> Result<u64, String> {
    let (number, multiplier) = [
        ("TiB", 1u64 << 40),
        ("GiB", 1u64 << 30),
        ("MiB", 1u64 << 20),
        ("KiB", 1u64 << 10),
        ("B", 1),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        value
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
    .unwrap_or((value, 1));
    if number.is_empty() {
        return Err("byte size must include an integer".to_owned());
    }
    number
        .parse::<u64>()
        .map_err(|_| {
            "byte size must be an integer followed by B, KiB, MiB, GiB, or TiB".to_owned()
        })?
        .checked_mul(multiplier)
        .ok_or_else(|| "byte size is too large".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_byte_thresholds() {
        assert_eq!(parse_byte_size("4096").unwrap(), 4096);
        assert_eq!(parse_byte_size("4KiB").unwrap(), 4096);
        assert_eq!(parse_byte_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert!(parse_byte_size("1MB").is_err());
        assert!(parse_byte_size("MiB").is_err());
    }
}
