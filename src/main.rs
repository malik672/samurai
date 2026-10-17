use clap::{Parser, Subcommand};
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
            println!("event={}:{}", summary.category, summary.event);
            println!("cpus={:?}", summary.cpus);
            println!("fields={}", summary.fields.join(","));
            println!("words={}", summary.words);
            println!("received={}", summary.received);
            println!("dropped={}", summary.dropped);
            println!("bytes={}", summary.bytes);
        }),
        Command::Analyze { recording } => samurai::smr::analyze(&recording).map(|analysis| {
            println!("recording={}", recording.display());
            println!(
                "event={}:{}",
                analysis.summary.category, analysis.summary.event
            );
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
            println!("file_order_timestamp_regressions={}", analysis.out_of_order);
            println!("cpu_counts:");
            for (cpu, count) in analysis.cpu_counts {
                println!("  {cpu}: {count}");
            }
            print_ranked("pid_counts", &analysis.pid_counts);
            for field in analysis.fields {
                print_ranked(&format!("field.{}", field.name), &field.values);
            }
        }),
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
