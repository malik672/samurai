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
        /// Stop after receiving this many records.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        /// Stop after this duration, for example `10s` or `2m`.
        #[arg(long, value_parser = parse_duration)]
        duration: Option<Duration>,
        /// Output records as text or JSON lines.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Override the embedded generic BPF object.
        #[arg(long)]
        object: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
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
        Command::Trace {
            event,
            fields,
            cpus,
            count,
            duration,
            format,
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
                count,
                duration,
                matches!(format, OutputFormat::Json),
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
