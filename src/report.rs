//! Self-contained offline HTML reports for native Samurai recordings.

use crate::smr::{FileActivity, RankedCount, SmrAnalysis, SmrProcess};
use std::{
    fmt::Write as _,
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
};

#[derive(Debug, Default)]
pub struct Selection {
    pub pids: Vec<u32>,
    pub processes: Vec<String>,
    pub excluded_processes: Vec<String>,
}

pub fn write_html(
    recording: &Path,
    output: &Path,
    top: usize,
    selection: &Selection,
) -> io::Result<()> {
    let summary = crate::smr::inspect(recording)?;
    let mut included = selection.pids.clone();
    for name in &selection.processes {
        let before = included.len();
        included.extend(
            summary
                .processes
                .iter()
                .filter(|process| process.name() == *name)
                .map(|process| process.pid),
        );
        if included.len() == before {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("recording contains no process named {name:?}"),
            ));
        }
    }
    let mut excluded = Vec::new();
    for name in &selection.excluded_processes {
        excluded.extend(
            summary
                .processes
                .iter()
                .filter(|process| process.name() == *name)
                .map(|process| process.pid),
        );
    }
    included.sort_unstable();
    included.dedup();
    excluded.sort_unstable();
    excluded.dedup();
    let included = (!included.is_empty()).then_some(included.as_slice());
    let analysis = crate::smr::analyze_filtered(recording, included, &excluded)?;
    let html = render_html(recording, &analysis, top, selection);
    let mut file = BufWriter::new(File::create(output)?);
    file.write_all(html.as_bytes())?;
    file.flush()
}

fn render_html(
    recording: &Path,
    analysis: &SmrAnalysis,
    top: usize,
    selection: &Selection,
) -> String {
    let summary = &analysis.summary;
    let duration_ns = analysis
        .first_timestamp_ns
        .zip(analysis.last_timestamp_ns)
        .map_or(0, |(first, last)| last.saturating_sub(first));
    let rate = if duration_ns == 0 {
        0.0
    } else {
        analysis.matched_received as f64 * 1_000_000_000.0 / duration_ns as f64
    };
    let mut html = String::with_capacity(32 * 1024);
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>Samurai trace report</title><style>");
    html.push_str(STYLE);
    html.push_str(".conclusion{font:600 18px/1.55 system-ui,sans-serif;max-width:900px;margin:0 0 18px}.technical{margin-top:16px}.technical>summary{cursor:pointer;color:var(--muted);padding:16px 4px;font-weight:700}.technical[open]>summary{color:var(--text)}");
    html.push_str("</style></head><body><main>");
    html.push_str("<header><div><p class=\"eyebrow\">SAMURAI TRACE REPORT</p><h1>");
    escape(
        &mut html,
        recording
            .file_name()
            .unwrap_or(recording.as_os_str())
            .to_string_lossy()
            .as_ref(),
    );
    html.push_str("</h1><p class=\"muted\">");
    escape(&mut html, &recording.display().to_string());
    html.push_str("</p></div><span class=\"badge ");
    if summary.dropped == 0 {
        html.push_str("good\">COMPLETE");
    } else {
        html.push_str("warn\">LOSS DETECTED");
    }
    html.push_str("</span></header>");

    if !selection.pids.is_empty()
        || !selection.processes.is_empty()
        || !selection.excluded_processes.is_empty()
    {
        html.push_str("<aside class=\"panel scope\"><strong>Report scope:</strong> ");
        if !selection.pids.is_empty() {
            let _ = write!(html, "PIDs {:?}. ", selection.pids);
        }
        if !selection.processes.is_empty() {
            html.push_str("Included processes ");
            escape(&mut html, &selection.processes.join(", "));
            html.push_str(". ");
        }
        if !selection.excluded_processes.is_empty() {
            html.push_str("Excluded processes ");
            escape(&mut html, &selection.excluded_processes.join(", "));
            html.push('.');
        }
        html.push_str("</aside>");
    }

    if summary.dropped != 0 {
        let _ = write!(
            html,
            "<aside class=\"warning\"><strong>Capture loss:</strong> {} records were overwritten before consumption. Rankings and totals may be incomplete.</aside>",
            summary.dropped
        );
    }
    html.push_str("<section class=\"metrics\">");
    if let Some(files) = &analysis.file_activity {
        metric(
            &mut html,
            "File operations",
            &commas(file_operation_count(files)),
            "completed calls",
        );
    } else {
        metric(
            &mut html,
            "Selected events",
            &commas(analysis.matched_received),
            "trace records",
        );
        metric(
            &mut html,
            "Trace event rate",
            &format_rate(rate),
            "records/s",
        );
    }
    metric(
        &mut html,
        "Dropped",
        &commas(summary.dropped),
        "whole capture",
    );
    metric(
        &mut html,
        "Event span",
        &format_duration(duration_ns),
        "elapsed",
    );
    metric(
        &mut html,
        "Recording",
        &format_bytes(summary.bytes),
        "whole capture",
    );
    metric(
        &mut html,
        "Active processes",
        &commas(analysis.active_pids.len() as u64),
        "with selected events",
    );
    html.push_str("</section>");

    if let Some(files) = &analysis.file_activity {
        behavior_summary(&mut html, files);
    }

    html.push_str("<details class=\"technical\"><summary>Technical details</summary>");

    section_start(
        &mut html,
        "Events",
        "Captured tracepoints and their exact record counts",
    );
    bars(
        &mut html,
        analysis
            .event_counts
            .iter()
            .map(|(name, count)| (name.as_str(), *count)),
        top,
    );
    section_end(&mut html);

    section_start(
        &mut html,
        "Event rate over time",
        "Sixty equal intervals across the completed recording",
    );
    timeline(&mut html, &analysis.timeline_counts);
    section_end(&mut html);

    section_start(
        &mut html,
        "CPU distribution",
        "Where the kernel executed captured events",
    );
    let cpu_labels = analysis
        .cpu_counts
        .iter()
        .map(|(cpu, count)| (format!("CPU {cpu}"), *count))
        .collect::<Vec<_>>();
    bars(
        &mut html,
        cpu_labels
            .iter()
            .map(|(name, count)| (name.as_str(), *count)),
        top,
    );
    section_end(&mut html);

    section_start(
        &mut html,
        "Busy processes",
        "Bounded heavy-hitter estimates from the recording",
    );
    ranked_table(&mut html, &analysis.pid_counts, top);
    section_end(&mut html);

    if let Some(files) = &analysis.file_activity {
        section_start(
            &mut html,
            "File activity",
            "Completed reads and writes, ranked by total transferred bytes",
        );
        file_table(&mut html, files, top);
        section_end(&mut html);
    }

    section_start(
        &mut html,
        "Process tree",
        "Recorded parent and child relationships",
    );
    process_table(&mut html, &summary.processes, &analysis.active_pids, top);
    section_end(&mut html);

    if !analysis.fields.is_empty() {
        section_start(
            &mut html,
            "Frequent field values",
            "Bounded heavy-hitter estimates for captured values",
        );
        for field in analysis
            .fields
            .iter()
            .filter(|field| !field.values.is_empty())
            .take(top)
        {
            html.push_str("<details><summary>");
            escape(&mut html, &field.name);
            html.push_str("</summary>");
            ranked_table(&mut html, &field.values, top.min(10));
            html.push_str("</details>");
        }
        section_end(&mut html);
    }

    html.push_str("</details>");

    html.push_str("<footer><span>Native SMR v");
    let _ = write!(html, "{}", summary.version);
    html.push_str("</span><span>Generated by Samurai</span></footer></main></body></html>");
    html
}

fn metric(html: &mut String, label: &str, value: &str, unit: &str) {
    html.push_str("<article class=\"metric\"><span>");
    escape(html, label);
    html.push_str("</span><strong>");
    escape(html, value);
    html.push_str("</strong><small>");
    escape(html, unit);
    html.push_str("</small></article>");
}

fn section_start(html: &mut String, title: &str, subtitle: &str) {
    html.push_str("<section class=\"panel\"><div class=\"section-title\"><div><h2>");
    escape(html, title);
    html.push_str("</h2><p>");
    escape(html, subtitle);
    html.push_str("</p></div></div>");
}

fn section_end(html: &mut String) {
    html.push_str("</section>");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilePurpose {
    Runtime,
    Environment,
    Output,
    Application,
}

fn file_purpose(path: &str) -> FilePurpose {
    if path.starts_with("<PID ") && !path.contains(">/") {
        FilePurpose::Output
    } else if path.starts_with("/proc/") || path.starts_with("/sys/") || path.starts_with("/dev/") {
        FilePurpose::Environment
    } else if path == "/etc/ld.so.cache"
        || path.contains("/.rustup/toolchains/")
        || path.ends_with(".so")
        || path.contains(".so.")
    {
        FilePurpose::Runtime
    } else {
        FilePurpose::Application
    }
}

fn behavior_summary(html: &mut String, files: &[FileActivity]) {
    let operations = file_operation_count(files);
    let mut read_bytes = 0u64;
    let mut written_bytes = 0u64;
    let mut output_bytes = 0u64;
    let mut runtime_paths = 0u64;
    let mut environment_paths = 0u64;
    let mut application_paths = 0u64;
    let mut failed_probes = 0u64;
    let mut other_failures = 0u64;
    for file in files {
        read_bytes = read_bytes.saturating_add(file.read_completed);
        written_bytes = written_bytes.saturating_add(file.write_completed);
        let purpose = file_purpose(&file.path);
        let accessed = file.opens != 0
            || file.reads != 0
            || file.writes != 0
            || file.mappings != 0
            || file.renames != 0
            || file.unlinks != 0
            || file.directories_created != 0;
        match purpose {
            FilePurpose::Runtime => runtime_paths += u64::from(accessed),
            FilePurpose::Environment => environment_paths += u64::from(accessed),
            FilePurpose::Output => output_bytes = output_bytes.saturating_add(file.write_completed),
            FilePurpose::Application => application_paths += u64::from(accessed),
        }
        if file.opens == 0
            && file.open_attempts != 0
            && file.reads == 0
            && file.writes == 0
            && file.close_attempts == 0
        {
            failed_probes = failed_probes.saturating_add(file.errors);
        } else {
            other_failures = other_failures.saturating_add(file.errors);
        }
    }

    section_start(
        html,
        "Application behavior",
        "Interpreted from completed file operations for the selected processes",
    );
    html.push_str("<p class=\"conclusion\">");
    if application_paths == 0 {
        html.push_str("The selected application loaded its runtime, inspected the Linux environment, accessed no application data files, and ");
    } else {
        let _ = write!(
            html,
            "The selected application loaded its runtime, inspected the Linux environment, accessed {application_paths} application data files, and "
        );
    }
    if output_bytes == 0 {
        html.push_str("produced no captured standard output.");
    } else {
        let _ = write!(
            html,
            "wrote {} to inherited output descriptors.",
            format_bytes(output_bytes)
        );
    }
    html.push_str("</p>");
    html.push_str("<div class=\"behavior\">");
    behavior_fact(
        html,
        "File operations",
        &commas(operations),
        "Correlated file and descriptor operations.",
    );
    behavior_fact(
        html,
        "Runtime startup",
        &format!("{runtime_paths} files"),
        "Runtime libraries and loader metadata successfully opened.",
    );
    behavior_fact(
        html,
        "Environment inspection",
        &format!("{environment_paths} files"),
        "Kernel, process, device, and resource-limit information.",
    );
    behavior_fact(
        html,
        "Application data",
        &format!("{application_paths} files"),
        if application_paths == 0 {
            "No application data files were observed."
        } else {
            "Files outside runtime startup and environment inspection."
        },
    );
    behavior_fact(
        html,
        "Data transferred",
        &format!(
            "{} read / {} written",
            format_bytes(read_bytes),
            format_bytes(written_bytes)
        ),
        &format!(
            "{} of writes went to inherited descriptors such as stdout or stderr.",
            format_bytes(output_bytes)
        ),
    );
    behavior_fact(
        html,
        "I/O failures",
        &commas(other_failures),
        &format!(
            "{failed_probes} unavailable paths were probed separately; those misses are not I/O failures."
        ),
    );
    html.push_str("</div>");
    section_end(html);
}

fn file_operation_count(files: &[FileActivity]) -> u64 {
    files.iter().fold(0u64, |total, file| {
        total.saturating_add(
            file.open_attempts
                .saturating_add(file.close_attempts)
                .saturating_add(file.reads)
                .saturating_add(file.writes)
                .saturating_add(file.descriptor_copies)
                .saturating_add(file.syncs)
                .saturating_add(file.mappings)
                .saturating_add(file.unmaps)
                .saturating_add(file.exec_releases)
                .saturating_add(file.renames)
                .saturating_add(file.unlinks)
                .saturating_add(file.directories_created),
        )
    })
}

fn behavior_fact(html: &mut String, label: &str, value: &str, explanation: &str) {
    html.push_str("<article class=\"fact\"><span>");
    escape(html, label);
    html.push_str("</span><strong>");
    escape(html, value);
    html.push_str("</strong><p>");
    escape(html, explanation);
    html.push_str("</p></article>");
}

fn timeline(html: &mut String, counts: &[u64]) {
    let maximum = counts.iter().copied().max().unwrap_or(1).max(1);
    html.push_str("<div class=\"timeline\" role=\"img\" aria-label=\"Event counts over time\">");
    for count in counts {
        let height = count.saturating_mul(100) / maximum;
        let _ = write!(
            html,
            "<i style=\"height:{height}%\" title=\"{} events\"></i>",
            commas(*count)
        );
    }
    html.push_str("</div><div class=\"timeline-axis\"><span>start</span><span>end</span></div>");
}

fn bars<'a>(html: &mut String, values: impl Iterator<Item = (&'a str, u64)>, top: usize) {
    let values = values.take(top).collect::<Vec<_>>();
    let maximum = values
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    html.push_str("<div class=\"bars\">");
    for (name, count) in values {
        let width = count.saturating_mul(100) / maximum;
        html.push_str("<div class=\"bar-row\"><span class=\"label\">");
        escape(html, name);
        let _ = write!(
            html,
            "</span><div class=\"track\"><i style=\"width:{width}%\"></i></div><b>{}</b></div>",
            commas(count)
        );
    }
    html.push_str("</div>");
}

fn ranked_table(html: &mut String, values: &[RankedCount], top: usize) {
    html.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Value</th><th>Count</th><th>Maximum error</th></tr></thead><tbody>");
    for value in values.iter().take(top) {
        html.push_str("<tr><td>");
        escape(html, &value.value);
        let _ = write!(
            html,
            "</td><td>{}</td><td>{}</td></tr>",
            commas(value.count),
            commas(value.error)
        );
    }
    html.push_str("</tbody></table></div>");
}

fn file_table(html: &mut String, files: &[FileActivity], top: usize) {
    let mut files = files.iter().collect::<Vec<_>>();
    files.sort_unstable_by(|left, right| {
        right
            .read_completed
            .saturating_add(right.write_completed)
            .cmp(&left.read_completed.saturating_add(left.write_completed))
            .then_with(|| left.path.cmp(&right.path))
    });
    html.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Path</th><th>Opens</th><th>Read</th><th>Written</th><th>Mapped total</th><th>Unmapped</th><th>Released by exec</th><th>Still tracked</th><th>Other operations</th><th>Errors</th></tr></thead><tbody>");
    for file in files.into_iter().take(top) {
        html.push_str("<tr><td class=\"path\">");
        escape(html, &file.path);
        let _ = write!(
            html,
            "</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            commas(file.opens),
            format_bytes(file.read_completed),
            format_bytes(file.write_completed),
            format_bytes(file.mapped_bytes),
            format_bytes(file.unmapped_bytes),
            format_bytes(file.exec_released_bytes),
            format_bytes(file.tracked_mapped_bytes),
            commas(
                file.descriptor_copies
                    .saturating_add(file.syncs)
                    .saturating_add(file.renames)
                    .saturating_add(file.unlinks)
                    .saturating_add(file.directories_created)
            ),
            commas(file.errors)
        );
    }
    html.push_str("</tbody></table></div>");
}

fn process_table(html: &mut String, processes: &[SmrProcess], active_pids: &[u32], top: usize) {
    html.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Process</th><th>PID</th><th>Parent PID</th></tr></thead><tbody>");
    for process in processes
        .iter()
        .filter(|process| active_pids.binary_search(&process.pid).is_ok())
        .take(top)
    {
        let depth = process_depth(process, processes);
        let _ = write!(html, "<tr><td style=\"padding-left:{}rem\">", 1 + depth);
        escape(html, &process.name());
        let _ = write!(
            html,
            "</td><td>{}</td><td>{}</td></tr>",
            process.pid, process.parent_pid
        );
    }
    html.push_str("</tbody></table></div>");
}

fn process_depth(process: &SmrProcess, processes: &[SmrProcess]) -> usize {
    let mut depth = 0usize;
    let mut parent = process.parent_pid;
    while parent != 0 && depth < processes.len().min(8) {
        let Ok(index) = processes.binary_search_by_key(&parent, |candidate| candidate.pid) else {
            break;
        };
        depth += 1;
        parent = processes[index].parent_pid;
    }
    depth
}

fn escape(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

fn commas(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, byte) in digits.bytes().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(byte));
    }
    output
}

fn format_rate(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else {
        format!("{value:.0}")
    }
}

fn format_duration(ns: u64) -> String {
    let seconds = ns as f64 / 1_000_000_000.0;
    if seconds >= 60.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{seconds:.2}s")
    } else {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < UNITS.len() {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

const STYLE: &str = r#"
:root{color-scheme:dark;--bg:#090c10;--panel:#11161d;--line:#25303c;--text:#e8edf2;--muted:#8c9baa;--red:#ff4d43;--amber:#ffbd2e;--green:#2ed68f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#281315 0,transparent 32rem),var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}main{width:min(1180px,calc(100% - 32px));margin:auto;padding:48px 0}header{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:28px}h1{font:700 clamp(26px,5vw,52px)/1.05 system-ui,sans-serif;margin:4px 0 8px;overflow-wrap:anywhere}h2{font:650 20px/1.2 system-ui,sans-serif;margin:0}.eyebrow{color:var(--red);font-weight:800;letter-spacing:.16em;margin:0}.muted,.section-title p{color:var(--muted);margin:4px 0}.badge{border:1px solid;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:800;white-space:nowrap}.good{color:var(--green);background:#0d2b21}.warn{color:var(--amber);background:#31250c}.warning{background:#2b1e0b;border:1px solid #6b4a10;border-radius:8px;padding:14px 16px;margin-bottom:20px}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px}.metric,.panel{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:10px}.metric{padding:16px}.metric span,.metric small,.fact span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.metric strong{display:block;font:700 24px/1.2 system-ui,sans-serif;margin:10px 0 4px}.panel{padding:20px;margin:12px 0}.section-title{display:flex;justify-content:space-between;margin-bottom:18px}.behavior{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.fact{background:#0c1117;border:1px solid var(--line);border-radius:8px;padding:14px}.fact strong{display:block;font:700 18px/1.2 system-ui,sans-serif;margin:8px 0}.fact p{color:var(--muted);margin:0}.bars{display:grid;gap:10px}.bar-row{display:grid;grid-template-columns:minmax(120px,2fr) 5fr 90px;align-items:center;gap:12px}.label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.track{height:8px;background:#222b34;border-radius:9px;overflow:hidden}.track i{display:block;height:100%;min-width:2px;background:linear-gradient(90deg,var(--red),#ff796f)}.bar-row b{text-align:right}.timeline{height:180px;display:flex;align-items:flex-end;gap:2px;border-bottom:1px solid var(--line);padding-top:12px}.timeline i{flex:1;min-height:1px;background:linear-gradient(180deg,#ff796f,var(--red));border-radius:2px 2px 0 0}.timeline-axis{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin-top:6px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:right;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}th:first-child,td:first-child{text-align:left}.path{max-width:560px;overflow-wrap:anywhere}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:700}details table{margin-top:10px}footer{display:flex;justify-content:space-between;color:var(--muted);padding:22px 4px}@media(max-width:900px){.metrics,.behavior{grid-template-columns:repeat(3,1fr)}}@media(max-width:600px){main{width:min(100% - 20px,1180px);padding-top:24px}.metrics,.behavior{grid-template-columns:repeat(2,1fr)}header{display:block}.badge{display:inline-block;margin-top:12px}.bar-row{grid-template-columns:100px 1fr 70px}.panel{padding:14px}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_untrusted_recording_text() {
        let mut output = String::new();
        escape(&mut output, "<script>&\"'");
        assert_eq!(output, "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn formats_human_values() {
        assert_eq!(commas(1_234_567), "1,234,567");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_duration(1_500_000_000), "1.50s");
    }

    #[test]
    fn classifies_file_behavior() {
        assert_eq!(file_purpose("/lib64/libc.so.6"), FilePurpose::Runtime);
        assert_eq!(file_purpose("/proc/self/maps"), FilePurpose::Environment);
        assert_eq!(file_purpose("<PID 7 FD 1>"), FilePurpose::Output);
        assert_eq!(file_purpose("data/orders.db"), FilePurpose::Application);
    }
}
