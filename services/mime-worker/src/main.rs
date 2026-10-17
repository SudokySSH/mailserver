//! AETHER MAIL MIME-воркер (Rust).
//! Читает .eml (файл из аргументов или stdin), разбирает MIME через mail-parser,
//! извлекает метаданные и проверяет вложения. JSON на stdout, код 0 — чисто, 1 — опасно.
use std::io::Read;
use std::process::ExitCode;

use mail_parser::{MessageParser, MimeHeaders, PartType};

/// Расширения, которые не должны проходить через почту никогда.
const BLOCKED_EXT: [&str; 14] = [
    "exe", "scr", "js", "jar", "bat", "cmd", "com", "pif", "vbs", "ps1", "msi", "dll", "hta", "lnk",
];
/// Двойные расширения — классика обмана: invoice.pdf.exe.
const SUSPECT_EXT: [&str; 5] = ["pdf", "doc", "docx", "xls", "xlsx"];

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let bytes = match args.get(1) {
        Some(path) => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cannot read {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            let mut b = Vec::new();
            if std::io::stdin().read_to_end(&mut b).is_err() {
                eprintln!("cannot read stdin");
                return ExitCode::FAILURE;
            }
            b
        }
    };

    let max_bytes: usize = std::env::var("MIME_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25 * 1024 * 1024);
    if bytes.len() > max_bytes {
        println!(
            "{{\"ok\":false,\"error\":\"message too large: {} > {}\"}}",
            bytes.len(),
            max_bytes
        );
        return ExitCode::FAILURE;
    }

    let msg = match MessageParser::default().parse(&bytes) {
        Some(m) => m,
        None => {
            println!("{{\"ok\":false,\"error\":\"unparseable MIME\"}}");
            return ExitCode::FAILURE;
        }
    };

    let subject = msg.subject().unwrap_or("");
    let from = msg
        .from()
        .and_then(|a| a.first())
        .and_then(|ad| ad.address().map(str::to_string))
        .unwrap_or_default();

    let mut findings: Vec<String> = Vec::new();
    let mut attachment_names: Vec<String> = Vec::new();
    let mut attachment_bytes: usize = 0;

    for att in msg.attachments() {
        if let Some(name) = att.attachment_name() {
            attachment_names.push(name.clone());
            let lower = name.to_lowercase();
            for ext in BLOCKED_EXT {
                if lower.ends_with(&format!(".{ext}")) {
                    findings.push(format!("blocked extension: {name}"));
                }
            }
            // двойное расширение: реальный суффикс после известного «безопасного»
            let parts: Vec<&str> = lower.split('.').collect();
            if parts.len() >= 3 && SUSPECT_EXT.contains(&parts[parts.len() - 2]) {
                findings.push(format!("double-extension disguise: {name}"));
            }
        }
        attachment_bytes += match &att.body {
            PartType::Binary(b) => b.len(),
            _ => 0,
        };
    }

    let max_attach_total: usize = std::env::var("MIME_MAX_ATTACH_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50 * 1024 * 1024);
    if attachment_bytes > max_attach_total {
        findings.push(format!(
            "attachments total too large: {attachment_bytes} > {max_attach_total}"
        ));
    }

    let names_json: Vec<String> = attachment_names
        .iter()
        .map(|n| format!("\"{}\"", json_escape(n)))
        .collect();
    let findings_json: Vec<String> = findings
        .iter()
        .map(|f| format!("\"{}\"", json_escape(f)))
        .collect();

    println!(
        "{{\"ok\":{},\"subject\":\"{}\",\"from\":\"{}\",\"attachments\":{},\"attachment_bytes\":{},\"attachment_names\":[{}],\"findings\":[{}]}}",
        findings.is_empty(),
        json_escape(subject),
        json_escape(&from),
        attachment_names.len(),
        attachment_bytes,
        names_json.join(","),
        findings_json.join(",")
    );

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
