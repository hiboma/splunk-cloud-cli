use crate::cli::OutputFormat;
use crate::error::Result;
use serde_json::Value;

/// `--format` に応じて `serde_json::Value` を stdout に整形出力する。
pub fn print_value(value: &Value, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(value)?);
        }
        OutputFormat::Pretty => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(value)?);
        }
        OutputFormat::Csv => {
            print_csv(value)?;
        }
    }
    Ok(())
}

/// Splunk REST の `entry` 配列または任意のレコード配列を CSV 化する。
fn print_csv(value: &Value) -> Result<()> {
    let rows = extract_rows(value);
    if rows.is_empty() {
        return Ok(());
    }

    let mut keys: Vec<String> = Vec::new();
    for row in &rows {
        if let Some(obj) = row.as_object() {
            for k in obj.keys() {
                if !keys.iter().any(|existing| existing == k) {
                    keys.push(k.clone());
                }
            }
        }
    }
    keys.sort();

    println!(
        "{}",
        keys.iter()
            .map(|k| csv_escape(k))
            .collect::<Vec<_>>()
            .join(",")
    );
    for row in &rows {
        let cells: Vec<String> = keys
            .iter()
            .map(|k| csv_escape(&format_cell(row.get(k))))
            .collect();
        println!("{}", cells.join(","));
    }
    Ok(())
}

fn extract_rows(value: &Value) -> Vec<Value> {
    // Splunk REST の一覧応答は `{ "entry": [...] }`、検索結果は `{ "results": [...] }` で返る。
    for key in &["results", "entry"] {
        if let Some(arr) = value.get(*key).and_then(|v| v.as_array()) {
            return arr.clone();
        }
    }
    if let Some(arr) = value.as_array() {
        return arr.clone();
    }
    Vec::new()
}

fn format_cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(a)) => serde_json::to_string(a).unwrap_or_default(),
        Some(Value::Object(o)) => serde_json::to_string(o).unwrap_or_default(),
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}
