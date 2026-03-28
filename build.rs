use std::path::Path;

fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("rss.ico");
    res.set_manifest_file("app.manifest");
    if let Err(err) = res.compile() {
        eprintln!("winres error: {err}");
    }

    if let Err(err) = generate_embedded_yara() {
        eprintln!("yara embed error: {err}");
    }
}

fn generate_embedded_yara() -> std::io::Result<()> {
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let yara_dir = manifest_dir.join("yara");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let out_file = out_dir.join("embedded_yara.rs");

    println!("cargo:rerun-if-changed={}", yara_dir.display());

    let mut entries: Vec<PathBuf> = Vec::new();
    if yara_dir.is_dir() {
        for entry in fs::read_dir(&yara_dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            if is_yara_file(&path) {
                println!("cargo:rerun-if-changed={}", path.display());
                entries.push(path);
            }
        }
    }

    entries.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    let mut out = String::new();
    out.push_str("pub struct EmbeddedRule { pub name: &'static str, pub source: &'static str }\n");
    out.push_str("pub const EMBEDDED_RULES: &[EmbeddedRule] = &[\n");
    for path in entries {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("rule");
        let rel = path.strip_prefix(&manifest_dir).unwrap_or(&path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        out.push_str("    EmbeddedRule { name: \"");
        out.push_str(name);
        out.push_str("\", source: include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/");
        out.push_str(&rel_str);
        out.push_str("\")) },\n");
    }
    out.push_str("];\n");

    let mut file = fs::File::create(out_file)?;
    file.write_all(out.as_bytes())?;
    Ok(())
}

fn is_yara_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
}
