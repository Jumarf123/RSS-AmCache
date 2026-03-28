#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use image::GenericImageView;
use rayon::prelude::*;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, SW_SHOW};
use yara_x::{Compiler, Scanner};

use amcache_rs::acquire;
use amcache_rs::hive;
use amcache_rs::parse;
use amcache_rs::types::{ParseOptions, Record, Schema};
use amcache_rs::util::trim_sha1;

mod embedded_yara {
    include!(concat!(env!("OUT_DIR"), "/embedded_yara.rs"));
}

fn main() {
    let log = LogSink::new();
    match ensure_elevated(&log) {
        Ok(EnsureOutcome::Spawned) => return,
        Ok(EnsureOutcome::Already) => {}
        Err(err) => {
            log.log_error(&format!("elevation error: {err}"));
            show_message("RSS-AmCache", &format!("Admin rights required. {err}"));
            return;
        }
    }

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1300.0, 700.0])
        .with_min_inner_size([1100.0, 600.0]);
    if let Some(icon) = load_app_icon(&log) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    let result = eframe::run_native(
        "RSS-AmCache",
        options,
        Box::new(|_cc| Ok(Box::new(App::new(log.clone())))),
    );

    if let Err(err) = result {
        let msg = format!("fatal error: {err}");
        log.log_error(&msg);
        show_message("RSS-AmCache", &msg);
    }
}

#[derive(Debug, Clone)]
enum YaraStatus {
    Matches(Vec<String>),
    NoMatch,
    Skipped,
    Error,
    Disabled,
}

impl YaraStatus {
    fn has_match(&self) -> bool {
        matches!(self, YaraStatus::Matches(v) if !v.is_empty())
    }

    fn display(&self) -> String {
        match self {
            YaraStatus::Matches(rules) => rules.join(" / "),
            YaraStatus::NoMatch => String::new(),
            YaraStatus::Skipped => String::new(),
            YaraStatus::Error => "error".to_string(),
            YaraStatus::Disabled => "rules missing".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct ScanEntry {
    index: usize,
    file_name: String,
    file_name_lower: String,
    path: String,
    path_lower: String,
    first_seen: String,
    first_seen_lower: String,
    last_seen: String,
    last_seen_lower: String,
    first_seen_dt: Option<OffsetDateTime>,
    last_seen_dt: Option<OffsetDateTime>,
    recent_30_days: bool,
    sha1: Option<String>,
    sha1_lower: String,
    deleted: bool,
    yara: YaraStatus,
    yara_display: String,
    yara_lower: String,
}

struct CandidateAgg {
    index: usize,
    path: String,
    sha1: Option<String>,
    key: String,
    first_dt: Option<OffsetDateTime>,
    last_dt: Option<OffsetDateTime>,
    recent_30: bool,
}

impl ScanEntry {
    fn new(
        index: usize,
        path: String,
        sha1: Option<String>,
        deleted: bool,
        yara: YaraStatus,
        first_seen: String,
        last_seen: String,
        first_seen_dt: Option<OffsetDateTime>,
        last_seen_dt: Option<OffsetDateTime>,
        recent_30_days: bool,
    ) -> Self {
        let file_name = Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let file_name_lower = file_name.to_lowercase();
        let path_lower = path.to_lowercase();
        let first_seen_lower = first_seen.to_lowercase();
        let last_seen_lower = last_seen.to_lowercase();
        let sha1_lower = sha1.clone().unwrap_or_default().to_lowercase();
        let yara_display = yara.display();
        let yara_lower = yara_display.to_lowercase();
        Self {
            index,
            file_name,
            file_name_lower,
            path,
            path_lower,
            first_seen,
            first_seen_lower,
            last_seen,
            last_seen_lower,
            first_seen_dt,
            last_seen_dt,
            recent_30_days,
            sha1,
            sha1_lower,
            deleted,
            yara,
            yara_display,
            yara_lower,
        }
    }

    fn deleted_label(&self) -> &'static str {
        if self.deleted {
            "yes"
        } else {
            "no"
        }
    }

    fn sha1_display(&self) -> &str {
        self.sha1.as_deref().unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortBy {
    File,
    Yara,
    Deleted,
    Path,
    FirstSeen,
    LastSeen,
    Sha1,
}

impl SortBy {
}

#[derive(Debug)]
struct Progress {
    scanned: usize,
    total: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Eng,
    Ru,
}

#[derive(Debug, Clone, Copy)]
enum StatusKey {
    Processing,
    Acquiring,
    LoadingHive,
    Parsing,
    Scanning,
    Ready,
}

#[derive(Debug, Clone)]
enum StatusMessage {
    Key(StatusKey),
    ExportedCsv(PathBuf),
    ExportedJson(PathBuf),
    Custom(String),
}

struct UiText {
    app_title: &'static str,
    processing: &'static str,
    processing_failed: &'static str,
    retry: &'static str,
    reload: &'static str,
    export_csv: &'static str,
    export_json: &'static str,
    options: &'static str,
    language: &'static str,
    lang_eng: &'static str,
    lang_ru: &'static str,
    filters: &'static str,
    search: &'static str,
    deleted_only: &'static str,
    no_deleted_only: &'static str,
    yara_only: &'static str,
    last_30_days: &'static str,
    rows: &'static str,
    errors: &'static str,
    file: &'static str,
    yara_detect: &'static str,
    deleted: &'static str,
    file_path: &'static str,
    first_seen: &'static str,
    last_seen: &'static str,
    sha1: &'static str,
    status_processing: &'static str,
    status_acquiring: &'static str,
    status_loading_hive: &'static str,
    status_parsing: &'static str,
    status_scanning: &'static str,
    status_ready: &'static str,
    status_exported_csv: &'static str,
    status_exported_json: &'static str,
    sort_hint: &'static str,
}

fn ui_text(lang: Language) -> UiText {
    match lang {
        Language::Eng => UiText {
            app_title: "RSS-AmCache",
            processing: "Processing Amcache entries",
            processing_failed: "Processing failed",
            retry: "Retry",
            reload: "Reload",
            export_csv: "Export CSV",
            export_json: "Export JSON",
            options: "Options",
            language: "Language",
            lang_eng: "Eng",
            lang_ru: "Ru",
            filters: "Filters",
            search: "Search",
            deleted_only: "Only deleted",
            no_deleted_only: "Only not deleted",
            yara_only: "YARA only",
            last_30_days: "Last 30 days",
            rows: "Rows",
            errors: "Errors",
            file: "File",
            yara_detect: "YARA detect",
            deleted: "Deleted",
            file_path: "File path",
            first_seen: "First seen",
            last_seen: "Last seen",
            sha1: "SHA1",
            status_processing: "Processing",
            status_acquiring: "Acquiring Amcache",
            status_loading_hive: "Loading hive",
            status_parsing: "Parsing",
            status_scanning: "Scanning YARA",
            status_ready: "Ready",
            status_exported_csv: "Exported CSV",
            status_exported_json: "Exported JSON",
            sort_hint: "Sort: click column headers",
        },
        Language::Ru => UiText {
            app_title: "RSS-AmCache",
            processing: "Обработка Amcache",
            processing_failed: "Ошибка обработки",
            retry: "Повторить",
            reload: "Обновить",
            export_csv: "Экспорт CSV",
            export_json: "Экспорт JSON",
            options: "Опции",
            language: "Язык",
            lang_eng: "Англ",
            lang_ru: "Рус",
            filters: "Фильтры",
            search: "Поиск",
            deleted_only: "Только удалённые",
            no_deleted_only: "Только не удалённые",
            yara_only: "Только YARA",
            last_30_days: "Последние 30 дней",
            rows: "Строки",
            errors: "Ошибки",
            file: "Файл",
            yara_detect: "YARA детект",
            deleted: "Удалён",
            file_path: "Путь к файлу",
            first_seen: "Первое время",
            last_seen: "Последнее время",
            sha1: "SHA1",
            status_processing: "Обработка",
            status_acquiring: "Чтение Amcache",
            status_loading_hive: "Загрузка улья",
            status_parsing: "Парсинг",
            status_scanning: "Сканирование YARA",
            status_ready: "Готово",
            status_exported_csv: "Экспорт CSV",
            status_exported_json: "Экспорт JSON",
            sort_hint: "Сортировка: клик по заголовку",
        },
    }
}

fn status_text(status: &StatusMessage, s: &UiText) -> String {
    match status {
        StatusMessage::Key(key) => match key {
            StatusKey::Processing => s.status_processing.to_string(),
            StatusKey::Acquiring => s.status_acquiring.to_string(),
            StatusKey::LoadingHive => s.status_loading_hive.to_string(),
            StatusKey::Parsing => s.status_parsing.to_string(),
            StatusKey::Scanning => s.status_scanning.to_string(),
            StatusKey::Ready => s.status_ready.to_string(),
        },
        StatusMessage::ExportedCsv(path) => {
            format!("{}: {}", s.status_exported_csv, path.display())
        }
        StatusMessage::ExportedJson(path) => {
            format!("{}: {}", s.status_exported_json, path.display())
        }
        StatusMessage::Custom(value) => value.clone(),
    }
}

#[derive(Debug)]
enum WorkerEvent {
    Status(StatusKey),
    Progress { scanned: usize, total: usize },
    Finished { entries: Vec<ScanEntry>, errors: Vec<String> },
    Failed(String),
}

#[derive(Clone)]
struct LogSink {
    file: Arc<Mutex<Option<File>>>,
}

impl LogSink {
    fn new() -> Self {
        let path = default_log_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }

    fn log_error(&self, message: &str) {
        self.log("ERROR", message);
    }

    fn log(&self, level: &str, message: &str) {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string());
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "[{timestamp}] {level}: {message}");
            }
        }
    }
}

fn default_log_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        PathBuf::from(dir)
            .join("RSS-AmCache")
            .join("rss-amcache.log")
    } else {
        std::env::temp_dir()
            .join("RSS-AmCache")
            .join("rss-amcache.log")
    }
}

fn load_app_icon(log: &LogSink) -> Option<egui::IconData> {
    let bytes = include_bytes!("../rss.ico");
    let image = match image::load_from_memory(bytes) {
        Ok(value) => value,
        Err(err) => {
            log.log_error(&format!("icon decode failed: {err}"));
            return None;
        }
    };
    let rgba = image.to_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

enum Mode {
    Loading,
    Ready,
    Error,
}

struct App {
    mode: Mode,
    entries: Vec<ScanEntry>,
    view: Vec<usize>,
    status: StatusMessage,
    progress: Option<Progress>,
    search: String,
    show_deleted_only: bool,
    show_not_deleted_only: bool,
    show_yara_only: bool,
    show_last_30_days: bool,
    sort_by: SortBy,
    sort_asc: bool,
    rx: Option<mpsc::Receiver<WorkerEvent>>,
    log: LogSink,
    errors: Vec<String>,
    fatal_error: Option<String>,
    theme_applied: bool,
    language: Language,
}

impl App {
    fn new(log: LogSink) -> Self {
        let mut app = Self {
            mode: Mode::Loading,
            entries: Vec::new(),
            view: Vec::new(),
            status: StatusMessage::Key(StatusKey::Processing),
            progress: None,
            search: String::new(),
            show_deleted_only: false,
            show_not_deleted_only: false,
            show_yara_only: false,
            show_last_30_days: false,
            sort_by: SortBy::File,
            sort_asc: true,
            rx: None,
            log,
            errors: Vec::new(),
            fatal_error: None,
            theme_applied: false,
            language: Language::Eng,
        };
        app.start_worker();
        app
    }

    fn start_worker(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.mode = Mode::Loading;
        self.status = StatusMessage::Key(StatusKey::Processing);
        self.progress = None;
        self.entries.clear();
        self.view.clear();
        self.errors.clear();
        self.fatal_error = None;

        let log = self.log.clone();
        thread::spawn(move || {
            if let Err(err) = run_pipeline(&tx, log.clone()) {
                log.log_error(&format!("worker failed: {err}"));
                let _ = tx.send(WorkerEvent::Failed(err.to_string()));
            }
        });
    }

    fn push_error(&mut self, message: String) {
        self.log.log_error(&message);
        self.errors.push(message);
    }

    fn handle_worker_events(&mut self) {
        let events = match self.rx.as_ref() {
            Some(rx) => rx.try_iter().collect::<Vec<_>>(),
            None => return,
        };
        let mut done = false;
        for event in events {
            match event {
                WorkerEvent::Status(key) => {
                    self.status = StatusMessage::Key(key);
                }
                WorkerEvent::Progress { scanned, total } => {
                    self.progress = Some(Progress { scanned, total });
                }
                WorkerEvent::Finished { entries, errors } => {
                    self.entries = entries;
                    self.errors = errors;
                    self.refresh_view();
                    self.status = StatusMessage::Key(StatusKey::Ready);
                    self.progress = None;
                    self.mode = Mode::Ready;
                    done = true;
                }
                WorkerEvent::Failed(message) => {
                    self.fatal_error = Some(message.clone());
                    self.status = StatusMessage::Custom(message);
                    self.progress = None;
                    self.mode = Mode::Error;
                    done = true;
                }
            }
        }
        if done {
            self.rx = None;
        }
    }

    fn refresh_view(&mut self) {
        let search = self.search.to_lowercase();
        self.view.clear();
        for (idx, entry) in self.entries.iter().enumerate() {
            if self.show_deleted_only && self.show_not_deleted_only {
                // both selected -> show all
            } else if self.show_deleted_only && !entry.deleted {
                continue;
            } else if self.show_not_deleted_only && entry.deleted {
                continue;
            }
            if self.show_yara_only && !entry.yara.has_match() {
                continue;
            }
            if self.show_last_30_days && !entry.recent_30_days {
                continue;
            }
            if !search.is_empty()
                && !entry.file_name_lower.contains(&search)
                && !entry.path_lower.contains(&search)
                && !entry.yara_lower.contains(&search)
                && !entry.first_seen_lower.contains(&search)
                && !entry.last_seen_lower.contains(&search)
                && !entry.sha1_lower.contains(&search)
            {
                continue;
            }
            self.view.push(idx);
        }
        let sort_by = self.sort_by;
        let sort_asc = self.sort_asc;
        self.view.sort_by(|a, b| {
            let left = &self.entries[*a];
            let right = &self.entries[*b];
            let mut cmp = match sort_by {
                SortBy::File => left.file_name_lower.cmp(&right.file_name_lower),
                SortBy::Yara => left.yara_lower.cmp(&right.yara_lower),
                SortBy::Deleted => left.deleted.cmp(&right.deleted),
                SortBy::Path => left.path_lower.cmp(&right.path_lower),
                SortBy::FirstSeen => compare_datetime(left.first_seen_dt, right.first_seen_dt),
                SortBy::LastSeen => compare_datetime(left.last_seen_dt, right.last_seen_dt),
                SortBy::Sha1 => left.sha1_lower.cmp(&right.sha1_lower),
            };
            if !sort_asc {
                cmp = cmp.reverse();
            }
            if cmp == Ordering::Equal {
                left.index.cmp(&right.index)
            } else {
                cmp
            }
        });
    }

    fn export_csv(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("RSS-AmCache.csv")
            .save_file()
        else {
            return;
        };
        match export_csv(&path, self.export_rows()) {
            Ok(()) => self.status = StatusMessage::ExportedCsv(path),
            Err(err) => self.push_error(format!("CSV export failed: {err}")),
        }
    }

    fn export_json(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("RSS-AmCache.json")
            .save_file()
        else {
            return;
        };
        match export_json(&path, self.export_rows()) {
            Ok(()) => self.status = StatusMessage::ExportedJson(path),
            Err(err) => self.push_error(format!("JSON export failed: {err}")),
        }
    }

    fn export_rows(&self) -> Vec<ExportRow> {
        let mut rows = Vec::with_capacity(self.view.len());
        for &idx in &self.view {
            let entry = &self.entries[idx];
            rows.push(ExportRow {
                file: entry.file_name.clone(),
                yara_detect: entry.yara_display.clone(),
                deleted: entry.deleted_label().to_string(),
                path: entry.path.clone(),
                first_seen: entry.first_seen.clone(),
                last_seen: entry.last_seen.clone(),
                sha1: entry.sha1_display().to_string(),
            });
        }
        rows
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            apply_red_black_theme(ctx);
            self.theme_applied = true;
        }
        self.handle_worker_events();
        let s = ui_text(self.language);
        let status_text = status_text(&self.status, &s);

        match self.mode {
            Mode::Loading => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.heading(s.processing);
                        if let Some(progress) = &self.progress {
                            let fraction = if progress.total == 0 {
                                0.0
                            } else {
                                progress.scanned as f32 / progress.total as f32
                            };
                            ui.add(egui::ProgressBar::new(fraction).show_percentage());
                            ui.label(format!("{}/{}", progress.scanned, progress.total));
                        }
                        ui.add_space(10.0);
                        ui.label(status_text);
                    });
                });
                ctx.request_repaint_after(Duration::from_millis(200));
            }
            Mode::Error => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading(s.processing_failed);
                        if let Some(message) = &self.fatal_error {
                            ui.label(message);
                        }
                        ui.add_space(10.0);
                        if ui.button(s.retry).clicked() {
                            self.start_worker();
                        }
                    });
                });
            }
            Mode::Ready => {
                let mut changed = false;
                egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
                    let frame = egui::Frame::NONE
                        .fill(egui::Color32::from_rgb(16, 0, 0))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 0, 0)))
                        .inner_margin(egui::Margin::same(8));
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading(s.app_title);
                            ui.add_space(12.0);
                            ui.label(&status_text);
                            if let Some(progress) = &self.progress {
                                ui.label(format!("{}/{}", progress.scanned, progress.total));
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.menu_button(s.options, |ui| {
                                    ui.label(s.language);
                                    ui.radio_value(&mut self.language, Language::Eng, s.lang_eng);
                                    ui.radio_value(&mut self.language, Language::Ru, s.lang_ru);
                                });
                                if ui.button(s.reload).clicked() {
                                    self.start_worker();
                                }
                                if ui.button(s.export_json).clicked() {
                                    self.export_json();
                                }
                                if ui.button(s.export_csv).clicked() {
                                    self.export_csv();
                                }
                            });
                        });
                    });
                    if changed {
                        self.refresh_view();
                    }
                });

                egui::SidePanel::left("filters")
                    .resizable(false)
                    .default_width(260.0)
                    .show(ctx, |ui| {
                        ui.add_space(4.0);
                        ui.heading(s.filters);
                        ui.separator();
                        ui.label(s.search);
                        if ui.text_edit_singleline(&mut self.search).changed() {
                            changed = true;
                        }
                        ui.add_space(8.0);
                        if ui.checkbox(&mut self.show_deleted_only, s.deleted_only).changed() {
                            changed = true;
                        }
                        if ui
                            .checkbox(&mut self.show_not_deleted_only, s.no_deleted_only)
                            .changed()
                        {
                            changed = true;
                        }
                        if ui.checkbox(&mut self.show_yara_only, s.yara_only).changed() {
                            changed = true;
                        }
                        if ui.checkbox(&mut self.show_last_30_days, s.last_30_days).changed() {
                            changed = true;
                        }
                        ui.add_space(8.0);
                        ui.label(s.sort_hint);
                        if changed {
                            self.refresh_view();
                        }
                    });

                egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(&status_text);
                        if let Some(progress) = &self.progress {
                            ui.label(format!("{}/{}", progress.scanned, progress.total));
                        }
                        ui.label(format!("{}: {}", s.rows, self.view.len()));
                    });
                });

                egui::CentralPanel::default().show(ctx, |ui| {
                    if !self.errors.is_empty() {
                        ui.collapsing(s.errors, |ui| {
                            for err in &self.errors {
                                ui.label(err);
                            }
                        });
                        ui.add_space(6.0);
                    }

                    let text_height = ui.text_style_height(&egui::TextStyle::Body);
                    let mut sort_changed = false;
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                        ui.set_min_width(1300.0);
                        TableBuilder::new(ui)
                            .striped(true)
                            .resizable(true)
                            .vscroll(true)
                            .min_scrolled_height(300.0)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::initial(160.0).resizable(true).at_least(120.0).clip(true))
                            .column(Column::initial(160.0).resizable(true).at_least(120.0).clip(true))
                            .column(Column::initial(80.0).resizable(true).at_least(70.0).clip(true))
                            .column(Column::initial(360.0).resizable(true).at_least(240.0).clip(true))
                            .column(Column::initial(120.0).resizable(true).at_least(110.0).clip(true))
                            .column(Column::initial(120.0).resizable(true).at_least(110.0).clip(true))
                            .column(Column::initial(260.0).resizable(true).at_least(200.0).clip(true))
                            .header(text_height + 6.0, |mut header| {
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.file,
                                        SortBy::File,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.yara_detect,
                                        SortBy::Yara,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.deleted,
                                        SortBy::Deleted,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.file_path,
                                        SortBy::Path,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.first_seen,
                                        SortBy::FirstSeen,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.last_seen,
                                        SortBy::LastSeen,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                                header.col(|ui| {
                                    sort_changed |= header_sort_label(
                                        ui,
                                        s.sha1,
                                        SortBy::Sha1,
                                        &mut self.sort_by,
                                        &mut self.sort_asc,
                                    );
                                });
                            })
                            .body(|body| {
                                body.rows(text_height + 4.0, self.view.len(), |mut row| {
                                    let idx = self.view[row.index()];
                                    let entry = &self.entries[idx];
                                    row.col(|ui| {
                                        add_trunc_label(ui, &entry.file_name);
                                    });
                                    row.col(|ui| {
                                        if entry.yara.has_match() {
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(&entry.yara_display)
                                                        .color(egui::Color32::from_rgb(255, 80, 80))
                                                        .strong(),
                                                )
                                                .truncate(),
                                            )
                                            .on_hover_text(&entry.yara_display);
                                        } else {
                                            add_trunc_label(ui, &entry.yara_display);
                                        }
                                    });
                                    row.col(|ui| {
                                        ui.label(entry.deleted_label());
                                    });
                                    row.col(|ui| {
                                        add_trunc_label(ui, &entry.path);
                                    });
                                    row.col(|ui| {
                                        add_trunc_label(ui, &entry.first_seen);
                                    });
                                    row.col(|ui| {
                                        add_trunc_label(ui, &entry.last_seen);
                                    });
                                    row.col(|ui| {
                                        add_trunc_label(ui, entry.sha1_display());
                                    });
                                });
                            });
                    });
                    if sort_changed {
                        self.refresh_view();
                    }
                });
            }
        }
    }
}

fn add_trunc_label(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(text).truncate())
        .on_hover_text(text);
}

fn header_sort_label(
    ui: &mut egui::Ui,
    title: &str,
    sort: SortBy,
    current: &mut SortBy,
    asc: &mut bool,
) -> bool {
    let arrow = if *current == sort {
        if *asc { " ^" } else { " v" }
    } else {
        ""
    };
    let label = format!("{title}{arrow}");
    let mut text = egui::RichText::new(label);
    if *current == sort {
        text = text.strong().color(egui::Color32::from_rgb(255, 80, 80));
    }
    if ui.add(egui::Label::new(text).sense(egui::Sense::click())).clicked() {
        if *current == sort {
            *asc = !*asc;
        } else {
            *current = sort;
            *asc = true;
        }
        return true;
    }
    false
}

fn compare_datetime(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Ordering {
    match (left, right) {
        (Some(l), Some(r)) => l.cmp(&r),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[derive(Debug, Serialize)]
struct ExportRow {
    file: String,
    yara_detect: String,
    deleted: String,
    path: String,
    first_seen: String,
    last_seen: String,
    sha1: String,
}

fn export_csv(path: &Path, rows: Vec<ExportRow>) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create csv {}", path.display()))?;
    let mut writer = csv::WriterBuilder::new().has_headers(true).from_writer(file);
    for row in rows {
        writer.serialize(row).context("write csv row")?;
    }
    writer.flush().context("flush csv writer")?;
    Ok(())
}

fn export_json(path: &Path, rows: Vec<ExportRow>) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create json {}", path.display()))?;
    serde_json::to_writer_pretty(file, &rows).context("write json")?;
    Ok(())
}

fn run_pipeline(tx: &mpsc::Sender<WorkerEvent>, log: LogSink) -> Result<()> {
    let mut errors = Vec::new();
    let now = OffsetDateTime::now_utc();
    let records = load_amcache_records(tx).context("load amcache records")?;
    let mut map: HashMap<(String, Option<String>), CandidateAgg> = HashMap::new();
    for (index, record) in records.into_iter().enumerate() {
        let (first_dt, last_dt, recent_30) = extract_dates(&record, now);
        let path = record.path.clone().or(record.lower_case_long_path.clone());
        let Some(path) = path else { continue };
        let sha1 = normalize_sha1(record.sha1.clone());
        let key = sha1.clone().unwrap_or_else(|| path.clone());
        let agg_key = (path.clone(), sha1.clone());
        let entry = map.entry(agg_key).or_insert_with(|| CandidateAgg {
            index,
            path: path.clone(),
            sha1: sha1.clone(),
            key,
            first_dt,
            last_dt,
            recent_30,
        });
        if index < entry.index {
            entry.index = index;
        }
        entry.first_dt = min_opt_dt(entry.first_dt, first_dt);
        entry.last_dt = max_opt_dt(entry.last_dt, last_dt);
        entry.recent_30 |= recent_30;
    }

    let mut candidates: Vec<CandidateAgg> = map.into_values().collect();
    candidates.sort_by_key(|c| c.index);

    let yara_rules = load_embedded_yara_rules(&log, &mut errors);

    let _ = tx.send(WorkerEvent::Status(StatusKey::Scanning));
    let mut unique_paths = Vec::new();
    let mut seen = HashSet::new();
    for candidate in &candidates {
        let path = &candidate.path;
        if seen.insert(path.clone()) {
            unique_paths.push(path.clone());
        }
    }

    let deleted_by_path: HashMap<String, bool> = unique_paths
        .par_iter()
        .map(|path| {
            let deleted = match fs::metadata(path) {
                Ok(metadata) => !metadata.is_file(),
                Err(_) => true,
            };
            (path.clone(), deleted)
        })
        .collect();

    let mut key_to_path: HashMap<String, String> = HashMap::new();
    for candidate in &candidates {
        if let Some(false) = deleted_by_path.get(&candidate.path) {
            key_to_path
                .entry(candidate.key.clone())
                .or_insert_with(|| candidate.path.clone());
        }
    }

    let total = key_to_path.len();
    let progress = Arc::new(AtomicUsize::new(0));
    let errors_shared: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let errors_for_threads = errors_shared.clone();
    let rules_available = yara_rules.is_some();
    let rules_for_threads = yara_rules.map(Arc::new);
    let log_for_threads = log.clone();

    let results: Vec<(String, YaraStatus)> = key_to_path
        .into_par_iter()
        .map(move |(key, path)| {
            let rules = rules_for_threads.as_ref();
            let yara_status = if rules.is_none() {
                YaraStatus::Disabled
            } else if let Some(bundle) = rules {
                let mut scanner = Scanner::new(&bundle.rules);
                match scanner.scan_file(&path) {
                    Ok(results) => {
                        let mut matched = HashSet::new();
                        for rule in results.matching_rules() {
                            let namespace = rule.namespace();
                            let display = bundle
                                .namespace_map
                                .get(namespace)
                                .map(|value| value.as_str())
                                .unwrap_or(namespace);
                            matched.insert(display.to_string());
                        }
                        if matched.is_empty() {
                            YaraStatus::NoMatch
                        } else {
                            let mut matched: Vec<String> = matched.into_iter().collect();
                            matched.sort();
                            YaraStatus::Matches(matched)
                        }
                    }
                    Err(err) => {
                        let message = format!("YARA scan failed for {}: {err}", path);
                        log_for_threads.log_error(&message);
                        if let Ok(mut guard) = errors_for_threads.lock() {
                            guard.push(message);
                        }
                        YaraStatus::Error
                    }
                }
            } else {
                YaraStatus::Disabled
            };

            let scanned = progress.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            if scanned % 25 == 0 || scanned == total {
                let _ = tx.send(WorkerEvent::Progress { scanned, total });
            }

            (key, yara_status)
        })
        .collect();

    let mut status_map: HashMap<String, YaraStatus> = HashMap::new();
    for (key, status) in results {
        status_map.insert(key, status);
    }
    if let Ok(mut guard) = errors_shared.lock() {
        errors.append(&mut guard);
    }

    let mut out = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let deleted = deleted_by_path.get(&candidate.path).copied().unwrap_or(true);
        let status = if !rules_available {
            YaraStatus::Disabled
        } else if deleted {
            YaraStatus::Skipped
        } else {
            status_map
                .get(&candidate.key)
                .cloned()
                .unwrap_or(YaraStatus::Error)
        };
        let first_seen = candidate.first_dt.map(format_short).unwrap_or_default();
        let last_seen = candidate.last_dt.map(format_short).unwrap_or_default();
        out.push(ScanEntry::new(
            candidate.index,
            candidate.path,
            candidate.sha1,
            deleted,
            status,
            first_seen,
            last_seen,
            candidate.first_dt,
            candidate.last_dt,
            candidate.recent_30,
        ));
    }

    let _ = tx.send(WorkerEvent::Finished { entries: out, errors });
    Ok(())
}

fn load_embedded_yara_rules(
    log: &LogSink,
    errors: &mut Vec<String>,
) -> Option<YaraBundle> {
    let mut compiler = Compiler::new();
    let mut any = false;
    let mut namespace_map: HashMap<String, String> = HashMap::new();
    for rule in embedded_yara::EMBEDDED_RULES {
        let display = rule.name.trim_end_matches(".yar").trim_end_matches(".yara");
        let namespace = sanitize_namespace(display);
        if let Some(existing) = namespace_map.get(&namespace) {
            if existing != display {
                let message = format!(
                    "yara namespace collision: {} maps to {} and {}",
                    namespace, existing, display
                );
                log.log_error(&message);
                errors.push(message);
            }
        } else {
            namespace_map.insert(namespace.clone(), display.to_string());
        }
        compiler.new_namespace(&namespace);
        match compiler.add_source(rule.source) {
            Ok(_) => {
                any = true;
            }
            Err(err) => {
                let message = format!("yara compile error in embedded {}: {err}", rule.name);
                log.log_error(&message);
                errors.push(message);
            }
        }
    }

    if !any {
        errors.push("no embedded yara rules compiled".to_string());
        return None;
    }

    let rules = Arc::new(compiler.build());
    Some(YaraBundle {
        rules,
        namespace_map: Arc::new(namespace_map),
    })
}

fn sanitize_namespace(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("rule");
    }
    if out
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        out.insert(0, '_');
    }
    out
}

fn load_amcache_records(tx: &mpsc::Sender<WorkerEvent>) -> Result<Vec<Record>> {
    let _ = tx.send(WorkerEvent::Status(StatusKey::Acquiring));
    let acquired = acquire::acquire_live(false).context("acquire live amcache")?;
    let temp_guard = acquired.temp_dir;
    let hive_path = acquired.hive_path.clone();
    let mut log_paths = Vec::new();
    if let Some(path) = acquired.log1_path.clone() {
        log_paths.push(path);
    }
    if let Some(path) = acquired.log2_path.clone() {
        log_paths.push(path);
    }
    if log_paths.is_empty() {
        log_paths = hive::find_log_paths(&hive_path);
    }
    let _ = tx.send(WorkerEvent::Status(StatusKey::LoadingHive));
    let load = hive::load_hive_from_path(&hive_path, &log_paths, true)
        .context("load amcache hive")?;
    let _ = tx.send(WorkerEvent::Status(StatusKey::Parsing));
    let options = ParseOptions {
        executed_only: false,
        include_low_confidence: true,
        include_associated: true,
        schema: Schema::Auto,
        no_logs: false,
        debug: false,
        source_method: acquired.source_method,
        hive_path: Some(hive_path),
    };
    let records = parse::parse_hive(&load.hive, &options).context("parse amcache hive")?;
    drop(temp_guard);
    Ok(records)
}

fn normalize_sha1(value: Option<String>) -> Option<String> {
    let value = value?;
    let trimmed = trim_sha1(&value);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

const SHORT_DATE_FORMAT: &[FormatItem<'static>] =
    format_description!("[day]/[month]/[year repr:last_two] [hour]:[minute]");
const LONG_DATE_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");

fn extract_dates(
    record: &Record,
    now: OffsetDateTime,
) -> (Option<OffsetDateTime>, Option<OffsetDateTime>, bool) {
    let cutoff = now - time::Duration::days(30);
    let mut min: Option<OffsetDateTime> = None;
    let mut max: Option<OffsetDateTime> = None;
    let mut recent_30 = false;
    for candidate in collect_time_candidates(record) {
        let Some(value) = candidate else { continue };
        let Some(dt) = parse_time_any(value) else { continue };
        min = Some(min.map_or(dt, |current| current.min(dt)));
        max = Some(max.map_or(dt, |current| current.max(dt)));
        if dt >= cutoff {
            recent_30 = true;
        }
    }
    (min, max, recent_30)
}

fn collect_time_candidates<'a>(record: &'a Record) -> [Option<&'a str>; 8] {
    [
        record.link_date_utc.as_deref(),
        record.last_mod_time_utc.as_deref(),
        record.file_created_utc.as_deref(),
        record.file_modified_utc.as_deref(),
        record.last_mod_time2_utc.as_deref(),
        record.compile_time_utc.as_deref(),
        record.record_key_lastwrite_utc.as_deref(),
        record.install_date_utc.as_deref(),
    ]
}

fn parse_time_any(value: &str) -> Option<OffsetDateTime> {
    if let Ok(dt) = OffsetDateTime::parse(value, &Rfc3339) {
        return Some(dt);
    }
    PrimitiveDateTime::parse(value, LONG_DATE_FORMAT)
        .ok()
        .map(|dt| dt.assume_utc())
}

fn format_short(dt: OffsetDateTime) -> String {
    dt.format(SHORT_DATE_FORMAT).unwrap_or_default()
}

fn min_opt_dt(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(l), Some(r)) => Some(l.min(r)),
        (Some(l), None) => Some(l),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}

fn max_opt_dt(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(l), Some(r)) => Some(l.max(r)),
        (Some(l), None) => Some(l),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}

fn show_message(title: &str, message: &str) {
    let title_wide = to_wide(title);
    let message_wide = to_wide(message);
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(message_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = OsStr::new(value).encode_wide().collect();
    wide.push(0);
    wide
}

enum EnsureOutcome {
    Already,
    Spawned,
}

fn apply_red_black_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    let black = egui::Color32::from_rgb(8, 8, 8);
    let darker = egui::Color32::from_rgb(4, 4, 4);
    let red = egui::Color32::from_rgb(180, 0, 0);
    let red_dim = egui::Color32::from_rgb(120, 0, 0);
    let text = egui::Color32::from_rgb(230, 230, 230);
    let text_dim = egui::Color32::from_rgb(170, 170, 170);

    visuals.window_fill = black;
    visuals.panel_fill = black;
    visuals.extreme_bg_color = darker;
    visuals.faint_bg_color = egui::Color32::from_rgb(20, 0, 0);
    visuals.code_bg_color = egui::Color32::from_rgb(15, 0, 0);
    visuals.window_shadow = egui::Shadow {
        offset: [0, 2],
        blur: 12,
        spread: 0,
        color: egui::Color32::from_rgba_unmultiplied(0, 0, 0, 80),
    };
    visuals.popup_shadow = egui::Shadow {
        offset: [0, 2],
        blur: 8,
        spread: 0,
        color: egui::Color32::from_rgba_unmultiplied(0, 0, 0, 80),
    };
    visuals.window_corner_radius = egui::CornerRadius::same(6);
    visuals.menu_corner_radius = egui::CornerRadius::same(4);
    visuals.selection.bg_fill = red_dim;
    visuals.selection.stroke = egui::Stroke::new(1.0, red);
    visuals.hyperlink_color = red;
    visuals.override_text_color = Some(text);

    visuals.widgets.noninteractive.bg_fill = black;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_dim);

    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(12, 12, 12);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text);

    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(30, 0, 0);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, text);

    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 0, 0);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, text);

    visuals.widgets.open.bg_fill = egui::Color32::from_rgb(25, 0, 0);
    visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, text);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(8);
    style.visuals = visuals;
    ctx.set_style(style);
}

fn ensure_elevated(log: &LogSink) -> Result<EnsureOutcome> {
    if is_elevated()? {
        return Ok(EnsureOutcome::Already);
    }
    let exe = std::env::current_exe().context("locate executable")?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_line = join_args(&args);

    let verb = to_wide("runas");
    let exe_wide = to_wide(&exe.to_string_lossy());
    let args_wide = if args_line.is_empty() {
        None
    } else {
        Some(to_wide(&args_line))
    };

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            args_wide
                .as_ref()
                .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr())),
            PCWSTR::null(),
            SW_SHOW,
        )
    };

    if result.0 as isize <= 32 {
        log.log_error(&format!("ShellExecuteW failed: {}", result.0 as isize));
        return Err(anyhow::anyhow!("UAC was canceled or failed."));
    }

    Ok(EnsureOutcome::Spawned)
}

fn join_args(args: &[String]) -> String {
    let mut out = String::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if arg.contains(' ') || arg.contains('"') {
            out.push('"');
            out.push_str(&arg.replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )?;
        let _ = CloseHandle(token);
        Ok(elevation.TokenIsElevated != 0)
    }
}
#[derive(Clone)]
struct YaraBundle {
    rules: Arc<yara_x::Rules>,
    namespace_map: Arc<HashMap<String, String>>,
}
