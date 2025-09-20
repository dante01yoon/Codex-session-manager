use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local, Utc};
use eframe::egui::{self, Color32, Key, RichText};
use eframe::{App, CreationContext};
use serde_json::Value;
use walkdir::WalkDir;

const PREVIEW_LIMIT: usize = 16;
const PREVIEW_CHAR_LIMIT: usize = 600;
const TITLE_CHAR_LIMIT: usize = 80;

fn main() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Codex Session Manager")
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Codex Session Manager",
        native_options,
        Box::new(|cc| Box::new(SessionManagerApp::new(cc))),
    )
    .map_err(|err| anyhow!("Failed to launch Codex Session Manager: {err}"))?;

    Ok(())
}

#[derive(Clone, Debug)]
struct SessionEntry {
    id: String,
    file_path: PathBuf,
    created_at: DateTime<Utc>,
    originator: Option<String>,
    instructions: Option<String>,
    cwd: Option<String>,
    title: Option<String>,
    preview_items: Vec<PreviewMessage>,
}

impl SessionEntry {
    fn matches_filter(&self, filter: &str) -> bool {
        if filter.trim().is_empty() {
            return true;
        }
        let needle = filter.to_lowercase();
        self.id.to_lowercase().contains(&needle)
            || self
                .title
                .as_deref()
                .map(|title| title.to_lowercase().contains(&needle))
                .unwrap_or(false)
            || self
                .cwd
                .as_deref()
                .map(|cwd| cwd.to_lowercase().contains(&needle))
                .unwrap_or(false)
            || self
                .originator
                .as_deref()
                .map(|origin| origin.to_lowercase().contains(&needle))
                .unwrap_or(false)
            || self.preview_items.iter().any(|item| {
                item.text
                    .to_lowercase()
                    .contains(&needle)
            })
    }

    fn display_title(&self) -> String {
        if let Some(title) = &self.title {
            return title.clone();
        }
        self.preview_items
            .first()
            .map(|item| {
                let prefix = format!("{} ", item.role.label());
                truncate_with_ellipsis(&(prefix + &item.text), TITLE_CHAR_LIMIT)
            })
            .unwrap_or_else(|| self.id.clone())
    }
}

#[derive(Clone, Debug)]
struct PreviewMessage {
    role: MessageRole,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageRole {
    User,
    Assistant,
    System,
    Tool,
    Other,
}

impl MessageRole {
    fn from_str(role: &str) -> Self {
        match role {
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "system" => Self::System,
            "tool" => Self::Tool,
            _ => Self::Other,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Assistant => "Codex",
            Self::System => "System",
            Self::Tool => "Tool",
            Self::Other => "Other",
        }
    }

    fn color(&self) -> Color32 {
        match self {
            Self::User => Color32::from_rgb(0x2c, 0x6e, 0x49),
            Self::Assistant => Color32::from_rgb(0x1f, 0x4b, 0x99),
            Self::System => Color32::from_rgb(0x75, 0x3a, 0x88),
            Self::Tool => Color32::from_rgb(0x8f, 0x5b, 0x29),
            Self::Other => Color32::from_rgb(0x44, 0x44, 0x44),
        }
    }
}

struct SessionManagerApp {
    sessions: Vec<SessionEntry>,
    filter: String,
    hovered_session: Option<usize>,
    selected_session: Option<usize>,
    load_error: Option<String>,
    resume_job: Option<ResumeJob>,
    resume_status: Option<ResumeStatus>,
}

impl SessionManagerApp {
    fn new(cc: &CreationContext<'_>) -> Self {
        cc.egui_ctx.set_pixels_per_point(1.2);

        let (sessions, load_error) = match load_sessions() {
            Ok(list) => (list, None),
            Err(err) => (Vec::new(), Some(format!("Failed to load sessions: {err:#}"))),
        };

        Self {
            sessions,
            filter: String::new(),
            hovered_session: None,
            selected_session: None,
            load_error,
            resume_job: None,
            resume_status: None,
        }
    }

    fn trigger_resume(&mut self, idx: usize) {
        let session_id = self.sessions[idx].id.clone();
        if let Some(job) = &self.resume_job {
            if job.session_id == session_id {
                return; // already resuming this session
            }
        }

        let (tx, rx) = mpsc::channel();
        thread::spawn({
            let session_id = session_id.clone();
            move || {
                let outcome = resume_session(&session_id);
                let _ = tx.send((session_id, outcome));
            }
        });

        self.resume_job = Some(ResumeJob {
            receiver: rx,
            session_id: session_id.clone(),
        });
        self.resume_status = Some(ResumeStatus::InFlight(session_id));
    }

    fn process_resume_job(&mut self, ctx: &egui::Context) {
        if let Some(job) = &self.resume_job {
            match job.receiver.try_recv() {
                Ok((session_id, result)) => {
                    self.resume_job = None;
                    self.resume_status = Some(match result {
                        Ok(()) => ResumeStatus::Success(session_id),
                        Err(err) => ResumeStatus::Failure(session_id, format!("{err:#}")),
                    });
                    ctx.request_repaint();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(120));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.resume_status = Some(ResumeStatus::Failure(
                        job.session_id.clone(),
                        "Resume task ended unexpectedly".to_string(),
                    ));
                    self.resume_job = None;
                }
            }
        }
    }
}

impl App for SessionManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_resume_job(ctx);

        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.hovered_session = None;
            self.selected_session = None;
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Filter:");
                let response = ui.text_edit_singleline(&mut self.filter);
                if response.changed() {
                    self.hovered_session = None;
                }
                if ui.button("Clear").clicked() {
                    self.filter.clear();
                }
            });
            if let Some(error) = &self.load_error {
                ui.add_space(4.0);
                ui.colored_label(Color32::from_rgb(0xcc, 0x00, 0x00), error);
            }
            if let Some(status) = &self.resume_status {
                ui.add_space(4.0);
                match status {
                    ResumeStatus::InFlight(id) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Launching \"codex resume {id}\"..."));
                        });
                    }
                    ResumeStatus::Success(id) => {
                        ui.colored_label(
                            Color32::from_rgb(0x0d, 0xa7, 0x55),
                            format!(
                                "Opened session {id} in a new terminal window."
                            ),
                        );
                    }
                    ResumeStatus::Failure(id, err) => {
                        ui.colored_label(
                            Color32::from_rgb(0xcc, 0x00, 0x00),
                            format!("Failed to resume {id}: {err}"),
                        );
                    }
                }
            }
            ui.add_space(6.0);
            ui.separator();
        });

        let filtered_indices: Vec<usize> = self
            .sessions
            .iter()
            .enumerate()
            .filter_map(|(idx, session)| session.matches_filter(&self.filter).then_some(idx))
            .collect();

        egui::SidePanel::left("session_list").resizable(true).show(ctx, |ui| {
            ui.heading(format!("Sessions ({})", filtered_indices.len()));
            ui.add_space(6.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, session_idx) in filtered_indices.iter().enumerate() {
                    let session = &self.sessions[*session_idx];
                    let timestamp = session
                        .created_at
                        .with_timezone(&Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string();
                    let label = format!("{}\n{}", session.display_title(), timestamp);
                    let response = ui.add(egui::SelectableLabel::new(
                        self.selected_session == Some(*session_idx),
                        label,
                    ));

                    if response.hovered() {
                        self.hovered_session = Some(*session_idx);
                    }
                    if response.clicked() {
                        self.selected_session = Some(*session_idx);
                        self.trigger_resume(*session_idx);
                    }

                    if i + 1 != filtered_indices.len() {
                        ui.separator();
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Conversation Preview");
            ui.add_space(4.0);
            let preview_idx = self.hovered_session.or(self.selected_session);
            match preview_idx {
                Some(idx) => {
                    let session = &self.sessions[idx];
                    ui.label(RichText::new(&session.id).monospace());
                    let formatted_time = session
                        .created_at
                        .with_timezone(&Local)
                        .format("%A, %d %B %Y %H:%M:%S")
                        .to_string();
                    ui.label(formatted_time);
                    if let Some(cwd) = &session.cwd {
                        ui.label(RichText::new(cwd).small());
                    }
                    if let Some(instr) = &session.instructions {
                        if !instr.trim().is_empty() {
                            ui.add_space(6.0);
                            ui.label(RichText::new("Session instructions:").strong());
                            ui.label(instr);
                        }
                    }
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if session.preview_items.is_empty() {
                            ui.label("No conversation messages recorded yet.");
                            return;
                        }
                        for message in &session.preview_items {
                            let header = RichText::new(message.role.label())
                                .color(message.role.color())
                                .strong();
                            ui.label(header);
                            ui.add_space(2.0);
                            ui.label(&message.text);
                            ui.add_space(8.0);
                        }
                    });
                }
                None => {
                    ui.label("Hover over a session to see its preview.");
                }
            }
        });
    }
}

struct ResumeJob {
    receiver: Receiver<(String, Result<()>)>,
    session_id: String,
}

enum ResumeStatus {
    InFlight(String),
    Success(String),
    Failure(String, String),
}

fn load_sessions() -> Result<Vec<SessionEntry>> {
    let base_dir = codex_sessions_dir()?;
    let mut sessions: Vec<SessionEntry> = WalkDir::new(base_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().map(|ext| ext == "jsonl").unwrap_or(false))
        .filter_map(|entry| match parse_session_file(entry.path()) {
            Ok(Some(session)) => Some(session),
            Ok(None) => None,
            Err(err) => {
                eprintln!(
                    "Skipping {} because it could not be parsed: {err:#}",
                    entry.path().display()
                );
                None
            }
        })
        .collect();

    sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(sessions)
}

fn parse_session_file(path: &Path) -> Result<Option<SessionEntry>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut created_at: Option<DateTime<Utc>> = None;
    let mut session_id: Option<String> = None;
    let mut instructions: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut originator: Option<String> = None;
    let mut preview_items: Vec<PreviewMessage> = Vec::new();
    let mut first_prompt: Option<String> = None;

    for line in reader.lines().take(400) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .with_context(|| format!("parsing JSON in {}", path.display()))?;
        let record_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();

        match record_type {
            "session_meta" => {
                if let Some(payload) = value.get("payload") {
                    if let Some(id) = payload.get("id").and_then(Value::as_str) {
                        session_id = Some(id.to_string());
                    }
                    if let Some(ts) = payload.get("timestamp").and_then(Value::as_str) {
                        if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                            created_at = Some(parsed.with_timezone(&Utc));
                        }
                    }
                    instructions = payload
                        .get("instructions")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    cwd = payload.get("cwd").and_then(Value::as_str).map(str::to_string);
                    originator = payload
                        .get("originator")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }
            }
            "response_item" => {
                if let Some(payload) = value.get("payload") {
                    let payload_type = payload
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if payload_type != "message" {
                        continue;
                    }
                    let role = payload
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or("other");
                    let message_role = MessageRole::from_str(role);
                    if let Some(raw_text) = extract_text(payload.get("content"))? {
                        let text = truncate_with_ellipsis(&raw_text, PREVIEW_CHAR_LIMIT);
                        if first_prompt.is_none() && message_role == MessageRole::User {
                            first_prompt = Some(truncate_with_ellipsis(&text, TITLE_CHAR_LIMIT));
                        }
                        preview_items.push(PreviewMessage { role: message_role, text });
                    }
                }
            }
            _ => {}
        }

        if preview_items.len() >= PREVIEW_LIMIT {
            break;
        }
    }

    let session_id = match session_id {
        Some(id) => id,
        None => return Ok(None),
    };
    let created_at = match created_at {
        Some(ts) => ts,
        None => {
            let metadata = std::fs::metadata(path)?;
            let fallback_time = metadata
                .created()
                .or_else(|_| metadata.modified())
                .unwrap_or(SystemTime::now());
            fallback_time.into()
        }
    };
    let title = first_prompt.or_else(|| {
        preview_items
            .first()
            .map(|msg| truncate_with_ellipsis(&msg.text, TITLE_CHAR_LIMIT))
    });

    Ok(Some(SessionEntry {
        id: session_id,
        file_path: path.to_path_buf(),
        created_at,
        originator,
        instructions,
        cwd,
        title,
        preview_items,
    }))
}

fn extract_text(content_value: Option<&Value>) -> Result<Option<String>> {
    let content = match content_value {
        Some(value) => value,
        None => return Ok(None),
    };

    if let Some(array) = content.as_array() {
        let mut combined = String::new();
        for item in array {
            let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
            match item_type {
                "input_text" | "output_text" | "text" => {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        if !combined.is_empty() {
                            combined.push_str("\n\n");
                        }
                        combined.push_str(text);
                    }
                }
                "tool_use" | "tool_result" => {
                    if let Some(name) = item.get("name").and_then(Value::as_str) {
                        if !combined.is_empty() {
                            combined.push_str("\n\n");
                        }
                        combined.push_str(&format!("[{name}]"));
                    }
                }
                _ => {}
            }
        }
        if combined.is_empty() {
            Ok(None)
        } else {
            Ok(Some(combined))
        }
    } else if let Some(text) = content.get("text").and_then(Value::as_str) {
        Ok(Some(text.to_string()))
    } else {
        Ok(None)
    }
}

fn truncate_with_ellipsis(input: &str, max_len: usize) -> String {
    if input.chars().count() <= max_len {
        return input.to_string();
    }
    let truncated: String = input.chars().take(max_len.saturating_sub(1)).collect();
    format!("{truncated}…")
}

fn codex_sessions_dir() -> Result<PathBuf> {
    let home = dirs_next::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    let sessions_dir = home.join(".codex").join("sessions");
    if !sessions_dir.exists() {
        return Err(anyhow!(
            "No Codex sessions found at {}",
            sessions_dir.display()
        ));
    }
    Ok(sessions_dir)
}

fn resume_session(session_id: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "tell application \"Terminal\"\nactivate\ndo script \"codex resume {}\"\nend tell",
            session_id
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .spawn()
            .with_context(|| "launching macOS Terminal via osascript")?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let command = format!(
            "Start-Process cmd -ArgumentList '/K codex resume {}'",
            session_id
        );
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &command])
            .spawn()
            .with_context(|| "launching Windows terminal with codex resume")?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::process::Command::new("sh")
            .args([
                "-c",
                &format!("(codex resume {} &)", session_id),
            ])
            .spawn()
            .with_context(|| "launching codex resume in shell")?;
        return Ok(());
    }
}
