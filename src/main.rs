use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::SystemTime;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use chrono::{DateTime, Local, Utc};
use gpui::prelude::FluentBuilder as _;
#[cfg(target_os = "linux")]
use gpui::StatefulInteractiveElement as _;
use gpui::{
    div, point, px, rgb, size, AnyElement, App, AppContext as _, Application, Bounds, BoxShadow,
    Context, HighlightStyle, Hsla, InteractiveElement as _, IntoElement, MouseButton,
    ParentElement as _, Render, SharedString, Styled as _, StyledText, Window, WindowBounds,
    WindowOptions,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::list::ListItem;
use gpui_component::scroll::ScrollableElement as _;
use gpui_component::{
    h_flex, theme, v_flex, ActiveTheme as _, Disableable as _, PixelsExt as _, Root, StyledExt as _,
};
use serde_json::Value;
use walkdir::WalkDir;

const PREVIEW_LIMIT: usize = 16;
const PREVIEW_CHAR_LIMIT: usize = 600;
const TITLE_CHAR_LIMIT: usize = 80;
const WINDOW_WIDTH_PX: f32 = 1220.0;
const WINDOW_HEIGHT_PX: f32 = 780.0;
const WINDOW_Y_SHIFT_RATIO: f32 = 0.08;
const APP_ID: &str = "com.1000ants.codex-session-manager";
const LIST_PANEL_WIDTH_PX: f32 = 372.0;
const SEARCH_WIDTH_PX: f32 = 760.0;
const TITLE_BLOCKED_PREFIXES: &[&str] = &[
    "# agents.md instructions for",
    "# agents.md",
    "<environment_context>",
    "<permissions instructions>",
    "<instructions>",
    "<app-context>",
    "<collaboration_mode>",
    "<apps_instructions>",
    "<skills_instructions>",
    "<plugins_instructions>",
];

fn main() -> Result<()> {
    let app = Application::new();
    app.run(|cx: &mut App| {
        gpui_component::init(cx);
        cx.activate(true);
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.open_window(window_options(cx), |window, cx| {
            let app = cx.new(|view_cx| SessionManagerApp::new(window, view_cx));
            cx.new(|root_cx| Root::new(app, window, root_cx))
        })
        .expect("failed to open Codex Session Manager window");
    });
    Ok(())
}

fn window_options(cx: &App) -> WindowOptions {
    let window_size = size(px(WINDOW_WIDTH_PX), px(WINDOW_HEIGHT_PX));
    let mut bounds = Bounds::centered(None, window_size, cx);
    let y_shift = WINDOW_HEIGHT_PX * WINDOW_Y_SHIFT_RATIO;
    bounds.origin.y = px((bounds.origin.y.as_f32() - y_shift).max(0.0));

    #[cfg(target_os = "linux")]
    let titlebar = None;
    #[cfg(not(target_os = "linux"))]
    let titlebar = Some(Default::default());

    #[cfg(target_os = "linux")]
    let window_decorations = Some(gpui::WindowDecorations::Client);
    #[cfg(not(target_os = "linux"))]
    let window_decorations = None;

    WindowOptions {
        app_id: Some(APP_ID.to_string()),
        titlebar,
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_decorations,
        ..WindowOptions::default()
    }
}

fn surface_shadow() -> Vec<BoxShadow> {
    vec![BoxShadow {
        color: theme::neutral_950().opacity(0.08),
        offset: point(px(0.0), px(10.0)),
        blur_radius: px(30.0),
        spread_radius: px(-14.0),
    }]
}

#[cfg(target_os = "linux")]
fn render_linux_window_controls(window: &Window) -> AnyElement {
    let button =
        |id: &'static str, label: &'static str, on_click: fn(&mut Window), is_close: bool| {
            div()
                .id(id)
                .flex()
                .w(px(36.0))
                .h_full()
                .items_center()
                .justify_center()
                .text_color(theme::neutral_700())
                .text_sm()
                .font_semibold()
                .hover(|style| {
                    style
                        .bg(if is_close {
                            theme::red_500()
                        } else {
                            theme::neutral_200()
                        })
                        .text_color(gpui::white())
                })
                .active(|style: gpui::StyleRefinement| {
                    style
                        .bg(if is_close {
                            theme::red_600()
                        } else {
                            theme::neutral_300()
                        })
                        .text_color(gpui::white())
                })
                .cursor_pointer()
                .on_mouse_down(MouseButton::Left, |_, window: &mut Window, cx: &mut App| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .on_click(move |_, window: &mut Window, cx: &mut App| {
                    cx.stop_propagation();
                    on_click(window);
                })
                .child(label)
        };

    h_flex()
        .items_center()
        .h_full()
        .child(button(
            "linux-window-minimize",
            "−",
            |window: &mut Window| window.minimize_window(),
            false,
        ))
        .child(button(
            "linux-window-zoom",
            if window.is_maximized() { "❐" } else { "□" },
            |window: &mut Window| window.zoom_window(),
            false,
        ))
        .child(button(
            "linux-window-close",
            "×",
            |window: &mut Window| window.remove_window(),
            true,
        ))
        .into_any_element()
}

#[cfg(not(target_os = "linux"))]
fn render_linux_window_controls(_window: &Window) -> AnyElement {
    div().into_any_element()
}

fn push_soft_wrapped_char(output: &mut String, ch: char) {
    output.push(ch);
    if matches!(ch, '/' | '\\' | '_' | '-' | '>' | '<') {
        output.push('\u{200b}');
    }
}

fn case_insensitive_match_ranges(haystack: &str, needle: &str) -> Vec<Range<usize>> {
    let needle = needle.trim();
    if needle.is_empty() {
        return Vec::new();
    }

    let needle_lower = needle.to_lowercase();
    let mut matches = Vec::new();

    for (start, _) in haystack.char_indices() {
        let mut candidate = String::new();

        for (offset, ch) in haystack[start..].char_indices() {
            candidate.extend(ch.to_lowercase());
            let end = start + offset + ch.len_utf8();

            if candidate == needle_lower {
                matches.push(start..end);
                break;
            }

            if !needle_lower.starts_with(&candidate) {
                break;
            }
        }
    }

    matches
}

fn first_case_insensitive_match_range(haystack: &str, needle: &str) -> Option<Range<usize>> {
    case_insensitive_match_ranges(haystack, needle)
        .into_iter()
        .next()
}

fn soft_wrap_text_with_highlights(
    input: &str,
    ranges: &[Range<usize>],
) -> (String, Vec<Range<usize>>) {
    let mut wrapped = String::new();
    let mut boundary_map = HashMap::new();

    boundary_map.insert(0usize, 0usize);
    for (idx, ch) in input.char_indices() {
        boundary_map.insert(idx, wrapped.len());
        push_soft_wrapped_char(&mut wrapped, ch);
    }
    boundary_map.insert(input.len(), wrapped.len());

    let mapped_ranges = ranges
        .iter()
        .filter_map(|range| {
            Some(
                boundary_map.get(&range.start)?.to_owned()
                    ..boundary_map.get(&range.end)?.to_owned(),
            )
        })
        .collect();

    (wrapped, mapped_ranges)
}

fn search_highlight_style() -> HighlightStyle {
    HighlightStyle {
        background_color: Some(theme::yellow_100().opacity(0.95)),
        ..Default::default()
    }
}

fn highlighted_search_text(text: &str, filter: &str) -> StyledText {
    let ranges = case_insensitive_match_ranges(text, filter);
    let (wrapped, wrapped_ranges) = soft_wrap_text_with_highlights(text, &ranges);
    let styled = StyledText::new(wrapped);

    if wrapped_ranges.is_empty() {
        styled
    } else {
        styled.with_highlights(
            wrapped_ranges
                .into_iter()
                .map(|range| (range, search_highlight_style()))
                .collect::<Vec<_>>(),
        )
    }
}

fn byte_index_for_char_offset(input: &str, char_offset: usize) -> usize {
    input
        .char_indices()
        .nth(char_offset)
        .map(|(idx, _)| idx)
        .unwrap_or(input.len())
}

fn excerpt_around_match(input: &str, range: Range<usize>, context_chars: usize) -> String {
    let match_start_chars = input[..range.start].chars().count();
    let match_end_chars = input[..range.end].chars().count();
    let total_chars = input.chars().count();

    let excerpt_start_chars = match_start_chars.saturating_sub(context_chars);
    let excerpt_end_chars = (match_end_chars + context_chars).min(total_chars);
    let excerpt_start = byte_index_for_char_offset(input, excerpt_start_chars);
    let excerpt_end = byte_index_for_char_offset(input, excerpt_end_chars);

    let mut excerpt = String::new();
    if excerpt_start > 0 {
        excerpt.push('…');
    }
    excerpt.push_str(&input[excerpt_start..excerpt_end]);
    if excerpt_end < input.len() {
        excerpt.push('…');
    }

    excerpt
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
        !case_insensitive_match_ranges(&self.id, filter).is_empty()
            || self
                .title
                .as_deref()
                .map(|title| !case_insensitive_match_ranges(title, filter).is_empty())
                .unwrap_or(false)
            || self
                .cwd
                .as_deref()
                .map(|cwd| !case_insensitive_match_ranges(cwd, filter).is_empty())
                .unwrap_or(false)
            || self
                .originator
                .as_deref()
                .map(|origin| !case_insensitive_match_ranges(origin, filter).is_empty())
                .unwrap_or(false)
            || self
                .preview_items
                .iter()
                .any(|item| !case_insensitive_match_ranges(&item.text, filter).is_empty())
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

    fn has_visible_row_match(&self, filter: &str) -> bool {
        let title = self.display_title();
        !case_insensitive_match_ranges(&title, filter).is_empty()
            || self
                .cwd
                .as_deref()
                .map(|cwd| !case_insensitive_match_ranges(cwd, filter).is_empty())
                .unwrap_or(false)
            || self
                .originator
                .as_deref()
                .map(|origin| !case_insensitive_match_ranges(origin, filter).is_empty())
                .unwrap_or(false)
    }

    fn hidden_match_context(&self, filter: &str) -> Option<String> {
        if filter.trim().is_empty() || self.has_visible_row_match(filter) {
            return None;
        }

        if !case_insensitive_match_ranges(&self.id, filter).is_empty() {
            return Some(format!("Session ID: {}", self.id));
        }

        self.preview_items.iter().find_map(|item| {
            let matched_range = first_case_insensitive_match_range(&item.text, filter)?;
            Some(format!(
                "{}: {}",
                item.role.label(),
                excerpt_around_match(&item.text, matched_range, 34)
            ))
        })
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

    fn section_title(&self) -> &'static str {
        match self {
            Self::User => "Prompt",
            Self::Assistant => "Response",
            Self::System => "System context",
            Self::Tool => "Tool event",
            Self::Other => "Message",
        }
    }

    fn color(&self) -> Hsla {
        match self {
            Self::User => rgb(0x2c6e49).into(),
            Self::Assistant => rgb(0x1f4b99).into(),
            Self::System => rgb(0x753a88).into(),
            Self::Tool => rgb(0x8f5b29).into(),
            Self::Other => rgb(0x444444).into(),
        }
    }
}

struct SessionManagerApp {
    sessions: Vec<SessionEntry>,
    filter: SharedString,
    filter_input: gpui::Entity<InputState>,
    _filter_subscription: gpui::Subscription,
    hovered_session: Option<usize>,
    selected_session: Option<usize>,
    load_error: Option<String>,
    resume_job: Option<ResumeJob>,
    resume_status: Option<ResumeStatus>,
}

impl SessionManagerApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search by title, path, id, origin, or preview text")
                .clean_on_escape()
                .default_value("")
        });
        let filter_subscription = cx.subscribe(
            &filter_input,
            |this, input: gpui::Entity<InputState>, event, cx| {
                if matches!(event, InputEvent::Change) {
                    this.filter = input.read(cx).value();
                    if !this.filter.trim().is_empty() {
                        this.hovered_session = None;
                    }
                    cx.notify();
                }
            },
        );

        let (sessions, load_error) = match load_sessions() {
            Ok(list) => (list, None),
            Err(err) => (
                Vec::new(),
                Some(format!("Failed to load sessions: {err:#}")),
            ),
        };

        Self {
            sessions,
            filter: SharedString::new(""),
            filter_input,
            _filter_subscription: filter_subscription,
            hovered_session: None,
            selected_session: None,
            load_error,
            resume_job: None,
            resume_status: None,
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.sessions
            .iter()
            .enumerate()
            .filter_map(|(idx, session)| {
                session.matches_filter(self.filter.as_ref()).then_some(idx)
            })
            .collect()
    }

    fn preview_idx(&self) -> Option<usize> {
        self.selected_session
    }

    fn can_open_selected_session(&self) -> bool {
        self.selected_session.is_some()
    }

    fn trigger_resume(&mut self, idx: usize) {
        let session_id = self.sessions[idx].id.clone();
        if let Some(job) = &self.resume_job {
            if job.session_id == session_id {
                return;
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

    fn process_resume_job(&mut self, cx: &mut Context<Self>) {
        if let Some(job) = &self.resume_job {
            match job.receiver.try_recv() {
                Ok((session_id, result)) => {
                    self.resume_job = None;
                    self.resume_status = Some(match result {
                        Ok(()) => ResumeStatus::Success(session_id),
                        Err(err) => ResumeStatus::Failure(session_id, format!("{err:#}")),
                    });
                    cx.notify();
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.resume_status = Some(ResumeStatus::Failure(
                        job.session_id.clone(),
                        "Resume task ended unexpectedly".to_string(),
                    ));
                    self.resume_job = None;
                    cx.notify();
                }
            }
        }
    }

    fn clear_filter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.filter = SharedString::new("");
        self.filter_input.update(cx, |input, input_cx| {
            input.set_value("", window, input_cx);
        });
        self.hovered_session = None;
        cx.notify();
    }

    fn render_status_banner(&self) -> Option<gpui::AnyElement> {
        self.resume_status.as_ref().map(|status| {
            let (text, color) = match status {
                ResumeStatus::InFlight(id) => (
                    format!("Launching `codex resume {id}`..."),
                    theme::sky_600(),
                ),
                ResumeStatus::Success(id) => (
                    format!("Opened session {id} in a new terminal window."),
                    theme::green_600(),
                ),
                ResumeStatus::Failure(id, err) => {
                    (format!("Failed to resume {id}: {err}"), theme::red_600())
                }
            };

            div()
                .w_full()
                .rounded_md()
                .border_1()
                .border_color(color.opacity(0.28))
                .bg(color.opacity(0.08))
                .px_3()
                .py_2()
                .text_sm()
                .whitespace_normal()
                .text_color(color)
                .child(text)
                .into_any_element()
        })
    }

    fn render_metadata_pair(
        &self,
        label: &str,
        value: impl Into<String>,
        filter: &str,
    ) -> gpui::AnyElement {
        let label = label.to_string();
        let value = value.into();
        v_flex()
            .w_full()
            .overflow_hidden()
            .gap_1()
            .child(
                div()
                    .w_full()
                    .overflow_hidden()
                    .text_xs()
                    .font_semibold()
                    .text_color(theme::neutral_500())
                    .child(label),
            )
            .child(
                div()
                    .w_full()
                    .overflow_hidden()
                    .text_sm()
                    .whitespace_normal()
                    .text_color(theme::neutral_800())
                    .child(highlighted_search_text(&value, filter)),
            )
            .into_any_element()
    }

    fn render_card(
        &self,
        eyebrow: &str,
        title: impl IntoElement,
        content: impl IntoElement,
    ) -> gpui::AnyElement {
        let eyebrow = eyebrow.to_string();
        v_flex()
            .w_full()
            .overflow_hidden()
            .gap_3()
            .rounded_xl()
            .border_1()
            .border_color(theme::neutral_200())
            .bg(gpui::white())
            .shadow(surface_shadow())
            .p_4()
            .child(
                v_flex()
                    .w_full()
                    .overflow_hidden()
                    .gap_1()
                    .child(
                        div()
                            .w_full()
                            .overflow_hidden()
                            .text_xs()
                            .font_semibold()
                            .text_color(theme::sky_700())
                            .child(eyebrow),
                    )
                    .child(
                        div()
                            .w_full()
                            .overflow_hidden()
                            .text_base()
                            .font_semibold()
                            .text_color(theme::neutral_950())
                            .whitespace_normal()
                            .child(title),
                    ),
            )
            .child(div().w_full().overflow_hidden().child(content))
            .into_any_element()
    }

    fn render_session_row(
        &self,
        session_idx: usize,
        entity: gpui::Entity<Self>,
    ) -> gpui::AnyElement {
        let session = &self.sessions[session_idx];
        let title = session.display_title();
        let filter = self.filter.as_ref();
        let timestamp = session
            .created_at
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M")
            .to_string();

        ListItem::new(("session", session_idx))
            .selected(self.selected_session == Some(session_idx))
            .on_mouse_enter({
                let entity = entity.clone();
                move |_, _, app| {
                    let _ = entity.update(app, |this, cx| {
                        if this.hovered_session != Some(session_idx) {
                            this.hovered_session = Some(session_idx);
                            cx.notify();
                        }
                    });
                }
            })
            .on_click({
                let entity = entity.clone();
                move |_, _, app| {
                    let _ = entity.update(app, |this, cx| {
                        this.hovered_session = Some(session_idx);
                        this.selected_session = Some(session_idx);
                        cx.notify();
                    });
                }
            })
            .child(
                v_flex()
                    .w_full()
                    .gap_1()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .whitespace_normal()
                            .line_clamp(2)
                            .text_color(theme::neutral_950())
                            .child(highlighted_search_text(&title, filter)),
                    )
                    .when_some(session.cwd.as_ref(), |this, cwd| {
                        this.child(
                            div()
                                .text_xs()
                                .whitespace_normal()
                                .line_clamp(1)
                                .text_color(theme::neutral_500())
                                .child(highlighted_search_text(cwd, filter)),
                        )
                    })
                    .when_some(session.hidden_match_context(filter), |this, context| {
                        this.child(
                            div()
                                .text_xs()
                                .whitespace_normal()
                                .line_clamp(2)
                                .text_color(theme::sky_700())
                                .child(highlighted_search_text(&context, filter)),
                        )
                    })
                    .child(
                        h_flex()
                            .w_full()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme::neutral_500())
                                    .child(timestamp),
                            )
                            .when_some(session.originator.as_ref(), |this, originator| {
                                this.child(
                                    div()
                                        .rounded_full()
                                        .bg(theme::neutral_100())
                                        .px_2()
                                        .py_1()
                                        .text_xs()
                                        .text_color(theme::neutral_600())
                                        .child(highlighted_search_text(originator, filter)),
                                )
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_empty_preview(&self) -> gpui::AnyElement {
        v_flex()
            .size_full()
            .w_full()
            .overflow_hidden()
            .items_start()
            .justify_start()
            .child(self.render_card("Preview", "No Session Selected", div()))
            .into_any_element()
    }

    fn render_session_preview(&self, idx: usize) -> gpui::AnyElement {
        let session = &self.sessions[idx];
        let filter = self.filter.as_ref();
        let formatted_time = session
            .created_at
            .with_timezone(&Local)
            .format("%A, %d %B %Y %H:%M:%S")
            .to_string();
        let overview_card = self.render_card(
            "Session Overview",
            highlighted_search_text(&session.display_title(), filter),
            v_flex()
                .w_full()
                .gap_4()
                .child(
                    div()
                        .w_full()
                        .text_sm()
                        .whitespace_normal()
                        .text_color(theme::neutral_600())
                        .child("Metadata is separated from the transcript so the message timeline stays easier to scan."),
                )
                .child(
                    v_flex()
                        .w_full()
                        .gap_3()
                        .child(self.render_metadata_pair("Session ID", session.id.clone(), filter))
                        .child(self.render_metadata_pair("Created", formatted_time, filter))
                        .when_some(session.originator.as_ref(), |this, originator| {
                            this.child(self.render_metadata_pair("Origin", originator.clone(), filter))
                        })
                        .when_some(session.cwd.as_ref(), |this, cwd| {
                            this.child(self.render_metadata_pair(
                                "Working Directory",
                                cwd.clone(),
                                filter,
                            ))
                        })
                        .child(self.render_metadata_pair(
                            "Session File",
                            session.file_path.display().to_string(),
                            filter,
                        )),
                )
                .when_some(session.instructions.as_ref(), |this, instructions| {
                    if instructions.trim().is_empty() {
                        this
                    } else {
                        this.child(
                            v_flex()
                                .w_full()
                                .gap_2()
                                .child(
                                    div()
                                        .w_full()
                                        .text_sm()
                                        .font_semibold()
                                        .text_color(theme::neutral_800())
                                        .child("Instructions"),
                                )
                                .child(
                                    div()
                                        .w_full()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(theme::neutral_200())
                                        .bg(theme::neutral_50())
                                        .px_3()
                                        .py_3()
                                        .text_sm()
                                        .whitespace_normal()
                                        .text_color(theme::neutral_700())
                                        .child(highlighted_search_text(instructions, filter)),
                                ),
                        )
                    }
                }),
        );

        v_flex()
            .size_full()
            .w_full()
            .min_h_0()
            .overflow_hidden()
            .child(
                div()
                    .w_full()
                    .flex_1()
                    .min_h_0()
                    .overflow_hidden()
                    .overflow_y_scrollbar()
                    .child(
                        v_flex()
                            .w_full()
                            .overflow_hidden()
                            .gap_4()
                            .child(overview_card)
                            .children(session.preview_items.iter().map(|message| {
                                self.render_card(
                                    message.role.label(),
                                    message.role.section_title(),
                                    v_flex()
                                        .w_full()
                                        .overflow_hidden()
                                        .gap_3()
                                        .child(
                                            div()
                                                .w_full()
                                                .overflow_hidden()
                                                .text_xs()
                                                .font_semibold()
                                                .text_color(message.role.color())
                                                .child(message.role.label()),
                                        )
                                        .child(
                                            div()
                                                .w_full()
                                                .overflow_hidden()
                                                .text_sm()
                                                .whitespace_normal()
                                                .text_color(theme::neutral_800())
                                                .child(highlighted_search_text(&message.text, filter)),
                                        ),
                                )
                            })),
                    ),
            )
            .when(session.preview_items.is_empty(), |this| {
                this.child(
                    self.render_card(
                        "Messages",
                        "No preview messages",
                        div()
                            .text_sm()
                            .whitespace_normal()
                            .text_color(theme::neutral_600())
                            .child("This session exists, but there were no previewable conversation messages in the first parsed records."),
                    ),
                )
            })
            .into_any_element()
    }
}

impl Render for SessionManagerApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.process_resume_job(cx);

        if self.resume_job.is_some() {
            cx.on_next_frame(window, |_, _, cx| {
                cx.notify();
            });
        }

        let filtered_indices = self.filtered_indices();
        let entity = cx.entity();

        div()
            .size_full()
            .bg(theme::neutral_50())
            .text_color(cx.theme().foreground)
            .child(
                v_flex()
                    .size_full()
                    .min_h_0()
                    .gap_5()
                    .when(cfg!(target_os = "linux"), |this| {
                        this.child(
                            div()
                                .h(px(40.0))
                                .bg(gpui::white())
                                .border_b_1()
                                .border_color(theme::neutral_200())
                                .on_mouse_down(MouseButton::Left, |_, window: &mut Window, _| {
                                    window.start_window_move();
                                })
                                .child(
                                    h_flex()
                                        .size_full()
                                        .items_center()
                                        .justify_between()
                                        .child(div().w(px(108.0)))
                                        .child(
                                            div()
                                                .flex_1()
                                                .flex()
                                                .justify_center()
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .font_semibold()
                                                        .text_color(theme::neutral_700())
                                                        .child("Codex Session Manager"),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .h_full()
                                                .items_center()
                                                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                                                    window.prevent_default();
                                                    cx.stop_propagation();
                                                })
                                                .child(render_linux_window_controls(window)),
                                        ),
                                ),
                        )
                    })
                    .p_5()
                    .child(
                        div()
                            .w_full()
                            .rounded_xl()
                            .border_1()
                            .border_color(theme::neutral_200())
                            .bg(gpui::white())
                            .shadow(surface_shadow())
                            .px_5()
                            .pb_4()
                            .pt_4()
                            .child(
                                v_flex()
                                    .w_full()
                                    .gap_4()
                                    .child(
                                        v_flex()
                                            .w_full()
                                            .gap_2()
                                            .child(
                                                v_flex()
                                                    .gap_2()
                                                    .child(
                                                        h_flex()
                                                            .w_full()
                                                            .items_center()
                                                            .gap_2()
                                                            .child(
                                                                div()
                                                                    .rounded_full()
                                                                    .bg(theme::sky_100())
                                                                    .px_3()
                                                                    .py_1()
                                                                    .text_xs()
                                                                    .font_semibold()
                                                                    .text_color(theme::sky_700())
                                                                    .child("Codex Session Manager"),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(theme::neutral_500())
                                                                    .child("Desktop session browser"),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .max_w(px(1040.0))
                                                            .text_sm()
                                                            .text_color(theme::neutral_600())
                                                            .whitespace_normal()
                                                            .child("Browse and Resume Sessions. Scan local Codex transcripts, preview them in wrapped cards, and jump back into a session without digging through raw JSONL files."),
                                                    ),
                                            )
                                            .child(
                                                v_flex()
                                                    .w_full()
                                                    .gap_2()
                                                    .rounded_lg()
                                                    .border_1()
                                                    .border_color(theme::neutral_200())
                                                    .bg(gpui::white())
                                                    .p_3()
                                                    .max_w(px(SEARCH_WIDTH_PX))
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .font_semibold()
                                                            .text_color(theme::neutral_500())
                                                            .child("Search"),
                                                    )
                                                    .child(
                                                        h_flex()
                                                            .w_full()
                                                            .items_center()
                                                            .gap_2()
                                                            .child(
                                                                div()
                                                                    .flex_1()
                                                                    .child(Input::new(&self.filter_input)),
                                                            )
                                                            .child(
                                                                Button::new("clear-filter")
                                                                    .outline()
                                                                    .label("Clear")
                                                                    .disabled(self.filter.trim().is_empty())
                                                                    .on_click(cx.listener(|this, _, window, cx| {
                                                                        this.clear_filter(window, cx);
                                                                    })),
                                                            ),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .whitespace_normal()
                                                            .text_color(theme::neutral_500())
                                                            .child("Filter by title, path, session id, origin, or preview text."),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        h_flex()
                                            .w_full()
                                            .items_center()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                h_flex()
                                                    .items_center()
                                                    .gap_2()
                                                    .child(
                                                        div()
                                                            .rounded_lg()
                                                            .bg(theme::neutral_100())
                                                            .px_3()
                                                            .py_2()
                                                            .text_sm()
                                                            .font_semibold()
                                                            .text_color(theme::neutral_800())
                                                            .child(format!(
                                                                "{} matching session{}",
                                                                filtered_indices.len(),
                                                                if filtered_indices.len() == 1 { "" } else { "s" }
                                                            )),
                                                    )
                                                    .when(self.selected_session.is_some(), |this| {
                                                        this.child(
                                                            div()
                                                                .rounded_lg()
                                                                .bg(theme::sky_50())
                                                                .px_3()
                                                                .py_2()
                                                                .text_sm()
                                                                .text_color(theme::sky_700())
                                                                .child("Selection ready"),
                                                        )
                                                    }),
                                            ),
                                    )
                                    .when_some(self.render_status_banner(), |this, banner| this.child(banner))
                                    .when_some(self.load_error.as_ref(), |this, error| {
                                        this.child(
                                            div()
                                                .rounded_md()
                                                .border_1()
                                                .border_color(theme::red_300())
                                                .bg(theme::red_50())
                                                .px_3()
                                                .py_2()
                                                .text_sm()
                                                .whitespace_normal()
                                                .text_color(theme::red_700())
                                                .child(error.clone()),
                                        )
                                    }),
                            ),
                    )
                    .child(
                        h_flex()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .gap_5()
                            .child(
                                v_flex()
                                    .w(px(LIST_PANEL_WIDTH_PX))
                                    .h_full()
                                    .min_h_0()
                                    .rounded_xl()
                                    .border_1()
                                    .border_color(theme::neutral_200())
                                    .bg(gpui::white())
                                    .shadow(surface_shadow())
                                    .child(
                                        v_flex()
                                            .gap_0()
                                            .px_4()
                                            .py_4()
                                            .border_b_1()
                                            .border_color(theme::neutral_200())
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_semibold()
                                                    .text_color(theme::neutral_950())
                                                    .child("Session Navigator"),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_h_0()
                                            .overflow_y_scrollbar()
                                            .child(
                                                v_flex()
                                                    .w_full()
                                                    .gap_2()
                                                    .p_3()
                                                    .when(filtered_indices.is_empty(), |this| {
                                                        this.child(
                                                            div()
                                                                .rounded_md()
                                                                .bg(theme::neutral_100())
                                                                .px_3()
                                                                .py_3()
                                                                .text_sm()
                                                                .whitespace_normal()
                                                                .text_color(theme::neutral_600())
                                                                .child("No sessions matched the current filter."),
                                                        )
                                                    })
                                                    .children(filtered_indices.into_iter().map(|session_idx| {
                                                        self.render_session_row(session_idx, entity.clone())
                                                    })),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .h_full()
                                    .min_h_0()
                                    .w_full()
                                    .overflow_hidden()
                                    .child(
                                        v_flex()
                                            .size_full()
                                            .w_full()
                                            .min_h_0()
                                            .gap_3()
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_h_0()
                                                    .w_full()
                                                    .overflow_hidden()
                                                    .child(self.preview_idx().map_or_else(
                                                        || self.render_empty_preview(),
                                                        |idx| self.render_session_preview(idx),
                                                    )),
                                            )
                                            .child(
                                                h_flex()
                                                    .w_full()
                                                    .justify_end()
                                                    .items_center()
                                                    .child(
                                                        Button::new("open-session-in-codex")
                                                            .primary()
                                                            .label("Open Session in Codex")
                                                            .disabled(!self.can_open_selected_session())
                                                            .on_click(cx.listener(|this, _, _, cx| {
                                                                if let Some(idx) = this.selected_session {
                                                                    this.trigger_resume(idx);
                                                                    cx.notify();
                                                                }
                                                            })),
                                                    ),
                                            ),
                                    ),
                            ),
                    ),
            )
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
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
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
                    cwd = payload
                        .get("cwd")
                        .and_then(Value::as_str)
                        .map(str::to_string);
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
                            first_prompt = derive_title_candidate(&raw_text);
                        }
                        preview_items.push(PreviewMessage {
                            role: message_role,
                            text,
                        });
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
            .iter()
            .find_map(|msg| derive_title_candidate(&msg.text))
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

fn derive_title_candidate(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if TITLE_BLOCKED_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return None;
    }

    let candidate = trimmed.lines().map(str::trim).find(|line| {
        !line.is_empty()
            && *line != "<image>"
            && *line != "</image>"
            && !line.starts_with("```")
            && !line.starts_with("![")
    })?;

    let normalized = normalize_title_line(candidate);
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(truncate_with_ellipsis(&collapsed, TITLE_CHAR_LIMIT))
    }
}

fn normalize_title_line(input: &str) -> String {
    let mut remaining = input;
    let mut normalized = String::new();

    while let Some(label_start) = remaining.find('[') {
        normalized.push_str(&remaining[..label_start]);
        let after_label_start = &remaining[label_start + 1..];

        let Some(label_end) = after_label_start.find(']') else {
            normalized.push_str(&remaining[label_start..]);
            return normalized;
        };

        let label = &after_label_start[..label_end];
        let after_label = &after_label_start[label_end + 1..];

        if let Some(link_target) = after_label.strip_prefix('(') {
            if let Some(link_end) = link_target.find(')') {
                let target = &link_target[..link_end];
                if target.starts_with("app://")
                    || target.starts_with("plugin://")
                    || target.starts_with('/')
                {
                    normalized.push_str(label.trim_start_matches('$'));
                    remaining = &link_target[link_end + 1..];
                    continue;
                }
            }
        }

        normalized.push('[');
        normalized.push_str(label);
        normalized.push(']');
        remaining = after_label;
    }

    normalized.push_str(remaining);
    normalized
}

fn codex_sessions_dir() -> Result<PathBuf> {
    let home =
        dirs_next::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
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
            .args(["-c", &format!("(codex resume {} &)", session_id)])
            .spawn()
            .with_context(|| "launching codex resume in shell")?;
        return Ok(());
    }
}
