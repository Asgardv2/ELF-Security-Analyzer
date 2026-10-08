#![allow(non_snake_case)]

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::io::Stdout;

use super::Window_Icon::{CaptionButton, IconTheme, WindowIcons};
use crate::analyzer::AnalysisReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowState {

    #[default]
    Normal,

    Maximized,

    Minimized,

    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAction {
    None,
    Minimize,
    ToggleMaximize,
    Close,
    NextTab,
    PrevTab,
    ScrollUp,
    ScrollDown,
}

pub struct Window {
    pub title: String,
    pub icons: WindowIcons,
    pub theme: IconTheme,
    pub state: WindowState,
    pub focused: bool,

    pub tab: usize,

    pub scroll: u16,
    pub tab_titles: Vec<String>,
}

impl Window {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            icons: WindowIcons::modern(),
            theme: IconTheme::default(),
            state: WindowState::Normal,
            focused: true,
            tab: 0,
            scroll: 0,
            tab_titles: vec![
                "Overview".into(),
                "Security".into(),
                "Sections".into(),
                "Symbols".into(),
                "Imports".into(),
                "Dynamic".into(),
                "Headers".into(),
            ],
        }
    }

    pub fn with_icons(mut self, icons: WindowIcons) -> Self {
        self.icons = icons;
        self
    }

    pub fn is_closed(&self) -> bool {
        self.state == WindowState::Closed
    }

    pub fn apply(&mut self, action: WindowAction) {
        match action {
            WindowAction::Minimize => {
                self.state = if self.state == WindowState::Minimized {
                    WindowState::Normal
                } else {
                    WindowState::Minimized
                };
            }
            WindowAction::ToggleMaximize => {
                self.state = if self.state == WindowState::Maximized {
                    WindowState::Normal
                } else {
                    WindowState::Maximized
                };
            }
            WindowAction::Close => self.state = WindowState::Closed,
            WindowAction::NextTab => {
                self.tab = (self.tab + 1) % self.tab_titles.len();
                self.scroll = 0;
            }
            WindowAction::PrevTab => {
                self.tab = self
                    .tab
                    .checked_sub(1)
                    .unwrap_or(self.tab_titles.len() - 1);
                self.scroll = 0;
            }
            WindowAction::ScrollUp => self.scroll = self.scroll.saturating_sub(1),
            WindowAction::ScrollDown => self.scroll = self.scroll.saturating_add(1),
            WindowAction::None => {}
        }
    }

    pub fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> WindowAction {
        let ctrl = mods.contains(KeyModifiers::CONTROL);
        let act = match (code, ctrl) {
            (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => WindowAction::Close,
            (KeyCode::Char('X'), _) => WindowAction::Close,
            (KeyCode::Char('c'), true) => WindowAction::Close,
            (KeyCode::Char('m'), _) => WindowAction::Minimize,
            (KeyCode::Char('M'), _) => WindowAction::ToggleMaximize,
            (KeyCode::F(11), _) => WindowAction::ToggleMaximize,
            (KeyCode::Tab, _) => WindowAction::NextTab,
            (KeyCode::BackTab, _) => WindowAction::PrevTab,
            (KeyCode::Right, _) | (KeyCode::Char('l'), _) => WindowAction::NextTab,
            (KeyCode::Left, _) | (KeyCode::Char('h'), _) => WindowAction::PrevTab,
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => WindowAction::ScrollDown,
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => WindowAction::ScrollUp,
            (KeyCode::PageDown, _) => {
                self.scroll = self.scroll.saturating_add(10);
                WindowAction::None
            }
            (KeyCode::PageUp, _) => {
                self.scroll = self.scroll.saturating_sub(10);
                WindowAction::None
            }
            _ => WindowAction::None,
        };
        self.apply(act);
        act
    }

    pub fn hit_test(&self, title_area: Rect, x: u16) -> Option<CaptionButton> {

        if x < title_area.x + title_area.width.saturating_sub(11) {
            return None;
        }
        let rel = x - (title_area.x + title_area.width.saturating_sub(11));
        match rel {
            0..=2 => Some(CaptionButton::Minimize),
            4..=6 => Some(CaptionButton::MaximizeRestore),
            8..=10 => Some(CaptionButton::Close),
            _ => None,
        }
    }

    pub fn outer_rect(&self, area: Rect) -> Rect {
        match self.state {
            WindowState::Maximized | WindowState::Closed => area,
            WindowState::Minimized => Rect {
                height: 3,
                ..centered_rect(area, 90, 3)
            },
            WindowState::Normal => centered_rect(area, 92, 90),
        }
    }

    pub fn title_line(&self) -> Line<'static> {
        let maximized = self.state == WindowState::Maximized;
        let max_glyph = if maximized {
            self.icons.restore
        } else {
            self.icons.maximize
        };
        let title_style = Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);
        vec![
            Span::styled(" ◢ ", Style::default().fg(Color::Cyan)),
            Span::styled(self.title.clone(), title_style),
            Span::raw("  "),
            Span::styled(
                format!("[{}]", self.icons.minimize),
                Style::default().fg(self.theme.minimize),
            ),
            Span::styled(
                self.icons.separator.to_string(),
                Style::default().fg(self.theme.separator),
            ),
            Span::styled(
                format!("[{}]", max_glyph),
                Style::default().fg(self.theme.maximize),
            ),
            Span::styled(
                self.icons.separator.to_string(),
                Style::default().fg(self.theme.separator),
            ),
            Span::styled(
                format!("[{}]", self.icons.close),
                Style::default()
                    .fg(self.theme.close)
                    .add_modifier(Modifier::BOLD),
            ),
        ]
        .into()
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, body: &Paragraph) {
        let outer = self.outer_rect(area);
        frame.render_widget(Clear, outer);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if self.focused {
                Color::Cyan
            } else {
                Color::DarkGray
            }))
            .title(self.title_line())
            .title_alignment(ratatui::layout::Alignment::Left);
        let inner = block.inner(outer);
        frame.render_widget(block, outer);
        if self.state == WindowState::Minimized {
            return;
        }
        frame.render_widget(body, inner);
    }
}

fn centered_rect(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(popup[1])[1]
}

pub fn window_frame(title: &str, body: &str) -> String {
    window_frame_with_icons(title, body, &WindowIcons::modern())
}

pub fn window_frame_with_icons(title: &str, body: &str, icons: &WindowIcons) -> String {
    let maximized = false;
    let max_glyph = if maximized {
        icons.restore
    } else {
        icons.maximize
    };
    let caption = format!(
        "[{}]{}[{}]{}[{}]",
        icons.minimize, icons.separator, max_glyph, icons.separator, icons.close
    );
    let body_lines: Vec<&str> = body.lines().collect();
    let width = body_lines
        .iter()
        .map(|l| l.chars().count())
        .chain(std::iter::once(title.chars().count() + caption.chars().count() + 8))
        .max()
        .unwrap_or(40)
        .clamp(40, 120);

    let mut out = String::new();

    let top_left = format!("┌─ ◢ {} ", title);
    let top_right = format!(" {} ─┐", caption);
    let fill = width.saturating_sub(top_left.chars().count() + top_right.chars().count());
    out.push_str(&top_left);
    out.push_str(&"─".repeat(fill));
    out.push_str(&top_right);
    out.push('\n');
    for line in body_lines {
        let len = line.chars().count();
        let pad = width.saturating_sub(len);
        out.push_str("│ ");
        out.push_str(line);
        out.push_str(&" ".repeat(pad.saturating_sub(2)));
        out.push_str(" │\n");
    }
    out.push('└');
    out.push_str(&"─".repeat(width));
    out.push('┘');
    out
}

pub fn run_tui(report: &AnalysisReport) -> Result<()> {
    use crossterm::{
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    };

    struct TuiGuard;
    impl Drop for TuiGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        }
    }

    enable_raw_mode()?;
    let _guard = TuiGuard;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut window = Window::new(format!("elfscope — {}", report.file));
    let res = event_loop(&mut terminal, &mut window, report);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    std::mem::forget(_guard);
    res
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    window: &mut Window,
    report: &AnalysisReport,
) -> Result<()> {
    use std::time::Duration;
    loop {
        terminal.draw(|f| {
            let area = f.area();
            let outer = window.outer_rect(area);
            f.render_widget(Clear, outer);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(window.title_line());
            let inner = block.inner(outer);
            f.render_widget(block, outer);

            if window.state == WindowState::Minimized {
                return;
            }

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(1)])
                .split(inner);

            let mut spans = Vec::new();
            for (i, t) in window.tab_titles.iter().enumerate() {
                let style = if i == window.tab {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                spans.push(Span::styled(format!(" {} ", t), style));
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                "  [Tab] tabs [j/k] scroll [m] min [M] max [q] close",
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);

            let text = tab_text(report, window.tab);
            let total = text.lines().count() as u16;
            let visible = chunks[1].height.max(1);
            let max_scroll = total.saturating_sub(visible);
            window.scroll = window.scroll.min(max_scroll);
            let body = Paragraph::new(text)
                .style(Style::default().fg(Color::White))
                .scroll((window.scroll, 0))
                .wrap(Wrap { trim: false });
            f.render_widget(body, chunks[1]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(k) if k.kind != event::KeyEventKind::Release => {
                    window.handle_key(k.code, k.modifiers);
                    if window.is_closed() {
                        break;
                    }
                }
                Event::Mouse(m) => {
                    use crossterm::event::{MouseButton, MouseEventKind};
                    if let MouseEventKind::Down(MouseButton::Left) = m.kind {

                        if let Ok(size) = terminal.size() {
                            let area = Rect {
                                x: 0,
                                y: 0,
                                width: size.width,
                                height: size.height,
                            };
                            let outer = window.outer_rect(area);
                            if let Some(btn) = window.hit_test(
                                Rect {
                                    x: outer.x,
                                    y: outer.y,
                                    width: outer.width,
                                    height: 1,
                                },
                                m.column,
                            ) {
                                match btn {
                                    CaptionButton::Minimize => {
                                        window.apply(WindowAction::Minimize)
                                    }
                                    CaptionButton::MaximizeRestore => {
                                        window.apply(WindowAction::ToggleMaximize)
                                    }
                                    CaptionButton::Close => break,
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if window.is_closed() {
            break;
        }
    }
    Ok(())
}

fn tab_text(report: &AnalysisReport, tab: usize) -> String {
    match tab {
        0 => crate::output::overview_text(report),
        1 => crate::output::security_text(&report.security),
        2 => crate::output::sections_text(&report.sections),
        3 => crate::output::symbols_text(&report.symbols, 200),
        4 => crate::output::imports_text(&report.imports, &report.libraries),
        5 => crate::output::dynamic_text(&report.dynamic),
        6 => crate::output::headers_text(report),
        _ => String::new(),
    }
}
