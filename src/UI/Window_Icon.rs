use ratatui::style::Color;

#[derive(Debug, Clone, Copy)]
pub struct WindowIcons {

    pub minimize: char,

    pub maximize: char,

    pub restore: char,

    pub close: char,

    pub separator: char,
}

impl Default for WindowIcons {
    fn default() -> Self {
        Self::modern()
    }
}

impl WindowIcons {

    pub fn modern() -> Self {
        Self {
            minimize: '─',
            maximize: '□',
            restore: '❐',
            close: '✕',
            separator: '│',
        }
    }

    pub fn ascii() -> Self {
        Self {
            minimize: '_',
            maximize: '#',
            restore: '=',
            close: 'x',
            separator: '|',
        }
    }

    pub fn mac() -> Self {
        Self {
            minimize: '–',
            maximize: '+',
            restore: '=',
            close: '×',
            separator: ' ',
        }
    }

    pub fn caption(&self, maximized: bool) -> String {
        let max = if maximized {
            self.restore
        } else {
            self.maximize
        };
        format!(
            "[{}]{s}[{}]{s}[{}]",
            self.minimize,
            max,
            self.close,
            s = self.separator
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IconTheme {
    pub minimize: Color,
    pub maximize: Color,
    pub close: Color,
    pub separator: Color,
}

impl Default for IconTheme {
    fn default() -> Self {
        Self {
            minimize: Color::Yellow,
            maximize: Color::Green,
            close: Color::Red,
            separator: Color::DarkGray,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptionButton {
    Minimize,
    MaximizeRestore,
    Close,
}
