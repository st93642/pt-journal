//! Terminal interface implementations.
//!
//! This module provides concrete implementations of the TerminalInterface
//! trait, allowing the panel to work with different terminal backends.

use super::interfaces::TerminalInterface;
use vte::TerminalExt;

/// Implementation of TerminalInterface using VTE terminal.
pub struct VteTerminal {
    _terminal: vte::Terminal,
}

impl VteTerminal {
    /// Creates a new VTE terminal interface.
    pub fn new(terminal: vte::Terminal) -> Self {
        Self {
            _terminal: terminal,
        }
    }
}

impl TerminalInterface for VteTerminal {
    fn write(&mut self, text: &str) {
        self._terminal.feed(text.as_bytes());
    }

    fn clear(&mut self) {
        self._terminal.reset(true, true);
    }

    fn execute(&mut self, command: &str) {
        let full_command = format!("{}\n", command);
        self._terminal.feed(full_command.as_bytes());
    }
}
