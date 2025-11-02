/// Tool execution UI components
/// 
/// Provides UI elements for running security tools from tutorial steps:
/// - Tool selection dropdown
/// - Configuration inputs
/// - Execute button
/// - Progress indicators
/// - Result display

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, ComboBoxText, Entry, Label, Orientation, Spinner, TextView};

use crate::tools::*;
use crate::tools::executor::DefaultExecutor;

/// Tool execution panel widget
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub tool_selector: ComboBoxText,
    pub target_entry: Entry,
    pub args_entry: Entry,
    pub execute_button: Button,
    pub spinner: Spinner,
    pub status_label: Label,
    pub output_view: TextView,
}

impl ToolExecutionPanel {
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Vertical, 12);
        container.set_margin_top(12);
        container.set_margin_bottom(12);
        container.set_margin_start(12);
        container.set_margin_end(12);

        // Header
        let header = Label::new(Some("Security Tool Execution"));
        header.add_css_class("title-3");
        container.append(&header);

        // Tool selector
        let tool_box = GtkBox::new(Orientation::Horizontal, 8);
        let tool_label = Label::new(Some("Tool:"));
        tool_label.set_width_chars(10);
        tool_label.set_xalign(0.0);
        
        let tool_selector = ComboBoxText::new();
        tool_selector.append(Some("nmap"), "Nmap - Port Scanner");
        tool_selector.append(Some("gobuster"), "Gobuster - Directory/Subdomain Enum");
        tool_selector.set_active_id(Some("nmap"));
        tool_selector.set_hexpand(true);
        
        tool_box.append(&tool_label);
        tool_box.append(&tool_selector);
        container.append(&tool_box);

        // Target input
        let target_box = GtkBox::new(Orientation::Horizontal, 8);
        let target_label = Label::new(Some("Target:"));
        target_label.set_width_chars(10);
        target_label.set_xalign(0.0);
        
        let target_entry = Entry::new();
        target_entry.set_placeholder_text(Some("e.g., scanme.nmap.org or http://example.com"));
        target_entry.set_hexpand(true);
        
        target_box.append(&target_label);
        target_box.append(&target_entry);
        container.append(&target_box);

        // Arguments input
        let args_box = GtkBox::new(Orientation::Horizontal, 8);
        let args_label = Label::new(Some("Arguments:"));
        args_label.set_width_chars(10);
        args_label.set_xalign(0.0);
        
        let args_entry = Entry::new();
        args_entry.set_placeholder_text(Some("e.g., -p 80,443 -sV"));
        args_entry.set_hexpand(true);
        
        args_box.append(&args_label);
        args_box.append(&args_entry);
        container.append(&args_box);

        // Execute button and spinner
        let button_box = GtkBox::new(Orientation::Horizontal, 8);
        
        let execute_button = Button::with_label("Execute Tool");
        execute_button.add_css_class("suggested-action");
        
        let spinner = Spinner::new();
        spinner.set_visible(false);
        
        let status_label = Label::new(Some("Ready"));
        status_label.set_hexpand(true);
        status_label.set_xalign(0.0);
        
        button_box.append(&execute_button);
        button_box.append(&spinner);
        button_box.append(&status_label);
        container.append(&button_box);

        // Output display
        let output_frame = gtk4::Frame::new(Some("Tool Output"));
        let output_scroll = gtk4::ScrolledWindow::new();
        output_scroll.set_min_content_height(200);
        output_scroll.set_vexpand(true);
        
        let output_view = TextView::new();
        output_view.set_editable(false);
        output_view.set_monospace(true);
        output_view.set_wrap_mode(gtk4::WrapMode::Word);
        output_view.set_margin_top(4);
        output_view.set_margin_bottom(4);
        output_view.set_margin_start(4);
        output_view.set_margin_end(4);
        
        output_scroll.set_child(Some(&output_view));
        output_frame.set_child(Some(&output_scroll));
        container.append(&output_frame);

        Self {
            container,
            tool_selector,
            target_entry,
            args_entry,
            execute_button,
            spinner,
            status_label,
            output_view,
        }
    }

    /// Set the status message
    pub fn set_status(&self, message: &str) {
        self.status_label.set_text(message);
    }

    /// Show/hide the progress spinner
    pub fn set_executing(&self, executing: bool) {
        if executing {
            self.spinner.set_visible(true);
            self.spinner.start();
            self.execute_button.set_sensitive(false);
            self.set_status("Executing...");
        } else {
            self.spinner.stop();
            self.spinner.set_visible(false);
            self.execute_button.set_sensitive(true);
        }
    }

    /// Append text to the output view
    pub fn append_output(&self, text: &str) {
        let buffer = self.output_view.buffer();
        let mut end_iter = buffer.end_iter();
        buffer.insert(&mut end_iter, text);
    }

    /// Clear the output view
    pub fn clear_output(&self) {
        let buffer = self.output_view.buffer();
        buffer.set_text("");
    }

    /// Get the selected tool name
    pub fn get_selected_tool(&self) -> Option<String> {
        self.tool_selector.active_id().map(|s| s.to_string())
    }

    /// Get the target value
    pub fn get_target(&self) -> String {
        self.target_entry.text().to_string()
    }

    /// Get the arguments value
    pub fn get_arguments(&self) -> Vec<String> {
        let args_str = self.args_entry.text().to_string();
        args_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }

    /// Wire up the execute button handler
    pub fn connect_execute<F>(&self, callback: F)
    where
        F: Fn() + 'static,
    {
        self.execute_button.connect_clicked(move |_| {
            callback();
        });
    }

    /// Wire up tool selector change handler
    pub fn connect_tool_changed<F>(&self, callback: F)
    where
        F: Fn(Option<String>) + 'static,
    {
        self.tool_selector.connect_changed(move |combo| {
            let tool_id = combo.active_id().map(|s| s.to_string());
            callback(tool_id);
        });
    }

    /// Update placeholder text based on selected tool
    pub fn update_placeholders(&self, tool_id: &str) {
        match tool_id {
            "nmap" => {
                self.target_entry.set_placeholder_text(Some("e.g., scanme.nmap.org or 192.168.1.1"));
                self.args_entry.set_placeholder_text(Some("e.g., -p 80,443 -sV"));
            }
            "gobuster" => {
                self.target_entry.set_placeholder_text(Some("e.g., http://example.com or example.com"));
                self.args_entry.set_placeholder_text(Some("e.g., -w /path/to/wordlist.txt"));
            }
            _ => {}
        }
    }
}

impl Default for ToolExecutionPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a security tool and return the result
/// Note: This is a simplified synchronous version for now.
/// For true async execution, consider using tokio or async-std.
pub fn execute_tool_sync_wrapper(
    tool_name: &str,
    target: &str,
    arguments: &[String],
) -> Result<ExecutionResult, String> {
    use crate::tools::integrations::nmap::{NmapTool, ScanType};
    use crate::tools::integrations::gobuster::{GobusterTool, GobusterMode};

    // Create executor
    let executor = DefaultExecutor::new();

    // Build config
    let mut config_builder = ToolConfig::builder().target(target);
    
    for arg in arguments {
        config_builder = config_builder.argument(arg);
    }
    
    let config = config_builder
        .build()
        .map_err(|e| format!("Failed to build config: {}", e))?;

    // Select and execute tool
    let result = match tool_name {
        "nmap" => {
            let tool = NmapTool::with_scan_type(ScanType::TcpConnect);
            executor.execute(&tool, &config)
        }
        "gobuster" => {
            let tool = GobusterTool::with_mode(GobusterMode::Dir);
            executor.execute(&tool, &config)
        }
        _ => return Err(format!("Unknown tool: {}", tool_name)),
    };

    result.map_err(|e| format!("Execution failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_execution_panel_creation() {
        // Skip GTK tests in non-graphical environment
        if gtk4::init().is_err() {
            println!("Skipping GTK test - no display available");
            return;
        }

        let panel = ToolExecutionPanel::new();
        assert_eq!(panel.get_target(), "");
        assert_eq!(panel.get_arguments().len(), 0);
    }

    #[test]
    fn test_parse_arguments() {
        if gtk4::init().is_err() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        panel.args_entry.set_text("-p 80,443 -sV");
        
        let args = panel.get_arguments();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "80,443");
        assert_eq!(args[2], "-sV");
    }

    #[test]
    fn test_tool_selection() {
        if gtk4::init().is_err() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        
        // Default should be nmap
        assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));
        
        // Switch to gobuster
        panel.tool_selector.set_active_id(Some("gobuster"));
        assert_eq!(panel.get_selected_tool(), Some("gobuster".to_string()));
    }

    #[test]
    fn test_status_updates() {
        if gtk4::init().is_err() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        
        panel.set_status("Testing status");
        assert_eq!(panel.status_label.text(), "Testing status");
        
        panel.set_executing(true);
        assert!(!panel.execute_button.is_sensitive());
        assert!(panel.spinner.is_visible());
        
        panel.set_executing(false);
        assert!(panel.execute_button.is_sensitive());
        assert!(!panel.spinner.is_visible());
    }

    #[test]
    fn test_output_operations() {
        if gtk4::init().is_err() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        
        panel.append_output("Line 1\n");
        panel.append_output("Line 2\n");
        
        let buffer = panel.output_view.buffer();
        let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
        assert!(text.contains("Line 1"));
        assert!(text.contains("Line 2"));
        
        panel.clear_output();
        let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
        assert_eq!(text, "");
    }
}
