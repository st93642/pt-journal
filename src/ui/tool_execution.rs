/// Tool execution UI components
///
/// Provides UI elements for running security tools from tutorial steps:
/// - Tool selection dropdown
/// - Configuration inputs
/// - Execute button
/// - Progress indicators
/// - Embedded terminal for output
use gtk4::prelude::*;
use gtk4::glib;
use vte::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Box as GtkBox, Button, ComboBoxText, Dialog, Entry, Label, Orientation, PasswordEntry,
    ResponseType, Spinner, ProgressBar,
};

use crate::tools::executor::DefaultExecutor;
use crate::tools::*;
use std::process::{Command, Stdio};

/// Tool execution panel widget
#[allow(deprecated)]
#[derive(Clone)]
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub tool_selector: ComboBoxText,
    pub target_entry: Entry,
    pub args_entry: Entry,
    pub execute_button: Button,
    pub cancel_button: Button,
    pub info_button: Button,
    pub spinner: Spinner,
    pub progress_bar: ProgressBar,
    pub status_label: Label,
    pub terminal: vte::Terminal,
}

#[allow(deprecated)]
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

        // Execute button, cancel button, and spinner
        let button_box = GtkBox::new(Orientation::Horizontal, 8);

        let execute_button = Button::with_label("Execute Tool");
        execute_button.add_css_class("suggested-action");

        let cancel_button = Button::with_label("Cancel");
        cancel_button.add_css_class("destructive-action");
        cancel_button.set_visible(false); // Hidden until execution starts

        let info_button = Button::with_label("ℹ️ Instructions");
        info_button.add_css_class("flat");

        let spinner = Spinner::new();
        spinner.set_visible(false);

        let status_label = Label::new(Some("Ready"));
        status_label.set_hexpand(true);
        status_label.set_xalign(0.0);

        button_box.append(&execute_button);
        button_box.append(&cancel_button);
        button_box.append(&info_button);
        button_box.append(&spinner);
        button_box.append(&status_label);
        container.append(&button_box);

        // Progress bar
        let progress_bar = ProgressBar::new();
        progress_bar.set_visible(false);
        progress_bar.set_show_text(true);
        container.append(&progress_bar);

        // Embedded Terminal
        let terminal_frame = gtk4::Frame::new(Some("Terminal"));
        let terminal_scroll = gtk4::ScrolledWindow::new();
        terminal_scroll.set_min_content_height(300);
        terminal_scroll.set_vexpand(true);
        terminal_scroll.set_hexpand(true);

        let terminal = vte::Terminal::new();
        terminal.set_scroll_on_output(true);
        terminal.set_scroll_on_keystroke(true);
        terminal.set_scrollback_lines(10000);
        terminal.set_mouse_autohide(true);
        
        // Set terminal colors (dark theme with better visibility)
        // Foreground and background
        let fg = gtk4::gdk::RGBA::new(0.9, 0.9, 0.9, 1.0);  // Light gray text
        let bg = gtk4::gdk::RGBA::new(0.12, 0.12, 0.12, 1.0);  // Dark gray background
        terminal.set_color_foreground(&fg);
        terminal.set_color_background(&bg);
        
        // Set 16-color palette for better visibility
        // This matches common terminal color schemes but with better contrast
        let palette = [
            // Normal colors (0-7)
            gtk4::gdk::RGBA::new(0.2, 0.2, 0.2, 1.0),      // 0: Black
            gtk4::gdk::RGBA::new(0.8, 0.3, 0.3, 1.0),      // 1: Red
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.4, 1.0),      // 2: Green
            gtk4::gdk::RGBA::new(0.8, 0.8, 0.3, 1.0),      // 3: Yellow
            gtk4::gdk::RGBA::new(0.4, 0.7, 1.0, 1.0),      // 4: Blue (directories) - Bright cyan-blue
            gtk4::gdk::RGBA::new(0.8, 0.4, 0.8, 1.0),      // 5: Magenta
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.8, 1.0),      // 6: Cyan
            gtk4::gdk::RGBA::new(0.85, 0.85, 0.85, 1.0),   // 7: White
            // Bright colors (8-15)
            gtk4::gdk::RGBA::new(0.4, 0.4, 0.4, 1.0),      // 8: Bright Black (Gray)
            gtk4::gdk::RGBA::new(1.0, 0.4, 0.4, 1.0),      // 9: Bright Red
            gtk4::gdk::RGBA::new(0.5, 1.0, 0.5, 1.0),      // 10: Bright Green
            gtk4::gdk::RGBA::new(1.0, 1.0, 0.5, 1.0),      // 11: Bright Yellow
            gtk4::gdk::RGBA::new(0.5, 0.8, 1.0, 1.0),      // 12: Bright Blue (also directories)
            gtk4::gdk::RGBA::new(1.0, 0.5, 1.0, 1.0),      // 13: Bright Magenta
            gtk4::gdk::RGBA::new(0.5, 1.0, 1.0, 1.0),      // 14: Bright Cyan
            gtk4::gdk::RGBA::new(1.0, 1.0, 1.0, 1.0),      // 15: Bright White
        ];
        let palette_refs: Vec<&gtk4::gdk::RGBA> = palette.iter().collect();
        terminal.set_colors(Some(&fg), Some(&bg), &palette_refs);
        
        // Add right-click context menu for copy/paste
        let right_click = gtk4::GestureClick::new();
        right_click.set_button(3); // Right mouse button
        
        let terminal_clone = terminal.clone();
        right_click.connect_pressed(move |_gesture, _n_press, x, y| {
            // Create context menu
            let menu = gtk4::gio::Menu::new();
            
            // Copy menu item
            menu.append(Some("Copy"), Some("terminal.copy"));
            
            // Paste menu item  
            menu.append(Some("Paste"), Some("terminal.paste"));
            
            // Create popover menu
            let popover = gtk4::PopoverMenu::from_model(Some(&menu));
            popover.set_parent(&terminal_clone);
            popover.set_has_arrow(false);
            popover.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            
            // Add action group for the terminal
            let action_group = gtk4::gio::SimpleActionGroup::new();
            
            // Copy action - using VTE's copy_clipboard_format
            let copy_action = gtk4::gio::SimpleAction::new("copy", None);
            let terminal_copy = terminal_clone.clone();
            copy_action.connect_activate(move |_, _| {
                terminal_copy.copy_clipboard_format(vte::Format::Text);
            });
            action_group.add_action(&copy_action);
            
            // Paste action
            let paste_action = gtk4::gio::SimpleAction::new("paste", None);
            let terminal_paste = terminal_clone.clone();
            paste_action.connect_activate(move |_, _| {
                terminal_paste.paste_clipboard();
            });
            action_group.add_action(&paste_action);
            
            // Insert action group
            terminal_clone.insert_action_group("terminal", Some(&action_group));
            
            popover.popup();
        });
        
        terminal.add_controller(right_click);
        
        // Spawn a shell in the terminal
        terminal.spawn_async(
            vte::PtyFlags::DEFAULT,
            None, // working directory (use current)
            &["/bin/bash"],
            &[], // environment
            glib::SpawnFlags::DEFAULT,
            || {}, // child setup
            -1, // timeout
            None::<&gtk4::gio::Cancellable>,
            |result| {
                if let Err(e) = result {
                    eprintln!("Failed to spawn terminal: {}", e);
                }
            },
        );

        terminal_scroll.set_child(Some(&terminal));
        terminal_frame.set_child(Some(&terminal_scroll));
        container.append(&terminal_frame);

        Self {
            container,
            tool_selector,
            target_entry,
            args_entry,
            execute_button,
            cancel_button,
            info_button,
            spinner,
            progress_bar,
            status_label,
            terminal,
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
            self.cancel_button.set_visible(true);
            self.progress_bar.set_visible(true);
            self.progress_bar.pulse();
            self.set_status("Executing...");
        } else {
            self.spinner.stop();
            self.spinner.set_visible(false);
            self.execute_button.set_sensitive(true);
            self.cancel_button.set_visible(false);
            self.progress_bar.set_visible(false);
        }
    }

    /// Write text to the terminal
    pub fn write_to_terminal(&self, text: &str) {
        self.terminal.feed(text.as_bytes());
    }

    /// Clear the terminal
    pub fn clear_terminal(&self) {
        self.terminal.reset(true, true);
    }

    /// Execute command in terminal
    pub fn execute_in_terminal(&self, command: &str) {
        // Feed the command to the terminal followed by Enter
        let full_command = format!("{}\n", command);
        self.terminal.feed(full_command.as_bytes());
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
        args_str.split_whitespace().map(|s| s.to_string()).collect()
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

    /// Wire up info button handler
    pub fn connect_info_clicked<F>(&self, callback: F)
    where
        F: Fn() + 'static,
    {
        self.info_button.connect_clicked(move |_| {
            callback();
        });
    }

    /// Show instructions dialog for the selected tool
    pub fn show_instructions_dialog(&self, window: &gtk4::Window) {
        let tool_id = self
            .get_selected_tool()
            .unwrap_or_else(|| "nmap".to_string());
        let instructions = get_tool_instructions(&tool_id);

        let dialog = Dialog::with_buttons(
            Some(&format!("{} - Full Instructions", instructions.name)),
            Some(window),
            gtk4::DialogFlags::DESTROY_WITH_PARENT, // Removed MODAL flag
            &[("Close", ResponseType::Close)],
        );

        dialog.set_default_size(1000, 650);

        // Connect close button to actually close the dialog
        dialog.connect_response(move |dialog, response| {
            if response == ResponseType::Close {
                dialog.close();
            }
        });

        let content = dialog.content_area();
        content.set_margin_top(12);
        content.set_margin_bottom(12);
        content.set_margin_start(12);
        content.set_margin_end(12);

        let scroll = gtk4::ScrolledWindow::new();
        scroll.set_vexpand(true);
        scroll.set_hexpand(true);

        let vbox = GtkBox::new(Orientation::Vertical, 12);

        // Description
        let desc_label = Label::new(Some(instructions.description));
        desc_label.set_wrap(true);
        desc_label.set_xalign(0.0);
        desc_label.set_margin_bottom(8);
        vbox.append(&desc_label);

        // Installation
        let install_frame = gtk4::Frame::new(Some("Installation"));
        let install_box = GtkBox::new(Orientation::Vertical, 4);
        install_box.set_margin_top(8);
        install_box.set_margin_bottom(8);
        install_box.set_margin_start(8);
        install_box.set_margin_end(8);

        for cmd in &instructions.installation {
            let cmd_box = create_copyable_command_row(cmd);
            install_box.append(&cmd_box);
        }
        install_frame.set_child(Some(&install_box));
        vbox.append(&install_frame);

        // Common Examples
        let examples_frame = gtk4::Frame::new(Some("Common Examples"));
        let examples_box = GtkBox::new(Orientation::Vertical, 8);
        examples_box.set_margin_top(8);
        examples_box.set_margin_bottom(8);
        examples_box.set_margin_start(8);
        examples_box.set_margin_end(8);

        for example in &instructions.examples {
            let example_title = Label::new(Some(&format!("• {}", example.description)));
            example_title.set_xalign(0.0);
            example_title.set_wrap(true);
            example_title.add_css_class("heading");
            examples_box.append(&example_title);

            let cmd_box = create_copyable_command_row(&example.command);
            cmd_box.set_margin_start(20);
            examples_box.append(&cmd_box);
        }
        examples_frame.set_child(Some(&examples_box));
        vbox.append(&examples_frame);

        // Common Flags
        let flags_frame = gtk4::Frame::new(Some("Common Flags"));
        let flags_box = GtkBox::new(Orientation::Vertical, 4);
        flags_box.set_margin_top(8);
        flags_box.set_margin_bottom(8);
        flags_box.set_margin_start(8);
        flags_box.set_margin_end(8);

        for flag in &instructions.common_flags {
            let flag_label = Label::new(Some(&format!("{} - {}", flag.flag, flag.description)));
            flag_label.set_xalign(0.0);
            flag_label.set_wrap(true);
            flags_box.append(&flag_label);
        }
        flags_frame.set_child(Some(&flags_box));
        vbox.append(&flags_frame);

        // Tips
        if !instructions.tips.is_empty() {
            let tips_frame = gtk4::Frame::new(Some("Tips & Best Practices"));
            let tips_box = GtkBox::new(Orientation::Vertical, 4);
            tips_box.set_margin_top(8);
            tips_box.set_margin_bottom(8);
            tips_box.set_margin_start(8);
            tips_box.set_margin_end(8);

            for tip in &instructions.tips {
                let tip_label = Label::new(Some(&format!("💡 {}", tip)));
                tip_label.set_xalign(0.0);
                tip_label.set_wrap(true);
                tips_box.append(&tip_label);
            }
            tips_frame.set_child(Some(&tips_box));
            vbox.append(&tips_frame);
        }

        scroll.set_child(Some(&vbox));
        content.append(&scroll);

        // Position dialog at top-left (0, 0) using window title matching
        let window_title = format!("{} - Full Instructions", instructions.name);
        
        // Show the dialog first
        dialog.present();
        
        // Then position it using a small delay to ensure it's mapped
        glib::timeout_add_local_once(std::time::Duration::from_millis(100), move || {
            // Try to position using wmctrl or xdotool if available
            let _ = std::process::Command::new("wmctrl")
                .args(&["-r", &window_title, "-e", "0,0,0,-1,-1"])
                .output();
            
            // Fallback to xdotool
            if let Ok(_) = std::process::Command::new("xdotool")
                .args(&["search", "--name", &window_title, "windowmove", "0", "0"])
                .output() {
                // Success
            }
        });
    }

    /// Update placeholder text based on selected tool
    pub fn update_placeholders(&self, tool_id: &str) {
        match tool_id {
            "nmap" => {
                self.target_entry
                    .set_placeholder_text(Some("e.g., scanme.nmap.org or 192.168.1.1"));
                self.args_entry
                    .set_placeholder_text(Some("e.g., -p 80,443 -sV"));
            }
            "gobuster" => {
                self.target_entry
                    .set_placeholder_text(Some("e.g., http://example.com or example.com"));
                self.args_entry
                    .set_placeholder_text(Some("e.g., -w /path/to/wordlist.txt"));
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

/// Tool instruction data structures
#[derive(Clone)]
struct ToolInstructions {
    name: String,
    description: &'static str,
    installation: Vec<String>,
    examples: Vec<ToolExample>,
    common_flags: Vec<ToolFlag>,
    tips: Vec<&'static str>,
}

#[derive(Clone)]
struct ToolExample {
    description: String,
    command: String,
}

#[derive(Clone)]
struct ToolFlag {
    flag: String,
    description: String,
}

/// Create a copyable command row with a copy button
/// Extracts and copies only the arguments portion (everything after the tool name)
fn create_copyable_command_row(command: &str) -> GtkBox {
    let row = GtkBox::new(Orientation::Horizontal, 8);

    // Full command for display
    let cmd_label = Label::new(Some(command));
    cmd_label.set_selectable(true);
    cmd_label.set_xalign(0.0);
    cmd_label.set_hexpand(true);
    cmd_label.add_css_class("monospace");

    // Extract arguments only (everything after first word/tool name)
    let args_only = extract_arguments(command);

    let copy_button = Button::with_label("📋 Copy");
    copy_button.add_css_class("flat");
    copy_button.set_tooltip_text(Some("Copy command to clipboard"));

    let args_clone = args_only.clone();
    copy_button.connect_clicked(move |_| {
        if let Some(display) = gtk4::gdk::Display::default() {
            let clipboard = display.clipboard();
            clipboard.set_text(&args_clone);
        }
    });

    row.append(&cmd_label);
    row.append(&copy_button);
    row
}

/// Extract arguments from a command (everything after the tool name, excluding target)
/// Examples:
///   "nmap -sS scanme.nmap.org" -> "-sS"
///   "nmap -p 80,443 -sV example.com" -> "-p 80,443 -sV"
///   "gobuster dir -u http://example.com -w wordlist.txt" -> "dir -u http://example.com -w wordlist.txt"
fn extract_arguments(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return String::new();
    }

    // Skip the first part (tool name like "nmap", "gobuster", "sudo")
    let mut start_idx = 1;

    // If command starts with "sudo", skip that and the next word (the actual tool)
    if parts[0] == "sudo" && parts.len() > 1 {
        start_idx = 2;
    }

    if start_idx >= parts.len() {
        return String::new();
    }

    // For nmap commands, the last argument is typically the target
    // For gobuster, arguments include the target as part of -u or -d flag
    let tool_name = if parts[0] == "sudo" && parts.len() > 1 {
        parts[1]
    } else {
        parts[0]
    };

    // For nmap, exclude the last argument (target)
    // For other tools like gobuster, keep all arguments
    let end_idx = if tool_name == "nmap" && parts.len() > start_idx + 1 {
        parts.len() - 1 // Exclude target
    } else {
        parts.len()
    };

    if start_idx >= end_idx {
        return String::new();
    }

    parts[start_idx..end_idx].join(" ")
}

/// Get tool instructions based on tool ID
fn get_tool_instructions(tool_id: &str) -> ToolInstructions {
    match tool_id {
        "nmap" => ToolInstructions {
            name: "Nmap".to_string(),
            description: "Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It can discover hosts and services on a network, determine operating systems, and identify security vulnerabilities.",
            installation: vec![
                "# Debian/Ubuntu".to_string(),
                "sudo apt install nmap".to_string(),
                "".to_string(),
                "# Red Hat/CentOS/Fedora".to_string(),
                "sudo yum install nmap".to_string(),
                "".to_string(),
                "# macOS (Homebrew)".to_string(),
                "brew install nmap".to_string(),
            ],
            examples: vec![
                ToolExample {
                    description: "Basic TCP SYN scan (fast, stealthy)".to_string(),
                    command: "nmap -sS scanme.nmap.org".to_string(),
                },
                ToolExample {
                    description: "Scan specific ports with version detection".to_string(),
                    command: "nmap -p 80,443 -sV example.com".to_string(),
                },
                ToolExample {
                    description: "Aggressive scan (OS detection, version, scripts, traceroute)".to_string(),
                    command: "nmap -A 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Scan entire subnet".to_string(),
                    command: "nmap -sn 192.168.1.0/24".to_string(),
                },
                ToolExample {
                    description: "Vulnerability scanning with NSE scripts".to_string(),
                    command: "nmap --script vuln 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "Scan all 65535 ports".to_string(),
                    command: "nmap -p- 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Fast scan (top 100 ports)".to_string(),
                    command: "nmap -F example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-sS".to_string(), description: "TCP SYN scan (default, stealthy)".to_string() },
                ToolFlag { flag: "-sT".to_string(), description: "TCP Connect scan (slower but reliable)".to_string() },
                ToolFlag { flag: "-sU".to_string(), description: "UDP scan".to_string() },
                ToolFlag { flag: "-sV".to_string(), description: "Service version detection".to_string() },
                ToolFlag { flag: "-O".to_string(), description: "OS detection".to_string() },
                ToolFlag { flag: "-A".to_string(), description: "Aggressive scan (OS, version, scripts, traceroute)".to_string() },
                ToolFlag { flag: "-p <ports>".to_string(), description: "Specify ports (e.g., -p 80,443 or -p 1-1000)".to_string() },
                ToolFlag { flag: "-p-".to_string(), description: "Scan all 65535 ports".to_string() },
                ToolFlag { flag: "-F".to_string(), description: "Fast scan (top 100 ports)".to_string() },
                ToolFlag { flag: "-T<0-5>".to_string(), description: "Timing template (0=slowest, 5=fastest)".to_string() },
                ToolFlag { flag: "--script <script>".to_string(), description: "Run NSE script (e.g., --script vuln)".to_string() },
                ToolFlag { flag: "-oN <file>".to_string(), description: "Normal output to file".to_string() },
                ToolFlag { flag: "-oX <file>".to_string(), description: "XML output to file".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-Pn".to_string(), description: "Skip host discovery (treat as online)".to_string() },
            ],
            tips: vec![
                "Always get written permission before scanning networks you don't own",
                "Use -T4 for faster scans on reliable networks, -T2 for IDS evasion",
                "Combine flags for comprehensive scans: nmap -sS -sV -O -T4 target",
                "NSE scripts are in /usr/share/nmap/scripts/ - explore them!",
                "Use --reason to see why ports are marked open/closed",
                "For web servers, try: nmap --script http-enum -p 80,443 target",
            ],
        },
        "gobuster" => ToolInstructions {
            name: "Gobuster".to_string(),
            description: "Gobuster is a tool for brute-forcing URIs (directories and files), DNS subdomains, virtual hostnames, and Amazon S3 buckets. It's fast, multi-threaded, and supports multiple modes of operation.",
            installation: vec![
                "# Install from GitHub releases".to_string(),
                "wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz".to_string(),
                "tar -xzf gobuster_Linux_x86_64.tar.gz".to_string(),
                "sudo mv gobuster /usr/local/bin/".to_string(),
                "".to_string(),
                "# Or install via Go".to_string(),
                "go install github.com/OJ/gobuster/v3@latest".to_string(),
                "".to_string(),
                "# Or using package manager (Kali Linux)".to_string(),
                "sudo apt install gobuster".to_string(),
            ],
            examples: vec![
                ToolExample {
                    description: "Directory/file brute-forcing (dir mode)".to_string(),
                    command: "gobuster dir -u http://example.com -w data/wordlists/common.txt".to_string(),
                },
                ToolExample {
                    description: "DNS subdomain enumeration".to_string(),
                    command: "gobuster dns -d example.com -w data/wordlists/subdomains.txt".to_string(),
                },
                ToolExample {
                    description: "Virtual host discovery".to_string(),
                    command: "gobuster vhost -u http://example.com -w data/wordlists/vhosts.txt".to_string(),
                },
                ToolExample {
                    description: "Directory scan with extensions and status codes".to_string(),
                    command: "gobuster dir -u http://example.com -w data/wordlists/common.txt -x php,html,txt -s 200,301,302".to_string(),
                },
                ToolExample {
                    description: "Fast scan with increased threads".to_string(),
                    command: "gobuster dir -u http://example.com -w data/wordlists/common.txt -t 50".to_string(),
                },
                ToolExample {
                    description: "Scan with custom User-Agent and cookies".to_string(),
                    command: "gobuster dir -u http://example.com -w data/wordlists/common.txt -a 'Mozilla/5.0' -c 'session=abc123'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "dir".to_string(), description: "Directory/file brute-forcing mode".to_string() },
                ToolFlag { flag: "dns".to_string(), description: "DNS subdomain brute-forcing mode".to_string() },
                ToolFlag { flag: "vhost".to_string(), description: "Virtual host brute-forcing mode".to_string() },
                ToolFlag { flag: "-u <url>".to_string(), description: "Target URL (for dir/vhost modes)".to_string() },
                ToolFlag { flag: "-d <domain>".to_string(), description: "Target domain (for dns mode)".to_string() },
                ToolFlag { flag: "-w <wordlist>".to_string(), description: "Path to wordlist file".to_string() },
                ToolFlag { flag: "-x <extensions>".to_string(), description: "File extensions to search (comma-separated)".to_string() },
                ToolFlag { flag: "-t <threads>".to_string(), description: "Number of concurrent threads (default: 10)".to_string() },
                ToolFlag { flag: "-s <codes>".to_string(), description: "Positive status codes (default: 200,204,301,302,307,401,403)".to_string() },
                ToolFlag { flag: "-b <codes>".to_string(), description: "Negative status codes (blacklist)".to_string() },
                ToolFlag { flag: "-a <agent>".to_string(), description: "Custom User-Agent string".to_string() },
                ToolFlag { flag: "-c <cookie>".to_string(), description: "Cookie string to use".to_string() },
                ToolFlag { flag: "-o <file>".to_string(), description: "Output file to write results".to_string() },
                ToolFlag { flag: "-k".to_string(), description: "Skip SSL certificate verification".to_string() },
                ToolFlag { flag: "-q".to_string(), description: "Quiet mode (no banner/progress)".to_string() },
            ],
            tips: vec![
                "PT Journal includes wordlists in data/wordlists/ (common.txt, subdomains.txt, vhosts.txt)",
                "Always use a good wordlist - quality over quantity! Try SecLists collection for more",
                "Start with small wordlists for quick reconnaissance, then use larger ones",
                "Use -x to check for backup files: -x .bak,.old,.backup,.zip",
                "Adjust threads (-t) based on target - too many can trigger rate limiting",
                "Combine with other tools: use Nmap results to target specific services",
                "Filter by status codes: -s 200,301,302 to reduce noise",
            ],
        },
        _ => ToolInstructions {
            name: "Unknown Tool".to_string(),
            description: "No instructions available for this tool.",
            installation: vec![],
            examples: vec![],
            common_flags: vec![],
            tips: vec![],
        },
    }
}

/// Execute a security tool and return the result
/// Note: This is a simplified synchronous version for now.
/// For true async execution, consider using tokio or async-std.
pub fn execute_tool_sync_wrapper(
    tool_name: &str,
    target: &str,
    arguments: &[String],
    sudo_password: Option<&str>,
) -> Result<ExecutionResult, String> {
    use crate::tools::integrations::gobuster::{GobusterMode, GobusterTool};
    use crate::tools::integrations::nmap::{NmapTool, ScanType};

    // If password provided, execute with sudo
    if let Some(password) = sudo_password {
        return execute_tool_with_sudo(tool_name, target, arguments, password);
    }

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

/// Strip ANSI escape codes from a string
fn strip_ansi_codes(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Found escape sequence, skip until we hit a letter
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    
    result
}

/// Strip ANSI codes but preserve all formatting (public for use in handlers)
pub fn strip_ansi_preserve_format(text: &str) -> String {
    text.lines()
        .map(|line| strip_ansi_codes(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Execute tool with sudo privileges and cancellation support
pub fn execute_tool_with_cancel(
    tool_name: &str,
    target: &str,
    arguments: &[String],
    sudo_password: Option<&str>,
    cancel_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    child_process: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
) -> Result<ExecutionResult, String> {
    if let Some(password) = sudo_password {
        return execute_tool_with_sudo_cancellable(tool_name, target, arguments, password, cancel_flag, child_process);
    }
    
    // Non-sudo path (not commonly used but keep for completeness)
    execute_tool_sync_wrapper(tool_name, target, arguments, None)
}

/// Execute tool with sudo privileges and cancellation support
fn execute_tool_with_sudo_cancellable(
    tool_name: &str,
    target: &str,
    arguments: &[String],
    password: &str,
    cancel_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    child_process: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
) -> Result<ExecutionResult, String> {
    let start = std::time::Instant::now();

    // Build command arguments
    let mut args = vec!["-S".to_string(), tool_name.to_string()];
    args.extend(arguments.iter().cloned());

    // For nmap, append target at the end (nmap-style: nmap -sS target)
    // For gobuster, target is already in arguments via -u or -d flag
    if tool_name == "nmap" {
        args.push(target.to_string());
    }

    // Execute with sudo using password from stdin
    let mut child = Command::new("sudo")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sudo: {}", e))?;

    // Store the process ID for cancellation
    if let Ok(mut guard) = child_process.lock() {
        *guard = Some(child.id());
    }

    // Write password to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        writeln!(stdin, "{}", password).map_err(|e| format!("Failed to write password: {}", e))?;
    }

    // Poll for completion or cancellation
    use std::time::Duration;
    loop {
        // Check if cancelled
        if cancel_flag.load(std::sync::atomic::Ordering::SeqCst) {
            // Kill the child process
            let _ = child.kill();
            return Err("Execution cancelled by user".to_string());
        }

        // Try to get status without blocking
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished
                let output = child.wait_with_output()
                    .map_err(|e| format!("Failed to collect output: {}", e))?;

                let duration = start.elapsed();

                // Get raw output
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();

                // Check for authentication failure
                let exit_code = status.code().unwrap_or(-1);
                if stderr.contains("Sorry, try again")
                    || stderr.contains("authentication failure")
                    || (stderr.contains("incorrect password") && exit_code != 0)
                {
                    return Err("Authentication failed: Incorrect password".to_string());
                }

                // Check for command not found
                if stderr.contains("command not found") || stderr.contains(": not found") || (exit_code == 127)
                {
                    return Err(format!("Tool '{}' not found. Please install it first.\nSee Instructions for installation commands.", tool_name));
                }

                // Return raw output for terminal display
                return Ok(ExecutionResult {
                    stdout,
                    stderr,
                    exit_code,
                    duration,
                    parsed_result: None,
                    evidence: vec![],
                });
            }
            Ok(None) => {
                // Still running, sleep briefly
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!("Error checking process status: {}", e));
            }
        }
    }
}

/// Execute tool with sudo privileges
fn execute_tool_with_sudo(
    tool_name: &str,
    target: &str,
    arguments: &[String],
    password: &str,
) -> Result<ExecutionResult, String> {
    let start = std::time::Instant::now();

    // Build command arguments
    let mut args = vec!["-S".to_string(), tool_name.to_string()];
    args.extend(arguments.iter().cloned());

    // For nmap, append target at the end (nmap-style: nmap -sS target)
    // For gobuster, target is already in arguments via -u or -d flag
    if tool_name == "nmap" {
        args.push(target.to_string());
    }

    // Execute with sudo using password from stdin
    let mut child = Command::new("sudo")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sudo: {}", e))?;

    // Write password to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        writeln!(stdin, "{}", password).map_err(|e| format!("Failed to write password: {}", e))?;
    }

    // Wait for completion
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for sudo: {}", e))?;

    let duration = start.elapsed();

    // Get raw output
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Check for authentication failure (more specific patterns)
    let exit_code = output.status.code().unwrap_or(-1);
    if stderr.contains("Sorry, try again")
        || stderr.contains("authentication failure")
        || (stderr.contains("incorrect password") && exit_code != 0)
    {
        return Err("Authentication failed: Incorrect password".to_string());
    }

    // Check for command not found (tool not installed)
    if stderr.contains("command not found") || stderr.contains(": not found") || (exit_code == 127)
    {
        return Err(format!("Tool '{}' not found. Please install it first.\nSee Instructions for installation commands.", tool_name));
    }

    // Return raw output for terminal display
    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        duration,
        parsed_result: None,
        evidence: vec![],
    })
}

/// Show password dialog and return password if user confirms
#[allow(deprecated)]
pub fn show_password_dialog(window: &gtk4::Window) -> Option<String> {
    let dialog = Dialog::with_buttons(
        Some("🔒 Root Authentication Required"),
        Some(window),
        gtk4::DialogFlags::MODAL | gtk4::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", ResponseType::Cancel),
            ("Authenticate", ResponseType::Accept),
        ],
    );

    dialog.set_default_response(ResponseType::Accept);
    dialog.set_default_size(400, -1);

    let content = dialog.content_area();
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    content.set_spacing(12);

    // Icon and message box
    let message_box = GtkBox::new(Orientation::Vertical, 8);

    let title_label = Label::new(Some("Security tools require elevated privileges"));
    title_label.add_css_class("title-4");
    title_label.set_wrap(true);

    let info_label = Label::new(Some(
        "Tools like Nmap and Gobuster need root access to perform low-level network operations.\nPlease enter your system password to continue."
    ));
    info_label.set_wrap(true);
    info_label.set_justify(gtk4::Justification::Center);
    info_label.add_css_class("dim-label");

    message_box.append(&title_label);
    message_box.append(&info_label);

    let password_entry = PasswordEntry::new();
    password_entry.set_show_peek_icon(true);
    password_entry.set_activates_default(true);
    password_entry.set_placeholder_text(Some("Enter your password"));

    content.append(&message_box);
    content.append(&password_entry);

    // Focus password entry when dialog opens
    password_entry.grab_focus();

    // Store password in a Rc<RefCell> to capture from closure
    let password_result = std::rc::Rc::new(std::cell::RefCell::new(None));
    let password_result_clone = password_result.clone();

    let password_entry_clone = password_entry.clone();
    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept {
            let password = password_entry_clone.text().to_string();
            if !password.is_empty() {
                *password_result_clone.borrow_mut() = Some(password);
            }
        }
        dialog.close();
    });

    dialog.present();

    // Run nested event loop to wait for dialog response
    while dialog.is_visible() {
        gtk4::glib::MainContext::default().iteration(true);
    }

    // Extract the password before the borrow is dropped
    let result = password_result.borrow().clone();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static GTK_INIT: Once = Once::new();

    fn ensure_gtk_init() -> bool {
        let mut result = true;
        GTK_INIT.call_once(|| {
            if gtk4::init().is_err() {
                eprintln!("Failed to initialize GTK - tests will be skipped");
                result = false;
            }
        });
        result
    }

    #[test]
    fn test_output_operations() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();

        panel.write_to_terminal("Line 1\n");
        panel.write_to_terminal("Line 2\n");

        // Note: We can't easily test terminal content without complex setup
        // The terminal methods work by feeding bytes to the VTE terminal

        panel.clear_terminal();
        // Terminal is cleared via reset command
    }
}
