use gtk4::prelude::*;
use gtk4::glib;
use vte::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Box as GtkBox, Button, ComboBoxText, Dialog, Frame, GestureClick, Label, Orientation,
    PopoverMenu, ResponseType, ScrolledWindow, Separator,
};
use std::process::Command;
use std::time::Duration;

/// Manual security tools panel with inline instructions and an embedded terminal
#[allow(deprecated)]
#[derive(Clone)]
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub tool_selector: ComboBoxText,
    pub info_button: Button,
    pub instructions_scroll: ScrolledWindow,
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
        let header = Label::new(Some("Security Tool Reference"));
        header.add_css_class("title-3");
        container.append(&header);

        // Tool selector row
        let tool_box = GtkBox::new(Orientation::Horizontal, 8);
        let tool_label = Label::new(Some("Tool:"));
        tool_label.set_width_chars(10);
        tool_label.set_xalign(0.0);

        let tool_selector = ComboBoxText::new();
        tool_selector.append(Some("nmap"), "Nmap - Port Scanner");
        tool_selector.append(Some("gobuster"), "Gobuster - Directory/Subdomain Enum");
        tool_selector.append(Some("ffuf"), "ffuf - Fast Web Fuzzer");
        tool_selector.append(Some("amass"), "Amass - Asset Discovery");
        tool_selector.append(Some("masscan"), "Masscan - Internet-scale Scanner");
        tool_selector.append(Some("sqlmap"), "sqlmap - SQL Injection");
        tool_selector.append(Some("hydra"), "Hydra - Login Brute Force");
        tool_selector.set_active_id(Some("nmap"));
        tool_selector.set_hexpand(true);

        let info_button = Button::with_label("Open Instructions Window");
        info_button.add_css_class("flat");

        tool_box.append(&tool_label);
        tool_box.append(&tool_selector);
        tool_box.append(&info_button);
        container.append(&tool_box);

        let notice = Label::new(Some(
            "Copy any command from the instructions below and paste it into the integrated terminal to run it manually.",
        ));
        notice.set_wrap(true);
        notice.set_xalign(0.0);
        notice.add_css_class("dim-label");
        container.append(&notice);

        // Instructions frame with scrolling content
        let instructions_frame = Frame::new(Some("Command Reference"));
        instructions_frame.set_hexpand(true);
        instructions_frame.set_vexpand(true);

        let instructions_scroll = ScrolledWindow::new();
        instructions_scroll.set_hexpand(true);
        instructions_scroll.set_vexpand(true);
        instructions_scroll.set_min_content_height(320);
        instructions_scroll.set_margin_top(8);
        instructions_scroll.set_margin_bottom(8);
        instructions_scroll.set_margin_start(8);
        instructions_scroll.set_margin_end(8);

        instructions_frame.set_child(Some(&instructions_scroll));
        container.append(&instructions_frame);

        // Embedded terminal setup
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

        let fg = gtk4::gdk::RGBA::new(0.9, 0.9, 0.9, 1.0);
        let bg = gtk4::gdk::RGBA::new(0.12, 0.12, 0.12, 1.0);
        terminal.set_color_foreground(&fg);
        terminal.set_color_background(&bg);

        let palette = [
            gtk4::gdk::RGBA::new(0.2, 0.2, 0.2, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.3, 0.3, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.4, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.8, 0.3, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.7, 1.0, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.4, 0.8, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.8, 1.0),
            gtk4::gdk::RGBA::new(0.85, 0.85, 0.85, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.4, 0.4, 1.0),
            gtk4::gdk::RGBA::new(1.0, 0.4, 0.4, 1.0),
            gtk4::gdk::RGBA::new(0.5, 1.0, 0.5, 1.0),
            gtk4::gdk::RGBA::new(1.0, 1.0, 0.5, 1.0),
            gtk4::gdk::RGBA::new(0.5, 0.8, 1.0, 1.0),
            gtk4::gdk::RGBA::new(1.0, 0.5, 1.0, 1.0),
            gtk4::gdk::RGBA::new(0.5, 1.0, 1.0, 1.0),
            gtk4::gdk::RGBA::new(1.0, 1.0, 1.0, 1.0),
        ];
        let palette_refs: Vec<&gtk4::gdk::RGBA> = palette.iter().collect();
        terminal.set_colors(Some(&fg), Some(&bg), &palette_refs);

        let right_click = GestureClick::new();
        right_click.set_button(3);

        let terminal_clone = terminal.clone();
        right_click.connect_pressed(move |_gesture, _n_press, x, y| {
            let menu = gtk4::gio::Menu::new();
            menu.append(Some("Copy"), Some("terminal.copy"));
            menu.append(Some("Paste"), Some("terminal.paste"));

            let popover = PopoverMenu::from_model(Some(&menu));
            popover.set_parent(&terminal_clone);
            popover.set_has_arrow(false);
            popover.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));

            let action_group = gtk4::gio::SimpleActionGroup::new();

            let copy_action = gtk4::gio::SimpleAction::new("copy", None);
            let terminal_copy = terminal_clone.clone();
            copy_action.connect_activate(move |_, _| {
                terminal_copy.copy_clipboard_format(vte::Format::Text);
            });
            action_group.add_action(&copy_action);

            let paste_action = gtk4::gio::SimpleAction::new("paste", None);
            let terminal_paste = terminal_clone.clone();
            paste_action.connect_activate(move |_, _| {
                terminal_paste.paste_clipboard();
            });
            action_group.add_action(&paste_action);

            terminal_clone.insert_action_group("terminal", Some(&action_group));
            popover.popup();
        });

        terminal.add_controller(right_click);

        terminal.spawn_async(
            vte::PtyFlags::DEFAULT,
            None,
            &["/bin/bash"],
            &[],
            glib::SpawnFlags::DEFAULT,
            || {},
            -1,
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

        let panel = Self {
            container,
            tool_selector,
            info_button,
            instructions_scroll,
            terminal,
        };

        panel.render_inline_instructions();

        let selector_clone = panel.tool_selector.clone();
        let panel_clone = panel.clone();
        selector_clone.connect_changed(move |_| {
            panel_clone.render_inline_instructions();
        });

        panel
    }

    pub fn get_selected_tool(&self) -> Option<String> {
        self.tool_selector.active_id().map(|s| s.to_string())
    }

    /// Rebuild inline instructions whenever the selected tool changes
    fn render_inline_instructions(&self) {
        let tool_id = self
            .get_selected_tool()
            .unwrap_or_else(|| "nmap".to_string());
        let instructions = get_tool_instructions(&tool_id);
        let content = build_instruction_sections(&instructions);
        self.instructions_scroll.set_child(Some(&content));
    }

    /// Show the instructions dialog for the selected tool
    pub fn show_instructions_dialog(&self, window: &gtk4::Window) {
        let tool_id = self
            .get_selected_tool()
            .unwrap_or_else(|| "nmap".to_string());
        let instructions = get_tool_instructions(&tool_id);

        let dialog = Dialog::with_buttons(
            Some(&format!("{} - Full Instructions", instructions.name)),
            Some(window),
            gtk4::DialogFlags::DESTROY_WITH_PARENT,
            &[("Close", ResponseType::Close)],
        );

        dialog.set_default_size(1000, 650);
        dialog.connect_response(|dialog, response| {
            if response == ResponseType::Close {
                dialog.close();
            }
        });

        let content = dialog.content_area();
        content.set_margin_top(12);
        content.set_margin_bottom(12);
        content.set_margin_start(12);
        content.set_margin_end(12);

        let scroll = ScrolledWindow::new();
        scroll.set_vexpand(true);
        scroll.set_hexpand(true);
        let instruction_box = build_instruction_sections(&instructions);
        scroll.set_child(Some(&instruction_box));
        content.append(&scroll);

        let window_title = format!("{} - Full Instructions", instructions.name);
        dialog.present();

        glib::timeout_add_local_once(Duration::from_millis(100), move || {
            let _ = Command::new("wmctrl")
                .args(["-r", &window_title, "-e", "0,0,0,-1,-1"])
                .output();

            let _ = Command::new("xdotool")
                .args(["search", "--name", &window_title, "windowmove", "0", "0"])
                .output();
        });
    }

    /// Write text to the terminal
    pub fn write_to_terminal(&self, text: &str) {
        self.terminal.feed(text.as_bytes());
    }

    /// Clear the terminal contents
    pub fn clear_terminal(&self) {
        self.terminal.reset(true, true);
    }

    /// Feed a command to the terminal (appends a newline)
    pub fn execute_in_terminal(&self, command: &str) {
        let full_command = format!("{}\n", command);
        self.terminal.feed(full_command.as_bytes());
    }
}

impl Default for ToolExecutionPanel {
    fn default() -> Self {
        Self::new()
    }
}

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

fn build_instruction_sections(instructions: &ToolInstructions) -> GtkBox {
    let root = GtkBox::new(Orientation::Vertical, 12);
    root.set_margin_top(8);
    root.set_margin_bottom(8);
    root.set_margin_start(8);
    root.set_margin_end(8);

    let title = Label::new(Some(&format!("{}", instructions.name)));
    title.add_css_class("title-4");
    title.set_xalign(0.0);
    root.append(&title);

    let description = Label::new(Some(instructions.description));
    description.set_wrap(true);
    description.set_xalign(0.0);
    root.append(&description);

    let hint = Label::new(Some(
        "💡 Tip: Use the copy buttons next to actual commands. Comments and headings are not copyable.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");
    root.append(&hint);

    if !instructions.installation.is_empty() {
        let frame = Frame::new(Some("Installation"));
        let install_box = GtkBox::new(Orientation::Vertical, 4);
        install_box.set_margin_top(8);
        install_box.set_margin_bottom(8);
        install_box.set_margin_start(8);
        install_box.set_margin_end(8);

        for line in &instructions.installation {
            match classify_instruction_line(line) {
                InstructionLine::Separator => {
                    let sep = Separator::new(Orientation::Horizontal);
                    sep.set_margin_top(4);
                    sep.set_margin_bottom(4);
                    install_box.append(&sep);
                }
                InstructionLine::Comment(text) => {
                    let label = create_instruction_label(text);
                    install_box.append(&label);
                }
                InstructionLine::Command(cmd) => {
                    let cmd_box = create_copyable_command_row(cmd);
                    install_box.append(&cmd_box);
                }
            }
        }

        frame.set_child(Some(&install_box));
        root.append(&frame);
    }

    if !instructions.examples.is_empty() {
        let frame = Frame::new(Some("Common Examples"));
        let example_box = GtkBox::new(Orientation::Vertical, 8);
        example_box.set_margin_top(8);
        example_box.set_margin_bottom(8);
        example_box.set_margin_start(8);
        example_box.set_margin_end(8);

        for example in &instructions.examples {
            let example_title = Label::new(Some(&format!("• {}", example.description)));
            example_title.set_xalign(0.0);
            example_title.set_wrap(true);
            example_title.add_css_class("heading");
            example_box.append(&example_title);

            let cmd_box = create_copyable_command_row(&example.command);
            cmd_box.set_margin_start(20);
            example_box.append(&cmd_box);
        }

        frame.set_child(Some(&example_box));
        root.append(&frame);
    }

    if !instructions.common_flags.is_empty() {
        let frame = Frame::new(Some("Helpful Flags"));
        let flags_box = GtkBox::new(Orientation::Vertical, 4);
        flags_box.set_margin_top(8);
        flags_box.set_margin_bottom(8);
        flags_box.set_margin_start(8);
        flags_box.set_margin_end(8);

        for flag in &instructions.common_flags {
            let label = Label::new(Some(&format!("{} — {}", flag.flag, flag.description)));
            label.set_xalign(0.0);
            label.set_wrap(true);
            flags_box.append(&label);
        }

        frame.set_child(Some(&flags_box));
        root.append(&frame);
    }

    if !instructions.tips.is_empty() {
        let frame = Frame::new(Some("Tips & Best Practices"));
        let tips_box = GtkBox::new(Orientation::Vertical, 4);
        tips_box.set_margin_top(8);
        tips_box.set_margin_bottom(8);
        tips_box.set_margin_start(8);
        tips_box.set_margin_end(8);

        for tip in &instructions.tips {
            let label = Label::new(Some(&format!("💡 {}", tip)));
            label.set_xalign(0.0);
            label.set_wrap(true);
            tips_box.append(&label);
        }

        frame.set_child(Some(&tips_box));
        root.append(&frame);
    }

    root
}

fn create_instruction_label(text: &str) -> Label {
    let label = Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("dim-label");
    label
}

fn create_copyable_command_row(command: &str) -> GtkBox {
    let row = GtkBox::new(Orientation::Horizontal, 8);

    let cmd_label = Label::new(Some(command));
    cmd_label.set_selectable(true);
    cmd_label.set_xalign(0.0);
    cmd_label.set_hexpand(true);
    cmd_label.set_wrap(true);
    cmd_label.add_css_class("monospace");

    let command_text = command.to_string();
    let copy_button = Button::with_label("📋 Copy");
    copy_button.add_css_class("flat");
    copy_button.set_tooltip_text(Some("Copy full command to clipboard"));
    copy_button.connect_clicked(move |_| {
        if let Some(display) = gtk4::gdk::Display::default() {
            let clipboard = display.clipboard();
            clipboard.set_text(&command_text);
        }
    });

    row.append(&cmd_label);
    row.append(&copy_button);
    row
}

enum InstructionLine<'a> {
    Comment(&'a str),
    Command(&'a str),
    Separator,
}

fn classify_instruction_line(line: &str) -> InstructionLine<'_> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        InstructionLine::Separator
    } else if trimmed.starts_with('#') {
        InstructionLine::Comment(trimmed)
    } else {
        InstructionLine::Command(line)
    }
}

fn get_tool_instructions(tool_id: &str) -> ToolInstructions {
    match tool_id {
        "nmap" => ToolInstructions {
            name: "Nmap".to_string(),
            description: "Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing. It discovers hosts, detects services, fingerprints OS metadata, and can execute NSE scripts for deeper checks.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install nmap",
                "",
                "# Red Hat/CentOS/Fedora",
                "sudo yum install nmap",
                "",
                "# macOS (Homebrew)",
                "brew install nmap",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic TCP SYN scan (fast, stealthy)".to_string(),
                    command: "sudo nmap -sS scanme.nmap.org".to_string(),
                },
                ToolExample {
                    description: "Scan specific ports with version detection".to_string(),
                    command: "sudo nmap -p 80,443 -sV example.com".to_string(),
                },
                ToolExample {
                    description: "Aggressive scan (OS detection, scripts, traceroute)".to_string(),
                    command: "sudo nmap -A 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Host discovery without port scan".to_string(),
                    command: "sudo nmap -sn 192.168.1.0/24".to_string(),
                },
                ToolExample {
                    description: "Full TCP scan with service detection".to_string(),
                    command: "sudo nmap -p- -sV 10.0.0.5".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-sS".to_string(), description: "TCP SYN scan (default, stealthy)".to_string() },
                ToolFlag { flag: "-sV".to_string(), description: "Service version detection".to_string() },
                ToolFlag { flag: "-O".to_string(), description: "OS detection".to_string() },
                ToolFlag { flag: "-A".to_string(), description: "Aggressive scan (OS, version, scripts, traceroute)".to_string() },
                ToolFlag { flag: "-p <ports>".to_string(), description: "List ports or ranges (e.g., -p 80,443 or -p 1-1000)".to_string() },
                ToolFlag { flag: "-T<0-5>".to_string(), description: "Timing template (0=slowest, 5=fastest)".to_string() },
                ToolFlag { flag: "--script <name>".to_string(), description: "Run NSE script (e.g., --script vuln)".to_string() },
                ToolFlag { flag: "-oN/-oX/-oG".to_string(), description: "Output to normal/XML/grepable files".to_string() },
            ],
            tips: vec![
                "Always run scans with permission and document scope clearly.",
                "Use -T4 for faster scans on reliable networks; -T2 when evading detection.",
                "Combine flags: sudo nmap -sS -sV -O -T4 target",
                "Enable verbose output with -v or --reason to inspect why ports are marked open or closed.",
                "Schedule long-running scans during maintenance windows to avoid network noise.",
            ],
        },
        "gobuster" => ToolInstructions {
            name: "Gobuster".to_string(),
            description: "Gobuster is a multithreaded directory, DNS, and virtual host brute-forcing tool. It is perfect for quickly finding hidden web content when you already know the hostname or base URL.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install gobuster",
                "",
                "# Install via Go",
                "go install github.com/OJ/gobuster/v3@latest",
                "",
                "# Manual download",
                "wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz",
                "tar -xzf gobuster_Linux_x86_64.tar.gz",
                "sudo mv gobuster /usr/local/bin/",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
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
                    description: "Directory scan with extensions and status filters".to_string(),
                    command: "gobuster dir -u https://example.com -w data/wordlists/common.txt -x php,txt,bak -s 200,204,301,302,403".to_string(),
                },
                ToolExample {
                    description: "Authenticated scan with cookies".to_string(),
                    command: "gobuster dir -u https://portal.example.com -w data/wordlists/common.txt -c 'session=abcd1234'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "dir/dns/vhost".to_string(), description: "Choose directory, DNS, or virtual host mode".to_string() },
                ToolFlag { flag: "-u/-d".to_string(), description: "Target base URL (-u) or domain (-d)".to_string() },
                ToolFlag { flag: "-w <wordlist>".to_string(), description: "Path to the wordlist file".to_string() },
                ToolFlag { flag: "-x <extensions>".to_string(), description: "Comma-separated extensions to append".to_string() },
                ToolFlag { flag: "-t <threads>".to_string(), description: "Adjust concurrency (default 10)".to_string() },
                ToolFlag { flag: "-s/-b".to_string(), description: "Positive (-s) or blacklist (-b) status codes".to_string() },
                ToolFlag { flag: "-a/-c/-H".to_string(), description: "Set User-Agent (-a), cookies (-c), or custom header (-H)".to_string() },
                ToolFlag { flag: "--delay".to_string(), description: "Add delay between requests to avoid throttling".to_string() },
            ],
            tips: vec![
                "Use smaller wordlists first to confirm interesting responses, then scale up.",
                "Leverage PT Journal wordlists in data/wordlists/ or swap in SecLists.",
                "Always review HTTP status codes; -s 200,204,301,302,307,401,403 keeps useful hits.",
                "Add -x php,asp,bak for common backup files.",
                "Combine Gobuster output with proxy logs for deeper insights.",
            ],
        },
        "ffuf" => ToolInstructions {
            name: "ffuf".to_string(),
            description: "ffuf (Fuzz Faster U Fool) is a blazing fast web fuzzer for discovering files, directories, parameters, and virtual hosts. It supports advanced filters to quickly isolate meaningful responses.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install ffuf",
                "",
                "# Install via Go",
                "go install github.com/ffuf/ffuf@latest",
                "",
                "# Manual build",
                "git clone https://github.com/ffuf/ffuf.git",
                "cd ffuf && go build",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Directory fuzzing".to_string(),
                    command: "ffuf -w data/wordlists/common.txt -u https://target/FUZZ".to_string(),
                },
                ToolExample {
                    description: "Parameter fuzzing".to_string(),
                    command: "ffuf -w params.txt -u 'https://target/search?FUZZ=test'".to_string(),
                },
                ToolExample {
                    description: "Find virtual hosts".to_string(),
                    command: "ffuf -w subdomains.txt -u http://target/ -H 'Host: FUZZ.target'".to_string(),
                },
                ToolExample {
                    description: "Filter by response size".to_string(),
                    command: "ffuf -w common.txt -u https://target/FUZZ -fs 0".to_string(),
                },
                ToolExample {
                    description: "Recursive fuzzing".to_string(),
                    command: "ffuf -w common.txt -u https://target/FUZZ -recursion -recursion-depth 2".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-w <wordlist>".to_string(), description: "Wordlist path".to_string() },
                ToolFlag { flag: "-u <url>".to_string(), description: "Target URL (use FUZZ keyword)".to_string() },
                ToolFlag { flag: "-H/-b".to_string(), description: "Inject headers or cookies".to_string() },
                ToolFlag { flag: "-recursion".to_string(), description: "Automatically revisit discovered paths".to_string() },
                ToolFlag { flag: "-mc/-fc".to_string(), description: "Filter by match or filter status codes".to_string() },
                ToolFlag { flag: "-fs/-fw".to_string(), description: "Filter by size (bytes) or words".to_string() },
                ToolFlag { flag: "-t/-p".to_string(), description: "Threads (-t) and delay (-p)".to_string() },
                ToolFlag { flag: "-o <file>".to_string(), description: "Write JSON output".to_string() },
            ],
            tips: vec![
                "Mark every location to fuzz with FUZZ (URL paths, headers, POST data).",
                "Use -ic to ignore wordlist comments when using SecLists.",
                "Stack filters (e.g., -mc 200 -fs 0) to hide noise quickly.",
                "Throttle threads (-t) for fragile targets or WAFs.",
                "Store results (-o output.json) for later analysis or reporting.",
            ],
        },
        "amass" => ToolInstructions {
            name: "Amass".to_string(),
            description: "OWASP Amass performs in-depth attack surface mapping for external assets. It combines passive and active reconnaissance with graph exports and historical tracking.",
            installation: vec![
                "# Snap package",
                "sudo snap install amass",
                "",
                "# Install via Go",
                "GO111MODULE=on go install -v github.com/owasp-amass/amass/v4/...",
                "",
                "# Docker",
                "docker pull caffix/amass",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Passive enumeration".to_string(),
                    command: "amass enum -passive -d example.com".to_string(),
                },
                ToolExample {
                    description: "Active brute-force with wordlist".to_string(),
                    command: "amass enum -active -brute -w data/wordlists/subdomains.txt -d example.com".to_string(),
                },
                ToolExample {
                    description: "ASN and netblock intel".to_string(),
                    command: "amass intel -asn 13335".to_string(),
                },
                ToolExample {
                    description: "Graph export".to_string(),
                    command: "amass viz -d example.com -o graph.gexf".to_string(),
                },
                ToolExample {
                    description: "Track changes over time".to_string(),
                    command: "amass track -d example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "enum/intel/viz/db/track".to_string(), description: "Module to run".to_string() },
                ToolFlag { flag: "-d/-df".to_string(), description: "Target domain or file with multiple domains".to_string() },
                ToolFlag { flag: "-brute".to_string(), description: "Enable brute-force enumeration".to_string() },
                ToolFlag { flag: "-src".to_string(), description: "Show data sources for findings".to_string() },
                ToolFlag { flag: "-ip".to_string(), description: "Include resolved IP addresses".to_string() },
                ToolFlag { flag: "-o/-json".to_string(), description: "Write results to text or JSON".to_string() },
            ],
            tips: vec![
                "Configure API keys (~/.config/amass/config.ini) for richer passive data.",
                "Use amass db to reuse previous discoveries during new engagements.",
                "Export graphs (viz) to share with teammates or include in reports.",
                "Blend passive + active modes for accuracy while limiting noise.",
            ],
        },
        "masscan" => ToolInstructions {
            name: "Masscan".to_string(),
            description: "Masscan is an Internet-scale port scanner capable of sending millions of packets per second. Use it for rapid discovery before deeper Nmap scans.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install masscan",
                "",
                "# Build from source",
                "git clone https://github.com/robertdavidgraham/masscan.git",
                "cd masscan && make",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Scan top 100 ports on a subnet".to_string(),
                    command: "sudo masscan 10.0.0.0/24 --top-ports 100 --rate 5000".to_string(),
                },
                ToolExample {
                    description: "Full TCP scan of a host".to_string(),
                    command: "sudo masscan 203.0.113.5 -p0-65535 --rate 10000".to_string(),
                },
                ToolExample {
                    description: "Slow scan to avoid detection".to_string(),
                    command: "sudo masscan 198.51.100.0/24 -p80,443 --rate 100".to_string(),
                },
                ToolExample {
                    description: "Scan known ports with banner grab".to_string(),
                    command: "sudo masscan 192.168.56.0/24 -p22,80,445 --banners".to_string(),
                },
                ToolExample {
                    description: "Exclude sensitive ranges".to_string(),
                    command: "sudo masscan 0.0.0.0/0 -p443 --excludefile exclude.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-p/-p0-65535".to_string(), description: "Port or port range".to_string() },
                ToolFlag { flag: "--top-ports <n>".to_string(), description: "Scan the most common ports".to_string() },
                ToolFlag { flag: "--rate".to_string(), description: "Packets per second".to_string() },
                ToolFlag { flag: "--adapter-ip/port".to_string(), description: "Bind to a specific source IP/port".to_string() },
                ToolFlag { flag: "--router-ip".to_string(), description: "Send packets via alternate gateway".to_string() },
                ToolFlag { flag: "--banners".to_string(), description: "Grab basic service banners".to_string() },
                ToolFlag { flag: "--exclude/--excludefile".to_string(), description: "Skip sensitive networks".to_string() },
                ToolFlag { flag: "-oX/-oJ/-oL".to_string(), description: "Output XML/JSON/list formats".to_string() },
            ],
            tips: vec![
                "Masscan requires root; consider --rate to respect network capacity.",
                "Use results as input to slower but deeper Nmap scans.",
                "Always exclude production ranges if not in scope.",
                "Plan scans during maintenance to avoid IDS alerts.",
            ],
        },
        "sqlmap" => ToolInstructions {
            name: "sqlmap".to_string(),
            description: "sqlmap automates the detection and exploitation of SQL injection flaws, supporting numerous DBMS engines and shell payloads.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install sqlmap",
                "",
                "# From source",
                "git clone https://github.com/sqlmapproject/sqlmap.git",
                "cd sqlmap",
                "python3 sqlmap.py --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic GET parameter test".to_string(),
                    command: "python3 sqlmap.py -u 'https://target/item.php?id=1' --batch".to_string(),
                },
                ToolExample {
                    description: "Use captured request file".to_string(),
                    command: "python3 sqlmap.py -r request.txt --level 3 --risk 2".to_string(),
                },
                ToolExample {
                    description: "Enumerate databases".to_string(),
                    command: "python3 sqlmap.py -u 'https://target/item.php?id=1' --dbs".to_string(),
                },
                ToolExample {
                    description: "Dump a table".to_string(),
                    command: "python3 sqlmap.py -u 'https://target/item.php?id=1' -D appdb -T users --dump".to_string(),
                },
                ToolExample {
                    description: "Obtain OS shell".to_string(),
                    command: "python3 sqlmap.py -u 'https://target/item.php?id=1' --os-shell".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u/-r".to_string(), description: "Direct URL (-u) or request file (-r)".to_string() },
                ToolFlag { flag: "--level/--risk".to_string(), description: "Depth of tests (1-5) and impact".to_string() },
                ToolFlag { flag: "--batch".to_string(), description: "Auto-confirm prompts".to_string() },
                ToolFlag { flag: "--dbs/-D/-T/-C".to_string(), description: "Enumerate DBs, tables, columns".to_string() },
                ToolFlag { flag: "--dump".to_string(), description: "Dump selected data".to_string() },
                ToolFlag { flag: "--os-shell/--sql-shell".to_string(), description: "Spawn command or SQL shells".to_string() },
                ToolFlag { flag: "--tamper".to_string(), description: "Apply tamper scripts (evasion)".to_string() },
                ToolFlag { flag: "--random-agent".to_string(), description: "Randomize User-Agent".to_string() },
            ],
            tips: vec![
                "Capture complex requests with Burp/ZAP and feed them via -r.",
                "Use lower --risk/--level on fragile production targets.",
                "Always document data extracted and clean up any uploaded shells.",
                "Tamper scripts can bypass WAF/IDS filters; try between attempts.",
            ],
        },
        "hydra" => ToolInstructions {
            name: "Hydra".to_string(),
            description: "Hydra is a fast network logon cracker that supports numerous protocols including SSH, RDP, FTP, SMB, HTTP, and databases.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install hydra",
                "",
                "# macOS (Homebrew)",
                "brew install hydra",
                "",
                "# Build from source",
                "git clone https://github.com/vanhauser-thc/thc-hydra.git",
                "cd thc-hydra && ./configure && make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "SSH brute force".to_string(),
                    command: "hydra -L users.txt -P passwords.txt ssh://192.168.1.50".to_string(),
                },
                ToolExample {
                    description: "HTTP POST form".to_string(),
                    command: "hydra -l admin -P passwords.txt 192.168.1.20 http-post-form \"/login:username=^USER^&password=^PASS^:F=Invalid\"".to_string(),
                },
                ToolExample {
                    description: "FTP login".to_string(),
                    command: "hydra -l admin -P passwords.txt ftp://10.0.0.10".to_string(),
                },
                ToolExample {
                    description: "RDP brute force".to_string(),
                    command: "hydra -L users.txt -P passwords.txt rdp://corpdc.local".to_string(),
                },
                ToolExample {
                    description: "MySQL authentication".to_string(),
                    command: "hydra -L users.txt -P passwords.txt mysql://db.internal".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-l/-L".to_string(), description: "Single username (-l) or username list (-L)".to_string() },
                ToolFlag { flag: "-p/-P".to_string(), description: "Single password (-p) or list (-P)".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Custom port".to_string() },
                ToolFlag { flag: "-S/-4/-6".to_string(), description: "SSL (-S) or force IPv4/IPv6".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Parallel tasks (threads)".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Stop on first valid credential".to_string() },
                ToolFlag { flag: "-V/-d".to_string(), description: "Verbose or debug output".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Write results to file".to_string() },
                ToolFlag { flag: "http-post-form".to_string(), description: "Module syntax for form-based auth".to_string() },
            ],
            tips: vec![
                "Verify you are allowed to brute force the service and coordinate with blue teams.",
                "Tune threads (-t) to respect target stability and lockout policies.",
                "Use stop-on-success (-f) to reduce noise once credentials are found.",
                "Combine Hydra with compromised wordlists unique to the engagement.",
            ],
        },
        _ => ToolInstructions {
            name: "Unknown Tool".to_string(),
            description: "No instructions are available for this tool yet.",
            installation: vec![],
            examples: vec![],
            common_flags: vec![],
            tips: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    static GTK_AVAILABLE: OnceLock<bool> = OnceLock::new();

    fn ensure_gtk_init() -> bool {
        *GTK_AVAILABLE.get_or_init(|| {
            if let Err(err) = gtk4::init() {
                eprintln!("Failed to initialize GTK - tests will be skipped: {}", err);
                false
            } else {
                true
            }
        })
    }

    #[test]
    fn test_tool_execution_panel_creation() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));
        assert!(panel.instructions_scroll.child().is_some());
    }

    #[test]
    fn test_tool_selection_updates() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        panel.tool_selector.set_active_id(Some("gobuster"));
        assert_eq!(panel.get_selected_tool(), Some("gobuster".to_string()));
        assert!(panel.instructions_scroll.child().is_some());
    }

    #[test]
    fn test_terminal_operations() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        panel.write_to_terminal("Line 1\\n");
        panel.clear_terminal();
        panel.execute_in_terminal("whoami");
    }
}
