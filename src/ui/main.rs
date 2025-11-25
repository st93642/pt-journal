use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Frame, Paned};
use std::cell::RefCell;
use std::rc::Rc;

use crate::dispatcher::create_dispatcher;
use crate::model::AppModel;
use crate::ui::state::StateManager;

pub fn build_ui(app: &Application, model: AppModel) {
    install_application_css();
    let model = Rc::new(RefCell::new(model));

    // Create dispatcher for event-driven communication
    let dispatcher = create_dispatcher();

    // Create state manager
    let state = Rc::new(StateManager::new(model.clone(), dispatcher.clone()));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("PT Journal")
        .default_width(1600) // Wider window for 3-column layout
        .default_height(900)
        .build();

    // Header bar with Open/Save and Sidebar toggle
    let (header, btn_open, btn_save, btn_save_as, btn_sidebar) =
        crate::ui::header_bar::create_header_bar();
    window.set_titlebar(Some(&header));

    // Left panel: phase selector + steps list
    let (left_box, phase_combo, steps_list) = crate::ui::sidebar::create_sidebar(&model);

    // Center panel: detail view with checkbox, title, description, chat
    let detail_panel = crate::ui::detail_panel::create_detail_panel();
    let center = detail_panel.center_container.clone();

    // Right panel: security tools
    let tool_frame = Frame::builder()
        .label("Security Tools")
        .child(&detail_panel.tool_panel.container)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(4)
        .margin_end(8)
        .build();

    // Keep reference to full detail_panel for handlers
    let detail_panel_ref = Rc::new(detail_panel);

    // Register UI update handlers
    let detail_panel_update = detail_panel_ref.clone();
    let state_update = state.clone();
    dispatcher.borrow_mut().register(
        "ui:chat_update",
        Box::new(move |msg| {
            if let crate::dispatcher::AppMessage::ChatMessageAdded(phase_idx, step_idx, message) =
                msg
            {
                let current_phase = state_update.current_phase();
                let current_step = state_update.current_step().unwrap_or(0);
                if *phase_idx == current_phase && *step_idx == current_step {
                    detail_panel_update.chat_panel.add_message(message);
                }
            }
        }),
    );

    // === SETUP SIGNAL HANDLERS ===

    // Quiz widget handlers
    crate::ui::handlers::setup_quiz_handlers(detail_panel_ref.clone(), state.clone());

    // Tool execution handlers
    crate::ui::handlers::setup_tool_execution_handlers(
        detail_panel_ref.clone(),
        state.clone(),
        &window,
    );

    // Phase selection handler
    let phase_handler_id = crate::ui::handlers::setup_phase_handler(
        &phase_combo,
        &steps_list,
        state.clone(),
        detail_panel_ref.clone(),
    );

    // Step selection handlers (wired during rebuild_steps_list)
    crate::ui::handlers::setup_step_handlers(&steps_list, state.clone(), detail_panel_ref.clone());

    // Notes text view handlers
    crate::ui::handlers::setup_notes_handlers(detail_panel_ref.clone(), state.clone());

    // Chat panel handlers
    crate::ui::handlers::setup_chat_handlers(detail_panel_ref.clone(), state.clone());

    // File operation handlers
    crate::ui::handlers::setup_file_handlers(
        &btn_open,
        &btn_save,
        &btn_save_as,
        &window,
        state.clone(),
        detail_panel_ref.clone(),
        &phase_combo,
        phase_handler_id,
        &steps_list,
    );

    // Sidebar toggle handler
    crate::ui::handlers::setup_sidebar_handler(&btn_sidebar, &left_box);

    // === LAYOUT ===
    // Three-column layout: Sidebar (left) | Content (center) | Tools (right)

    // First split: center + tools
    let center_tools_paned = Paned::new(gtk4::Orientation::Horizontal);
    center_tools_paned.set_start_child(Some(&center));
    center_tools_paned.set_end_child(Some(&tool_frame));
    center_tools_paned.set_position(900); // Center takes 900px, tools get the rest
    center_tools_paned.set_resize_start_child(true);
    center_tools_paned.set_resize_end_child(true);
    center_tools_paned.set_shrink_start_child(false);
    center_tools_paned.set_shrink_end_child(false);

    // Second split: sidebar + (center + tools)
    let main_paned = Paned::new(gtk4::Orientation::Horizontal);
    main_paned.set_start_child(Some(&left_box));
    main_paned.set_end_child(Some(&center_tools_paned));
    main_paned.set_position(320); // Sidebar width
    main_paned.set_resize_start_child(true);
    main_paned.set_resize_end_child(true);
    main_paned.set_shrink_start_child(false);
    main_paned.set_shrink_end_child(false);

    window.set_child(Some(&main_paned));

    // === INITIAL LOAD ===
    // Load first phase and step
    crate::ui::handlers::rebuild_steps_list(&steps_list, &state.model(), &detail_panel_ref);

    window.present();

    // Rebuild phase combo after window is presented to ensure proper refresh
    glib::idle_add_local_once(move || {
        crate::ui::handlers::rebuild_phase_combo(&phase_combo, &state.model());
    });
}

fn install_application_css() {
    if let Some(display) = gtk4::gdk::Display::default() {
        let provider = gtk4::CssProvider::new();
        if let Err(err) = provider.load_from_data(CHAT_PANEL_CSS.as_bytes()) {
            eprintln!("Failed to load application CSS: {err}");
            return;
        }
        gtk4::StyleContext::add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

const CHAT_PANEL_CSS: &str = r#"
.chat-panel {
    background-color: rgba(3, 12, 8, 0.35);
    border: 1px solid rgba(34, 135, 91, 0.6);
    border-radius: 12px;
}

.chat-history {
    background-color: rgba(5, 18, 10, 0.92);
    border-radius: 12px;
    border: 1px solid rgba(40, 168, 106, 0.65);
    padding: 6px;
}

.chat-history row {
    background: transparent;
    border-bottom: 1px solid rgba(40, 168, 106, 0.2);
    margin-bottom: 2px;
    padding-bottom: 4px;
}

.chat-history row:last-child {
    border-bottom: none;
}

.chat-message label {
    color: #c5ffd0;
}

.chat-message .timestamp {
    color: #7dd899;
    font-size: 0.85em;
}

.chat-message .user-message {
    color: #adffb9;
    font-weight: 600;
}

.chat-message .assistant-message {
    color: #d0ffe0;
}

.chat-input {
    background-color: rgba(3, 15, 8, 0.95);
    border-radius: 10px;
    border: 1px solid rgba(40, 168, 106, 0.7);
    padding: 8px;
    color: #c5ffd0;
}

.chat-input text {
    color: #c5ffd0;
    caret-color: #c5ffd0;
}

.chat-input.placeholder text {
    color: rgba(197, 255, 208, 0.5);
}

.chat-input-scroll {
    background: transparent;
    border: none;
}

.chat-panel button {
    margin-top: 6px;
}
"#;
