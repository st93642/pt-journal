use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Frame, Paned};
use std::cell::RefCell;
use std::rc::Rc;

use crate::dispatcher::create_event_bus;
use crate::model::AppModel;
use crate::ui::state::StateManager;

pub fn build_ui(app: &Application, model: AppModel) {
    let model = Rc::new(RefCell::new(model));

    // Create event bus for event-driven communication
    let dispatcher = create_event_bus();

    // Create state manager
    let state = Rc::new(StateManager::new(model.clone(), dispatcher.clone()));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("PT Journal")
        .default_width(1600) // Wider window for 3-column layout
        .default_height(900)
        .resizable(true)
        .build();

    // Position window at top-left corner (0,0)
    // Note: Due to GTK trait bounds conflicts with VTE, we use a workaround
    window.present();

    // Attempt to position the window using available methods
    let window_clone = window.clone();
    glib::idle_add_local_once(move || {
        // Try to set window position using surface if available
        if let Some(_surface) = window_clone.surface() {
            // Use a simple approach - the window manager may still override this
            // In production, you might want to use window manager hints or environment variables
        }
    });

    // Load custom CSS for chat panel styling
    let css_provider = gtk4::CssProvider::new();
    css_provider.load_from_string(
        r#"
        .chat-panel {
            background-color: rgba(0, 20, 0, 0.9);
            border: 1px solid #00ff00;
            border-radius: 8px;
        }
        
        .chat-history {
            background-color: rgba(0, 10, 0, 0.8);
            padding: 12px;
        }
        
        .chat-input {
            color: #00ff00;
            background-color: rgba(0, 20, 0, 0.9);
            font-family: monospace;
            font-size: 12px;
            padding: 8px;
        }
        
        .chat-input text {
            color: #00ff00;
            background-color: rgba(0, 20, 0, 0.9);
            padding: 8px;
        }
        
        .chat-message-content {
            color: #00ff00;
            font-family: monospace;
            font-size: 11px;
        }
        
        .assistant-content {
            font-size: 14px;
        }
        
        .user-message {
            color: #00ff00;
            font-weight: bold;
        }
        
        .assistant-message {
            color: #00ff00;
            font-style: italic;
        }
        
        .timestamp {
            color: #666666;
            font-size: 9px;
        }
        
        .error {
            color: #ff6b6b;
            background-color: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff6b6b;
            border-radius: 4px;
            padding: 4px;
        }
        vte-terminal {
            background-color: #f0f0f0;
            color: #000000;
        }
        "#,
    );

    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().unwrap(),
        &css_provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Header bar with Open/Save and Sidebar toggle
    let (header, btn_sidebar) = crate::ui::header_bar::create_header_bar();
    window.set_titlebar(Some(&header));

    // Left panel: phase selector + steps list
    let (left_box, phase_combo, steps_list) = crate::ui::sidebar::create_sidebar(&model);

    // Center panel: detail view with checkbox, title, description, chat
    let detail_panel = crate::ui::detail_panel::create_detail_panel();
    let center = detail_panel.container().clone();

    // Right panel: security tools
    let tool_frame = Frame::builder()
        .label("Security Tools")
        .child(&detail_panel.tool_panel().container)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(4)
        .margin_end(8)
        .vexpand(true)
        .hexpand(true)
        .build();

    // Keep reference to full detail_panel for handlers
    let detail_panel_ref = Rc::new(detail_panel);

    // Register UI update handlers
    let detail_panel_update = detail_panel_ref.clone();
    let state_update = state.clone();
    dispatcher.borrow_mut().on_chat_message_added =
        Box::new(move |phase_idx, step_idx, message| {
            let current_phase = state_update.current_phase();
            let current_step = state_update.current_step().unwrap_or(0);
            if phase_idx == current_phase && step_idx == current_step {
                detail_panel_update.chat_panel().add_message(&message);
            }
        });

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
    let _phase_handler_id = crate::ui::handlers::setup_phase_handler(
        &phase_combo,
        &steps_list,
        state.clone(),
        detail_panel_ref.clone(),
    );

    // Step selection handlers (wired during rebuild_steps_list)
    crate::ui::handlers::setup_step_handlers(&steps_list, state.clone(), detail_panel_ref.clone());

    // Chat panel handlers
    crate::ui::handlers::setup_chat_handlers(detail_panel_ref.clone(), state.clone());

    // Sidebar toggle handler
    let _sidebar_handlers = crate::ui::handlers::setup_sidebar_handler(&btn_sidebar, &left_box);

    // === LAYOUT ===
    // Three-column layout: Sidebar (left) | Content (center) | Tools (right)

    // First split: center + tools
    let center_tools_paned = Paned::new(gtk4::Orientation::Horizontal);
    center_tools_paned.set_start_child(Some(&center));
    center_tools_paned.set_end_child(Some(&tool_frame));
    center_tools_paned.set_position(1000); // Center takes 1000px, tools get more space
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
    crate::ui::handlers::rebuild_steps_list(&steps_list, &state, &detail_panel_ref);

    // Rebuild phase combo after window is presented to ensure proper refresh
    glib::idle_add_local_once(move || {
        crate::ui::handlers::rebuild_phase_combo(&phase_combo, &state);
    });
}
