//! State management abstractions and patterns.
//!
//! This module provides standardized interfaces for updating application state
//! in a thread-safe manner with proper error handling and event dispatching.

pub mod updater;
pub mod updates;

pub use updater::{StateUpdater, UpdateContext, UpdateResult, UpdateError, ModelAccessor, EventDispatcher};
pub use updates::{
    SelectPhase, SelectStep, UpdateStepStatus, UpdateStepNotes, UpdateStepDescriptionNotes,
    UpdatePhaseNotes, UpdateGlobalNotes, AddChatMessage, AddEvidence, RemoveEvidence, SetChatModel
};