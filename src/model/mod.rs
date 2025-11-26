pub mod app_model;
pub mod chat;
pub mod quiz;
pub mod session;
pub mod step;

// Re-exports for public API compatibility
pub use app_model::{ActiveStepSnapshot, AppModel, StepSummary};
pub use chat::{ChatMessage, ChatRole};
pub use quiz::{QuestionProgress, QuizAnswer, QuizQuestion, QuizStatistics, QuizStep};
pub use session::Session;
pub use step::{Evidence, LegacyTutorialData, Phase, Step, StepContent, StepStatus};