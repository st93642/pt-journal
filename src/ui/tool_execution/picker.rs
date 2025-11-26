//! Pure data transformation logic for tool category and tool selection.
//!
//! This module extracts the tool picker model logic from GTK widgets,
//! making it testable without GTK initialization. It handles:
//! - Determining the default category (nmap's category or first category)
//! - Determining the default tool (nmap or first tool in category)
//! - Filtering tools by category
//! - Preserving manifest ordering

use crate::ui::tool_instructions::{self, CategoryGroup, ToolManifestEntry};

/// A reusable model describing the tool picker state derived from manifest data.
#[derive(Debug, Clone)]
pub struct ToolPickerModel {
    groups: Vec<CategoryGroup>,
    default_category_index: usize,
    default_tool_id: String,
}

impl ToolPickerModel {
    /// Constructs the picker model from the manifest and grouped manifest data.
    ///
    /// The default selection order is:
    /// 1. Prefer the `nmap` tool if present in the manifest
    /// 2. Otherwise, select the first tool in the first category
    pub fn from_manifest() -> Self {
        let groups = tool_instructions::grouped_manifest();
        if groups.is_empty() {
            return Self::empty();
        }

        let manifest = tool_instructions::manifest();
        let nmap_entry = manifest.iter().find(|entry| entry.id == "nmap");

        let default_category_name = nmap_entry
            .map(|entry| entry.category.clone())
            .or_else(|| groups.first().map(|group| group.name.clone()))
            .unwrap_or_default();

        let default_category_index = groups
            .iter()
            .position(|group| group.name == default_category_name)
            .unwrap_or(0);

        let default_tool_id = nmap_entry
            .map(|entry| entry.id.clone())
            .or_else(|| {
                groups
                    .get(default_category_index)
                    .and_then(|group| group.tools.first())
                    .map(|tool| tool.id.clone())
            })
            .or_else(|| {
                groups
                    .first()
                    .and_then(|group| group.tools.first())
                    .map(|tool| tool.id.clone())
            })
            .unwrap_or_else(|| "".to_string());

        Self {
            groups,
            default_category_index,
            default_tool_id,
        }
    }

    /// Creates an empty picker model (used when manifest fails to load).
    pub fn empty() -> Self {
        Self {
            groups: Vec::new(),
            default_category_index: 0,
            default_tool_id: String::new(),
        }
    }

    /// Returns the grouped categories for the picker.
    pub fn groups(&self) -> &[CategoryGroup] {
        &self.groups
    }

    /// Returns the default category name.
    pub fn default_category(&self) -> Option<&str> {
        self.groups
            .get(self.default_category_index)
            .map(|group| group.name.as_str())
    }

    /// Returns the index of the default category.
    pub fn default_category_index(&self) -> usize {
        self.default_category_index
    }

    /// Returns the default tool ID to select.
    pub fn default_tool_id(&self) -> &str {
        &self.default_tool_id
    }

    /// Returns the tools for a category while preserving manifest order.
    pub fn tools_for_category(&self, category: &str) -> &[ToolManifestEntry] {
        self.groups
            .iter()
            .find(|group| group.name == category)
            .map(|group| group.tools.as_slice())
            .unwrap_or(&[])
    }

    /// Returns true if the model contains any categories.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}
