use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, sync::OnceLock};

const MANIFEST_PATH: &str = "data/tool_instructions/manifest.json";
const INSTRUCTIONS_PATH: &str = "data/tool_instructions/instructions.json";

static REGISTRY: OnceLock<ToolInstructionRegistry> = OnceLock::new();

#[derive(Debug, Default)]
struct ToolInstructionRegistry {
    manifest: Vec<ToolManifestEntry>,
    instructions: HashMap<String, ToolInstructions>,
}

/// Returns the manifest entries loaded from disk.
pub fn manifest() -> &'static [ToolManifestEntry] {
    &registry().manifest
}

/// Returns the manifest grouped by category while preserving file order.
pub fn grouped_manifest() -> Vec<CategoryGroup> {
    let mut groups: Vec<CategoryGroup> = Vec::new();
    for entry in &registry().manifest {
        if let Some(last) = groups.last_mut() {
            if last.name == entry.category {
                last.tools.push(entry.clone());
                continue;
            }
        }
        groups.push(CategoryGroup {
            name: entry.category.clone(),
            tools: vec![entry.clone()],
        });
    }
    groups
}

/// Returns true if the catalog has instructions for the requested id.
pub fn has_tool(id: &str) -> bool {
    registry().instructions.contains_key(id)
}

/// Returns the instruction document for the provided tool id, if it exists.
pub fn get_instructions(id: &str) -> Option<&'static ToolInstructions> {
    registry().instructions.get(id)
}

fn registry() -> &'static ToolInstructionRegistry {
    REGISTRY.get_or_init(|| {
        load_registry().unwrap_or_else(|err| {
            eprintln!("[tool_instructions] Failed to load instruction data: {err}");
            ToolInstructionRegistry::default()
        })
    })
}

fn load_registry() -> Result<ToolInstructionRegistry> {
    let manifest = load_manifest()?;
    let instructions = load_instruction_documents()?;

    let mut filtered_manifest = Vec::with_capacity(manifest.len());
    for entry in manifest {
        if instructions.contains_key(&entry.id) {
            filtered_manifest.push(entry);
        } else {
            return Err(anyhow!(
                "Manifest entry '{}' does not have an instruction document",
                entry.id
            ));
        }
    }

    if filtered_manifest.len() != instructions.len() {
        let manifest_ids: HashMap<_, _> = filtered_manifest
            .iter()
            .map(|entry| (&entry.id, entry))
            .collect();
        for key in instructions.keys() {
            if !manifest_ids.contains_key(key) {
                eprintln!("[tool_instructions] Instruction file contains unused tool id '{key}'");
            }
        }
    }

    Ok(ToolInstructionRegistry {
        manifest: filtered_manifest,
        instructions,
    })
}

fn load_manifest() -> Result<Vec<ToolManifestEntry>> {
    let contents = fs::read_to_string(MANIFEST_PATH)
        .with_context(|| format!("Unable to read manifest at {MANIFEST_PATH}"))?;
    let entries: Vec<ToolManifestEntry> = serde_json::from_str(&contents)
        .with_context(|| format!("Invalid manifest JSON at {MANIFEST_PATH}"))?;
    if entries.is_empty() {
        return Err(anyhow!("Tool instruction manifest is empty"));
    }
    Ok(entries)
}

fn load_instruction_documents() -> Result<HashMap<String, ToolInstructions>> {
    let contents = fs::read_to_string(INSTRUCTIONS_PATH)
        .with_context(|| format!("Unable to read instructions at {INSTRUCTIONS_PATH}"))?;
    let mut docs: Vec<ToolInstructions> = serde_json::from_str(&contents)
        .with_context(|| format!("Invalid instructions JSON at {INSTRUCTIONS_PATH}"))?;

    let mut map = HashMap::with_capacity(docs.len());
    for doc in docs.drain(..) {
        if map.contains_key(&doc.id) {
            return Err(anyhow!(
                "Duplicate instruction document defined for tool '{}'.",
                doc.id
            ));
        }
        validate_instruction(&doc)?;
        map.insert(doc.id.clone(), doc);
    }

    if map.is_empty() {
        return Err(anyhow!("No instruction documents were loaded"));
    }

    Ok(map)
}

fn validate_instruction(doc: &ToolInstructions) -> Result<()> {
    if let Some(table) = &doc.comparison_table {
        let column_count = table.columns.len();
        if column_count > 0 {
            for (idx, row) in table.rows.iter().enumerate() {
                if row.len() != column_count {
                    return Err(anyhow!(
                        "Comparison table for '{}' row {} has {} columns but expected {}",
                        doc.id,
                        idx + 1,
                        row.len(),
                        column_count
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolManifestEntry {
    pub id: String,
    pub label: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct CategoryGroup {
    pub name: String,
    pub tools: Vec<ToolManifestEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolInstructions {
    pub id: String,
    pub name: String,
    pub summary: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub installation_guides: Vec<InstallationGuide>,
    #[serde(default)]
    pub quick_examples: Vec<CommandExample>,
    #[serde(default)]
    pub step_sequences: Vec<InstructionSequence>,
    #[serde(default)]
    pub workflow_guides: Vec<WorkflowGuide>,
    #[serde(default)]
    pub output_notes: Vec<OutputNote>,
    #[serde(default)]
    pub common_flags: Vec<FlagEntry>,
    #[serde(default)]
    pub operational_tips: Vec<String>,
    #[serde(default)]
    pub advanced_usage: Vec<AdvancedExample>,
    #[serde(default)]
    pub comparison_table: Option<ComparisonTable>,
    #[serde(default)]
    pub resources: Vec<ResourceLink>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallationGuide {
    pub platform: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub steps: Vec<GuideStep>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuideStep {
    pub detail: String,
    #[serde(default)]
    pub copyable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandExample {
    pub description: String,
    pub command: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlagEntry {
    pub flag: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstructionSequence {
    pub title: String,
    #[serde(default)]
    pub steps: Vec<SequenceStep>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SequenceStep {
    pub title: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowGuide {
    pub name: String,
    #[serde(default)]
    pub stages: Vec<WorkflowStage>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowStage {
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputNote {
    pub indicator: String,
    pub meaning: String,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvancedExample {
    pub title: String,
    #[serde(default)]
    pub scenario: Option<String>,
    pub command: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComparisonTable {
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLink {
    pub label: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_registry_loaded() -> &'static ToolInstructionRegistry {
        if REGISTRY.get().is_none() {
            let data = load_registry().expect("instructions should load in tests");
            let _ = REGISTRY.set(data);
        }
        registry()
    }

    #[test]
    fn manifest_matches_instruction_documents() {
        let registry = load_registry().expect("instructions should load");
        assert!(!registry.manifest.is_empty());
        assert_eq!(registry.manifest.len(), registry.instructions.len());
        for entry in &registry.manifest {
            assert!(registry.instructions.contains_key(&entry.id));
        }
    }

    #[test]
    fn grouped_manifest_preserves_ordering() {
        let registry = ensure_registry_loaded();
        let groups = grouped_manifest();
        assert!(!groups.is_empty());
        let mut idx = 0;
        for group in groups {
            for tool in group.tools {
                assert_eq!(tool.category, group.name);
                assert_eq!(tool.id, registry.manifest[idx].id);
                idx += 1;
            }
        }
    }
}
