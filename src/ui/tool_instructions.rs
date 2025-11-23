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
        // Check if we already have a group for this category
        let existing_group = groups.iter_mut().find(|g| g.name == entry.category);
        if let Some(group) = existing_group {
            group.tools.push(entry.clone());
        } else {
            groups.push(CategoryGroup {
                name: entry.category.clone(),
                tools: vec![entry.clone()],
            });
        }
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

    fn assert_instruction_has_required_sections(doc: &ToolInstructions, id: &str) {
        assert!(
            doc.installation_guides.len() >= 3,
            "expected at least three installation guides for {id}"
        );
        for guide in &doc.installation_guides {
            assert!(
                !guide.steps.is_empty(),
                "installation guide '{}' for {id} must include steps",
                guide.platform
            );
        }
        assert!(
            !doc.step_sequences.is_empty(),
            "step sequences missing for {id}"
        );
        assert!(
            !doc.workflow_guides.is_empty(),
            "workflow guides missing for {id}"
        );
        assert!(
            !doc.output_notes.is_empty(),
            "output notes missing for {id}"
        );
        assert!(
            !doc.advanced_usage.is_empty(),
            "advanced usage missing for {id}"
        );
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

        // Check that each category appears only once
        let mut seen_categories = std::collections::HashSet::new();
        for group in &groups {
            assert!(!seen_categories.contains(&group.name), "Category '{}' appears multiple times", group.name);
            seen_categories.insert(group.name.clone());
        }

        // Check that all tools are included and grouped correctly
        let mut total_tools = 0;
        for group in &groups {
            for tool in &group.tools {
                assert_eq!(tool.category, group.name, "Tool '{}' has wrong category", tool.id);
                total_tools += 1;
            }
        }
        assert_eq!(total_tools, registry.manifest.len(), "Not all tools are included in groups");

        // Check that tools within each category are in the order they appear in the manifest
        for group in &groups {
            let mut expected_order: Vec<_> = registry.manifest.iter()
                .filter(|entry| entry.category == group.name)
                .map(|entry| entry.id.clone())
                .collect();

            let actual_order: Vec<_> = group.tools.iter()
                .map(|tool| tool.id.clone())
                .collect();

            assert_eq!(actual_order, expected_order, "Tools in category '{}' are not in manifest order", group.name);
        }
    }

    #[test]
    fn recon_scanning_tools_have_populated_sections() {
        let registry = load_registry().expect("instructions should load");
        let critical_tools = [
            "nmap",
            "masscan",
            "naabu",
            "amass",
            "sublist3r",
            "theHarvester",
            "dnsrecon",
            "dnsenum",
            "maltego",
            "recon-ng",
            "photon",
            "spiderfoot",
            "nikto",
            "dirb",
            "gobuster",
            "ffuf",
            "wfuzz",
            "enum4linux",
            "smbmap",
            "snmpwalk",
            "onesixtyone",
            "sslyze",
            "testssl",
            "wpscan",
            "joomscan",
            "nuclei",
            "whatweb",
            "wappalyzer",
            "subjack",
        ];

        for id in critical_tools {
            let doc = registry
                .instructions
                .get(id)
                .unwrap_or_else(|| panic!("missing instructions for {id}"));
            assert_instruction_has_required_sections(doc, id);
        }
    }

    #[test]
    fn exploitation_and_credential_tools_have_populated_sections() {
        let registry = load_registry().expect("instructions should load");
        let tools = [
            "sqlmap",
            "metasploit",
            "searchsploit",
            "commix",
            "weevely",
            "hydra",
            "medusa",
            "ncrack",
            "patator",
            "john",
            "hashcat",
            "fcrackzip",
            "pdfcrack",
            "crunch",
            "cewl",
            "hashid",
        ];

        for id in tools {
            let doc = registry
                .instructions
                .get(id)
                .unwrap_or_else(|| panic!("missing instructions for {id}"));
            assert_instruction_has_required_sections(doc, id);
        }
    }

    #[test]
    fn post_ex_priv_esc_and_wireless_tools_have_populated_sections() {
        let registry = load_registry().expect("instructions should load");
        let tools = [
            "mimikatz",
            "pspy",
            "chisel",
            "ligolo-ng",
            "pwncat",
            "evil-winrm",
            "bloodhound-python",
            "impacket-scripts",
            "powersploit",
            "empire",
            "linpeas",
            "winpeas",
            "linux-smart-enumeration",
            "linux-exploit-suggester",
            "windows-exploit-suggester",
            "aircrack-ng",
            "kismet",
            "reaver",
            "bully",
            "wifite",
            "mdk4",
        ];

        for id in tools {
            let doc = registry
                .instructions
                .get(id)
                .unwrap_or_else(|| panic!("missing instructions for {id}"));
            assert_instruction_has_required_sections(doc, id);
        }
    }
}
