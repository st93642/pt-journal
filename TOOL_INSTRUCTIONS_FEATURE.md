# Security Tool Instruction System

The security tool reference inside PT Journal is now powered by structured data files instead of hard-coded Rust match statements. This document explains how the system is organized, how the UI consumes the data, and how to author new instructional content.

## Architecture Overview

```
data/tool_instructions/
├── manifest.json       # ordered list of tools exposed in the UI
└── instructions.json   # rich instruction documents keyed by id
```

* `src/ui/tool_instructions.rs` loads the manifest and instruction catalog once at startup using `OnceLock`. It validates the data (manifest ↔ instructions parity, comparison-table dimensions, etc.) and exposes helpers such as `manifest()`, `grouped_manifest()`, and `get_instructions(id)`.
* `ToolExecutionPanel` now pulls its combo-box entries from the manifest groups (Recon, Scanning, Exploitation, …). No tool can appear in the UI without a backing instruction document.
* Inline and dialog instructions are rendered by `build_instruction_sections`, which knows how to visualize each structured section (installation guides, workflows, comparison tables, resource links, etc.). Optional sections are skipped automatically.

## Data Schema

### Manifest (`manifest.json`)
Each entry describes a selectable tool:

```json
{
  "id": "nmap",
  "label": "Nmap - Port Scanner",
  "category": "Scanning & Enumeration"
}
```

* `id` – unique identifier, referenced by instructions and UI.
* `label` – text shown in the combo box.
* `category` – grouping label; order in the file defines the group order in the UI.

### Instructions (`instructions.json`)
Each instruction document contains:

| Field | Type | Notes |
| --- | --- | --- |
| `id`, `name`, `summary` | string | Primary metadata (must match manifest id). |
| `details` | string? | Optional longer description paragraph. |
| `installation_guides` | array of `{ platform, summary?, steps[] }` | Steps support `copyable` commands for per-platform cards. |
| `quick_examples` | array of `{ description, command, notes[] }` | Replaces the old ad-hoc examples block. |
| `common_flags` | array of `{ flag, description }` | Highlight frequently used switches. |
| `operational_tips` | array of strings | Rendered as 💡 tips. |
| `step_sequences` | array of named sequences with ordered steps (`title`, `details?`, `command?`). |
| `workflow_guides` | array of `{ name, stages[] }` to describe end-to-end flows. |
| `output_notes` | array of `{ indicator, meaning, severity? }` for interpreting scanner output. |
| `advanced_usage` | array of `{ title, scenario?, command, notes[] }` for expert workflows. |
| `comparison_table` | `{ caption?, columns[], rows[][] }` – row lengths must match column count. |
| `resources` | array of `{ label, url, description? }` – displayed as clickable `LinkButton`s. |

Example snippet:

```json
{
  "id": "nmap",
  "name": "Nmap",
  "summary": "Nmap (Network Mapper) ...",
  "installation_guides": [
    {
      "platform": "Debian/Ubuntu",
      "steps": [
        { "detail": "sudo apt install nmap", "copyable": true }
      ]
    }
  ],
  "quick_examples": [
    {
      "description": "Full TCP scan",
      "command": "sudo nmap -p- -sV 10.0.0.5",
      "notes": []
    }
  ],
  "workflow_guides": [
    {
      "name": "Layered scanning workflow",
      "stages": [
        {
          "label": "Mass discovery",
          "description": "Kick off masscan or naabu ...",
          "command": "sudo masscan ..."
        }
      ]
    }
  ]
}
```

Any field may be omitted (Serde defaults will build empty collections). The UI automatically skips empty sections and logs meaningful warnings when the selected tool lacks data.

## Adding or Updating Tool Instructions

1. **Add manifest entry** – insert the tool into `data/tool_instructions/manifest.json`, keeping categories grouped logically.
2. **Add instruction document** – append a new object to `instructions.json` with the same `id`. At minimum provide `name`, `summary`, installation guides, quick examples, flags, and tips.
3. **Use the rich sections** when appropriate:
   * Step sequences for playbooks/checklists.
   * Workflow guides for layered processes (e.g., masscan → nmap).
   * Output notes for triaging confusing scanner messages.
   * Advanced usage for expert-only flags or scenarios.
   * Comparison tables/resources for contextual knowledge.
4. **Validate** – run `cargo test` (or rely on CI) to execute `tool_instructions::tests::manifest_matches_instruction_documents`, which ensures every manifest id has a matching document and that comparison tables are well formed.
5. **Preview** – launch the app or run the `ToolExecutionPanel` tests to ensure the new sections render correctly.

## Runtime Behavior & Fallbacks

* The manifest is grouped during initialization so `ComboBoxText` entries stay ordered by category without manual `append` calls.
* Tool selection defaults to `nmap` when present; otherwise the first manifest entry is selected. If no instructions can be loaded, the panel displays a descriptive placeholder.
* Dialog and inline views share the same renderer. Optional sections disappear automatically, so partial documents are acceptable during authoring.
* A missing or malformed document logs a warning and shows the fallback card instead of panicking, keeping the UI responsive.

## Authoring Tips

* Prefer actionable commands (with `copyable: true`) and follow each with short notes for context.
* When outlining playbooks, keep steps concise; use the `details` field for background and `command` for the exact snippet.
* Use comparison tables sparingly—they’re great for contrasting scanners or modes within the same family.
* Link to high-value resources (official docs, curated cheat sheets, internal runbooks) so analysts can dive deeper directly from PT Journal.

With this system, expanding the instruction catalog no longer requires touching Rust source code—contributors can focus on curating high-quality operational content.
