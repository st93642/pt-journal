#!/usr/bin/env python3
"""Utility script to audit tutorial phases and tool instruction coverage.

This script parses `src/tutorials/mod.rs` to determine the ordered list of
phases, inspects each JSON definition under `data/tutorials/`, and summarizes
step counts, quiz references, and AI-focused content. It also groups tool
instructions based on the manifest and surfaces categories that already include
AI/LLM tooling.

The output is emitted as JSON for easy downstream processing when authoring
curriculum audits or roadmap documents.
"""
from __future__ import annotations

import json
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any

BASE_DIR = Path(__file__).resolve().parents[1]
MOD_PATH = BASE_DIR / "src" / "tutorials" / "mod.rs"
TUTORIAL_DIR = BASE_DIR / "data" / "tutorials"
TOOL_MANIFEST = BASE_DIR / "data" / "tool_instructions" / "manifest.json"

AI_KEYWORDS = {"ai", "genai", "llm", "rag", "rag-based", "ai-powered", "automation-ai"}
AI_TAGS = {"ai", "llm", "genai", "rag", "machine-learning", "ai-assisted", "ai-security"}


@dataclass
class PhaseSummary:
    order: int
    id: str
    title: str
    type: str
    step_count: int
    quiz_step_count: int
    quiz_file_refs: List[str]
    ai_focus: bool
    description: str


@dataclass
class ToolCategorySummary:
    name: str
    tool_count: int
    ai_tool_ids: List[str]
    tools: List[Dict[str, str]]


def tokenize(text: str) -> List[str]:
    return re.split(r"[\s_\-/]+", text.lower()) if text else []


def infer_ai_focus(phase_id: str, title: str, description: str, steps: List[dict]) -> bool:
    tokens = set(tokenize(phase_id) + tokenize(title) + tokenize(description))
    if tokens & AI_KEYWORDS:
        return True
    for step in steps:
        step_tokens = set(tokenize(step.get("title", "")) + tokenize(step.get("content", "")))
        tags = {t.lower() for t in step.get("tags", [])}
        if step_tokens & AI_KEYWORDS or tags & AI_TAGS:
            return True
    return False


def parse_phase_order() -> List[str]:
    mod_text = MOD_PATH.read_text()
    fn_idx = mod_text.find("pub fn load_tutorial_phases")
    if fn_idx == -1:
        raise RuntimeError("Unable to locate load_tutorial_phases() definition")
    vec_idx = mod_text.find("vec![", fn_idx)
    if vec_idx == -1:
        raise RuntimeError("Unable to locate vec![] initialization")
    idx = vec_idx + len("vec![")
    depth = 1
    body_chars: List[str] = []
    while idx < len(mod_text) and depth > 0:
        ch = mod_text[idx]
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                break
        body_chars.append(ch)
        idx += 1
    body = ''.join(body_chars)
    return re.findall(r'load_tutorial_phase\("([^\"]+)"\)', body)


def load_phase_summary(phase_id: str, order: int) -> PhaseSummary:
    path = TUTORIAL_DIR / f"{phase_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing tutorial definition: {path}")
    data = json.loads(path.read_text())
    steps = data.get("steps", [])
    quiz_step_count = 0
    quiz_refs: List[str] = []
    for step in steps:
        tags = {tag.lower() for tag in step.get("tags", [])}
        if "quiz" in tags:
            quiz_step_count += 1
            content = step.get("content", "")
            prefix = "Quiz content loaded from "
            if content.startswith(prefix):
                quiz_refs.append(content.removeprefix(prefix))
    ai_focus = infer_ai_focus(phase_id, data.get("title", phase_id), data.get("description", ""), steps)
    return PhaseSummary(
        order=order,
        id=phase_id,
        title=data.get("title", phase_id),
        type=data.get("type", "tutorial"),
        step_count=len(steps),
        quiz_step_count=quiz_step_count,
        quiz_file_refs=quiz_refs,
        ai_focus=ai_focus,
        description=data.get("description", ""),
    )


def load_tool_categories() -> List[ToolCategorySummary]:
    entries = json.loads(TOOL_MANIFEST.read_text())
    grouped: "OrderedDict[str, List[dict]]" = OrderedDict()
    for entry in entries:
        grouped.setdefault(entry["category"], []).append(entry)
    ai_tool_ids = {
        entry["id"]
        for entry in entries
        if any(token in tokenize(entry["label"]) for token in ("ai", "llm", "genai"))
        or "ai" in entry["id"].lower()
        or "llm" in entry["id"].lower()
        or "rag" in entry["id"].lower()
    }

    summaries: List[ToolCategorySummary] = []
    for name, tools in grouped.items():
        category_ai_tools = [t["id"] for t in tools if t["id"] in ai_tool_ids]
        summaries.append(
            ToolCategorySummary(
                name=name,
                tool_count=len(tools),
                ai_tool_ids=category_ai_tools,
                tools=tools,
            )
        )
    return summaries


def main() -> None:
    phase_ids = parse_phase_order()
    phases = [load_phase_summary(pid, idx + 1) for idx, pid in enumerate(phase_ids)]
    total_steps = sum(phase.step_count for phase in phases)
    total_quiz_steps = sum(phase.quiz_step_count for phase in phases)
    ai_phases = [phase.id for phase in phases if phase.ai_focus]

    tool_categories = load_tool_categories()
    total_tools = sum(cat.tool_count for cat in tool_categories)

    output: Dict[str, Any] = {
        "phase_count": len(phases),
        "total_steps": total_steps,
        "total_quiz_steps": total_quiz_steps,
        "ai_phase_count": len(ai_phases),
        "phases": [asdict(phase) for phase in phases],
        "tool_category_count": len(tool_categories),
        "tool_categories": [asdict(cat) for cat in tool_categories],
        "total_tools": total_tools,
    }
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
