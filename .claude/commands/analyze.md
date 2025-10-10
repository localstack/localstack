---
description: Perform a non-destructive cross-artifact consistency and quality analysis across spec.md, plan.md, and tasks.md after task generation.
---

The user input to you can be provided directly by the agent or as a command argument - you **MUST** consider it before proceeding with the prompt (if not empty).

User input:

$ARGUMENTS

Goal: Identify inconsistencies, duplications, ambiguities, and underspecified items across the three core artifacts (`spec.md`, `plan.md`, `tasks.md`) before implementation. This command MUST run only after `/tasks` has successfully produced a complete `tasks.md`.

STRICTLY READ-ONLY: Do **not** modify any files. Output a structured analysis report. Offer an optional remediation plan (user must explicitly approve before any follow-up editing commands would be invoked manually).

Constitution Authority: The project constitution (`.specify/memory/constitution.md`) is **non-negotiable** within this analysis scope. Constitution conflicts are automatically CRITICAL and require adjustment of the spec, plan, or tasks—not dilution, reinterpretation, or silent ignoring of the principle. If a principle itself needs to change, that must occur in a separate, explicit constitution update outside `/analyze`.

Execution steps:

1. Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` once from repo root and parse JSON for FEATURE_DIR and AVAILABLE_DOCS. Derive absolute paths:
   - SPEC = FEATURE_DIR/spec.md
   - PLAN = FEATURE_DIR/plan.md
   - TASKS = FEATURE_DIR/tasks.md
   Abort with an error message if any required file is missing (instruct the user to run missing prerequisite command).

2. Load artifacts:
   - Parse spec.md sections: Overview/Context, Functional Requirements, Non-Functional Requirements, User Stories, Edge Cases (if present).
   - Parse plan.md: Architecture/stack choices, Data Model references, Phases, Technical constraints.
   - Parse tasks.md: Task IDs, descriptions, phase grouping, parallel markers [P], referenced file paths.
   - Load constitution `.specify/memory/constitution.md` for principle validation.

3. Build internal semantic models:
   - Requirements inventory: Each functional + non-functional requirement with a stable key (derive slug based on imperative phrase; e.g., "User can upload file" -> `user-can-upload-file`).
   - User story/action inventory.
   - Task coverage mapping: Map each task to one or more requirements or stories (inference by keyword / explicit reference patterns like IDs or key phrases).
   - Constitution rule set: Extract principle names and any MUST/SHOULD normative statements.

4. Detection passes:
   A. Duplication detection:
      - Identify near-duplicate requirements. Mark lower-quality phrasing for consolidation.
   B. Ambiguity detection:
      - Flag vague adjectives (fast, scalable, secure, intuitive, robust) lacking measurable criteria.
      - Flag unresolved placeholders (TODO, TKTK, ???, <placeholder>, etc.).
   C. Underspecification:
      - Requirements with verbs but missing object or measurable outcome.
      - User stories missing acceptance criteria alignment.
      - Tasks referencing files or components not defined in spec/plan.
   D. Constitution alignment:
      - Any requirement or plan element conflicting with a MUST principle.
      - Missing mandated sections or quality gates from constitution.
   E. Coverage gaps:
      - Requirements with zero associated tasks.
      - Tasks with no mapped requirement/story.
      - Non-functional requirements not reflected in tasks (e.g., performance, security).
   F. Inconsistency:
      - Terminology drift (same concept named differently across files).
      - Data entities referenced in plan but absent in spec (or vice versa).
      - Task ordering contradictions (e.g., integration tasks before foundational setup tasks without dependency note).
      - Conflicting requirements (e.g., one requires to use Next.js while other says to use Vue as the framework).

5. Severity assignment heuristic:
   - CRITICAL: Violates constitution MUST, missing core spec artifact, or requirement with zero coverage that blocks baseline functionality.
   - HIGH: Duplicate or conflicting requirement, ambiguous security/performance attribute, untestable acceptance criterion.
   - MEDIUM: Terminology drift, missing non-functional task coverage, underspecified edge case.
   - LOW: Style/wording improvements, minor redundancy not affecting execution order.

6. Produce a Markdown report (no file writes) with sections:

   ### Specification Analysis Report
   | ID | Category | Severity | Location(s) | Summary | Recommendation |
   |----|----------|----------|-------------|---------|----------------|
   | A1 | Duplication | HIGH | spec.md:L120-134 | Two similar requirements ... | Merge phrasing; keep clearer version |
   (Add one row per finding; generate stable IDs prefixed by category initial.)

   Additional subsections:
   - Coverage Summary Table:
     | Requirement Key | Has Task? | Task IDs | Notes |
   - Constitution Alignment Issues (if any)
   - Unmapped Tasks (if any)
   - Metrics:
     * Total Requirements
     * Total Tasks
     * Coverage % (requirements with >=1 task)
     * Ambiguity Count
     * Duplication Count
     * Critical Issues Count

7. At end of report, output a concise Next Actions block:
   - If CRITICAL issues exist: Recommend resolving before `/implement`.
   - If only LOW/MEDIUM: User may proceed, but provide improvement suggestions.
   - Provide explicit command suggestions: e.g., "Run /specify with refinement", "Run /plan to adjust architecture", "Manually edit tasks.md to add coverage for 'performance-metrics'".

8. Ask the user: "Would you like me to suggest concrete remediation edits for the top N issues?" (Do NOT apply them automatically.)

Behavior rules:
- NEVER modify files.
- NEVER hallucinate missing sections—if absent, report them.
- KEEP findings deterministic: if rerun without changes, produce consistent IDs and counts.
- LIMIT total findings in the main table to 50; aggregate remainder in a summarized overflow note.
- If zero issues found, emit a success report with coverage statistics and proceed recommendation.

Context: $ARGUMENTS
