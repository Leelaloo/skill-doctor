# Skill Doctor

[![Scanned by Skill Doctor](https://img.shields.io/badge/Skill%20Doctor-96%2F100%20EXCELLENT-brightgreen)](https://github.com/Leelaloo/skill-doctor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.txt)

> **The pre-flight check for the agent skill supply chain — free to audit what you install, paid to gate what you publish.**

Paste any Claude Code skill in. Get a 0-100 quality score, a DO-NOT-INSTALL safety gate, auto-remediation diffs, and self-contained SVG badges.

---

## Key Features

- **Spec Validation:** Verifies official `SKILL.md` frontmatter, metadata schema, and required fields.
- **Dead-Path Detection:** Identifies missing or broken script/file references before installation.
- **Threat & Injection Scanning:** 46 checks (31 behavioral regex patterns + 15 unicode steganography characters) detecting prompt injection, interpreter pipes, obfuscated execution, and credential exfiltration.
- **Advisory Safety Gate:** Caps score below 50 and flags explicit **DO NOT INSTALL** warnings when CRITICAL findings are detected.
- **SVG Score Badges:** Generates clean, self-contained SVG score badges carrying the footer *Scanned by Skill Doctor*.
- **Auto-Remediation (`--fix`):** Previews and applies safe mechanical fixes (`chmod +x`, UTF-8 BOM stripping, frontmatter stubs, license stubs).
- **GitHub CI Action:** Drop-in composite action (`action/action.yml`) to audit incoming pull requests automatically.

---

## Quick Start

Run Skill Doctor against any local agent skill directory using Python 3:

```bash
# Run full static audit
python3 scripts/doctor.py <target-skill-folder> --json report.json

# Generate an SVG score badge
python3 scripts/doctor.py <target-skill-folder> --badge score.svg

# Preview safe mechanical fixes (dry-run mode)
python3 scripts/doctor.py <target-skill-folder> --fix

# Apply mechanical fixes & view re-scan score delta (Publisher Toolkit)
python3 scripts/doctor.py <target-skill-folder> --fix --apply
```

---

## Scoring Bands

- **90–100 EXCELLENT:** Clean structure, valid references, zero security warnings.
- **75–89 GOOD:** Solid quality; minor non-security recommendations.
- **50–74 NEEDS WORK:** Missing docs or broken script references present.
- **<50 BROKEN / RISKY (DO NOT INSTALL):** Capped score due to CRITICAL security findings or major structural breaks.

---

## Pricing & Tiers

Skill Doctor is built on an **open-source core (MIT License)**. Safety features are free forever so anyone can safely inspect untrusted skills.

| Feature | Free Core (Open Source) | Publisher Toolkit ($19.99 list / $14.99 launch) |
| :--- | :---: | :---: |
| **CLI Scanner & 0-100 Rubric** | Free Forever | Included |
| **46 Security & Threat Rules** | Free Forever | Included |
| **DO-NOT-INSTALL Gate** | Free Forever | Included |
| **SVG Badges ('Scanned by Skill Doctor')** | Free Forever | Included |
| **`--fix` Safe Auto-Remediation** | Dry-Run Preview | Full Auto-Apply & Delta Rescan |
| **GitHub CI Action Integration** | Manual Scripting | Included (`action/action.yml`) |
| **Support & Priority Pattern Updates** | Community / Issues | Direct Support & Priority Updates |

*Roadmap note:* A $49/mo Team Tier is planned for multi-repository organization policy enforcement later.

---

## Security Disclosure & Limitations

Skill Doctor is a **static analysis tool**. It adheres to explicit security boundaries:

1. **Static Analysis Only:** Skill Doctor never executes code within target skills. It cannot observe dynamic runtime conversations or multi-turn agent interactions.
2. **Red-Team Coverage (3/5):** In red-team evaluations, Skill Doctor scored 3/5 detection coverage. Scanner rules model skills as static files, while dynamic attackers model skills as conversational flows.
3. **Advisory Scoring:** Quality scores and DO-NOT-INSTALL verdicts are heuristic indicators designed for pre-flight safety checking.

---

## Repository & License

- **GitHub Repository:** [Leelaloo/skill-doctor](https://github.com/Leelaloo/skill-doctor)
- **License:** Open-source core licensed under the [MIT License](LICENSE.txt).
