# Research Intelligence Report
## Princeton AI + Security Tools Deep Dive

*Generated: 2026-01-27*
*Framework: DeadMan Toolkit v5.3*

---

## Executive Summary

Comprehensive research into AI safety, security tools, and methodologies discovered through rabbit hole investigation of Princeton AI resources and related security frameworks.

---

## 1. AI RED TEAMING FRAMEWORKS

### 1.1 DeepTeam (Confident AI)
**Repository:** https://github.com/confident-ai/deepteam
**License:** Apache 2.0

**40+ Vulnerability Classes:**
- Bias (gender, race, political, religion)
- PII Leakage (direct, session, database access)
- Misinformation (factual errors, unsupported claims)
- Robustness issues (input overreliance, hijacking)
- Toxicity, Hate Speech, Harmful Content

**10+ Attack Strategies:**
- Single-turn: Prompt Injection, Leetspeak, ROT-13, Math Problem
- Multi-turn: Linear Jailbreaking, Tree Jailbreaking, Crescendo Jailbreaking

**Integration Path for BlackBox:**
```python
from deepteam import red_team
from deepteam.vulnerabilities import Bias, PII, Toxicity
from deepteam.attacks.single_turn import PromptInjection
from deepteam.attacks.multi_turn import CrescendoJailbreak
```

### 1.2 NVIDIA Garak
**Repository:** https://github.com/NVIDIA/garak
**Website:** https://garak.ai

**Capabilities:**
- 100+ attack vectors with up to 20,000 prompts per run
- Hallucination, data leakage, prompt injection detection
- Toxicity, misinformation, jailbreak scanning

**Installation:**
```bash
pip install -U git+https://github.com/NVIDIA/garak.git@main
```

**Usage:**
```bash
garak --model_type openai --model_name gpt-3.5-turbo --probes encoding
garak --model_type huggingface --model_name gpt2 --probes dan.Dan_11_0
```

### 1.3 Anthropic Petri
**Repository:** https://github.com/safety-research/petri
**Purpose:** Multi-turn AI safety auditing

**Architecture:**
- Auditor: Crafts probing scenarios
- Target: Model being tested
- Judge: Scores transcripts

**Installation:**
```bash
pip install git+https://github.com/safety-research/petri
```

### 1.4 AISafetyLab (Tsinghua)
**Repository:** https://github.com/thu-coai/AISafetyLab

**Attack Methods (13):**
- White-box: GCG
- Gray-box: AdvPrompter, AutoDAN, LAA
- Black-box: GPTFuzzer, Cipher, DeepInception, ICL Attack, Jailbroken, Multilingual, PAIR, ReNeLLM, TAP

**Defense Methods (14):**
- Preprocessing: PPL, Self Reminder, Prompt Guard, Goal Prioritization, Paraphrase, ICD
- Intraprocess: SmoothLLM, SafeDecoding, DRO, Erase and Check, Robust Aligned
- Postprocess: Self Evaluation, Aligner
- Training-time: Safety Data Tuning, Safe RLHF, Safe Unlearning

**Evaluation Scorers (10):**
- PatternScorer, PrefixMatchScorer, ClassificationScorer
- ShieldLMScorer, LlamaGuard3Scorer, HarmBenchScorer
- ReasoningShieldScorer, PromptedLLMScorer, OverRefusalScorer

---

## 2. PRINCETON AI SAFETY RESEARCH

### 2.1 Catastrophic Jailbreak via Generation Exploitation
**Paper:** arXiv:2310.06987
**Repository:** https://github.com/Princeton-SysML/Jailbreak_LLM

**Key Finding:** Manipulating decoding parameters bypasses alignment.

**Attack Parameters:**
| Configuration | Attack Success Rate |
|---|---|
| Greedy decoding | 16% |
| Temperature exploitation | 47% |
| Top-k exploitation | 54% |
| Top-p exploitation | 77% |
| Combined exploitation | 81% |

**Implication:** Alignment can be broken without prompt engineering.

### 2.2 Fine-tuning Compromises Safety
**Paper:** arXiv:2310.03693
**Repository:** https://github.com/LLM-Tuning-Safety/LLMs-Finetuning-Safety

**Risk Levels:**
1. **Explicit Harm:** 10 adversarial examples jailbreak GPT-3.5 for $0.20
2. **Implicit Harm:** 10 benign-appearing prompts reorient priorities
3. **Benign Data:** Even Alpaca/Dolly datasets degrade safety

**Key Insight:** Larger learning rates + smaller batch sizes = worse safety.

### 2.3 SORRY-Bench Safety Taxonomy
**Paper:** ICLR 2025
**Repository:** https://github.com/SORRY-Bench/sorry-bench
**Website:** https://sorry-bench.github.io

**44 Safety Categories across 4 domains:**
1. Hate Speech Generation
2. Assistance with Crimes or Torts
3. Potentially Inappropriate Topics
4. Potentially Unqualified Advice

**20 Linguistic Mutations:**
- Writing styles: interrogative, misspellings, slang
- Persuasion: logical appeal
- Encoding: ASCII, Caesar cipher, ROT-13
- Multi-language: translations

**Key Metric:** LLM scores range 6% to 90% on SORRY-Bench.

### 2.4 POLARIS Lab
**Website:** https://www.polarislab.org

**AI Law Tracker:** Documents AI hallucination citations in court filings.
**Statutory Construction for AI:** Computational framework for law-following AI.

---

## 3. CRITICAL VULNERABILITIES

### 3.1 CVE-2025-32711 (EchoLeak)
**CVSS:** 9.3 Critical
**Product:** Microsoft 365 Copilot
**Type:** Zero-click prompt injection

**Attack Chain:**
1. Bypass XPIA classifier
2. Circumvent link redaction with reference-style Markdown
3. Exploit auto-fetched images
4. Abuse Microsoft Teams proxy in CSP

**Impact:** Full privilege escalation across LLM trust boundaries without user interaction.

**Mitigations:**
- Prompt partitioning
- Enhanced input/output filtering
- Provenance-based access control
- Strict content security policies

### 3.2 CVE-2025-64496 (Open WebUI)
**CVSS:** 7.3 High
**Type:** SSE Code Injection RCE
**Fixed In:** 0.6.35

**Found 5 vulnerable instances in our scanning campaign.**

---

## 4. ATTACK METHODOLOGIES

### 4.1 Promptfoo Attack Strategies
**Documentation:** https://www.promptfoo.dev/docs/red-team/

**Prompt Injection Types:**
- Direct injection via user input
- Indirect injection via RAG/context
- SQL/Shell injection via LLM

**Jailbreak Techniques:**
- TAP (Tree of Attacks with Pruning)
- Suffix injection
- ASCII art obfuscation
- Many-shot jailbreaking
- Crescendo attacks

### 4.2 Prompt Hacking Resources
**Repository:** https://github.com/PromptLabs/Prompt-Hacking-Resources

**Key Resources:**
- InjectPrompt.com - Jailbreak catalogue
- LearnPrompting.org - Technique tutorials
- HackAPrompt.com - Competitions
- RedTeam Arena - Gamified exploitation

### 4.3 Website Reverse Engineering
**Source:** freeCodeCamp Guide

**Methodology:**
1. Explore website with DevTools Network tab
2. Identify API endpoints (filter XHR/Fetch)
3. Analyze request structure (headers, body, params)
4. Extract authentication (cookies, tokens)
5. Validate in Postman/cURL
6. Implement programmatically

---

## 5. TOOL INTEGRATION MATRIX

| Tool | Purpose | Integration Priority |
|------|---------|---------------------|
| DeepTeam | LLM Red Teaming | HIGH |
| Garak | Vulnerability Scanning | HIGH |
| Petri | Safety Auditing | MEDIUM |
| AISafetyLab | Attack/Defense Research | HIGH |
| SORRY-Bench | Safety Evaluation | MEDIUM |
| Promptfoo | Red Team Automation | HIGH |

---

## 6. RECOMMENDED INTEGRATIONS

### 6.1 For BlackBox
- Add `modules/ai_security/` with red teaming wrappers
- Integrate DeepTeam for LLM vulnerability testing
- Add Garak probes for automated scanning
- Create pipelines for CVE detection (like EchoLeak patterns)

### 6.2 For CLAUDE.md
- Add AI safety axioms from Princeton research
- Document jailbreak awareness (generation exploitation)
- Add fine-tuning safety considerations
- Include prompt injection defense patterns

### 6.3 For rules.yaml
- Add SORRY-Bench 44 categories to safety taxonomy
- Add 20 linguistic mutation patterns for detection
- Create rule chains for multi-turn jailbreak detection
- Add EchoLeak-style attack pattern rules

---

## 7. SOURCES

### Primary Sources
- [DeepTeam GitHub](https://github.com/confident-ai/deepteam)
- [NVIDIA Garak](https://github.com/NVIDIA/garak)
- [Anthropic Petri](https://github.com/safety-research/petri)
- [AISafetyLab](https://github.com/thu-coai/AISafetyLab)
- [Princeton Jailbreak](https://github.com/Princeton-SysML/Jailbreak_LLM)
- [SORRY-Bench](https://github.com/SORRY-Bench/sorry-bench)
- [Promptfoo Red Team](https://www.promptfoo.dev/docs/red-team/)
- [Prompt Hacking Resources](https://github.com/PromptLabs/Prompt-Hacking-Resources)

### Princeton Resources
- [Princeton AI Alignment](https://sites.google.com/princeton.edu/princeton-ai-alignment)
- [POLARIS Lab](https://www.polarislab.org/)
- [COS 597Q AI Safety Course](https://sites.google.com/view/cos598aisafety/)
- [AI Lab](https://ai.princeton.edu/ai-lab)

### CVE Research
- [EchoLeak Paper](https://arxiv.org/abs/2509.10540)
- [CVE-2025-32711 Analysis](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)

---

## 8. ADDITIONAL FRAMEWORKS

### 8.1 Microsoft PyRIT
**Repository:** https://github.com/Azure/PyRIT
**License:** MIT
**Stars:** 3.4k

**Battle-tested by Microsoft AI Red Team in 100+ operations.**

**Key Features:**
- Multi-turn conversation orchestration
- Audio, image, mathematical converters
- Azure Content Safety integration
- Multi-modal testing (vision, speech)
- Integrated into Azure AI Foundry (2025)

**Installation:**
```bash
pip install pyrit
# Requires Python 3.10, 3.11, or 3.12
```

### 8.2 Black Hat Rust
**Repository:** https://github.com/skerkour/black-hat-rust
**Stars:** 4.3k

**Chapter Structure:**
- Part I: Reconnaissance (discovery, async, crawling)
- Part II: Exploitation (fuzzing, exploits, shellcode, phishing)
- Part III: Implant Development (RAT, encryption, worms)

**Key Techniques:**
- Multi-threaded attack surface discovery
- Fuzzing for vulnerability discovery
- Shellcode without stdlib
- WebAssembly phishing toolkit
- Cross-platform RAT development

### 8.3 POLARIS Lab AI Law Tracker
**Website:** https://www.polarislab.org/ai-law-tracker.html

**Tracked Categories:**
1. Fake Citations/AI Hallucinations
2. AI Use in Court (No Hallucinations)
3. Copyright Litigation
4. AI Liability & Defamation
5. First Amendment Challenges

**Use Case:** Documenting AI failure modes in legal contexts.

---

## 9. ATTACK SUCCESS RATES (RESEARCH DATA)

| Attack Type | Baseline | Exploited | Source |
|-------------|----------|-----------|--------|
| Greedy decoding | 16% | - | Princeton SysML |
| Temperature exploit | 16% | 47% | Princeton SysML |
| Top-k exploit | 16% | 54% | Princeton SysML |
| Top-p exploit | 16% | 77% | Princeton SysML |
| Combined exploit | 16% | **81%** | Princeton SysML |
| 10 adversarial examples | 0% | **95%** | Fine-tuning Safety |
| Generation-aware defense | 95% | 69% | Princeton SysML |

---

## 10. TOOL INSTALLATION QUICK REFERENCE

```bash
# DeepTeam
pip install -U deepteam

# NVIDIA Garak
pip install -U git+https://github.com/NVIDIA/garak.git@main

# PyRIT (Microsoft)
pip install pyrit

# Petri (Anthropic)
pip install git+https://github.com/safety-research/petri

# AISafetyLab
git clone git@github.com:thu-coai/AISafetyLab.git && pip install -e .

# SORRY-Bench
git clone https://github.com/SORRY-Bench/sorry-bench.git
```

---

## 11. INTEGRATION CHECKLIST

### For BlackBox
- [x] Added SORRY-Bench taxonomy to ai_rules.py
- [x] Added EchoLeak attack chain patterns
- [x] Added generation exploitation parameters
- [x] Created HackerOne API integration module
- [ ] Add PyRIT orchestrator wrapper
- [ ] Add Garak probe integration
- [ ] Add DeepTeam vulnerability scanner

### For CLAUDE.md
- [x] Added AI Safety Awareness section
- [x] Added known attack vectors
- [x] Added defense layers
- [x] Added red team tools reference

### For rules.yaml / ai_rules.py
- [x] Added 44-category SORRY-Bench taxonomy
- [x] Added 20 linguistic mutations
- [x] Added generation exploit parameters
- [ ] Add PyRIT converter patterns
- [ ] Add multi-modal attack rules

---

*DeadMan Toolkit v5.3 - Research Intelligence*
*Authorization > Evidence > Minimal Impact > Ethics*
*Last Updated: 2026-01-27*
