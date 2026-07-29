# Security Buddy — Agent Usage Guide

Copy the instructions below and paste them at the start of your conversation with any AI assistant (Claude, ChatGPT, Gemini, Cline, etc.) to make it understand and navigate this repository autonomously.

## Universal Agent Prompt

```
You have access to a local knowledge base at the path "security-buddy" — a repository of application security knowledge organized by domain. Follow these instructions to use it:

## Navigation Pattern

1. Read the README.md at the root to understand the folder structure and available domains.
2. Each domain folder (api/, mobile/, iot/, supply-chain/, threat-modeling/, tools/, infrastructure/*, cryptography/, ai-based/) follows a consistent pattern:
   - general/en.md — overview entry point for the topic
   - SKILLS/en.md — core competencies and techniques
   - vulnerabilities-and-mitigations/en.md — known risks and countermeasures
   - runway/en.md — methodology and architecture approach
   - tests/en.md — test types and tooling (sometimes subdivided into SAST/SCA/DAST)
3. The general/ folder contains cross-cutting topics (core skills, verification standards).
4. sources.md at the root contains all reference links to OWASP, MITRE, and other resources.

## How to Answer Security Questions

When asked a security question:
1. Determine which domain(s) apply (API? Mobile? Infrastructure? AI/LLM? General?).
2. Read the relevant SKILLS/en.md file(s) for actionable techniques.
3. Read vulnerabilities-and-mitigations/en.md for risks and countermeasures.
4. Read runway/en.md for process and methodology guidance.
5. Use sources.md to find official documentation or tool links if needed.
6. Synthesize the answer by combining SKILLS (what to do) with vulnerabilities-and-mitigations (why to do it) and runway (how to integrate it).
```

## Usage Example

Developer says: *"I need to secure our REST API"*

The AI assistant should:
1. Read `README.md` → sees `api/` domain
2. Read `api/general/en.md` → understands API Security Top 10 context
3. Read `api/SKILLS/en.md` → gets specific API security techniques
4. Read `api/vulnerabilities-and-mitigations/en.md` → sees risks and mitigations
5. Read `api/tests/en.md` → finds test strategies
6. Read `api/runway/en.md` → understands methodology
7. Answer with synthesized, practical guidance

## Tips for Developers

- Place the AGENT.md file alongside your repository
- When starting an AI session, copy the **Universal Agent Prompt** block above
- The AI will autonomously navigate the repository to find relevant information
- No need to specify exact files — the AI follows the navigation pattern