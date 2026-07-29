[Cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/AI_Agent_Security_Cheat_Sheet.md)


The strongest start is to read [OWASP dev guide](https://devguide.owasp.org/).

![LLM Application Architecture and Threat Modeling](./LLM%20Application%20Architecture%20and%20Threat%20Modeling.png)

source: [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

1.  **SAST (Pre-commit / semgrep)**: Use comments to suppress FP rules. For example, `# nosemgrep: python.lang.security.audit.audit-dangerous-jinja-template` when you have a valid reason. Write **custom rules** to be as specific as possible to your codebase, reducing generic FPs.
2.  **DAST (nuclei / ZAP)**: Configure a **baseline scan** first. True positives will appear as deviations from the baseline. Use the **authentication** features to ensure you're only scanning authorized endpoints.
3.  **Evals (LLM tests)**: This is the hardest area. Mitigate FPs by:
    *   **Using a Judge LLM**: Instead of simple string matching, use a separate model (e.g., LlamaGuard) to score if a prompt "attempted" a jailbreak. This handles linguistic variations but introduces its own costs .
    *   **Threshold Tuning**: Use probabilistic scores and set a high threshold (e.g., >0.9) for critical blocking actions.
    *   **Structured Reports**: As your notes mention, "Важно: P0, P1, P2". Categorize findings by severity. An alert (P2) is just an info message; a critical vulnerability (P0) is a hard failure.