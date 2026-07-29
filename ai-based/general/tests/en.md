

| **Test Type** | **Examples / Tools** | **What It Covers** | **Implementation Idea** |
| :--- | :--- | :--- | :--- |
| **Pre-commit Hooks (SAST)** | `semgrep`, custom rules | **LLM01, LLM05, LLM07**: Prevents developers from hardcoding secrets, writing insecure prompt concatenation (e.g., f-string with user input), or embedding system prompts in client-side code. | A `semgrep` rule to flag `f"System: {user_input}"` patterns or any string containing "API_KEY" or "SECRET". |
| **Software Composition Analysis (SCA)** | `trivy`, `safety`, `dependabot` | **LLM03**: Detects known vulnerabilities in Python packages (e.g., `transformers`, `langchain`) and base container images. | `trivy fs .` or `trivy image your-llm-image`. Must also check for `requirements.txt` and `pyproject.toml`. |
| **Dynamic Security Testing (DAST)** | `nuclei`, custom fuzzing, `ZAP` | **LLM01, LLM06, LLM09**: Tests the running application. `nuclei` has templates for prompt injection and path traversal. Can be extended to test for jailbreaks, agent tool misuse, and excessive consumption. | Use `nuclei -t http/ai/` or build a custom fuzzer to send adversarial prompts and validate the JSON response structure. |
| **LLM-Specific Evals** | Frameworks like `garak`, `PromptInject`, `deepeval` | **LLM01, LLM02, LLM04, LLM08, LLM09**: A separate category of tests specifically designed to "break" the LLM. They evaluate for hallucinations, toxicity, prompt injection, and data leakage. These should be run in CI/CD against the model endpoint. | Use `garak` to run a suite of prompt injection probes. Check `deepeval` for custom metrics like answer relevancy and hallucination. |
| **Runtime Guardrails** | `neuraltrust`, `futureagi`, `guardrails.ai` | **LLM01, LLM02, LLM05, LLM07**: Runtime inline checks that intercept prompts before they hit the model and responses before they are sent to the user. This is a runtime *test* that enforces policy. | Integrate a guardrail to scan for PII (e.g., using Presidio), block prompt injection attempts, and validate output schemas. |
| **Security Boundary Testing** | Manual Red Teaming, Automated Scanners | **LLM06, LLM08, LLM09**: Testing for vulnerabilities in the model’s integration with other systems—can it be tricked into SQL injection, command injection, or excessive function calls? | Simulate multi-step attacks targeting external tools and plugins . Ensure the model cannot issue commands like `rm -rf` or SQL `DROP`. |

### **Reaction to FPs in Your Reporting**

*   **Record FPs**: When an analyst classifies a finding as a false positive, it should be logged.
*   **Tune Rules**: Use this log to refine your detection logic. For `semgrep`, write a "path" filter (e.g., `- exclude: path/to/tests/`) to skip test files, reducing noise.
*   **Automated Retesting**: The report should include a re-test status. After a fix, the security check runs again. If it fails again, the report updates from "Remediated" to "Failed."