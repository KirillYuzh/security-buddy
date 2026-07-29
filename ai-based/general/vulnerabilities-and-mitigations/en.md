
### **LLM01: Prompt Injection**
* **Risk**: Attacker manipulates the model by inputting hidden instructions, overriding system prompts. "Direct" (user input) and "Indirect" (files, parsing...) .
* **Mitigation**:
  * "Чёткие рамки работы (указание роли и обязанностей в системном промпте)".
  * "Отображение правил оценки (внутренняя логика, лимиты, ключевые слов...)".
  * "Использовать guardrails вне самой LLM. Наличие правил в системном промпте не гарантия их выполнения."
* **Tests & Skills**: **Adversarial Red Teaming** (use `garak` or `deepeval` to test for injection), **AI Gateway & Guardrails** (runtime checks). Pre-commit: flag dangerous `eval()` or `exec()` of user input.

### **LLM02: Sensitive Information Disclosure**
* **Risk**: Model leaks PII, credentials, or proprietary data in its output. "Неавторизованный доступ к информации" .
* **Mitigation**:
  * "Отделение чувствительной информации так, чтобы модель не имела к ним доступа, вынесение из системного промпта".
  * "Маскирование чувствительных данных при обучении".
  * "Использовать RBAC для ограничения неавторизованного доступа".
* **Tests & Skills**: **AI Gateway & Guardrails** (output redaction for PII). DAST: send prompts designed to extract hidden data.

### **LLM03: Supply Chain**
* **Risk**: Compromised third-party packages, model weights, or data sources lead to vulnerabilities.
* **Mitigation**:
  * "Инвентаризация через генерацию AI/ML BOM файлов" (e.g., OWASP AI BOM).
  * "Постоянные проверки на наличие спрятанного кода... добавлять данные только из проверенных источников".
  * "Коллаборация и проверка LoRA адаптеров" (Colluding LoRA adapters).
* **Tests & Skills**: **SCA** (`trivy`), **Data & Supply Chain Hygiene** (monitor DVC, check provenance). Pre-commit: pin dependencies to specific hashes.

### **LLM04: Data and Model Poisoning**
* **Risk**: Adversaries corrupt training/fine-tuning data to create a backdoor (e.g., a ROME-based attack).
* **Mitigation**:
  * "Валидация данных перед добавлением в RAG".
  * "Децентрализованное обучение моделей на разных серверах и датасетах".
  * "Proof Pudding attack" (requires defenses against subtle poisoning).
* **Tests & Skills**: **MLOps & Observability** (track training data lineage, evals for drift). **Adversarial Red Teaming** (probe for backdoor triggers).

### **LLM05: Improper Output Handling**
* **Risk**: LLM output is used unsafely, leading to XSS, RCE, or SSRF. "Некорректный/предвзятый ответ". .
* **Mitigation**:
  * "Санитайзинг, ASVS".
  * "Фильтрация и санитайзинг ввода/вывода".
  * "Валидация ответа".
* **Tests & Skills**: **SAST** (`semgrep`) scans for output used in DOM sinks, shell commands, or SQL queries. Pre-commit is critical here.

### **LLM06: Excessive Agency**
* **Risk**: The LLM agent has too many permissions, allowing it to perform unintended harmful actions (e.g., delete data).
* **Mitigation**:
  * "Политика минимальных привилегий для агентов, постоянный пересмотр прав".
  * "Проверка tools/plugins на отсутствие ненужного функционала (update/delete/message sending/crawling...)".
  * "Human-in-the-loop для важных действий".
* **Tests & Skills**: **Agent Security** (design principle). Pre-commit: scan for agent definitions that use dangerous tools. Runtime: enforce authorization checks.

### **LLM07: System Prompt Leakage**
* **Risk**: The system prompt is extracted via a jailbreak or error message. "Раскрытие информации об архитектуре/системном промпте".
* **Mitigation**:
  * "Отображение роли пользователя или других существующих ролей внутри системы".
  * "Вынесение разделения доступа... использовать несколько моделей... с минимальными привилегиями".
  * "Максимальное вынесение проверок из системного промпта в окружение модели".
* **Tests & Skills**: **Adversarial Red Teaming** (attempt to extract system prompt), **AI Gateway** (canary token detection).

### **LLM08: Vector & Embedding Weaknesses**
* **Risk**: Attacks on the RAG pipeline, like embedding inversion or cross-context conflict. "Кросс-контекстные утечки и конфликты в федеративных знаниях". .
* **Mitigation**:
  * "DB партиционирование на основе прав текущей роли через явную логику".
  * "Проверки при объединении данных (на конфликты, аудит...)".
  * "Glitch token filtering перед добавлением в контекстное окно".
* **Tests & Skills**: **Data & Supply Chain Hygiene**. DAST: test if RAG retrieves cross-tenant data. **Adversarial Red Teaming**: test for embedding inversion.

### **LLM09: Misinformation**
* **Risk**: LLM gives incorrect/false info, leading to user harm. "Пользователь основывает своё решение на неверном ответе".
* **Mitigation**:
  * "Добавить проверку фактов и регулярный пересмотр данных человеком".
  * "Использовать RAG как базу знаний для ответов".
  * "Предупреждать пользователя о возможной неточности ответов".
* **Tests & Skills**: **LLM-Specific Evals** (hallucination score). **AI Gateway** (grounding checks). **MLOps & Observability** (monitor model drift on evals).

### **LLM10: Unbounded Consumption**
* **Risk**: DoS or Denial of Wallet due to excessive token usage, loops, or large requests. "Экономические потери (избыточно потраченные ресурсы)" .
* **Mitigation**:
  * "Rate-limiting для использования модели".
  * "Resource allocation, мониторинг и работа с динамическим выделением ресурсов".
  * "Ограничить или замаскировать отображение `logit_bias` и `logprobs`".
* **Tests & Skills**: **AI Gateway & Guardrails** (enforce rate limiting). DAST: fuzz the API with large payloads.
