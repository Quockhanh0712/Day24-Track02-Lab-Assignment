# MedViet Data Governance & Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a robust, compliant Data Governance & Security pipeline for the MedViet AI Platform, covering PII Detection/Anonymization, RBAC (FastAPI + Casbin), Envelope Encryption, Data Quality Validation (Great Expectations), ABAC (OPA Policy), and Security Scanning (git-secrets, bandit).

**Architecture:** A Python/FastAPI backend integrated with Presidio Analyzer/Anonymizer, Casbin for RBAC, Cryptography for envelope encryption, and Great Expectations for dataset validation.

**Tech Stack:** Python 3.12, FastAPI, Casbin, Presidio, spaCy (vi_core_news_lg), Faker, Cryptography, Great Expectations, OPA, pytest, bandit.

## Global Constraints
- NĐ13/2023 Localization and Consent rules must be respected.
- PII Detection rate must be >= 95% on sample patient data.
- No plaintext credentials or secrets in source files (subject to git-secrets hook checking).

---

### Task 1: PII Recognizers & Analyzer Engine (`detector.py`)

**Files:**
- Modify: `src/pii/detector.py`
- Test: `tests/test_pii.py` (specifically check custom analyzer initialization)

**Interfaces:**
- Produces: `build_vietnamese_analyzer() -> AnalyzerEngine`
- Produces: `detect_pii(text: str, analyzer: AnalyzerEngine) -> list`

- [ ] **Step 1: Write build_vietnamese_analyzer**
  Set up Custom Pattern Recognizers for CCCD (12 digits) and Phone (VN format starting with 03/05/07/08/09). Set up spacy NLP engine using `vi_core_news_lg`. Add regex Vietnamese name recognizer to ensure 95%+ detection.
  ```python
  from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
  from presidio_analyzer.nlp_engine import NlpEngineProvider
  
  def build_vietnamese_analyzer() -> AnalyzerEngine:
      cccd_pattern = Pattern(
          name="cccd_pattern",
          regex=r"\b\d{12}\b",
          score=0.9
      )
      cccd_recognizer = PatternRecognizer(
          supported_entity="VN_CCCD",
          patterns=[cccd_pattern],
          context=["cccd", "căn cước", "chứng minh", "cmnd"]
      )
      phone_recognizer = PatternRecognizer(
          supported_entity="VN_PHONE",
          patterns=[Pattern(
              name="vn_phone",
              regex=r"\b0[35789]\d{8}\b",
              score=0.85
          )],
          context=["điện thoại", "sdt", "phone", "liên hệ"]
      )
      person_recognizer = PatternRecognizer(
          supported_entity="PERSON",
          supported_language="vi",
          patterns=[Pattern(
              name="vn_person_latin",
              regex=r"\b[A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ][a-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]*(?:\s+[A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐa-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]+){0,3}\b",
              score=0.65
          )]
      )
      provider = NlpEngineProvider(nlp_configuration={
          "nlp_engine_name": "spacy",
          "models": [{"lang_code": "vi", "model_name": "vi_core_news_lg"}]
      })
      nlp_engine = provider.create_engine()
      analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["vi"])
      analyzer.registry.add_recognizer(cccd_recognizer)
      analyzer.registry.add_recognizer(phone_recognizer)
      analyzer.registry.add_recognizer(person_recognizer)
      return analyzer
  ```

- [ ] **Step 2: Write detect_pii**
  ```python
  def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
      return analyzer.analyze(
          text=text,
          language="vi",
          entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
      )
  ```

- [ ] **Step 3: Commit**
  ```bash
  git add src/pii/detector.py
  git commit -m "feat: implement Vietnamese PII detectors"
  ```

---

### Task 2: PII Anonymization Engine (`anonymizer.py`)

**Files:**
- Modify: `src/pii/anonymizer.py`

**Interfaces:**
- Consumes: `build_vietnamese_analyzer() -> AnalyzerEngine`, `detect_pii(text: str, analyzer: AnalyzerEngine) -> list`
- Produces: `MedVietAnonymizer.anonymize_text(text: str, strategy: str) -> str`
- Produces: `MedVietAnonymizer.anonymize_dataframe(df: pd.DataFrame) -> pd.DataFrame`
- Produces: `MedVietAnonymizer.calculate_detection_rate(original_df: pd.DataFrame, pii_columns: list) -> float`

- [ ] **Step 1: Implement anonymize_text**
  Support replace (Faker), mask, and hash (SHA-256) strategies.
  ```python
  import hashlib
  
  # inside anonymize_text:
  if strategy == "replace":
      operators = {
          "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
          "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
          "VN_CCCD": OperatorConfig("replace", {"new_value": fake.ssn() if hasattr(fake, 'ssn') else "012345678901"}),
          "VN_PHONE": OperatorConfig("replace", {"new_value": "09" + "".join([str(random.randint(0,9)) for _ in range(8)])}),
      }
  elif strategy == "mask":
      operators = {
          "PERSON": OperatorConfig("mask", {"chars_to_mask": 8, "masking_char": "*", "from_end": True}),
          "EMAIL_ADDRESS": OperatorConfig("mask", {"chars_to_mask": 8, "masking_char": "*", "from_end": True}),
          "VN_CCCD": OperatorConfig("mask", {"chars_to_mask": 10, "masking_char": "*", "from_end": True}),
          "VN_PHONE": OperatorConfig("mask", {"chars_to_mask": 8, "masking_char": "*", "from_end": True}),
      }
  elif strategy == "hash":
      # We implement custom hashing via operator or direct substitution, but for Presidio, custom hash operator works as follows:
      # Presidio anonymizer has a custom operator. We can pass a lambda or use "custom" operator.
      # Let's define a custom hashing logic in operators:
      def hash_value(val):
          return hashlib.sha256(val.encode('utf-8')).hexdigest()
      operators = {
          "PERSON": OperatorConfig("custom", {"lambda": hash_value}),
          "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": hash_value}),
          "VN_CCCD": OperatorConfig("custom", {"lambda": hash_value}),
          "VN_PHONE": OperatorConfig("custom", {"lambda": hash_value}),
      }
  ```

- [ ] **Step 2: Implement anonymize_dataframe**
  ```python
  def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
      df_anon = df.copy()
      for col in ["ho_ten", "dia_chi", "email"]:
          if col in df_anon.columns:
              df_anon[col] = df_anon[col].astype(str).apply(lambda x: self.anonymize_text(x, "replace"))
      for col in ["cccd"]:
          if col in df_anon.columns:
              # For numeric fields like cccd, replace directly with fake cccd
              df_anon[col] = df_anon[col].apply(lambda x: "".join([str(random.randint(0,9)) for _ in range(12)]))
      for col in ["so_dien_thoai"]:
          if col in df_anon.columns:
              df_anon[col] = df_anon[col].apply(lambda x: "0" + str(random.choice([3,5,7,8,9])) + "".join([str(random.randint(0,9)) for _ in range(8)]))
      return df_anon
  ```

- [ ] **Step 3: Implement calculate_detection_rate**
  Calculate percentage of cells containing PII that detect at least 1 PII entity.
  ```python
  def calculate_detection_rate(self, original_df: pd.DataFrame, pii_columns: list) -> float:
      total = 0
      detected = 0
      for col in pii_columns:
          for value in original_df[col].astype(str):
              total += 1
              results = detect_pii(value, self.analyzer)
              if len(results) > 0:
                  detected += 1
      return detected / total if total > 0 else 0.0
  ```

- [ ] **Step 4: Commit**
  ```bash
  git add src/pii/anonymizer.py
  git commit -m "feat: implement MedVietAnonymizer class"
  ```

---

### Task 3: PII Unit Tests (`test_pii.py`)

**Files:**
- Modify: `tests/test_pii.py`

- [ ] **Step 1: Write test assertions in test_pii.py**
  Ensure cccd, phone, and email detection and anonymization logic are properly verified, meeting the requirement of detection rate >= 95%.
  ```python
  # Write pytest assertions matching the placeholders in tests/test_pii.py
  ```

- [ ] **Step 2: Run pytest to verify all tests pass**
  Run: `pytest tests/test_pii.py -v`
  Expected: All tests pass.

- [ ] **Step 3: Commit**
  ```bash
  git add tests/test_pii.py
  git commit -m "test: add robust unit tests for PII pipeline"
  ```

---

### Task 4: Casbin RBAC Policies (`policy.csv`, `rbac.py`)

**Files:**
- Modify: `src/access/policy.csv`
- Modify: `src/access/rbac.py`

**Interfaces:**
- Produces: `get_current_user` dependency
- Produces: `require_permission(resource: str, action: str)` decorator

- [ ] **Step 1: Define CSV policies**
  Configure roles (admin, ml_engineer, data_analyst, intern) with specific resource access.
  ```csv
  # policies in src/access/policy.csv
  ```

- [ ] **Step 2: Implement get_current_user**
  Parse Bearer token. Raise 401 HTTPExceptions on error.
  ```python
  def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
      if not authorization or not authorization.startswith("Bearer "):
          raise HTTPException(status_code=401, detail="Missing token")
      token = authorization.split(" ")[1]
      user = MOCK_USERS.get(token)
      if not user:
          raise HTTPException(status_code=401, detail="Invalid token")
      return user
  ```

- [ ] **Step 3: Implement require_permission**
  Verify Casbin enforcement and raise 403 HTTPExceptions when forbidden.
  ```python
  # use enforcer.enforce(role, resource, action)
  ```

- [ ] **Step 4: Commit**
  ```bash
  git add src/access/policy.csv src/access/rbac.py
  git commit -m "feat: integrate Casbin RBAC security decorators"
  ```

---

### Task 5: FastAPI Endpoints (`main.py`)

**Files:**
- Modify: `src/api/main.py`

- [ ] **Step 1: Write endpoints in main.py**
  Implement raw patient reader (first 10 records), anonymized reader, aggregation aggregator, and patient deleter.
  ```python
  # complete main.py endpoints
  ```

- [ ] **Step 2: Run verification tests for API endpoints**
  Create a test script or use pytest to verify FastAPI endpoints and mock authentication.
  
- [ ] **Step 3: Commit**
  ```bash
  git add src/api/main.py
  git commit -m "feat: complete FastAPI endpoints with RBAC protection"
  ```

---

### Task 6: Envelope Encryption Vault (`vault.py`)

**Files:**
- Modify: `src/encryption/vault.py`

**Interfaces:**
- Produces: `SimpleVault.encrypt_data(plaintext: str) -> dict`
- Produces: `SimpleVault.decrypt_data(encrypted_payload: dict) -> str`

- [ ] **Step 1: Implement vault encryption roundtrip**
  Complete `_load_or_create_kek`, `generate_dek`, `decrypt_dek`, `encrypt_data`, and `decrypt_data` using `AESGCM`. Clear DEK plaintext from memory.
  
- [ ] **Step 2: Run interactive test script**
  Create `tests/test_vault.py` or run a python subprocess to assert envelope encryption validity.
  
- [ ] **Step 3: Commit**
  ```bash
  git add src/encryption/vault.py
  git commit -m "feat: implement envelope encryption in SimpleVault"
  ```

---

### Task 7: Great Expectations Quality Checks (`validation.py`)

**Files:**
- Modify: `src/quality/validation.py`

- [ ] **Step 1: Write Great Expectations rules in validation.py**
  Create the expectation suite validating CCCD length, test result ranges, email format, and unique patient IDs.
  
- [ ] **Step 2: Implement validate_anonymized_data validation rules**
  Ensure processed files contain no raw 12-digit CCCDs and maintain row integrity.
  
- [ ] **Step 3: Commit**
  ```bash
  git add src/quality/validation.py
  git commit -m "feat: configure Great Expectations data quality validation"
  ```

---

### Task 8: OPA Policies & Compliance Checklist (`opa_policy.rego`, `compliance_checklist.md`)

**Files:**
- Modify: `policies/opa_policy.rego`
- Modify: `compliance_checklist.md`

- [ ] **Step 1: Complete REGO rules**
  Write analyst policy, intern policy, and external export restriction logic in `opa_policy.rego`.
  
- [ ] **Step 2: Complete Compliance Checklist**
  Provide technical mappings for TODO fields under section E and F of `compliance_checklist.md`.
  
- [ ] **Step 3: Commit**
  ```bash
  git add policies/opa_policy.rego compliance_checklist.md
  git commit -m "compliance: implement OPA policies and compliance checklist"
  ```

---

### Task 9: Security Hook Setup & Reports Export (Finalization)

**Files:**
- Create: `reports/` folder
- Create: `.github/hooks/pre-commit` (and copy to `.git/hooks/pre-commit`)

- [ ] **Step 1: Write security pre-commit hook**
  Incorporate git-secrets, bandit SAST scan, and pip-audit CVE checks. Make it executable.
  
- [ ] **Step 2: Run all scans and export reports**
  Output pytest logs, bandit output, and trufflehog checks to the `reports/` folder.
  
- [ ] **Step 3: Commit and zip final submission**
  Build the required submit zip file.
  
- [ ] **Step 4: Commit**
  ```bash
  git add .github/hooks/pre-commit
  git commit -m "security: add pre-commit security hook"
  ```
