# Design Specification: Data Governance & Security for MedViet AI Platform

**Date:** 2026-06-30  
**Author:** Antigravity (AI pair programmer)  
**Status:** Approved  

---

## 1. Goal Description

This design specification outlines the implementation plan for the Data Governance & Security Pipeline at MedViet. The pipeline is designed to meet NĐ13/ISO 27001 requirements while handling sensitive patient data. It involves five main technical areas:
- **PII Detection & Anonymization** (spaCy, Presidio Engine, and custom Vietnamese Pattern Recognizers)
- **Role-Based Access Control (RBAC)** (FastAPI and Casbin enforcer)
- **Envelope Encryption** (AES-256-GCM using python cryptography)
- **Data Quality & Schema Validation** (Great Expectations validation suite)
- **Attribute-Based Policy Evaluation** (Open Policy Agent)
- **Security Scanning & Compliance Checklist** (git-secrets, bandit, compliance documentation)

---

## 2. Technical Architecture & Component Design

### 2.1 PII Detection & Anonymization
To achieve a detection rate of >= 95% on Vietnamese patient data:
- We configure a spaCy NLP engine using `vi_core_news_lg`.
- We implement custom pattern recognizers for:
  - **CCCD:** A 12-digit pattern `\b\d{12}\b` with Vietnamese keywords (`cccd`, `căn cước`, `chứng minh`, `cmnd`).
  - **Phone:** A Vietnamese phone regex `\b0[35789]\d{8}\b` with Vietnamese keywords (`điện thoại`, `sdt`, `phone`, `liên hệ`).
  - **Person:** A custom Vietnamese capitalized name regex recognizer as a fallback, ensuring name identification is robust.
- We support three anonymization strategies:
  - `replace`: Replaces entities with fake values using Faker (`vi_VN`).
  - `mask`: Masks characters (e.g. replacing with `*`).
  - `hash`: One-way SHA-256 hash.

### 2.2 Role-Based Access Control (RBAC)
- Integrate Casbin with standard RBAC policy definition.
- Expose four endpoints:
  - `/api/patients/raw` (Admin read only)
  - `/api/patients/anonymized` (Admin and ML Engineer read)
  - `/api/metrics/aggregated` (Admin, ML Engineer, and Data Analyst read)
  - `/api/patients/{patient_id}` (Admin delete only)
- Raise appropriate HTTP exceptions (401 for unauthorized, 403 for forbidden access).

### 2.3 Envelope Encryption
- Implement a simulation of envelope encryption using AES-256-GCM.
- KEK (Key Encryption Key) is read from or saved to `.vault_key`.
- DEK (Data Encryption Key) is generated per encryption session, encrypted using KEK, and used to encrypt/decrypt text columns. Plaintext DEK is explicitly deleted from memory using `del`.

### 2.4 Data Quality Validation
- Use Great Expectations to validate raw and processed data.
- Ensure patient ID uniqueness, non-null properties, valid CCCD length (12), valid email formats, and reasonable range of test results (`ket_qua_xet_nghiem` between 0 and 50).

### 2.5 Policy Enforcement with OPA
- Complete the OPA rego rules in `policies/opa_policy.rego`.
- Restrict export of restricted data to external countries (allow only when destination is VN).

---

## 3. Scope of Work

The implementation touches the following files in `medviet-governance/`:
- [MODIFY] [detector.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/pii/detector.py)
- [MODIFY] [anonymizer.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/pii/anonymizer.py)
- [MODIFY] [test_pii.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/tests/test_pii.py)
- [MODIFY] [policy.csv](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/access/policy.csv)
- [MODIFY] [rbac.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/access/rbac.py)
- [MODIFY] [main.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/api/main.py)
- [MODIFY] [vault.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/encryption/vault.py)
- [MODIFY] [validation.py](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/src/quality/validation.py)
- [MODIFY] [opa_policy.rego](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/policies/opa_policy.rego)
- [MODIFY] [compliance_checklist.md](file:///a:/AIK20_aithucchien/Track2/Day24-Track02-Lab-Assignment/medviet-governance/compliance_checklist.md)

---

## 4. Verification Plan

- Run pytest on `tests/test_pii.py` to confirm detection rates and anonymization.
- Add and run tests for Casbin RBAC, FastAPI Endpoints, SimpleVault Encryption, and Great Expectations Quality Checks.
- Run OPA eval commands to verify policies.
- Run bandit, trufflehog, and git-secrets scripts to verify security scanning.
