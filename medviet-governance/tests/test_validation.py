# tests/test_validation.py
import pytest
import os
import pandas as pd
from src.quality.validation import build_patient_expectation_suite, validate_anonymized_data
from src.pii.anonymizer import MedVietAnonymizer

def test_build_expectation_suite():
    suite = build_patient_expectation_suite()
    assert suite is not None
    assert suite.name == "patient_data_suite"

def test_validation_raw_vs_anonymized(tmp_path):
    anonymizer = MedVietAnonymizer()
    raw_df = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    
    # 1. Anonymize dataframe
    anon_df = anonymizer.anonymize_dataframe(raw_df)
    
    # Save raw to temp path to verify it fails Check 1 (since raw comparing with raw has common CCCDs)
    raw_temp_path = tmp_path / "raw_temp.csv"
    raw_df.to_csv(raw_temp_path, index=False)
    raw_validation = validate_anonymized_data(str(raw_temp_path))
    # It must fail because original CCCDs exist in itself
    assert raw_validation["success"] is False
    assert any("original CCCD" in check for check in raw_validation["failed_checks"])

    # 2. Save anonymized to temp path and validate
    anon_temp_path = tmp_path / "anon_temp.csv"
    anon_df.to_csv(anon_temp_path, index=False)
    anon_validation = validate_anonymized_data(str(anon_temp_path))
    
    # It must pass
    assert anon_validation["success"] is True
    assert len(anon_validation["failed_checks"]) == 0
    assert anon_validation["stats"]["total_rows"] == len(raw_df)
