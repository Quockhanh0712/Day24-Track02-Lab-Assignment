# tests/test_api.py
import pytest
import pandas as pd
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "MedViet Data API"}

def test_raw_patients_access():
    # 1. No token -> 401
    response = client.get("/api/patients/raw")
    assert response.status_code == 401
    assert "Missing token" in response.json()["detail"]

    # 2. Invalid token -> 401
    response = client.get("/api/patients/raw", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert "Invalid token" in response.json()["detail"]

    # 3. bob (ml_engineer) -> 403
    response = client.get("/api/patients/raw", headers={"Authorization": "Bearer token-bob"})
    assert response.status_code == 403
    assert "cannot 'read' on 'patient_data'" in response.json()["detail"]

    # 4. carol (data_analyst) -> 403
    response = client.get("/api/patients/raw", headers={"Authorization": "Bearer token-carol"})
    assert response.status_code == 403

    # 5. dave (intern) -> 403
    response = client.get("/api/patients/raw", headers={"Authorization": "Bearer token-dave"})
    assert response.status_code == 403

    # 6. alice (admin) -> 200
    response = client.get("/api/patients/raw", headers={"Authorization": "Bearer token-alice"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 10
    # Ensure raw PII keys are present
    assert "ho_ten" in data[0]
    assert "cccd" in data[0]

def test_anonymized_patients_access():
    # 1. bob (ml_engineer) -> 200
    response = client.get("/api/patients/anonymized", headers={"Authorization": "Bearer token-bob"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    # Ensure it's anonymized (names are fake, cccds are fake/changed)
    raw_df = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    original_cccds = raw_df["cccd"].tolist()
    assert data[0]["cccd"] not in original_cccds

    # 2. dave (intern) -> 403
    response = client.get("/api/patients/anonymized", headers={"Authorization": "Bearer token-dave"})
    assert response.status_code == 403

def test_aggregated_metrics_access():
    # 1. carol (data_analyst) -> 200
    response = client.get("/api/metrics/aggregated", headers={"Authorization": "Bearer token-carol"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert "benh" in data[0]
    assert "count" in data[0]

    # 2. dave (intern) -> 403
    response = client.get("/api/metrics/aggregated", headers={"Authorization": "Bearer token-dave"})
    assert response.status_code == 403

def test_delete_patient_access():
    raw_df = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    patient_id = raw_df["patient_id"].iloc[0]

    # 1. bob (ml_engineer) -> 403
    response = client.delete(f"/api/patients/{patient_id}", headers={"Authorization": "Bearer token-bob"})
    assert response.status_code == 403

    # 2. alice (admin) -> 200
    response = client.delete(f"/api/patients/{patient_id}", headers={"Authorization": "Bearer token-alice"})
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    # Confirm it is removed from raw data
    new_df = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    assert patient_id not in new_df["patient_id"].values
