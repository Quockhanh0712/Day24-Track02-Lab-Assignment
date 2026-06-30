# src/api/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import os
from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

RAW_DATA_PATH = "data/raw/patients_raw.csv"

# --- ENDPOINT 1 ---
@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(
    current_user: dict = Depends(get_current_user)
):
    """
    Trả về raw patient data (chỉ admin được phép).
    Load từ data/raw/patients_raw.csv
    Trả về 10 records đầu tiên dưới dạng JSON.
    """
    if not os.path.exists(RAW_DATA_PATH):
        raise HTTPException(status_code=404, detail="Raw data file not found")
    
    df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    first_10 = df.head(10)
    return first_10.to_dict(orient="records")

# --- ENDPOINT 2 ---
@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(
    current_user: dict = Depends(get_current_user)
):
    """
    Trả về anonymized data (ml_engineer và admin được phép).
    Load raw data → anonymize → trả về JSON.
    """
    if not os.path.exists(RAW_DATA_PATH):
        raise HTTPException(status_code=404, detail="Raw data file not found")
    
    df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    df_anon = anonymizer.anonymize_dataframe(df)
    return df_anon.to_dict(orient="records")

# --- ENDPOINT 3 ---
@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(
    current_user: dict = Depends(get_current_user)
):
    """
    Trả về aggregated metrics (data_analyst, ml_engineer, admin).
    Ví dụ: số bệnh nhân theo từng loại bệnh (không có PII).
    """
    if not os.path.exists(RAW_DATA_PATH):
        raise HTTPException(status_code=404, detail="Raw data file not found")
    
    df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    # Group by 'benh' and calculate counts
    metrics = df.groupby("benh").size().reset_index(name="count")
    return metrics.to_dict(orient="records")

# --- ENDPOINT 4 ---
@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Chỉ admin được xóa. Các role khác nhận 403.
    """
    if not os.path.exists(RAW_DATA_PATH):
        raise HTTPException(status_code=404, detail="Raw data file not found")
    
    df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    if patient_id not in df["patient_id"].values:
         raise HTTPException(status_code=404, detail=f"Patient with ID {patient_id} not found")
    
    # Filter out patient
    df_new = df[df["patient_id"] != patient_id]
    df_new.to_csv(RAW_DATA_PATH, index=False)
    
    return {"status": "success", "message": f"Patient {patient_id} deleted successfully"}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
