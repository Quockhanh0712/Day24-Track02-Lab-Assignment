# src/quality/validation.py
import pandas as pd
import great_expectations as gx
from great_expectations.core.expectation_suite import ExpectationSuite
import os

def build_patient_expectation_suite() -> ExpectationSuite:
    """
    Tạo expectation suite cho anonymized patient data.
    """
    context = gx.get_context()
    
    # Lấy hoặc tạo expectation suite
    try:
        suite = context.suites.get("patient_data_suite")
    except Exception:
        suite = context.suites.add(ExpectationSuite(name="patient_data_suite"))

    # Lấy validator
    df = pd.read_csv("data/raw/patients_raw.csv", dtype=str)
    # Convert numeric validation columns to correct types for validator checking
    df["ket_qua_xet_nghiem"] = pd.to_numeric(df["ket_qua_xet_nghiem"], errors="coerce")
    
    batch = context.data_sources.pandas_default.read_dataframe(df)
    validator = context.get_validator(batch=batch, expectation_suite=suite)

    # --- TASK: Thêm các expectations ---

    # 1. patient_id không được null
    validator.expect_column_values_to_not_be_null("patient_id")

    # 2. cccd phải có đúng 12 ký tự
    validator.expect_column_value_lengths_to_equal(
        column="cccd",
        value=12
    )

    # 3. ket_qua_xet_nghiem phải trong khoảng [0, 50]
    validator.expect_column_values_to_be_between(
        column="ket_qua_xet_nghiem",
        min_value=0.0,
        max_value=50.0
    )

    # 4. benh phải thuộc danh sách hợp lệ
    valid_conditions = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
    validator.expect_column_values_to_be_in_set(
        column="benh",
        value_set=valid_conditions
    )

    # 5. email phải match regex pattern
    validator.expect_column_values_to_match_regex(
        column="email",
        regex=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    # 6. Không được có duplicate patient_id
    validator.expect_column_values_to_be_unique(column="patient_id")

    # validator.save_expectation_suite() is not needed/supported in the same way in 1.x
    # because context.suites.add already saves it or we can do context.suites.add_or_update(suite)
    context.suites.add_or_update(suite)
    return suite


def validate_anonymized_data(filepath: str) -> dict:
    """
    Validate anonymized data.
    Trả về dict: {"success": bool, "failed_checks": list, "stats": dict}
    """
    df = pd.read_csv(filepath, dtype=str)
    
    results = {
        "success": True,
        "failed_checks": [],
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns)
        }
    }

    raw_filepath = "data/raw/patients_raw.csv"
    if not os.path.exists(raw_filepath):
        results["success"] = False
        results["failed_checks"].append("Raw patients file not found for comparison")
        return results

    df_raw = pd.read_csv(raw_filepath, dtype=str)

    # Check 1: Không còn CCCD gốc dạng số thuần túy
    # (sau anonymization, cccd phải là fake hoặc masked)
    raw_cccds = set(df_raw["cccd"].tolist())
    anon_cccds = set(df["cccd"].tolist())
    common_cccds = raw_cccds.intersection(anon_cccds)
    if len(common_cccds) > 0:
        results["success"] = False
        results["failed_checks"].append(f"Found {len(common_cccds)} original CCCD values in anonymized data")

    # Check 2: Không có null values trong các cột quan trọng
    important_cols = ["patient_id", "ho_ten", "cccd", "so_dien_thoai", "email", "benh", "ket_qua_xet_nghiem"]
    for col in important_cols:
        if col in df.columns:
            null_count = df[col].isnull().sum()
            if null_count > 0:
                results["success"] = False
                results["failed_checks"].append(f"Column '{col}' contains {null_count} null values")
        else:
            results["success"] = False
            results["failed_checks"].append(f"Missing important column: '{col}'")

    # Check 3: Số rows phải bằng original
    if len(df) != len(df_raw):
        results["success"] = False
        results["failed_checks"].append(f"Row count mismatch: raw={len(df_raw)}, anonymized={len(df)}")

    return results
