# src/pii/anonymizer.py
import pandas as pd
import random
import hashlib
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker
from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")

class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """
        Anonymize text với strategy được chọn.

        Strategies:
        - "mask"    : Nguyen Van A → N****** V** A
        - "replace" : thay bằng fake data (dùng Faker)
        - "hash"    : SHA-256 one-way hash
        - "generalize": chỉ dùng cho tuổi/năm sinh
        """
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        # Implement operators dict dựa trên strategy
        operators = {}

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", 
                          {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", 
                                 {"new_value": fake.email()}),   # fake email
                "VN_CCCD": OperatorConfig("replace", 
                           {"new_value": "".join([str(random.randint(0, 9)) for _ in range(12)])}),          # fake CCCD
                "VN_PHONE": OperatorConfig("replace", 
                            {"new_value": f"0{random.choice([3,5,7,8,9])}" + "".join([str(random.randint(0, 9)) for _ in range(8)])}),         # fake phone
            }
        elif strategy == "mask":
            def mask_person(val: str) -> str:
                words = val.split()
                return " ".join([w[0] + "*" * (len(w) - 1) if len(w) > 1 else w for w in words])

            def mask_email(val: str) -> str:
                if "@" in val:
                    local, domain = val.split("@", 1)
                    return (local[0] + "*" * (len(local) - 1) if len(local) > 1 else local) + "@" + domain
                return val

            def mask_cccd(val: str) -> str:
                if len(val) >= 4:
                    return val[:2] + "*" * (len(val) - 4) + val[-2:]
                return "*" * len(val)

            def mask_phone(val: str) -> str:
                if len(val) >= 5:
                    return val[:3] + "*" * (len(val) - 5) + val[-2:]
                return "*" * len(val)

            operators = {
                "PERSON": OperatorConfig("custom", {"lambda": mask_person}),
                "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": mask_email}),
                "VN_CCCD": OperatorConfig("custom", {"lambda": mask_cccd}),
                "VN_PHONE": OperatorConfig("custom", {"lambda": mask_phone}),
            }
        elif strategy == "hash":
            def hash_value(val: str) -> str:
                return hashlib.sha256(val.encode('utf-8')).hexdigest()

            operators = {
                "PERSON": OperatorConfig("custom", {"lambda": hash_value}),
                "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": hash_value}),
                "VN_CCCD": OperatorConfig("custom", {"lambda": hash_value}),
                "VN_PHONE": OperatorConfig("custom", {"lambda": hash_value}),
            }

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame.
        - Cột text (ho_ten, dia_chi, email): dùng anonymize_text()
        - Cột cccd, so_dien_thoai: replace trực tiếp bằng fake data
        - Cột benh, ket_qua_xet_nghiem: GIỮ NGUYÊN (cần cho model training)
        - Cột patient_id: GIỮ NGUYÊN (pseudonym đã đủ an toàn)
        """
        df_anon = df.copy()

        # Cột text (ho_ten, dia_chi, email)
        for col in ["ho_ten", "dia_chi", "email"]:
            if col in df_anon.columns:
                df_anon[col] = df_anon[col].astype(str).apply(
                    lambda x: self.anonymize_text(x, strategy="replace")
                )

        # Cột cccd
        if "cccd" in df_anon.columns:
            df_anon["cccd"] = df_anon["cccd"].apply(
                lambda x: "".join([str(random.randint(0, 9)) for _ in range(12)])
            )

        # Cột so_dien_thoai
        if "so_dien_thoai" in df_anon.columns:
            df_anon["so_dien_thoai"] = df_anon["so_dien_thoai"].apply(
                lambda x: f"0{random.choice([3,5,7,8,9])}" + "".join([str(random.randint(0, 9)) for _ in range(8)])
            )

        return df_anon

    def calculate_detection_rate(self, 
                                  original_df: pd.DataFrame,
                                  pii_columns: list) -> float:
        """
        Tính % PII được detect thành công.
        Mục tiêu: > 95%

        Logic: với mỗi ô trong pii_columns,
               kiểm tra xem detect_pii() có tìm thấy ít nhất 1 entity không.
        """
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                # Xử lý các giá trị bị mất số 0 đầu do ép kiểu số trong pandas
                if value.endswith(".0"):
                    value = value[:-2]
                if col == "cccd":
                    value = value.zfill(12)
                elif col == "so_dien_thoai":
                    value = value.zfill(10)
                
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
