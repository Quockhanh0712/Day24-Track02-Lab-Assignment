# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [x] Backup cũng phải ở trong lãnh thổ VN
- [x] Log việc transfer data ra ngoài nếu có (chặn qua OPA rule khi đích đến không phải VN)

## B. Explicit Consent
- [x] Thu thập consent trước khi dùng data cho AI training
- [x] Có mechanism để user rút consent (Right to Erasure - API DELETE endpoint)
- [x] Lưu consent record với timestamp

## C. Breach Notification (72h)
- [x] Có incident response plan
- [x] Alert tự động khi phát hiện breach (Prometheus + Grafana Alerts)
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment
- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: `dpo@medviet.vn`

## E. Technical Controls (mapping từ requirements)
| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) | ✅ Done | Platform Team |
| Encryption | Envelope Encryption (SimpleVault AES-256-GCM) | ✅ Done | Infra Team |
| Audit logging | FastAPI Access Logger + Rotated File Logs | ✅ Done | Platform Team |
| Breach detection | Prometheus metrics + Grafana alert thresholds | ✅ Done | Security Team |

## F. Mổ tả technical solution chi tiết
- **Audit logging:** Triển khai FastAPI logging middleware ghi nhận chi tiết mọi hoạt động truy cập dữ liệu (User, IP, Resource, Action, Status Code) vào tệp log phân tán được luân chuyển (rotated) hàng ngày và đồng bộ lên hệ thống giám sát tập trung (như AWS CloudWatch hoặc ELK stack), đáp ứng yêu cầu lưu trữ lịch sử kiểm toán của NĐ13.
- **Breach detection:** Xuất chỉ số (metrics) từ FastAPI sang Prometheus (số lượng request lỗi 403, số lượng dữ liệu truy xuất lớn đột biến) và thiết lập Alertmanager của Grafana gửi cảnh báo tức thì qua email/Slack cho Security Team khi phát hiện lưu lượng truy cập bất thường, hỗ trợ ứng phó sự cố trong thời gian vàng 72 giờ.
