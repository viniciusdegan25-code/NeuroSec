from sqlalchemy import Column, Integer, String, Text, Float, DateTime
from datetime import datetime
from app.db.database import Base

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)  # ex: sast_sql_1, dast_hsts_2
    internal_id = Column(Integer, index=True)
    asset_type = Column(String, default="CODE")     # CODE, URL, DEPENDENCY, CLOUD
    asset_name = Column(String)                     # login.py, https://app.empresa.com, etc.
    vuln_type = Column(String)                      # SQL Injection, Hardcoded Secrets, Missing CSP, etc.
    cve_id = Column(String, nullable=True)          # CVE-2024-1182, etc.
    owasp_category = Column(String, nullable=True)  # A03:2021 - Injection
    line_number = Column(Integer, default=0)
    severity = Column(String, default="MEDIUM")     # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = Column(Float, default=5.0)
    status = Column(String, default="open")          # open, patch_ready, remediated, false_positive
    days_open = Column(Integer, default=1)
    ai_diagnosis = Column(Text, nullable=True)
    original_code = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)
    patch_file = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))
    updated_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)                         # PATCH_APPROVED, SCAN_EXECUTED, STATUS_CHANGED
    target_vuln_id = Column(Integer, nullable=True)
    vuln_key = Column(String, nullable=True)
    operator = Column(String, default="SecOps Lead")
    details = Column(Text)
    diff_preview = Column(Text, nullable=True)
    timestamp = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String)                      # SAST, DAST, SCA, CLOUD, FULL
    target = Column(String)                         # Path, URL or Repo name
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    score_snapshot = Column(Integer, default=100)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    asset_type = Column(String, default="REPO")     # REPO, WEB_APP, API_SERVICE, CLOUD_CONTAINER
    criticality = Column(String, default="TIER_1_CRITICAL")
    environment = Column(String, default="production")
    last_scanned = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))

class EnterpriseLead(Base):
    __tablename__ = "enterprise_leads"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    corporate_email = Column(String, nullable=False, index=True)
    company_name = Column(String, nullable=False)
    job_title = Column(String, default="Executivo / Analista")
    company_size = Column(String, default="50-200")
    main_challenge = Column(String, default="ASPM & Postura de Segurança")
    status = Column(String, default="new")          # new, contacted, demo_scheduled
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
