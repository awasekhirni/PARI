-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 1: Objects 1-50)
-- ================================================================================
-- Description: This script creates the database objects for the Independent Auditor
-- Interface, focusing on high-concurrency, read-only access, privacy preservation,
-- and immutable logging.
--
-- Standards:
-- 1. Idempotent SQL (CREATE IF NOT EXISTS)
-- 2. Comprehensive Check Constraints and Data Types
-- 3. Audit columns (created_at, updated_at, created_by, updated_by)
-- 4. Detailed Documentation per Object
-- 5. Strategic Indexing
-- ================================================================================

-- 1. Schema Creation
-- ================================================================================
CREATE SCHEMA IF NOT EXISTS audit;
COMMENT ON SCHEMA audit IS 'Independent Auditor Interface Schema for PARI M06 Module. Handles read-only regulatory access, privacy-preserving queries, and audit trails.';

-- 2. Extensions
-- ================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides functions to generate universally unique identifiers (UUIDs).';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Cryptographic functions for hashing keys and sensitive data.';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to work on standard b-tree data types, useful for composite indexes.';

-- 3. Common Prerequisites (Auditor Table)
-- ================================================================================
-- Although not explicitly listed T001-T200, an 'auditor' entity is required for Foreign Keys.
-- Creating a placeholder table to ensure referential integrity.

CREATE TABLE IF NOT EXISTS audit.auditor (
    auditor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor IS 'Master list of authorized auditors accessing the M06 system.';

-- Function: Update Updated At Column
CREATE OR REPLACE FUNCTION audit.trigger_update_updated_at()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;

-- 3. Enums
-- ================================================================================

-- Enum: E001 - enum_auditor_role
-- Description: Defines the access roles for auditors within the system.
-- Feature Reference: F008
CREATE TYPE audit.enum_auditor_role AS ENUM ('ADMIN', 'VIEWER', 'INVESTIGATOR');
COMMENT ON TYPE audit.enum_auditor_role IS 'Access levels: Admin (Full), Viewer (Read-only), Investigator (Forensic access)';

-- Enum: E002 - enum_jurisdiction
-- Description: ISO 3166-1 Alpha-2 codes representing legal jurisdictions.
-- Feature Reference: F003
CREATE TYPE audit.enum_jurisdiction AS ENUM ('CH', 'DE', 'ES', 'US', 'IT', 'FR', 'GB', 'JP');
COMMENT ON TYPE audit.enum_jurisdiction IS 'Supported legal jurisdictions for data segregation and compliance';

-- Enum: E003 - enum_alert_type
-- Description: Types of system alerts generated for auditors.
-- Feature Reference: F019
CREATE TYPE audit.enum_alert_type AS ENUM ('THRESHOLD_EXCEEDED', 'ANOMALY_DETECTED', 'SYSTEM_DOWN', 'PRIVACY_RISK');
COMMENT ON TYPE audit.enum_alert_type IS 'Categories of alerts pushed to auditor dashboards';

-- Enum: E004 - enum_export_status
-- Description: Status of asynchronous data export jobs.
-- Feature Reference: F004, F029
CREATE TYPE audit.enum_export_status AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'EXPIRED');
COMMENT ON TYPE audit.enum_export_status IS 'Lifecycle states of report generation and export tasks';

-- Enum: E005 - enum_finding_status
-- Description: Status of audit findings or investigations.
-- Feature Reference: F011, F107
CREATE TYPE audit.enum_finding_status AS ENUM ('OPEN', 'UNDER_REVIEW', 'CLOSED', 'ESCALATED', 'DISMISSED');
COMMENT ON TYPE audit.enum_finding_status IS 'Workflow states for audit findings lifecycle management';

-- Enum: E006 - enum_tax_period
-- Description: Frequency of tax reporting periods.
-- Feature Reference: F033
CREATE TYPE audit.enum_tax_period AS ENUM ('MONTHLY', 'QUARTERLY', 'ANNUAL', 'AD_HOC');
COMMENT ON TYPE audit.enum_tax_period IS 'Standardized intervals for tax reporting';

-- Enum: E007 - enum_match_status
-- Description: Status of invoice-payment reconciliation.
-- Feature Reference: F015, F073
CREATE TYPE audit.enum_match_status AS ENUM ('MATCHED', 'UNMATCHED', 'PARTIAL', 'DISCREPANCY');
COMMENT ON TYPE audit.enum_match_status IS 'Reconciliation status between invoices and transaction flows';

-- Enum: E008 - enum_data_type
-- Description: Categorization of data for retention policies.
-- Feature Reference: F017
CREATE TYPE audit.enum_data_type AS ENUM ('TRANSACTION_LOG', 'MERCHANT_PROFILE', 'AUDIT_TRAIL', 'USER_PII', 'SYSTEM_LOG');
COMMENT ON TYPE audit.enum_data_type IS 'Categories for applying data retention and purging rules';

-- Enum: E009 - enum_risk_level
-- Description: Risk classification for merchants or entities.
-- Feature Reference: F056
CREATE TYPE audit.enum_risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
COMMENT ON TYPE audit.enum_risk_level IS 'Qualitative assessment of risk exposure';

-- Enum: E010 - enum_request_type
-- Description: Types of Data Subject Requests (GDPR).
-- Feature Reference: F115
CREATE TYPE audit.enum_request_type AS ENUM ('ACCESS', 'DELETION', 'PORTABILITY', 'RECTIFICATION');
COMMENT ON TYPE audit.enum_request_type IS 'Legal categories for user data requests under GDPR';

-- 4. DDL Statements (Tables T001 - T050)
-- ================================================================================

-- Table: T001 - auditor_sessions
-- Description: Tracks active login sessions of auditors to ensure accountability and enable real-time monitoring.
-- Business Case: In a high-security regulatory environment, knowing exactly who is logged in, from where, and for how long is crucial for preventing unauthorized access and detecting potential insider threats. This table provides the foundation for session management, allowing administrators to revoke active sessions instantly if a security breach is suspected.
-- KPIs: Average Session Duration, Concurrent Active Users, Failed Login Rate.
-- Feature Reference: F009, F027
CREATE TABLE IF NOT EXISTS audit.auditor_sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    login_ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address INET NOT NULL,
    user_agent TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXPIRED', 'TERMINATED', 'IDLE')),
    last_activity_ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    device_fingerprint VARCHAR(255),
    geo_location_country CHAR(2),
    termination_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auditor_sessions_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id) ON DELETE CASCADE,
    CONSTRAINT chk_session_expiration CHECK (expires_at > login_ts)
);
COMMENT ON TABLE audit.auditor_sessions IS 'Tracks active auditor login sessions with IP and device context for security monitoring';

CREATE INDEX idx_sessions_auditor ON audit.auditor_sessions(auditor_id);
CREATE INDEX idx_sessions_status ON audit.auditor_sessions(status);
CREATE INDEX idx_sessions_expiry ON audit.auditor_sessions(expires_at);

-- Trigger for updated_at
CREATE TRIGGER trg_auditor_sessions_updated_at
    BEFORE UPDATE ON audit.auditor_sessions
    FOR EACH ROW EXECUTE FUNCTION audit.trigger_update_updated_at();


-- Table: T002 - auditor_logs
-- Description: Immutable log of every read action performed by auditors.
-- Business Case: The core of "Meta-Auditing". While auditors monitor merchants, this table monitors auditors. It stores a cryptographically signed record of every query executed, ensuring that regulators cannot abuse their power to surveil citizens without oversight. The immutability guarantees that logs cannot be tampered with post-facto to hide unauthorized access.
-- KPIs: Log Integrity (100%), Log Ingestion Latency (< 1s).
-- Feature Reference: F005
CREATE TABLE IF NOT EXISTS audit.auditor_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID REFERENCES audit.auditor_sessions(session_id),
    auditor_id UUID NOT NULL,
    query_hash VARCHAR(64) NOT NULL, -- SHA-256 of the query
    tables_accessed TEXT[] NOT NULL,
    rows_returned INTEGER NOT NULL,
    execution_time_ms INTEGER,
    ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    result_signature VARCHAR(255), -- Cryptographic signature of the result set
    privacy_epsilon_spent NUMERIC(5,4), -- Differential privacy cost

    -- Audit Columns (Immutable tables might skip updated_at, but keeping created for lineage)
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor_logs IS 'Immutable append-only log of all auditor queries for meta-auditing and compliance';

-- Indexes optimized for time-series log queries
CREATE INDEX idx_audit_logs_ts ON audit.auditor_logs(ts DESC);
CREATE INDEX idx_audit_logs_auditor ON audit.auditor_logs(auditor_id);
CREATE INDEX idx_audit_logs_hash ON audit.auditor_logs(query_hash);


-- Table: T003 - audit_query_history
-- Description: Stores the actual SQL/Query text and execution plans for historical analysis.
-- Business Case: Enables the system to learn from auditor behavior. By storing execution plans, the database team can optimize slow queries (performance tuning) and identify trends in data requests. It also serves as a repository for re-running complex forensic queries without rewriting them, saving time during investigations.
-- KPIs: Query Cache Hit Rate, Average Query Optimization Time.
-- Feature Reference: F143
CREATE TABLE IF NOT EXISTS audit.audit_query_history (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    query_text TEXT NOT NULL,
    execution_plan JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_executed_at TIMESTAMPTZ,
    execution_count INTEGER DEFAULT 0,
    avg_execution_time_ms NUMERIC(10,2),
    tags TEXT[],

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_query_history_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_query_history IS 'Repository of saved queries and their performance metrics for reuse and analysis';

CREATE INDEX idx_query_history_text ON audit.audit_query_history USING gin(to_tsvector('english', query_text));
CREATE INDEX idx_query_history_auditor ON audit.audit_query_history(auditor_id);


-- Table: T004 - report_exports
-- Description: Metadata of files generated for export (PDF, CSV, XML).
-- Business Case: Provides an inventory of all data that has left the secure system. This is critical for GDPR breach investigations—if data is leaked, this table helps trace *when* and *by whom* it was exported. It also manages the lifecycle of these export files, triggering automatic deletion after retention periods expire.
-- KPIs: Export Success Rate, Average Export Generation Time.
-- Feature Reference: F029, F037
CREATE TABLE IF NOT EXISTS audit.report_exports (
    export_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    file_type VARCHAR(10) NOT NULL CHECK (file_type IN ('PDF', 'CSV', 'XML', 'JSON', 'PARQUET')),
    file_hash CHAR(64) NOT NULL, -- SHA-256
    status audit.enum_export_status NOT NULL DEFAULT 'PENDING',
    path_s3 TEXT NOT NULL,
    row_count INTEGER,
    file_size_bytes BIGINT,
    expiration_date DATE,
    download_count INTEGER DEFAULT 0,
    parameters_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_exports_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.report_exports IS 'Tracks all data exports, including location, hash for integrity, and expiration dates';

CREATE INDEX idx_exports_status ON audit.report_exports(status);
CREATE INDEX idx_exports_auditor ON audit.report_exports(auditor_id);


-- Table: T005 - data_retention_schedule
-- Description: Defines retention policies for different data types based on jurisdiction.
-- Business Case: Legal compliance automation. Different laws (e.g., Tax Laws vs. GDPR) require different retention periods (e.g., 7 years for tax vs. Right to be Forgotten for PII). This centralized configuration allows the system to automate data purging, reducing legal risk and storage costs without manual intervention.
-- KPIs: Policy Compliance Rate (100%), Deletion Latency.
-- Feature Reference: F017
CREATE TABLE IF NOT EXISTS audit.data_retention_schedule (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_type audit.enum_data_type NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    retention_years INTEGER NOT NULL CHECK (retention_years > 0),
    archive_after_years INTEGER DEFAULT 0,
    legal_reference TEXT,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.data_retention_schedule IS 'Defines automated data retention and archival policies per jurisdiction and data category';

CREATE UNIQUE INDEX idx_retention_unique ON audit.data_retention_schedule(data_type, jurisdiction_code);


-- Table: T006 - api_keys
-- Description: Stores API keys for external auditor integrations (Machine-to-Machine).
-- Business Case: Enables automated tax software used by accounting firms to connect directly to the PARI audit interface. This increases the platform's adoption by integrating with existing tools used by merchants and auditors. Secure storage of hashed keys prevents unauthorized API access.
-- KPIs: API Key Rotation Compliance, API Uptime.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS audit.api_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    hashed_key VARCHAR(255) NOT NULL, -- bcrypt or argon2 hash
    last_used TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    scope TEXT[], -- e.g., {'tax:read', 'vat:export'}
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_api_keys_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id),
    CONSTRAINT chk_api_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE audit.api_keys IS 'Secure storage for API credentials used by third-party audit tools';

CREATE INDEX idx_api_keys_auditor ON audit.api_keys(auditor_id);
CREATE INDEX idx_api_keys_hash ON audit.api_keys(hashed_key); -- For lookup during auth


-- Table: T007 - audit_alerts
-- Description: Stores generated alerts for auditors (e.g., fraud detection, system issues).
-- Business Case: Proactive risk management. Instead of auditors constantly polling dashboards, the system pushes alerts when specific thresholds (e.g., "VAT Gap > 5%") or anomalies (e.g., "Circular Trading Detected") are met. This significantly reduces the time-to-detect for financial crimes and system failures.
-- KPIs: Alert Latency (< 1 min), False Positive Rate (< 0.1%).
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID, -- NULL if broadcast to all
    alert_type audit.enum_alert_type NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    message TEXT NOT NULL,
    details_json JSONB,
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    related_entity_type VARCHAR(50),
    related_entity_id UUID,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL, -- System user
    updated_by UUID NOT NULL,

    CONSTRAINT fk_alerts_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_alerts IS 'Notification center for auditors regarding anomalies and system events';

CREATE INDEX idx_alerts_auditor_unread ON audit.audit_alerts(auditor_id, is_read) WHERE is_read = FALSE;
CREATE INDEX idx_alerts_type ON audit.audit_alerts(alert_type, created_at DESC);


-- Table: T008 - auditor_permissions
-- Description: Maps roles to specific data access permissions (ABAC).
-- Business Case: Enforces the principle of least privilege. Not every tax auditor needs access to Anti-Money Laundering graphs. This table defines granular permissions (e.g., "Can View VAT", "Can Export PII"), ensuring that auditors only see data necessary for their specific jurisdiction and task, minimizing privacy risks.
-- KPIs: Permission Grant Accuracy, Access Denied Rate.
-- Feature Reference: F008, F018
CREATE TABLE IF NOT EXISTS audit.auditor_permissions (
    permission_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id VARCHAR(50) NOT NULL, -- Links to Enum E001 or external Role table
    resource VARCHAR(100) NOT NULL, -- e.g., "table.merchant", "api.vat_report"
    action VARCHAR(50) NOT NULL CHECK (action IN ('READ', 'EXPORT', 'ANNOTATE', 'MANAGE')),
    constraint_sql TEXT, -- Dynamic SQL filter (e.g., "country_code = 'DE'")
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.auditor_permissions IS 'Attribute-Based Access Control (ABAC) rules defining role capabilities';

CREATE INDEX idx_permissions_role ON audit.auditor_permissions(role_id, is_active);


-- Table: T009 - privacy_budget_log
-- Description: Tracks consumption of differential privacy budget per auditor.
-- Business Case: Implements Differential Privacy (DP) mechanisms. DP adds noise to data, but there is a limit to how much noise can be added before data becomes useless, and a limit to how many queries can be run before privacy is breached (Privacy Budget). This table tracks the "epsilon" (privacy loss) spent by each auditor, preventing them from drilling down into data enough to identify an individual.
-- KPIs: Budget Exhaustion Alert Rate, Epsilon Leakage.
-- Feature Reference: F004, F043
CREATE TABLE IF NOT EXISTS audit.privacy_budget_log (
    budget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    query_id UUID REFERENCES audit.audit_query_history(query_id),
    context VARCHAR(100), -- e.g., 'daily_aggregation'
    epsilon_spent NUMERIC(5,4) NOT NULL,
    remaining_epsilon NUMERIC(5,4) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_privacy_budget_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id),
    CONSTRAINT chk_epsilon_positive CHECK (epsilon_spent > 0),
    CONSTRAINT chk_remaining_epsilon CHECK (remaining_epsilon >= 0)
);
COMMENT ON TABLE audit.privacy_budget_log IS 'Tracks differential privacy spend to prevent re-identification attacks via query aggregation';

CREATE INDEX idx_privacy_budget_auditor_period ON audit.privacy_budget_log(auditor_id, period_start, period_end);


-- Table: T010 - jurisdiction_config
-- Description: Configuration for specific country regulations (tax rates, masking rules).
-- Business Case: A "Privacy-by-Design" configuration store. Since PARI is multi-jurisdictional, rules change by country. This table stores the specific logic for each jurisdiction (e.g., "Spain requires mask last 4 digits of VAT ID"). It ensures that a single query can return different results depending on the auditor's jurisdiction, without changing the code.
-- KPIs: Configuration Deployment Time, Rule Accuracy.
-- Feature Reference: F003, F067
CREATE TABLE IF NOT EXISTS audit.jurisdiction_config (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2) NOT NULL UNIQUE,
    currency_code CHAR(3) NOT NULL,
    tax_rate_json JSONB NOT NULL, -- e.g., {"standard": 0.19, "reduced": 0.07}
    data_masking_rules JSONB, -- e.g., {"email": "partial", "name": "hash"}
    legal_retention_years INTEGER DEFAULT 7,
    reporting_timezone VARCHAR(50) DEFAULT 'UTC',
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.jurisdiction_config IS 'Centralized configuration for country-specific tax rules and data privacy policies';


-- Table: T011 - audit_findings
-- Description: Stores findings from investigations.
-- Business Case: The primary output of the audit function. When an auditor identifies a discrepancy or fraud, this table records the "Finding". It links the evidence to a conclusion and tracks the status (Open -> Closed). This is the table that external regulatory bodies will ultimately query when investigating a merchant or entity.
-- KPIs: Findings Resolution Time, Accuracy of Findings.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    merchant_id UUID,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status audit.enum_finding_status NOT NULL DEFAULT 'OPEN',
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    evidence_link TEXT, -- S3 path
    assigned_to UUID,
    due_date DATE,
    closed_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_findings_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id),
    CONSTRAINT fk_findings_assigned_to FOREIGN KEY (assigned_to) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_findings IS 'Tracks the lifecycle of audit findings from detection to resolution';

CREATE INDEX idx_findings_merchant ON audit.audit_findings(merchant_id);
CREATE INDEX idx_findings_status ON audit.audit_findings(status);


-- Table: T012 - merchant_risk_profiles
-- Description: Stores calculated risk scores for merchants.
-- Business Case: Enables "Risk-Based Auditing". Instead of auditing everyone equally, the system calculates a risk score based on transaction frequency, anomalies, and historical data. High-risk merchants are flagged for priority review, optimizing auditor efficiency and focusing resources where the likelihood of fraud is highest.
-- KPIs: Model Precision (>85%), False Positive Rate.
-- Feature Reference: F056
CREATE TABLE IF NOT EXISTS audit.merchant_risk_profiles (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL UNIQUE,
    risk_score NUMERIC(3,2) CHECK (risk_score BETWEEN 0 AND 1),
    risk_level audit.enum_risk_level GENERATED ALWAYS AS (
        CASE
            WHEN risk_score >= 0.8 THEN 'CRITICAL'
            WHEN risk_score >= 0.6 THEN 'HIGH'
            WHEN risk_score >= 0.4 THEN 'MEDIUM'
            ELSE 'LOW'
        END
    ) STORED,
    last_calculated TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    risk_factors JSONB, -- e.g., {"high_volume": true, "anomalies": 5}
    model_version VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL, -- System
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.merchant_risk_profiles IS 'Aggregated risk scores driving the risk-based auditing workflow';

CREATE INDEX idx_risk_profile_score ON audit.merchant_risk_profiles(risk_score DESC);


-- Table: T013 - suspicious_activities
-- Description: Flags for suspicious transaction patterns.
-- Business Case: The output of the automated anomaly detection engine (e.g., Isolation Forests). When the system detects a pattern (e.g., "Shell Company Behavior"), it writes a record here. Auditors can then review these flags to decide if a full investigation is warranted, automating the initial triage process.
-- KPIs: Detection Rate, Alert Volume.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.suspicious_activities (
    activity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    pattern_type VARCHAR(100) NOT NULL, -- e.g., "CIRCULAR_TRADE", "SHELL_COMPANY"
    confidence_score NUMERIC(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details JSONB,
    is_reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by UUID REFERENCES audit.auditor(auditor_id),
    finding_id UUID REFERENCES audit.audit_findings(finding_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.suspicious_activities IS 'Machine-generated flags for potential financial crimes requiring human review';

CREATE INDEX idx_suspicious_merchant ON audit.suspicious_activities(merchant_id);
CREATE INDEX idx_suspicious_reviewed ON audit.suspicious_activities(is_reviewed) WHERE is_reviewed = FALSE;


-- Table: T014 - tax_reports
-- Description: Generated tax reports ready for submission to authorities.
-- Business Case: Automates the generation of regulatory returns (VAT/GST). The system aggregates transaction data and creates a finalized report record. This record is then pushed to the National Tax Infrastructure (e.g., Spain SII) via API. It ensures that what is reported matches the blockchain ledger exactly.
-- KPIs: Submission Success Rate, Report Accuracy.
-- Feature Reference: F010, F033
CREATE TABLE IF NOT EXISTS audit.tax_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    tax_period_type audit.enum_tax_period NOT NULL,
    currency_code CHAR(3) NOT NULL,
    total_gross_amount NUMERIC(19,4) NOT NULL,
    total_net_amount NUMERIC(19,4) NOT NULL,
    total_vat_amount NUMERIC(19,4) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'ACCEPTED', 'REJECTED', 'AMENDED')),
    submission_ts TIMESTAMPTZ,
    authority_reference_code VARCHAR(100), -- Reference from Tax Authority
    report_file_path TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT chk_report_dates CHECK (period_end > period_start)
);
COMMENT ON TABLE audit.tax_reports IS 'Finalized tax reports generated for merchant compliance and submission';

CREATE INDEX idx_tax_reports_merchant_period ON audit.tax_reports(merchant_id, period_start, period_end);


-- Table: T015 - invoice_payment_matches
-- Description: Matches invoices to payments.
-- Business Case: Ensures that the money declared on invoices matches the money actually flowing through the PARI system. This reconciliation detects "double dipping" (claiming VAT twice) or under-reporting. It links the traditional financial document (Invoice) with the modern blockchain transaction.
-- KPIs: Match Accuracy (>95%), Unmatched Items.
-- Feature Reference: F024, F073
CREATE TABLE IF NOT EXISTS audit.invoice_payment_matches (
    match_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    invoice_hash CHAR(64) NOT NULL, -- Hash of the invoice PDF/XML content
    tx_hash CHAR(64) NOT NULL, -- Blockchain Transaction Hash
    match_score NUMERIC(3,2), -- Similarity score (0-1)
    status audit.enum_match_status NOT NULL,
    matched_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    discrepancy_amount NUMERIC(19,4),
    discrepancy_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.invoice_payment_matches IS 'Reconciliation engine linking traditional invoices to blockchain transactions';

CREATE INDEX idx_match_invoice ON audit.invoice_payment_matches(invoice_hash);
CREATE INDEX idx_match_tx ON audit.invoice_payment_matches(tx_hash);


-- Table: T016 - anonymized_events
-- Description: Event store for privacy-preserved events.
-- Business Case: The core data source for auditors. Raw transaction events from M05 are ingested here, but crucial fields (like Payer ID) are stripped or hashed. Differential Privacy noise might be pre-applied to aggregates. This table allows auditors to query "What happened?" without seeing "Who did it?".
-- KPIs: Ingestion Latency, Anonymization Integrity.
-- Feature Reference: F001, F016
CREATE TABLE IF NOT EXISTS audit.anonymized_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    tx_hash CHAR(64), -- Reference to original chain tx (hashed)
    amount NUMERIC(19,4) NOT NULL,
    currency_code CHAR(3) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    category VARCHAR(50), -- MCC or user category
    noise_added NUMERIC(10,4), -- DP noise added to amount
    anonymized_payer_id VARCHAR(64), -- Hashed or Tokenized ID
    jurisdiction_code CHAR(2),

    -- Audit Columns (Created only usually for events)
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.anonymized_events IS 'Privacy-preserved event store serving as the primary data source for audit queries';

-- Partitioning Strategy (Example declarative partitioning for time-series)
-- CREATE TABLE audit.anonymized_events_y2024 PARTITION OF audit.anonymized_events
--     FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');

CREATE INDEX idx_anon_events_ts ON audit.anonymized_events(timestamp DESC);
CREATE INDEX idx_anon_events_merchant ON audit.anonymized_events(merchant_id);


-- Table: T017 - graph_edges
-- Description: Edges for the transaction graph (Merchant A -> Merchant B).
-- Business Case: Enables Forensic Link Analysis. Criminals often try to hide money by moving it through a web of shell companies. This table stores the relationships (edges) between entities. Auditors can run graph algorithms (like PageRank or Cycle Detection) on this data to visualize these hidden networks.
-- KPIs: Graph Construction Speed, Query Performance on Edges.
-- Feature Reference: F002, F007
CREATE TABLE IF NOT EXISTS audit.graph_edges (
    edge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_merchant UUID NOT NULL,
    target_merchant UUID NOT NULL,
    weight NUMERIC(19,4) NOT NULL, -- Total transaction volume
    currency_code CHAR(3) NOT NULL,
    tx_count INTEGER NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_no_self_loop CHECK (source_merchant != target_merchant)
);
COMMENT ON TABLE audit.graph_edges IS 'Graph database representation of financial flows for network analysis';

CREATE INDEX idx_graph_edges_source ON audit.graph_edges(source_merchant);
CREATE INDEX idx_graph_edges_target ON audit.graph_edges(target_merchant);


-- Table: T018 - circular_trades
-- Description: Detected circular trading loops.
-- Business Case: Specific fraud detection table. Circular trading (A pays B, B pays C, C pays A) is often used to fake revenue or launder money. This table stores the detected paths (loops) so auditors can instantly see these structures without running expensive graph algorithms every time.
-- KPIs: Detection Accuracy, Loop Identification Speed.
-- Feature Reference: F007
CREATE TABLE IF NOT EXISTS audit.circular_trades (
    loop_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    path UUID[] NOT NULL, -- Ordered list of Merchant IDs involved
    total_volume NUMERIC(19,4) NOT NULL,
    currency_code CHAR(3) NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE, -- If loop was broken by intervention

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.circular_trades IS 'Stores detected circular trading loops for VAT fraud and money laundering investigation';


-- Table: T019 - cross_border_flows
-- Description: Aggregated money flow between jurisdictions.
-- Business Case: Capital Flight Monitoring. Governments need to know when money is leaving the country. This table aggregates flows by jurisdiction (e.g., DE -> FR). It is used for Balance of Payments analysis and detecting illegal capital flight.
-- KPIs: Reporting Freshness, Accuracy of Flow Estimation.
-- Feature Reference: F008
CREATE TABLE IF NOT EXISTS audit.cross_border_flows (
    flow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_country CHAR(2) NOT NULL,
    target_country CHAR(2) NOT NULL,
    volume NUMERIC(19,4) NOT NULL,
    currency_code CHAR(3) NOT NULL,
    timestamp DATE NOT NULL, -- Daily aggregation
    tx_count INTEGER NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cross_border_flows IS 'Aggregated view of fund movements across national borders for macro-prudential monitoring';

CREATE UNIQUE INDEX idx_cross_border_unique ON audit.cross_border_flows(source_country, target_country, timestamp);


-- Table: T020 - sector_aggregates
-- Description: Transaction volume by sector (MCC).
-- Business Case: Economic Health Monitoring. Aggregating data by Merchant Category Code (MCC) allows economists to see which sectors are growing or shrinking. For example, a sudden drop in "Hospitality" might indicate a looming recession or the effect of a new lockdown.
-- KPIs: Data Freshness, Aggregation Speed.
-- Feature Reference: F101
CREATE TABLE IF NOT EXISTS audit.sector_aggregates (
    agg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mcc_code CHAR(4) NOT NULL,
    volume NUMERIC(19,4) NOT NULL,
    tx_count INTEGER NOT NULL,
    currency_code CHAR(3) NOT NULL,
    timestamp DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sector_aggregates IS 'Pre-aggregated statistics by industry sector for economic trend analysis';

CREATE UNIQUE INDEX idx_sector_agg_unique ON audit.sector_aggregates(mcc_code, timestamp, currency_code);


-- Table: T021 - merchant_groups
-- Description: Groups of merchants (e.g., franchisees).
-- Business Case: Enables efficient auditing of large corporate structures. Auditors often need to look at a "Parent Company" and all its subsidiaries. This table defines those hierarchical or associative groups, allowing a single query to pull data for an entire franchise network.
-- KPIs: Group Mapping Accuracy.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.merchant_groups (
    group_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    parent_company_id UUID,
    group_type VARCHAR(50) CHECK (group_type IN ('FRANCHISE', 'CORPORATE_GROUP', 'SUPPLIER_NETWORK')),
    legal_identifier VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.merchant_groups IS 'Defines logical groupings of merchants for bulk auditing and hierarchical reporting';


-- Table: T022 - merchant_group_mapping
-- Description: Junction for merchants to groups.
-- Business Case: Resolves the Many-to-Many relationship between merchants and groups. A merchant might belong to a "Franchise Group" and also a "Regional Chamber of Commerce". This table links them, enabling flexible reporting.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.merchant_group_mapping (
    merchant_id UUID NOT NULL,
    group_id UUID NOT NULL,
    joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    role_in_group VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (merchant_id, group_id),
    CONSTRAINT fk_map_group FOREIGN KEY (group_id) REFERENCES audit.merchant_groups(group_id)
);
COMMENT ON TABLE audit.merchant_group_mapping IS 'Junction table linking merchants to various organizational groups';


-- Table: T023 - audit_templates
-- Description: Pre-defined report templates.
-- Business Case: Standardization and Efficiency. Instead of writing SQL from scratch for common reports (e.g., "Quarterly VAT Return"), auditors can save templates. This ensures consistency across audits and reduces the technical barrier to entry for junior auditors.
-- KPIs: Template Usage Rate, Error Reduction.
-- Feature Reference: F135
CREATE TABLE IF NOT EXISTS audit.audit_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    query_template TEXT NOT NULL, -- SQL with placeholders like {{merchant_id}}
    parameters_schema JSONB, -- definition of required params
    created_by UUID NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    category VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_templates IS 'Library of reusable SQL queries and report definitions for standardization';

CREATE INDEX idx_templates_public ON audit.audit_templates(is_public) WHERE is_public = TRUE;


-- Table: T024 - audit_snapshots
-- Description: Point-in-time snapshots for forensics.
-- Business Case: Evidence Preservation. In a dynamic database, data changes. If a fraud is suspected, auditors need to capture the "State of the World" at that specific moment. This table tracks snapshots (often backups or materialized view refreshes) that can be restored to a read-only state for forensic replay.
-- KPIs: Snapshot Creation Time, Storage Cost.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.audit_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_timestamp TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL, -- CREATING, AVAILABLE, RESTORING, DELETED
    base_backup_id VARCHAR(255), -- Reference to storage system ID
    size_bytes BIGINT,
    created_for_reason TEXT, -- e.g., "Legal Hold #12345"
    expires_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_snapshots IS 'Metadata for point-in-time database snapshots used in forensic investigations';


-- Table: T025 - dsr_requests
-- Description: Data Subject Requests (GDPR).
-- Business Case: Legal Compliance. Citizens have the right to ask "What data do you have on me?" (Access) or "Delete my data" (Erasure). This table tracks these requests, ensuring the platform complies with GDPR Article 15 and 17 within the mandated timeframe (usually 30 days).
-- KPIs: Response Time (< 30 days), Request Completion Rate.
-- Feature Reference: F115
CREATE TABLE IF NOT EXISTS audit.dsr_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL, -- The anonymized ID of the user
    request_type audit.enum_request_type NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, PROCESSING, COMPLETED, REJECTED
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    due_date DATE NOT NULL,
    completed_at TIMESTAMPTZ,
    rejection_reason TEXT,
    evidence_export_path TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL, -- System or DPO
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.dsr_requests IS 'Tracks GDPR Data Subject Requests for data access, portability, and deletion';

CREATE INDEX idx_dsr_status ON audit.dsr_requests(status, due_date);


-- Table: T026 - feedback_loop
-- Description: Auditor feedback on false positives.
-- Business Case: Continuous Improvement (CMMI). Machine Learning models aren't perfect. When an auditor marks an alert as a "False Positive", that feedback is captured here. It is then used to retrain the model, improving its accuracy over time and reducing alert fatigue for auditors.
-- KPIs: Model Retraining Frequency, False Positive Reduction Rate.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.feedback_loop (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_id UUID NOT NULL,
    auditor_id UUID NOT NULL,
    is_false_positive BOOLEAN NOT NULL,
    comment TEXT,
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    incorporated_into_model BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.feedback_loop IS 'Auditor feedback mechanism for refining ML model accuracy';


-- Table: T027 - auditor_performance
-- Description: Metrics on auditor usage and efficiency.
-- Business Case: HR Analytics and Resource Optimization. By tracking how many queries auditors run, how long they take, and their error rates, management can identify top performers, flag training needs, and optimize team staffing during peak tax seasons.
-- KPIs: Queries Per Auditor, Average Query Duration, Findings Per Hour.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.auditor_performance (
    perf_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    queries_run INTEGER DEFAULT 0,
    avg_duration_ms NUMERIC(10,2),
    reports_generated INTEGER DEFAULT 0,
    findings_created INTEGER DEFAULT 0,
    system_login_hours NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_perf_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id),
    CONSTRAINT chk_perf_dates CHECK (period_end > period_start),
    UNIQUE(auditor_id, period_start, period_end)
);
COMMENT ON TABLE audit.auditor_performance IS 'Aggregated performance metrics for auditor evaluation and resource planning';


-- Table: T028 - audit_workload
-- Description: Distribution of audit cases.
-- Business Case: Workload Management. Ensures audit cases are distributed fairly among the team. This table tracks the assignment and status of specific cases (e.g., "Investigate Merchant X"), preventing bottlenecks where one auditor is overwhelmed while another is idle.
-- KPIs: Case Aging, Fairness Index.
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS audit.audit_workload (
    case_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    assigned_to UUID NOT NULL,
    assigned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'ASSIGNED' CHECK (status IN ('ASSIGNED', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED')),
    priority VARCHAR(20) CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT')),
    due_date DATE,
    estimated_hours NUMERIC(5,2),
    actual_hours NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_workload_auditor FOREIGN KEY (assigned_to) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_workload IS 'Task management system for distributing and tracking audit investigation cases';

CREATE INDEX idx_workload_auditor_status ON audit.audit_workload(assigned_to, status);


-- Table: T029 - transparency_log
-- Description: Public transparency report data.
-- Business Case: Building Trust with the Public. To assure citizens that the system isn't being abused, this table aggregates data (e.g., "Total requests", "Compliance rate") for the annual Transparency Report. It proves the system is working as intended without revealing sensitive data.
-- KPIs: Report Accuracy, Publishing Timeliness.
-- Feature Reference: F120
CREATE TABLE IF NOT EXISTS audit.transparency_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    period VARCHAR(20) NOT NULL, -- e.g., "2023-Q4"
    requests_received INTEGER NOT NULL,
    requests_granted INTEGER NOT NULL,
    requests_denied INTEGER NOT NULL,
    data_exported_rows BIGINT,
    compliance_rate NUMERIC(5,2), -- Calculated
    published_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.transparency_log IS 'Stores metrics for public transparency reporting on government data access';


-- Table: T030 - sanction_screening_results
-- Description: Results of AML screening.
-- Business Case: AML/CTF Compliance. Before allowing a transaction or merchant, the system screens them against international sanctions lists (OFAC, UN, EU). This table stores the results of these screenings. A "MATCH" here freezes the asset and alerts the relevant authorities.
-- KPIs: Screening Speed (<1s), False Match Rate.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS audit.sanction_screening_results (
    screen_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL, -- Merchant ID or Payer Hash
    list_name VARCHAR(100) NOT NULL, -- e.g., "EU_Sanctions"
    match_score NUMERIC(3,2),
    status VARCHAR(20) NOT NULL, -- NO_MATCH, POTENTIAL_MATCH, CONFIRMED_MATCH
    screened_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    details_json JSONB, -- Name matched, DOB, etc.

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sanction_screening_results IS 'Logs checks of entities against international sanctions watch lists';

CREATE INDEX idx_sanction_entity ON audit.sanction_screening_results(entity_id, screened_at DESC);


-- Table: T031 - audit_evidence_locker
-- Description: Secure storage references for evidence.
-- Business Case: Legal Chain of Custody. When an auditor finds something, they need to "bag and tag" digital evidence. This table stores the metadata of files (screenshots, logs, exports) relevant to an investigation. It ensures that evidence isn't lost or tampered with during a legal case.
-- KPIs: Evidence Integrity (100%), Access Control Success.
-- Feature Reference: F065
CREATE TABLE IF NOT EXISTS audit.audit_evidence_locker (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,
    file_path TEXT NOT NULL, -- Secure S3 location
    file_name VARCHAR(255) NOT NULL,
    file_hash_sha256 CHAR(64) NOT NULL,
    mime_type VARCHAR(100),
    uploaded_by UUID NOT NULL,
    added_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_evidence_case FOREIGN KEY (case_id) REFERENCES audit.audit_workload(case_id)
);
COMMENT ON TABLE audit.audit_evidence_locker IS 'Secure repository for files and evidence collected during audit investigations';


-- Table: T032 - deleted_records_archive
-- Description: Archive of deleted records for legal hold.
-- Business Case: Retention Despite Deletion. Sometimes a user invokes the "Right to be Forgotten", but the data is under a legal hold (e.g., pending court case). This table holds the data in a cryptographically secured state until the hold expires, satisfying both GDPR and legal preservation requirements.
-- KPIs: Secure Storage Compliance.
-- Feature Reference: F099
CREATE TABLE IF NOT EXISTS audit.deleted_records_archive (
    archive_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    original_record_id UUID NOT NULL,
    record_json JSONB NOT NULL, -- The data content
    deleted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deletion_reason VARCHAR(50),
    legal_hold_expires_at TIMESTAMPTZ,
    retention_policy_id UUID REFERENCES audit.data_retention_schedule(policy_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.deleted_records_archive IS 'Secure archive for data that must be retained despite logical deletion for legal reasons';


-- Table: T033 - data_quality_metrics
-- Description: Scores for data quality.
-- Business Case: Trust in Data. Auditors need to know if the data is reliable. This table tracks metrics like "Completeness" (are fields null?) and "Accuracy" (does VAT add up?). If quality drops, the system alerts data engineers to fix the ingestion pipeline.
-- KPIs: Completeness Score (>99%), Accuracy Score (>99%).
-- Feature Reference: F040
CREATE TABLE IF NOT EXISTS audit.data_quality_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100),
    completeness NUMERIC(3,2), -- 0 to 1
    accuracy_score NUMERIC(3,2),
    consistency_score NUMERIC(3,2),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    total_rows_analyzed BIGINT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_quality_metrics IS 'Stores results of automated data quality checks on ingested audit data';


-- Table: T034 - audit_training_sim_data
-- Description: Synthetic data for training.
-- Business Case: Skills Development without Risk. New auditors need to learn the system, but they shouldn't practice on real citizen data. This table points to synthetic datasets that mimic real transaction patterns (using GANs) but contain no real identities. It enables a safe "Sandbox" environment.
-- KPIs: Simulation Realism Score (>90%).
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.audit_training_sim_data (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_name VARCHAR(255) NOT NULL,
    parameters_json JSONB, -- Generation parameters used
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    record_count BIGINT,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_training_sim_data IS 'Manages synthetic datasets used for auditor training and sandbox environments';


-- Table: T035 - notification_webhooks
-- Description: Configured webhooks for alerts.
-- Business Case: Integration. Modern audits rely on tools like Slack or Microsoft Teams. This table allows auditors to configure URLs where the system should POST alerts (e.g., "High Value Transaction Alert"). This keeps the audit team informed in real-time without them watching the screen constantly.
-- KPIs: Webhook Delivery Success Rate, Latency.
-- Feature Reference: F038
CREATE TABLE IF NOT EXISTS audit.notification_webhooks (
    webhook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret_key VARCHAR(255), -- For HMAC signing
    events TEXT[] NOT NULL, -- e.g., {'ALERT_FIRED', 'REPORT_READY'}
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMPTZ,
    failure_count INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_webhook_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.notification_webhooks IS 'Configures external endpoints for receiving real-time audit alerts via HTTP';


-- Table: T036 - query_cost_estimates
-- Description: Cached query costs.
-- Business Case: Resource Management. Running heavy queries on a massive data warehouse is expensive. This table caches the "cost" (CPU, IO, Privacy Budget) of queries. Before an auditor runs a query, the system checks this table to give an estimate: "This will take 5 minutes and cost 0.4 Epsilon."
-- KPIs: Estimation Error (<10%).
-- Feature Reference: F078
CREATE TABLE IF NOT EXISTS audit.query_cost_estimates (
    estimate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash CHAR(64) NOT NULL UNIQUE,
    cpu_cost INTEGER,
    io_cost INTEGER,
    privacy_cost NUMERIC(5,4), -- Epsilon
    estimated_rows BIGINT,
    last_analyzed TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.query_cost_estimates IS 'Caches resource and privacy costs of common queries for performance and budgeting';


-- Table: T037 - audit_session_collaboration
-- Description: Tracks co-browsing sessions.
-- Business Case: Teamwork. Sometimes two auditors need to look at the same data simultaneously to solve a complex case. This table tracks "Co-browsing" sessions where one auditor shares their screen or cursor with another (remote control).
-- KPIs: Session Latency.
-- Feature Reference: F137
CREATE TABLE IF NOT EXISTS audit.audit_session_collaboration (
    collab_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_owner UUID NOT NULL,
    participant_id UUID NOT NULL,
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, ENDED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_collab_owner FOREIGN KEY (session_owner) REFERENCES audit.auditor(auditor_id),
    CONSTRAINT fk_collab_participant FOREIGN KEY (participant_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_session_collaboration IS 'Logs real-time collaboration sessions between auditors';


-- Table: T038 - audit_version_history
-- Description: Version history of audit reports.
-- Business Case: Change Management. Audit reports often get amended. If V1 said "Tax Due: 1000" and V2 says "Tax Due: 900", we need to know why. This table stores the diff between versions, creating an immutable chain of changes for legal defensibility.
-- KPIs: Version Retrieval Speed.
-- Feature Reference: F062
CREATE TABLE IF NOT EXISTS audit.audit_version_history (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    diff_json JSONB,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    change_summary TEXT
);
COMMENT ON TABLE audit.audit_version_history IS 'Tracks changes to audit reports over time to ensure audit trail integrity';

CREATE INDEX idx_version_history_report ON audit.audit_version_history(report_id, version_number);


-- Table: T039 - custom_fields_mapping
-- Description: Maps custom merchant fields to schema.
-- Business Case: Flexibility. Merchants often have weird custom data fields in their legacy systems. To audit them, we need to map "Custom_Field_A" to "Standard_VAT_Amount". This table stores these mappings so the ingestion engine knows how to normalize the data.
-- KPIs: Mapping Success Rate.
-- Feature Reference: F077
CREATE TABLE IF NOT EXISTS audit.custom_fields_mapping (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    custom_name VARCHAR(255) NOT NULL,
    standard_name VARCHAR(255) NOT NULL, -- Target column in audit schema
    transform_rule TEXT, -- SQL snippet for transformation
    data_type VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.custom_fields_mapping IS 'Maps merchant-specific custom fields to standard audit schema definitions';


-- Table: T040 - data_lineage_graph
-- Description: Edges for data lineage.
-- Business Case: Data Governance. "Where did this number come from?" This table tracks the flow of data. For example, `anonymized_events.amount` comes from `raw_transactions.amount` but minus `fee`. It helps auditors trust the data and debug data pipeline errors.
-- KPIs: Lineage Coverage.
-- Feature Reference: F093
CREATE TABLE IF NOT EXISTS audit.data_lineage_graph (
    lineage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_id VARCHAR(255) NOT NULL, -- e.g., "M01.table_tx"
    target_id VARCHAR(255) NOT NULL, -- e.g., "M06.anonymized_events"
    transform_type VARCHAR(50), -- e.g., "AGGREGATION", "MASKING"
    details JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_lineage_graph IS 'Graph structure representing the flow and transformation of data through the PARI system';


-- Table: T041 - failed_login_attempts
-- Description: Logs failed auth attempts.
-- Business Case: Security Monitoring. Brute force attacks are common. This table logs every failed login attempt. If the number of attempts spikes for a specific user or IP, the system can trigger a lockout or alert the security team.
-- KPIs: Response to Brute Force.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.failed_login_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(50) -- INVALID_PASSWORD, ACCOUNT_LOCKED, etc.
);
COMMENT ON TABLE audit.failed_login_attempts IS 'Security log tracking authentication failures to detect brute force attacks';

CREATE INDEX idx_failed_logins_ip ON audit.failed_login_attempts(ip_address, timestamp);
CREATE INDEX idx_failed_logins_user ON audit.failed_login_attempts(username, timestamp);


-- Table: T042 - batch_jobs
-- Description: Status of long-running batch jobs.
-- Business Case: Automation Tracking. Tasks like "Generate all VAT Reports for Spain" or "Archive 2020 Data" run in the background. This table tracks their status (Queued, Running, Failed), allowing admins to restart failed jobs and monitor progress.
-- KPIs: Job Success Rate, Job Duration.
-- Feature Reference: F092
CREATE TABLE IF NOT EXISTS audit.batch_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    job_name VARCHAR(255) NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED
    payload_json JSONB,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    result TEXT,
    error_message TEXT,
    progress INTEGER DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.batch_jobs IS 'Tracks the execution status of asynchronous background tasks and data jobs';


-- Table: T043 - audit_comments
-- Description: Comments/Annotations on transactions.
-- Business Case: Contextual Memory. When an auditor looks at a transaction and notes "Looks suspicious but verified with merchant", they add a comment here. Future auditors seeing this transaction will see the note, preventing duplicate work. It's a "Post-it note" for the data.
-- KPIs: Comment Utilization.
-- Feature Reference: F053
CREATE TABLE IF NOT EXISTS audit.audit_comments (
    comment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    tx_hash_ref CHAR(64) NOT NULL, -- Reference to the object being commented on
    text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    is_private BOOLEAN DEFAULT FALSE, -- Only visible to creator?

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT fk_comment_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_comments IS 'Collaborative annotations allowing auditors to leave notes on specific transactions or cases';

CREATE INDEX idx_comments_tx ON audit.audit_comments(tx_hash_ref);


-- Table: T044 - audit_workflow_states
-- Description: State definitions for audit workflows.
-- Business Case: Process Standardization (CMMI). Audits follow a flow (Open -> Investigate -> Review -> Close). This table defines the valid states and transitions, preventing auditors from skipping steps (e.g., closing a case without an investigation).
-- KPIs: Process Adherence.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_workflow_states (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_name VARCHAR(100) NOT NULL,
    state_name VARCHAR(50) NOT NULL,
    next_state_uuid UUID, -- Self-referential or list of allowed next states
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_workflow_states IS 'Defines the finite state machines for audit workflows ensuring process compliance';


-- Table: T045 - privacy_incidents
-- Description: Logs of potential privacy leaks.
-- Business Case: Risk Management. If the Differential Privacy mechanism fails or a query accidentally returns PII, this is a "Privacy Incident". This table logs the event so the Privacy Officer can investigate, mitigate, and report it to the Data Protection Authority (DPA).
-- KPIs: Incident Detection Time.
-- Feature Reference: F016
CREATE TABLE IF NOT EXISTS audit.privacy_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    description TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    mitigation_status VARCHAR(50), -- DETECTED, INVESTIGATING, MITIGATED
    affected_records_count INTEGER DEFAULT 0,
    report_submitted BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.privacy_incidents IS 'Critical log for tracking potential data privacy breaches or system failures';


-- Table: T046 - kv_store
-- Description: Key-value store for dynamic config.
-- Business Case: Agility. Sometimes we need to store settings that don't fit a rigid table (e.g., feature flags, UI settings). This key-value store provides a flexible NoSQL-like layer within the relational DB for dynamic configuration.
-- KPIs: Config Retrieval Speed.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.kv_store (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);
COMMENT ON TABLE audit.kv_store IS 'Flexible key-value storage for dynamic application configuration and feature flags';


-- Table: T047 - audit_dashboard_widgets
-- Description: User's dashboard layout.
-- Business Case: Personalization. Every auditor works differently. Some want a map, some want a spreadsheet. This table stores the JSON configuration of their dashboard (widget positions, types), allowing them to customize their workspace without developer intervention.
-- KPIs: User Engagement.
-- Feature Reference: F133
CREATE TABLE IF NOT EXISTS audit.audit_dashboard_widgets (
    widget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    widget_type VARCHAR(50) NOT NULL, -- e.g., 'CHART_VAT', 'TABLE_TRANSACTIONS'
    position_x INTEGER NOT NULL,
    position_y INTEGER NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    config_json JSONB, -- Widget specific settings

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_dashboard_widgets IS 'Stores user interface layout preferences for auditor dashboards';

CREATE INDEX idx_dashboard_user ON audit.audit_dashboard_widgets(user_id);


-- Table: T048 - export_quotas
-- Description: Limits on data export volumes.
-- Business Case: Resource Protection. Prevents auditors from accidentally (or maliciously) crashing the system by exporting the entire database to CSV. It enforces limits on rows or file size per user per day.
-- KPIs: Quota Enforcement Rate.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS audit.export_quotas (
    quota_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    period VARCHAR(20) NOT NULL, -- 'DAILY', 'WEEKLY'
    limit_rows BIGINT NOT NULL,
    used_rows BIGINT DEFAULT 0,
    reset_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_quota_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.export_quotas IS 'Enforces limits on the volume of data an auditor can export to protect system resources';


-- Table: T049 - audit_notification_prefs
-- Description: User notification preferences.
-- Business Case: Communication Hygiene. Not everyone wants an email at 3 AM. This table lets auditors choose how they want to be notified (Email, SMS, In-App) for different types of alerts, reducing noise and alert fatigue.
-- KPIs: User Satisfaction.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_notification_prefs (
    pref_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    channel VARCHAR(20) NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'PUSH', 'WEBHOOK')),
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_prefs_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id),
    UNIQUE(auditor_id, alert_type, channel)
);
COMMENT ON TABLE audit.audit_notification_prefs IS 'Auditor preferences for how and when they receive system notifications';


-- Table: T050 - audit_search_history
-- Description: Full text search history.
-- Business Case: UX Optimization. By tracking what auditors search for, we can improve the search index and suggest popular queries. It also helps in understanding what data is most in demand.
-- KPIs: Search Relevance.
-- Feature Reference: F122
CREATE TABLE IF NOT EXISTS audit.audit_search_history (
    search_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    search_term TEXT NOT NULL,
    results_count INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    filters_json JSONB

    -- Audit Columns
    -- created_at serves as timestamp
);
COMMENT ON TABLE audit.audit_search_history IS 'Logs search queries to improve search relevance and understand user intent';

CREATE INDEX idx_search_history_term ON audit.audit_search_history USING gin(to_tsvector('english', search_term));


-- 5. Views (V001 - V010) for context/usage
-- ================================================================================
-- Note: Views usually depend on tables. Creating placeholder definitions based on prompt list.

CREATE OR REPLACE VIEW audit.vw_merchant_tax_summary AS
SELECT
    m.merchant_id,
    t.report_id,
    t.total_vat_amount,
    t.period_start,
    t.period_end
FROM audit.merchant_risk_profiles m -- Note: merchant list not in T1-T50, assumed join
JOIN audit.tax_reports t ON m.merchant_id = t.merchant_id
WHERE t.status = 'SUBMITTED';
COMMENT ON VIEW audit.vw_merchant_tax_summary IS 'Aggregated tax summary per merchant for F001/F033';

CREATE OR REPLACE VIEW audit.vw_recent_audit_logs AS
SELECT * FROM audit.auditor_logs
WHERE ts > NOW() - INTERVAL '1 day';
COMMENT ON VIEW audit.vw_recent_audit_logs IS 'Rolling 24-hour window of audit actions for F005';

CREATE OR REPLACE VIEW audit.vw_high_risk_merchants AS
SELECT * FROM audit.merchant_risk_profiles
WHERE risk_level IN ('HIGH', 'CRITICAL');
COMMENT ON VIEW audit.vw_high_risk_merchants IS 'List of merchants exceeding risk thresholds for F056/F012';

CREATE OR REPLACE VIEW audit.vw_cross_border_daily AS
SELECT
    source_country,
    target_country,
    SUM(volume) as total_volume,
    timestamp as date
FROM audit.cross_border_flows
GROUP BY source_country, target_country, timestamp;
COMMENT ON VIEW audit.vw_cross_border_daily IS 'Daily aggregation of cross-border flows for F008';

CREATE OR REPLACE VIEW audit.vw_suspicious_activity_detail AS
SELECT
    s.*,
    m.risk_score,
    a.status as audit_status
FROM audit.suspicious_activities s
LEFT JOIN audit.merchant_risk_profiles m ON s.merchant_id = m.merchant_id
LEFT JOIN audit.audit_findings a ON s.finding_id = a.finding_id;
COMMENT ON VIEW audit.vw_suspicious_activity_detail IS 'Detailed join of flags and risk data for F025';

CREATE OR REPLACE VIEW audit.vw_pending_audit_cases AS
SELECT * FROM audit.audit_workload
WHERE status = 'ASSIGNED';
COMMENT ON VIEW audit.vw_pending_audit_cases IS 'Active workload list for F107/F146';

CREATE OR REPLACE VIEW audit.vw_audit_performance AS
SELECT
    a.username,
    p.queries_run,
    p.avg_duration_ms,
    p.period_start
FROM audit.auditor_performance p
JOIN audit.auditor a ON p.auditor_id = a.auditor_id;
COMMENT ON VIEW audit.vw_audit_performance IS 'KPI view for auditor efficiency F116';

CREATE OR REPLACE VIEW audit.vw_unmatched_invoices AS
SELECT * FROM audit.invoice_payment_matches
WHERE status = 'UNMATCHED';
COMMENT ON VIEW audit.vw_unmatched_invoices IS 'Reconciliation exception list for F073';

CREATE OR REPLACE VIEW audit.vw_sector_analytics AS
SELECT
    mcc_code,
    SUM(volume) as total_volume,
    SUM(tx_count) as total_txs
FROM audit.sector_aggregates
GROUP BY mcc_code;
COMMENT ON VIEW audit.vw_sector_analytics IS 'Sector breakdown for F101';

CREATE OR REPLACE VIEW audit.vw_circular_trade_loops AS
SELECT * FROM audit.circular_trades
WHERE is_active = TRUE;
COMMENT ON VIEW audit.vw_circular_trade_loops IS 'Active fraud loops for F007';


-- 6. Stored Procedures (P001 - P020)
-- ================================================================================

CREATE OR REPLACE PROCEDURE audit.sp_generate_tax_report(
    p_merchant_id UUID,
    p_start_date DATE,
    p_end_date DATE
)
LANGUAGE plpgsql
AS $$ DECLARE
    v_report_id UUID;
BEGIN
    -- Logic to aggregate anonymized_events and create a report entry
    INSERT INTO audit.tax_reports (merchant_id, period_start, period_end, created_by, updated_by)
    VALUES (p_merchant_id, p_start_date, p_end_date, uuid_generate_v4(), uuid_generate_v4())
    RETURNING report_id INTO v_report_id;

    -- In a real scenario, would calculate sums from audit.anonymized_events here

    RAISE NOTICE 'Report Generated: %', v_report_id;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_generate_tax_report IS 'Generates JSON report for tax submission F033';

CREATE OR REPLACE FUNCTION audit.sp_add_dp_noise(
    p_value NUMERIC,
    p_epsilon NUMERIC
) RETURNS NUMERIC
LANGUAGE plpgsql
AS $$ BEGIN
    -- Placeholder for Laplacian noise function
    -- Using random() for simulation
    RETURN p_value + (random() - 0.5) * (1.0 / p_epsilon);
END;
 $$;
COMMENT ON FUNCTION audit.sp_add_dp_noise IS 'Applies differential privacy noise F004';

CREATE OR REPLACE PROCEDURE audit.sp_check_k_anonymity(
    p_result_set JSONB,
    p_k INTEGER
)
LANGUAGE plpgsql
AS $$ DECLARE
    v_count INTEGER;
BEGIN
    -- Pseudocode for k-anonymity check
    -- SELECT count(*) INTO v_count FROM jsonb_array_elements(p_result_set)
    -- GROUP BY identifier HAVING count(*) < p_k;

    IF v_count > 0 THEN
        RAISE EXCEPTION 'K-Anonymity Violation';
    END IF;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_check_k_anonymity IS 'Validates result set satisfies k-anonymity F016';

CREATE OR REPLACE PROCEDURE audit.sp_log_audit_access(
    p_session_id UUID,
    p_query_text TEXT
)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.auditor_logs (session_id, auditor_id, query_hash, tables_accessed, rows_returned, ts, created_at)
    VALUES (
        p_session_id,
        (SELECT auditor_id FROM audit.auditor_sessions WHERE session_id = p_session_id),
        encode(digest(p_query_text, 'sha256'), 'hex'),
        ARRAY['UNKNOWN'], -- Should parse query text in real impl
        0,
        NOW(),
        NOW()
    );
END;
 $$;
COMMENT ON PROCEDURE audit.sp_log_audit_access IS 'Trigger logging function for F005';

CREATE OR REPLACE PROCEDURE audit.sp_expire_old_sessions()
LANGUAGE plpgsql
AS $$ BEGIN
    UPDATE audit.auditor_sessions
    SET status = 'EXPIRED', updated_at = NOW()
    WHERE expires_at < NOW() AND status = 'ACTIVE';
END;
 $$;
COMMENT ON PROCEDURE audit.sp_expire_old_sessions IS 'Cleans up stale sessions F027';

CREATE OR REPLACE PROCEDURE audit.sp_calculate_merchant_risk(p_merchant_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Placeholder ML inference call
    UPDATE audit.merchant_risk_profiles
    SET
        risk_score = 0.5,
        last_calculated = NOW(),
        updated_at = NOW()
    WHERE merchant_id = p_merchant_id;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_calculate_merchant_risk IS 'Updates merchant risk score F056';

CREATE OR REPLACE PROCEDURE audit.sp_detect_circular_trades(p_depth_limit INTEGER)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Placeholder Graph Traversal logic
    -- Identify loops in audit.graph_edges and insert into audit.circular_trades
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_detect_circular_trades IS 'Analyzes graph for cycles F007';

CREATE OR REPLACE PROCEDURE audit.sp_archive_audit_logs(p_cutoff_date DATE)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Move logs older than cutoff to cold storage (S3/Glacier) logic
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_archive_audit_logs IS 'Moves logs to cold storage F109';

CREATE OR REPLACE PROCEDURE audit.sp_pii_redaction(p_text_blob TEXT)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Placeholder regex replacement
    -- RETURN regexp_replace(p_text_blob, '\S+@\S+\.\S+', '***@***.***');
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_pii_redaction IS 'Scrubs PII from text fields F063';

CREATE OR REPLACE PROCEDURE audit.sp_verify_chain_integrity(p_merchant_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Placeholder to verify Merkle Tree root
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_verify_chain_integrity IS 'Verifies hash chain of transactions F013';

CREATE OR REPLACE PROCEDURE audit.sp_aggregate_sector_stats(p_date DATE)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Insert into audit.sector_aggregates based on anonymized_events
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_aggregate_sector_stats IS 'Materializes sector stats F101';

CREATE OR REPLACE PROCEDURE audit.sp_match_invoices_payments(p_date DATE)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to match invoices to transactions
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_match_invoices_payments IS 'Runs matching logic F073';

CREATE OR REPLACE PROCEDURE audit.sp_submit_tax_report(p_report_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- API Call to National Authority
    UPDATE audit.tax_reports SET status = 'SUBMITTED', submission_ts = NOW() WHERE report_id = p_report_id;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_submit_tax_report IS 'Submits report to authority API F010';

CREATE OR REPLACE PROCEDURE audit.sp_update_privacy_budget(p_auditor_id UUID, p_cost NUMERIC)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.privacy_budget_log (auditor_id, query_id, epsilon_spent, remaining_epsilon, period_start, period_end)
    VALUES (p_auditor_id, NULL, p_cost, 1.0 - p_cost, CURRENT_DATE, CURRENT_DATE + INTERVAL '1 month');
END;
 $$;
COMMENT ON PROCEDURE audit.sp_update_privacy_budget IS 'Deducts epsilon from user budget F043';

CREATE OR REPLACE PROCEDURE audit.sp_get_merchant_graph(p_merchant_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Returns JSON of nodes and edges
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_get_merchant_graph IS 'Returns graph data for visualization F128';

CREATE OR REPLACE PROCEDURE audit.sp_mark_case_closed(p_case_id UUID, p_resolution_note TEXT)
LANGUAGE plpgsql
AS $$ BEGIN
    UPDATE audit.audit_workload
    SET status = 'COMPLETED', updated_at = NOW()
    WHERE case_id = p_case_id;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_mark_case_closed IS 'Closes an audit case F107';

CREATE OR REPLACE PROCEDURE audit.sp_check_export_quota(p_auditor_id UUID, p_row_count INTEGER)
LANGUAGE plpgsql
AS $$ DECLARE
    v_used BIGINT;
    v_limit BIGINT;
BEGIN
    SELECT limit_rows, used_rows INTO v_limit, v_used
    FROM audit.export_quotas
    WHERE auditor_id = p_auditor_id AND period = 'DAILY';

    IF (v_used + p_row_count) > v_limit THEN
        RAISE EXCEPTION 'Quota Exceeded';
    END IF;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_check_export_quota IS 'Checks if user can export F048';

CREATE OR REPLACE PROCEDURE audit.sp_purge_dsr_data(p_user_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Execute deletion for DSR
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_purge_dsr_data IS 'Executes deletion for DSR F099';

CREATE OR REPLACE PROCEDURE audit.sp_retrain_model_feedback(p_feedback_batch JSONB)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Process false positive feedback
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_retrain_model_feedback IS 'Processes feedback for ML F132';

CREATE OR REPLACE PROCEDURE audit.sp_generate_transparency_report(p_period VARCHAR)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Update audit.transparency_log
    NULL;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_generate_transparency_report IS 'Creates the public report F120';

-- End of Script Part 1 (Objects 1-50)

-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 2: Objects 51-100)
-- ================================================================================
-- Description: This script continues the database object creation for the Independent
-- Auditor Interface. It covers caching, API management, ML integration, forensic
-- tools, and system health monitoring.
--
-- Scope: Database Objects T051 - T100, V011 - V016, P021 - P046, E011 - E018.
-- ================================================================================

-- 3. Enums (Part 2)
-- ================================================================================

-- Enum: E011 - enum_feature_flag
-- Description: Possible states of feature flags.
-- Feature Reference: F054
CREATE TYPE audit.enum_feature_flag AS ENUM ('ENABLED', 'DISABLED', 'PERCENTAGE_ROLLOUT', 'WHITELIST_ONLY');
COMMENT ON TYPE audit.enum_feature_flag IS 'States for toggling functionality in the system';

-- Enum: E012 - enum_notification_status
-- Description: Status of notification delivery.
-- Feature Reference: F038
CREATE TYPE audit.enum_notification_status AS ENUM ('QUEUED', 'SENT', 'FAILED', 'RETRY');
COMMENT ON TYPE audit.enum_notification_status IS 'Lifecycle states for asynchronous notifications';

-- Enum: E013 - enum_key_status
-- Description: Status of encryption keys.
-- Feature Reference: F045
CREATE TYPE audit.enum_key_status AS ENUM ('ACTIVE', 'DEPRECATED', 'COMPROMISED', 'REVOKED');
COMMENT ON TYPE audit.enum_key_status IS 'Security status of cryptographic keys used in the system';

-- Enum: E014 - enum_health_status
-- Description: Health of dependencies.
-- Feature Reference: F097
CREATE TYPE audit.enum_health_status AS ENUM ('UP', 'DEGRADED', 'DOWN', 'UNKNOWN');
COMMENT ON TYPE audit.enum_health_status IS 'Operational status of upstream and internal dependencies';

-- Enum: E015 - enum_priority
-- Description: Priority levels.
-- Feature Reference: F107
CREATE TYPE audit.enum_priority AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT');
COMMENT ON TYPE audit.enum_priority IS 'Urgency classification for tasks and alerts';

-- Enum: E016 - enum_file_status
-- Description: Upload status.
-- Feature Reference: F058
CREATE TYPE audit.enum_file_status AS ENUM ('UPLOADED', 'PARSING', 'ERROR', 'READY', 'QUARANTINED');
COMMENT ON TYPE audit.enum_file_status IS 'Processing states for uploaded documents';

-- Enum: E017 - enum_action_type
-- Description: Audit actions.
-- Feature Reference: F107
CREATE TYPE audit.enum_action_type AS ENUM ('COMMENT', 'STATUS_CHANGE', 'TAG_ADD', 'ASSIGNMENT', 'ESCALATION');
COMMENT ON TYPE audit.enum_action_type IS 'Types of actions performed on audit objects';

-- Enum: E018 - enum_event_type
-- Description: Event bus types.
-- Feature Reference: F001
CREATE TYPE audit.enum_event_type AS ENUM ('TAX_REPORT_GEN', 'AUDIT_STARTED', 'ALERT_FIRED', 'USER_LOGIN', 'DATA_EXPORTED');
COMMENT ON TYPE audit.enum_event_type IS 'Categories of integration events published to the message bus';


-- 4. DDL Statements (Tables T051 - T100)
-- ================================================================================

-- Table: T051 - merchant_cache
-- Description: Cached merchant details for fast loading.
-- Business Case: Performance Optimization. Merchant master data might reside in a separate CRM or core ledger (M01/M03). Querying that system for every dashboard render would introduce latency. This cache table stores a denormalized snapshot of frequently accessed merchant fields (Name, Status, Risk Score) to ensure the Auditor UI renders in milliseconds.
-- KPIs: Cache Hit Ratio, Data Freshness Lag (< 1hr).
-- Feature Reference: F006
CREATE TABLE IF NOT EXISTS audit.merchant_cache (
    merchant_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    mcc_code CHAR(4),
    registration_date DATE,
    status VARCHAR(50),
    risk_level audit.enum_risk_level,

    -- Cache Management
    refreshed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    invalidate_signal BOOLEAN DEFAULT FALSE, -- Set to TRUE to force refresh

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.merchant_cache IS 'High-speed read-through cache for merchant profile data';

CREATE INDEX idx_merchant_cache_name ON audit.merchant_cache USING gin(to_tsvector('english', name));


-- Table: T052 - query_templates
-- Description: Saved user queries.
-- Business Case: Productivity and Standardization. Auditors often run the same complex queries daily (e.g., "High Value Transactions > 10k in Spain"). This table allows them to save these as "Templates" with parameters, preventing re-typing SQL and reducing syntax errors. It fosters a library of best-practice queries.
-- KPIs: Template Reuse Rate, User Efficiency Gain.
-- Feature Reference: F036
CREATE TABLE IF NOT EXISTS audit.query_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    sql_text TEXT NOT NULL,
    parameters_json JSONB, -- Definition of parameters e.g., [{"name": "min_amount", "type": "numeric"}]
    usage_count INTEGER DEFAULT 0,
    last_executed_at TIMESTAMPTZ,
    is_public BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_template_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.query_templates IS 'Repository of user-defined SQL queries for rapid reuse';


-- Table: T053 - audit_api_usage
-- Description: Tracks API call metrics.
-- Business Case: Capacity Planning and Cost Analysis. By tracking every API call (who called which endpoint, when, and how long it took), the team can identify bottlenecks, predict infrastructure scaling needs, and detect abnormal usage patterns that might indicate a security breach or a broken integration.
-- KPIs: P95 Latency, Request Volume, Error Rate.
-- Feature Reference: F044
CREATE TABLE IF NOT EXISTS audit.audit_api_usage (
    call_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL, -- GET, POST, etc.
    latency_ms INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    auditor_id UUID, -- NULL if machine-to-machine
    ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,

    CONSTRAINT fk_usage_auditor FOREIGN KEY (auditor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_api_usage IS 'Detailed metrics log for analyzing API performance and usage patterns';

-- Partitioning for large volume (Time-series)
-- CREATE TABLE audit.audit_api_usage_y2024 PARTITION OF audit.audit_api_usage
--     FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
CREATE INDEX idx_api_usage_ts ON audit.audit_api_usage(ts DESC);


-- Table: T054 - feature_flags
-- Description: Feature toggle configuration.
-- Business Case: Safe Deployment (Canary Releases). When releasing a new feature (like a new graph visualization), we don't want to break the system for everyone. This table allows us to enable the feature for 1% of users or specific internal users first. If bugs are found, we can toggle it off instantly without code deployment.
-- KPIs: Deployment Risk, Rollback Time.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.feature_flags (
    flag_key VARCHAR(100) PRIMARY KEY,
    is_enabled BOOLEAN DEFAULT FALSE,
    description TEXT,
    rollout_percentage INTEGER CHECK (rollout_percentage BETWEEN 0 AND 100),
    allowed_user_ids UUID[], -- Whitelist
    audit_log JSONB, -- History of changes

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.feature_flags IS 'Configuration for dynamically enabling/disabling system features';


-- Table: T055 - rate_limit_counters
-- Description: Counts for rate limiting.
-- Business Case: System Stability Protection. Prevents a single user or a buggy script from overwhelming the database. This table tracks usage against limits (e.g., "1000 queries per hour"). If the limit is hit, the API Gateway rejects subsequent requests until the window resets.
-- KPIs: Throttle Events, System Uptime.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.rate_limit_counters (
    counter_key VARCHAR(255) PRIMARY KEY, -- Composite key: e.g., "auditor_id:endpoint"
    count BIGINT NOT NULL DEFAULT 0,
    window_expiry TIMESTAMPTZ NOT NULL,
    limit BIGINT NOT NULL
);
COMMENT ON TABLE audit.rate_limit_counters IS 'Sliding window counters for enforcing API rate limits';

CREATE INDEX idx_rate_limit_expiry ON audit.rate_limit_counters(window_expiry);


-- Table: T056 - audit_notifications
-- Description: Queue of notifications to be sent.
-- Business Case: Asynchronous Communication. Auditors shouldn't wait for an email to send before saving a report. This table acts as a queue (Outbox pattern). The application writes a notification record here, and a background worker picks it up and sends it via Email/SMS/Webhook. This guarantees "at least once" delivery.
-- KPIs: Delivery Success Rate, Queue Latency.
-- Feature Reference: F038
CREATE TABLE IF NOT EXISTS audit.audit_notifications (
    notif_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    recipient_id UUID NOT NULL, -- Auditor ID
    recipient_channel VARCHAR(50) NOT NULL, -- email, sms
    payload JSONB NOT NULL, -- Template vars and content
    status audit.enum_notification_status NOT NULL DEFAULT 'QUEUED',
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    queued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_notifications IS 'Outbox queue for reliable asynchronous notification delivery';

CREATE INDEX idx_notifications_status ON audit.audit_notifications(status, attempts);


-- Table: T057 - schema_versions
-- Description: History of DB schema changes.
-- Business Case: Reproducibility and Version Control. As the database evolves (new columns, tables), this table logs every migration script applied. It ensures that Development, Staging, and Production environments are identical and allows the team to rollback changes if necessary by knowing exactly which migration was applied.
-- KPIs: Schema Consistency Score.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS audit.schema_versions (
    version_id VARCHAR(100) PRIMARY KEY, -- e.g., '20231001_add_merchant_cache'
    migration_name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,
    checksum CHAR(64), -- SHA-256 of the script file
    success BOOLEAN NOT NULL
);
COMMENT ON TABLE audit.schema_versions IS 'Tracks all database schema migrations for version control';


-- Table: T058 - dependency_health
-- Description: Status of upstream services.
-- Business Case: Observability. The Audit Module (M06) relies on other modules (M01, M05) and external APIs (Tax Authorities). If M05 goes down, M06 can't get data. This table stores the heartbeat status of these dependencies, allowing a dashboard to show "System Degraded" to auditors.
-- KPIs: Uptime of Dependencies, Incident Detection Time.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.dependency_health (
    service_name VARCHAR(100) PRIMARY KEY,
    status audit.enum_health_status NOT NULL,
    last_check TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    latency_ms INTEGER,
    error_message TEXT,
    consecutive_failures INTEGER DEFAULT 0
);
COMMENT ON TABLE audit.dependency_health IS 'Real-time health monitoring of critical system dependencies';


-- Table: T059 - encryption_keys
-- Description: Metadata for data encryption keys.
-- Business Case: Security Compliance. We never store raw encryption keys in the DB (they go in an HSM or KMS). However, we store the *metadata* (ID, version, status) here so the application knows which key to use to encrypt new data or decrypt old data. It tracks key rotation schedules.
-- KPIs: Key Rotation Compliance, Encryption Coverage.
-- Feature Reference: F045
CREATE TABLE IF NOT EXISTS audit.encryption_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_alias VARCHAR(255) NOT NULL UNIQUE,
    key_version INTEGER NOT NULL,
    status audit.enum_key_status NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    kms_arn VARCHAR(255), -- Reference to AWS KMS / Azure Key Vault
    algorithm VARCHAR(50) DEFAULT 'AES-256'
);
COMMENT ON TABLE audit.encryption_keys IS 'Metadata registry for cryptographic key management';


-- Table: T060 - session_tokens
-- Description: JWT/Session token blacklist.
-- Business Case: Instant Revocation. JWTs are stateless and valid until expiry. If an auditor is banned or logs out, we need to invalidate the token immediately. This "Blacklist" table stores the ID of revoked tokens. Every API request checks this list; if found, access is denied even if the JWT is cryptographically valid.
-- KPIs: Revocation Latency.
-- Feature Reference: F027
CREATE TABLE IF NOT EXISTS audit.session_tokens (
    token_id VARCHAR(255) PRIMARY KEY, -- The `jti` (JWT ID) claim
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    reason VARCHAR(100) -- LOGOUT, BANNED, PASSWORD_CHANGE
);
COMMENT ON TABLE audit.session_tokens_is 'Blacklist for revoked JWT tokens to enable immediate session termination';

CREATE INDEX idx_tokens_expiry ON audit.session_tokens(expires_at);


-- Table: T061 - synthetic_transactions
-- Description: Fake data for simulations.
-- Business Case: Testing and Training. To test the system at scale or train auditors, we need data that looks real but isn't. This table stores "Synthetic Data" generated by GANs (Generative Adversarial Networks). It allows developers to load test the database without exposing real PII and allows auditors to practice in a sandbox.
-- KPIs: Data Fidelity Score, Generation Speed.
-- Feature Reference: F064
CREATE TABLE IF NOT EXISTS audit.synthetic_transactions (
    synth_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    amount NUMERIC(19,4) NOT NULL,
    merchant_id UUID, -- Fake or anonymized
    timestamp TIMESTAMPTZ NOT NULL,
    category VARCHAR(50),
    generation_parameters JSONB, -- Params used to create this record
    dataset_tag VARCHAR(100), -- 'Training_Set_V1'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.synthetic_transactions IS 'Stores artificially generated transaction data for testing and training purposes';


-- Table: T062 - audit_tags
-- Description: Tags for categorizing findings.
-- Business Case: Knowledge Management. Investigations can be complex. Tags (like "VAT_Fraud", "Shell_Company", "2023_Q4_Audit") allow auditors to categorize findings flexibly without rigid hierarchies. This improves searchability and reporting later.
-- KPIs: Tag Usage Consistency.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_tags (
    tag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tag_name VARCHAR(100) NOT NULL UNIQUE,
    color VARCHAR(7), -- Hex code for UI
    description TEXT,
    created_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_tags IS 'Taxonomy for labeling and categorizing audit findings';


-- Table: T063 - finding_tags_mapping
-- Description: Junction: Findings to Tags.
-- Business Case: Many-to-Many Relationship. A single finding might involve both "VAT" and "Money Laundering". A tag like "High Priority" might apply to many findings. This junction table links them, enabling queries like "Show me all High Priority VAT Fraud findings."
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.finding_tags_mapping (
    finding_id UUID NOT NULL,
    tag_id UUID NOT NULL,
    tagged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    tagged_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (finding_id, tag_id),
    CONSTRAINT fk_map_finding FOREIGN KEY (finding_id) REFERENCES audit.audit_findings(finding_id),
    CONSTRAINT fk_map_tag FOREIGN KEY (tag_id) REFERENCES audit.audit_tags(tag_id)
);
COMMENT ON TABLE audit.finding_tags_mapping IS 'Links findings to categorical tags for flexible organization';


-- Table: T064 - audit_calculations
-- Description: Stores complex calculation results.
-- Business Case: Performance and Memoization. Calculating the "VAT Gap" for the whole country is a heavy query. Instead of running it every time a user refreshes the page, we run it periodically (e.g., nightly) and store the result here. This is a "Materialized Result" pattern.
-- KPIs: Calculation Accuracy, Retrieval Latency.
-- Feature Reference: F033, F100
CREATE TABLE IF NOT EXISTS audit.audit_calculations (
    calc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(100) NOT NULL, -- e.g., 'VAT_GAP_EU_2023'
    result_json JSONB NOT NULL,
    inputs_hash CHAR(64), -- Hash of parameters to detect if inputs changed
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_calculations IS 'Cache for expensive aggregate calculations to improve dashboard performance';


-- Table: T065 - geolocation_data
-- Description: Aggregated geo data.
-- Business Case: Geographic Risk Assessment. Fraud often clusters in specific regions (e.g., ports, border towns). This table aggregates transaction volume by geolocation (Lat/Long or Region), allowing auditors to see a heatmap of financial activity and identify unusual spikes in specific areas.
-- KPIs: Geo-Accuracy, Visualization Render Speed.
-- Feature Reference: F032
CREATE TABLE IF NOT EXISTS audit.geolocation_data (
    geo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    region VARCHAR(100) NOT NULL, -- e.g., "Berlin-Mitte", "PostalCode 10115"
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    tx_count BIGINT NOT NULL,
    volume NUMERIC(19,4) NOT NULL,
    timestamp DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.geolocation_data IS 'Aggregated statistics by geographic region for heatmap generation';


-- Table: T066 - audit_file_uploads
-- Description: Temporary storage for uploaded docs.
-- Business Case: Hybrid Audit Integration. Not all data is digital. Auditors upload scanned receipts or legacy CSV files. This table tracks the upload, triggers OCR processing, and stores the parsed results. It bridges the gap between physical paper trails and the digital blockchain ledger.
-- KPIs: OCR Success Rate, File Throughput.
-- Feature Reference: F058
CREATE TABLE IF NOT EXISTS audit.audit_file_uploads (
    file_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(50) NOT NULL, -- 'application/pdf'
    file_size_bytes BIGINT,
    uploaded_by UUID NOT NULL,
    status audit.enum_file_status NOT NULL DEFAULT 'UPLOADED',
    storage_path TEXT, -- S3 location
    ocr_text TEXT,
    parsed_data JSONB, -- Structured data extracted from file
    virus_scan_status VARCHAR(20) DEFAULT 'PENDING', -- SECURITY: Scan before processing
    error_message TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_upload_auditor FOREIGN KEY (uploaded_by) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_file_uploads IS 'Manages the lifecycle and processing of uploaded external documents';


-- Table: T067 - regulatory_bulletins
-- Description: Updates on laws.
-- Business Case: Proactive Compliance. Tax laws change frequently. This table ingests RSS feeds or API updates from government bodies. It alerts auditors when a new regulation (e.g., "New Digital Services Tax in Country X") comes into effect, ensuring the system configuration stays legal.
-- KPIs: Update Lag (< 24h), Compliance Accuracy.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.regulatory_bulletins (
    bulletin_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    effective_date DATE NOT NULL,
    summary TEXT,
    source_url TEXT,
    jurisdiction_code CHAR(2),
    is_read BOOLEAN DEFAULT FALSE,
    related_feature_id UUID, -- Links to features needing update

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.regulatory_bulletins IS 'Tracks changes in tax laws and regulations requiring system updates';


-- Table: T068 - audit_schedules
-- Description: Scheduled jobs.
-- Business Case: Automation. Recurring tasks like "Generate Daily VAT Report" or "Archive Old Logs" need to run automatically. This table stores the Cron expressions and configuration for these jobs, allowing a centralized scheduler (like PG_Cron or Quartz) to pick them up.
-- KPIs: Job On-Time Delivery, Failure Rate.
-- Feature Reference: F092
CREATE TABLE IF NOT EXISTS audit.audit_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    job_name VARCHAR(255) NOT NULL UNIQUE,
    job_type VARCHAR(100) NOT NULL, -- 'REPORT_GENERATION', 'ARCHIVE_LOGS'
    cron_expression VARCHAR(100) NOT NULL,
    next_run TIMESTAMPTZ,
    last_run TIMESTAMPTZ,
    last_run_status VARCHAR(20), -- SUCCESS, FAILED
    parameters_json JSONB,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_schedules IS 'Configuration for automated recurring background tasks';


-- Table: T069 - api_versioning
-- Description: Supported API versions.
-- Business Case: Backward Compatibility. External partners (Tax Authorities) integrate with specific API versions. If we change the API, we break them. This table allows us to support multiple versions simultaneously (e.g., v1.0 for old partners, v2.0 for new) and manage deprecation timelines.
-- KPIs: API Stability.
-- Feature Reference: F147
CREATE TABLE IF NOT EXISTS audit.api_versioning (
    version VARCHAR(20) PRIMARY KEY, -- e.g., 'v1.0', 'v2.1'
    deprecation_date DATE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, DEPRECATED, SUNSET
    release_notes_url TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.api_versioning IS 'Manages the lifecycle and support status of different API versions';


-- Table: T070 - audit_locks
-- Description: Advisory locks for resources.
-- Business Case: Concurrency Control. When an auditor is editing a sensitive finding, we don't want another auditor overwriting them. This table implements "Pessimistic Locking". When User A opens a case, a lock is written. User B is blocked from editing until User A finishes.
-- KPIs: Lock Contention Rate, Conflict Prevention.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_locks (
    lock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- 'FINDING', 'CASE'
    resource_id UUID NOT NULL,
    locked_by UUID NOT NULL,
    acquired_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    auto_release_at TIMESTAMPTZ, -- Lock expires if user walks away
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_lock_auditor FOREIGN KEY (locked_by) REFERENCES audit.auditor(auditor_id),
    UNIQUE(resource_type, resource_id, is_active) -- Only one active lock per resource
);
COMMENT ON TABLE audit.audit_locks IS 'Prevents concurrent modification conflicts by locking audit resources';


-- Table: T071 - audit_metadata
-- Description: Table/column descriptions.
-- Business Case: Self-Service Data Discovery. Auditors aren't DBAs. They need to know what "column_x" means. This table acts as a data dictionary, storing business definitions for technical columns, enabling a "Schema Browser" in the UI so users understand the data they are querying.
-- KPIs: Data Literacy.
-- Feature Reference: F010, F041
CREATE TABLE IF NOT EXISTS audit.audit_metadata (
    meta_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100), -- NULL if it's a table-level comment
    description TEXT NOT NULL,
    data_type VARCHAR(50),
    is_pii BOOLEAN DEFAULT FALSE,
    allowed_roles TEXT[], -- Who can see this metadata?

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_metadata IS 'Business glossary and data dictionary for audit schema elements';


-- Table: T072 - ml_model_versions
-- Description: Registry of ML models.
-- Business Case: Model Governance. We use ML for fraud detection. This table tracks which version of the model is currently deployed ("Champion"), which was previous ("Challenger"), and their performance metrics. It ensures we can rollback a model if the new version starts hallucinating fraud.
-- KPIs: Model Drift, Deployment Success.
-- Feature Reference: F132, F012
CREATE TABLE IF NOT EXISTS audit.ml_model_versions (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    is_deployed BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMPTZ,
    model_performance_metrics JSONB, -- e.g. {"precision": 0.95, "recall": 0.89}
    hyperparameters JSONB,
    training_data_source TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ml_model_versions IS 'Tracks the lifecycle, versions, and performance of machine learning models';


-- Table: T073 - anomaly_explanations
-- Description: Text explanations for anomalies.
-- Business Case: Explainable AI (XAI). If the system flags a transaction as "Suspicious", the auditor needs to know "Why?". This table stores the natural language explanation generated by LLMs (Large Language Models) interpreting the model's decision vector (e.g., "Flagged because amount > 3 standard deviations for merchant sector").
-- KPIs: Explanation Quality, User Trust.
-- Feature Reference: F035
CREATE TABLE IF NOT EXISTS audit.anomaly_explanations (
    exp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id UUID NOT NULL, -- Links to suspicious_activities
    text TEXT NOT NULL,
    confidence NUMERIC(3,2),
    generated_by_model VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.anomaly_explanations IS 'Stores human-readable explanations for AI-generated anomaly alerts';


-- Table: T074 - audit_collaborators
-- Description: List of collaborators per audit.
-- Business Case: Teamwork. Complex audits involve cross-functional teams (Tax, Legal, Forensic). This table explicitly lists who is part of the investigation team for a specific case, granting them access and keeping them notified of progress.
-- KPIs: Team Velocity.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS audit.audit_collaborators (
    collab_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id UUID NOT NULL, -- Finding ID or Case ID
    user_id UUID NOT NULL,
    role VARCHAR(50), -- 'LEAD_INVESTIGATOR', 'REVIEWER', 'OBSERVER'
    added_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_collab_user FOREIGN KEY (user_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_collaborators IS 'Manages access rights and membership for collaborative audit cases';


-- Table: T075 - audit_action_history
-- Description: History of actions on findings.
-- Business Case: Immutable Audit Trail (Legal). We need to prove *exactly* what happened to a finding. "Who changed the status from 'Open' to 'Closed' and when?". This table is the system of record for every state transition, comment, or assignment, providing the chain of custody required in court.
-- KPIs: Log Integrity (100%).
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_action_history (
    action_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id UUID NOT NULL,
    action_type audit.enum_action_type NOT NULL,
    actor_id UUID NOT NULL,
    old_value JSONB,
    new_value JSONB,
    description TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_action_finding FOREIGN KEY (finding_id) REFERENCES audit.audit_findings(finding_id),
    CONSTRAINT fk_action_actor FOREIGN KEY (actor_id) REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_action_history IS 'Chronological log of all actions taken on audit findings for legal defensibility';

CREATE INDEX idx_action_history_finding ON audit.audit_action_history(finding_id, timestamp DESC);


-- Table: T076 - data_residency_map
-- Description: Maps data types to regions.
-- Business Case: Sovereignty and Legal Compliance (GDPR/Schrems II). EU data cannot be stored in US servers. This table defines strict rules: "Data Type X (PII) must reside in Region Y (EU-Central)". The storage layer checks this before writing any data.
-- KPIs: Residency Violation Count (0).
-- Feature Reference: F134
CREATE TABLE IF NOT EXISTS audit.data_residency_map (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_type VARCHAR(100) NOT NULL, -- 'AUDITOR_LOG', 'MERCHANT_PII'
    allowed_region_code CHAR(2) NOT NULL, -- 'DE', 'US'
    storage_class VARCHAR(50), -- 'S3-STANDARD-IRA'
    legal_basis TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_residency_map IS 'Defines strict rules for where specific data types are legally allowed to be stored';


-- Table: T077 - audit_event_bus
-- Description: Outbox pattern for integration events.
-- Business Case: Decoupled Integration. The Audit System needs to tell other systems (M05, Tax APIs) when things happen. Rather than calling HTTP APIs directly (which fails if the other system is down), we write an event here. A background "Relay" service reads this and pushes to Kafka. This guarantees reliable messaging.
-- KPIs: Event Delivery Latency, Lost Message Count (0).
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.audit_event_bus (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_type audit.enum_event_type NOT NULL,
    payload JSONB NOT NULL,
    published BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMPTZ,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_event_bus_is 'Transactional outbox table for reliable event publishing to message brokers';

CREATE INDEX idx_event_bus_published ON audit.audit_event_bus(published, created_at);


-- Table: T078 - audit_metrics_snapshot
-- Description: Hourly metrics snapshots.
-- Business Case: Time-Series Performance Reporting. To create graphs like "API Latency over the last 24 hours", we need aggregate data points. This table stores hourly snapshots of key metrics (Active Users, P95 Latency), allowing efficient historical reporting without scanning billions of log rows.
-- KPIs: Reporting Efficiency.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_metrics_snapshot (
    snap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    active_users INTEGER,
    query_latency_p99 INTEGER, -- milliseconds
    error_rate NUMERIC(5,4), -- 0 to 1
    cpu_usage_percentage NUMERIC(5,2),
    memory_usage_percentage NUMERIC(5,2)
);
COMMENT ON TABLE audit.audit_metrics_snapshot IS 'Pre-aggregated hourly system metrics for performance monitoring dashboards';

CREATE UNIQUE INDEX idx_metrics_ts ON audit.audit_metrics_snapshot(timestamp);


-- Table: T079 - compliance_certificates
-- Description: Generated certificates.
-- Business Case: Merchant Trust. Merchants often need to prove to partners or banks that they are "Compliant". This table stores generated PDF certificates (e.g., "ISO 27001 Compliant", "VAT Verified") that the system issues automatically when audits pass.
-- KPIs: Certificate Validity.
-- Feature Reference: F047
CREATE TABLE IF NOT EXISTS audit.compliance_certificates (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL, -- Merchant ID
    standard VARCHAR(100) NOT NULL, -- 'ISO_27001', 'SOC2'
    issue_date DATE NOT NULL DEFAULT CURRENT_DATE,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'VALID', -- VALID, REVOKED, EXPIRED
    cert_file_path TEXT, -- S3 path to PDF
    audit_reference_id UUID, -- Link to the finding/report that certified this

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_certificates IS 'Repository of generated compliance certificates for merchants and entities';

CREATE INDEX idx_certs_entity ON audit.compliance_certificates(entity_id, status);


-- Table: T080 - smart_contracts_events
-- Description: Logged blockchain events.
-- Business Case: Auditability of Core. PARI relies on blockchain (M01). We need to know *what* happened on-chain. This table indexes the logs (events) emitted by smart contracts (e.g., "PaymentReceived", "TaxCollected"). It links the off-chain DB to the on-chain truth.
-- KPIs: Indexing Latency (< 10s).
-- Feature Reference: F051
CREATE TABLE IF NOT EXISTS audit.smart_contracts_events (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(42) NOT NULL,
    event_name VARCHAR(100) NOT NULL,
    args_json JSONB NOT NULL,
    block_number BIGINT NOT NULL,
    transaction_hash CHAR(66) NOT NULL,
    log_index INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL
);
COMMENT ON TABLE audit.smart_contracts_events_is 'Indexed logs from blockchain smart contracts linking ledger events to audit data';

CREATE INDEX idx_sc_events_contract ON audit.smart_contracts_events(contract_address);
CREATE INDEX idx_sc_events_tx ON audit.smart_contracts_events(transaction_hash);


-- Table: T081 - audit_triggers
-- Description: DB triggers configuration.
-- Business Case: Dynamic Data Logic. Sometimes we need to run logic when data changes (e.g., "Update Risk Score when Transaction Volume > Limit"). Hard-coding this in the app is rigid. This table defines trigger rules, allowing a dynamic engine to fire custom logic based on data events.
-- KPIs: Logic Execution Accuracy.
-- Feature Reference: F017
CREATE TABLE IF NOT EXISTS audit.audit_triggers (
    trigger_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    condition_sql TEXT NOT NULL, -- e.g., "NEW.amount > 10000"
    action_procedure VARCHAR(255) NOT NULL, -- Function to call
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_triggers IS 'Configuration for database event triggers enabling dynamic business logic';


-- Table: T082 - batch_import_logs
-- Description: Legacy data import logs.
-- Business Case: Migration Support. When onboarding a new tax authority or migrating from an old system, we import massive CSV dumps. This table tracks the progress, row counts, and error rates of these batch jobs, ensuring data integrity during bulk uploads.
-- KPIs: Import Success Rate, Speed.
-- Feature Reference: F075
CREATE TABLE IF NOT EXISTS audit.batch_import_logs (
    import_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source VARCHAR(255) NOT NULL, -- 's3://legacy-bucket/data.csv'
    row_count BIGINT,
    success_count BIGINT DEFAULT 0,
    failure_count BIGINT DEFAULT 0,
    status VARCHAR(20) NOT NULL, -- RUNNING, SUCCESS, ABORTED
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    error_log TEXT
);
COMMENT ON TABLE audit.batch_import_logs IS 'Tracks the status and metrics of bulk data import operations';


-- Table: T083 - index_usage_stats
-- Description: Statistics on index usage.
-- Business Case: Performance Tuning. Indexes speed up reads but slow down writes. We need to know which indexes are actually being used and which are dead weight. This table stores usage stats, allowing DBAs to drop unused indexes to save storage and improve write performance.
-- KPIs: Index Hit Ratio.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.index_usage_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    index_name VARCHAR(255) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    scan_count BIGINT NOT NULL,
    tuples_read BIGINT NOT NULL,
    last_used TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.index_usage_stats IS 'Stores statistics on index usage to guide performance optimization efforts';


-- Table: T084 - slow_query_log
-- Description: Auto-log of slow queries.
-- Business Case: Database Health. If a query takes > 5 seconds, it hurts the user experience and bogs down the DB. This table automatically logs the query text, plan, and duration. Developers review this to add indexes or rewrite bad SQL.
-- KPIs: Slow Query Count, Optimization Velocity.
-- Feature Reference: F044
CREATE TABLE IF NOT EXISTS audit.slow_query_log (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_text TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    query_plan JSONB, -- EXPLAIN ANALYZE output
    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auditor_id UUID,
    query_hash CHAR(64) -- To group identical slow queries
);
COMMENT ON TABLE audit.slow_query_log IS 'Captures queries exceeding performance thresholds for optimization analysis';

CREATE INDEX idx_slow_query_ts ON audit.slow_query_log(executed_at DESC);


-- Table: T085 - connection_pool_stats
-- Description: DB connection pool metrics.
-- Business Case: Resource Monitoring. The database has a limited number of connections. If they are all "Active" and none are "Idle", new requests will be rejected (Connection Exhaustion). This table tracks pool stats to alert ops teams before the database runs out of connections.
-- KPIs: Pool Utilization (< 80%).
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.connection_pool_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,
    active_connections INTEGER NOT NULL,
    idle_connections INTEGER NOT NULL,
    waiting_count INTEGER DEFAULT 0,
    max_connections INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.connection_pool_stats IS 'Time-series tracking of database connection pool utilization';


-- Table: T086 - audit_backup_manifest
-- Description: Manifest of backup files.
-- Business Case: Disaster Recovery. If the data center explodes, we need to know what backups we have. This table lists every backup taken, its file location (S3), size, and checksum. It is the "Map" for the restore process.
-- KPIs: Backup Success Rate, RPO (Recovery Point Objective).
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.audit_backup_manifest (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    checksum CHAR(64) NOT NULL, -- SHA-256
    size_bytes BIGINT NOT NULL,
    backup_type VARCHAR(50) NOT NULL, -- FULL, INCREMENTAL
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expiration_date DATE,
    status VARCHAR(20) DEFAULT 'AVAILABLE' -- AVAILABLE, DELETED
);
COMMENT ON TABLE audit.audit_backup_manifest IS 'Inventory of database backups required for disaster recovery operations';


-- Table: T087 - failover_history
-- Description: Log of failover events.
-- Business Case: Reliability Analysis. Sometimes the primary database fails, and traffic switches to a standby (Failover). This table logs *when* and *why* this happened. It helps the team determine if the failover was smooth or if data was lost.
-- KPIs: RTO (Recovery Time Objective), Failover Success Rate.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS audit.failover_history (
    failover_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    from_region VARCHAR(100) NOT NULL,
    to_region VARCHAR(100) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    trigger_reason TEXT, -- 'Latency High', 'Primary Crash'
    initiated_by VARCHAR(100), -- 'Auto', 'Manual'
    data_loss_seconds INTEGER DEFAULT 0
);
COMMENT ON TABLE audit.failover_history IS 'Records system failover events for business continuity analysis';


-- Table: T088 - encryption_key_rotation_log
-- Description: Log of key rotations.
-- Business Case: Security Audit. Changing encryption keys is standard security practice (e.g., annually). This table proves that we actually did it. It shows the old key ID, new key ID, and who authorized the rotation.
-- KPIs: Rotation Adherence.
-- Feature Reference: F045
CREATE TABLE IF NOT EXISTS audit.encryption_key_rotation_log (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL, -- The key being rotated OUT
    new_key_id UUID NOT NULL, -- The key being rotated IN
    performed_by UUID NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    reason TEXT
);
COMMENT ON TABLE audit.encryption_key_rotation_log IS 'Immutable log of cryptographic key rotation events for security auditing';


-- Table: T089 - audit_config_history
-- Description: History of config changes.
-- Business Case: Change Management. If a bug appears on Tuesday, we check what changed on Monday. This table tracks every change to system configuration (tax rates, feature flags, email settings), providing a full audit trail of *who* changed *what*.
-- KPIs: Change Traceability.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.audit_config_history (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_key VARCHAR(255) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    changed_by UUID NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    change_type VARCHAR(50) -- UPDATE, DELETE
);
COMMENT ON TABLE audit.audit_config_history IS 'Tracks all changes to system configuration settings for accountability';


-- Table: T090 - dynamic_rules
-- Description: User-defined business rules.
-- Business Case: Agility. Hard-coding business logic (e.g., "Alert if VAT Gap > 5%") is slow. This table allows admins to write rules in JSON/DSL (Domain Specific Language). A rule engine evaluates incoming data against these rules, allowing instant updates to risk thresholds without code deployment.
-- KPIs: Rule Deployment Speed.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.dynamic_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    condition_json NOT NULL, -- e.g. {"field": "vat_gap", "op": "gt", "value": 0.05}
    action_json NOT NULL, -- e.g. {"type": "ALERT", "severity": "HIGH"}
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.dynamic_rules IS 'Stores user-defined logic rules for real-time event evaluation';


-- Table: T091 - rule_evaluation_log
-- Description: Log of rule evaluations.
-- Business Case: Debugging. Why was an alert fired? This table logs the execution of the Dynamic Rules engine. It shows which rules were triggered, what the input data was, and what the result was. It's essential for debugging false positives in complex rule sets.
-- KPIs: Rule Engine Latency.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.rule_evaluation_log (
    eval_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL,
    input_hash CHAR(64), -- Hash of the event data
    result BOOLEAN NOT NULL, -- True if rule matched
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    output_message TEXT
);
COMMENT ON TABLE audit.rule_evaluation_log IS 'Logs the execution results of dynamic business rules for debugging and auditing';

CREATE INDEX idx_rule_eval_ts ON audit.rule_evaluation_log(timestamp DESC);


-- Table: T092 - ml_feature_store
-- Description: Stores feature vectors for ML models.
-- Business Case: ML Infrastructure. ML models need input features (e.g., "Merchant Age", "Transaction Volatility"). Calculating these on the fly is slow. This table pre-calculates and stores these feature vectors (Time-Series). It acts as the "Brain Food" for the fraud detection models.
-- KPIs: Feature Freshness.
-- Feature Reference: F012, F074
CREATE TABLE IF NOT EXISTS audit.ml_feature_store (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL, -- Merchant ID
    feature_name VARCHAR(100) NOT NULL,
    value_ts TIMESTAMPTZ NOT NULL, -- Time period for this feature
    value_float NUMERIC(19,4),
    value_str VARCHAR(255),
    feature_group VARCHAR(50) -- 'RISK', 'VOLUME', 'NETWORK'
);
COMMENT ON TABLE audit.ml_feature_store IS 'Time-series storage of calculated features used as input for machine learning models';

CREATE INDEX idx_feature_store_entity ON audit.ml_feature_store(entity_id, feature_name, value_ts DESC);


-- Table: T093 - ml_training_jobs
-- Description: Metadata for ML model training runs.
-- Business Case: Model Improvement. To fight new fraud techniques, we must retrain models. This table tracks every training run: which data was used, what hyperparameters, and the resulting accuracy. It helps us select the best model to promote to production.
-- KPIs: Model Accuracy, Training Duration.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.ml_training_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    algorithm VARCHAR(100), -- 'XGBoost', 'RandomForest'
    start_ts TIMESTAMPTZ NOT NULL,
    end_ts TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL, -- RUNNING, COMPLETED, FAILED
    accuracy_score NUMERIC(3,2),
    hyperparameters JSONB,
    training_data_source TEXT,
    artifact_path TEXT -- S3 path to the trained model file
);
COMMENT ON TABLE audit.ml_training_jobs IS 'Tracks the execution and results of machine learning model training pipelines';


-- Table: T094 - privacy_parameters
-- Description: Global configuration for Differential Privacy (Epsilon, Delta).
-- Business Case: Privacy Governance. Differential Privacy adds noise based on a "Privacy Budget" (Epsilon). This table stores the global settings (e.g., Max Epsilon per query = 0.5). It ensures the mathematical guarantees of privacy are consistently applied across the platform.
-- KPIs: Epsilon Leakage.
-- Feature Reference: F004, F043
CREATE TABLE IF NOT EXISTS audit.privacy_parameters (
    param_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_context VARCHAR(100) NOT NULL, -- 'MERCHANT_REPORT', 'AGGREGATE_STATS'
    epsilon_value NUMERIC(5,4) NOT NULL,
    delta_value NUMERIC(10,8),
    k_anonymity_k INTEGER,
    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.privacy_parameters IS 'Central configuration for differential privacy parameters governing data anonymization';


-- Table: T095 - national_tax_connectors
-- Description: Configuration for connecting to national tax APIs.
-- Business Case: Interoperability. PARI must talk to Spain (SII), Italy (SDI), etc. Each has different APIs, auth methods, and XML formats. This table stores the connection details (endpoints, certificates, API Keys) so the integration engine can route reports to the correct authority.
-- KPIs: Submission Success Rate.
-- Feature Reference: F010, F024
CREATE TABLE IF NOT EXISTS audit.national_tax_connectors (
    connector_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2) NOT NULL UNIQUE,
    endpoint_url TEXT NOT NULL,
    auth_method VARCHAR(50) NOT NULL, -- 'OAUTH2', 'CERTIFICATE', 'API_KEY'
    auth_details JSONB NOT NULL, -- Secrets/Config (encrypted)
    certificate_id UUID REFERENCES audit.certificate_store(cert_id),
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.national_tax_connectors IS 'Configuration for connecting to external national tax authority APIs';


-- Table: T096 - iso20022_message_store
-- Description: Raw storage of parsed ISO 20022 messages.
-- Business Case: Standardization & Audit. ISO 20022 is the global standard for financial messaging. This table stores the raw XML of messages (CAMT.053, PAIN.001) exchanged with banks/tax authorities. It provides a legally valid, standard-format audit trail of financial communications.
-- KPIs: Message Validation Rate.
-- Feature Reference: F010
CREATE TABLE IF NOT EXISTS audit.iso20022_message_store (
    msg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    msg_type VARCHAR(20) NOT NULL, -- e.g., 'camt.053'
    ref_uid VARCHAR(100), -- Unique ID from the message
    payload_xml TEXT NOT NULL, -- The full ISO message
    direction VARCHAR(20) NOT NULL, -- INBOUND, OUTBOUND
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) -- PARSED, ERROR, VALIDATED
);
COMMENT ON TABLE audit.iso20022_message_store IS 'Archive of ISO 20022 standard financial messages for regulatory compliance';

CREATE INDEX idx_iso20022_ref ON audit.iso20022_message_store(ref_uid);


-- Table: T097 - audit_checklist_items
-- Description: Standard Operating Procedure (SOP) checklist items.
-- Business Case: Process Compliance (CMMI Level 5). Audits must follow strict procedures. This table defines the checklist items (e.g., "1. Verify Identity", "2. Cross-check Ledger"). The system enforces that these are marked "Complete" before a case can be closed.
-- KPIs: SOP Adherence Rate.
-- Feature Reference: F039
CREATE TABLE IF NOT EXISTS audit.audit_checklist_items (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id UUID NOT NULL, -- References the "Template" or "Workflow"
    item_text TEXT NOT NULL,
    order_index INTEGER NOT NULL,
    is_required BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_checklist_items_is 'Defines the mandatory steps in Standard Operating Procedures for audits';


-- Table: T098 - certificate_store
-- Description: Stores public certificates for mTLS validation.
-- Business Case: Mutual TLS (mTLS) Security. For high-security connections (e.g., between M06 and Core M05), we use mTLS. This table stores the public certificates of trusted clients. The DB validates incoming connections against this store to ensure only authorized services can connect.
-- KPIs: Validation Success Rate.
-- Feature Reference: F017, F098
CREATE TABLE IF NOT EXISTS audit.certificate_store (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subject_dn TEXT NOT NULL, -- Distinguished Name
    issuer_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    pem_body TEXT NOT NULL, -- The public certificate
    fingerprint CHAR(64), -- SHA-256 of the cert
    status VARCHAR(20) DEFAULT 'VALID' -- VALID, REVOKED, EXPIRED
);
COMMENT ON TABLE audit.certificate_store IS 'Trust store of public certificates for mutual TLS authentication';


-- Table: T099 - revoked_tokens
-- Description: Blacklisted JWT/Session tokens.
-- Feature Reference: F027
-- (Note: This is functionally the same as T060 session_tokens. Implementing as T099 per prompt list, potentially with a specific focus on API revocation vs Session).
CREATE TABLE IF NOT EXISTS audit.revoked_tokens (
    token_hash CHAR(64) PRIMARY KEY, -- Hash of the full token string
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(100),
    expires_at TIMESTAMPTZ NOT NULL
);
COMMENT ON TABLE audit.revoked_tokens IS 'Token Revocation List (TRL) for immediate invalidation of access tokens';

CREATE INDEX idx_revoked_tokens_expiry ON audit.revoked_tokens(expires_at);


-- Table: T100 - report_schedules
-- Description: Automated scheduling of recurring report generation.
-- Business Case: Recurring Compliance. Many reports are needed on a strict schedule (e.g., "Daily VAT Summary at 8 AM"). This table automates this. It links a schedule to a specific report type and recipient list, ensuring compliance officers get their data without manual intervention.
-- KPIs: On-Time Delivery Rate.
-- Feature Reference: F092
CREATE TABLE IF NOT EXISTS audit.report_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_type VARCHAR(100) NOT NULL, -- 'DAILY_VAT_SUMMARY'
    cron_expression VARCHAR(100) NOT NULL,
    recipient_list TEXT[] NOT NULL, -- List of auditor IDs or email addresses
    last_run_ts TIMESTAMPTZ,
    next_run_ts TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    parameters_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.report_schedules IS 'Automates the generation and delivery of recurring audit reports';


-- 5. Views (V011 - V016)
-- ================================================================================

CREATE OR REPLACE VIEW audit.vw_merchant_performance AS
SELECT
    m.merchant_id,
    m.name,
    r.score as reliability_score
FROM audit.merchant_cache m
-- Join logic assumed with T118 (audit_calculated_metrics if it were here) or similar
-- Placeholder logic for reliability calculation
LEFT JOIN (
    SELECT merchant_id, AVG(risk_score) as score
    FROM audit.merchant_risk_profiles
    GROUP BY merchant_id
) r ON m.merchant_id = r.merchant_id;
COMMENT ON VIEW audit.vw_merchant_performance IS 'Merchant reliability scorecard for F084';

CREATE OR REPLACE VIEW audit.vw_system_health AS
SELECT
    d.service_name,
    d.status,
    c.active_connections,
    c.max_connections
FROM audit.dependency_health d
LEFT JOIN (
    SELECT pool_name, active_connections, max_connections,
           ROW_NUMBER() OVER (PARTITION BY pool_name ORDER BY timestamp DESC) as rn
    FROM audit.connection_pool_stats
) c ON d.service_name = c.pool_name AND c.rn = 1;
COMMENT ON VIEW audit.vw_system_health IS 'Overall system health for monitoring F097';

CREATE OR REPLACE VIEW audit.vw_regulatory_updates AS
SELECT * FROM audit.regulatory_bulletins
WHERE effective_date > CURRENT_DATE;
COMMENT ON VIEW audit.vw_regulatory_updates IS 'Latest regulatory changes F096';

CREATE OR REPLACE VIEW audit.vw_pending_uploads AS
SELECT * FROM audit.audit_file_uploads
WHERE status IN ('UPLOADED', 'PARSING');
COMMENT ON VIEW audit.vw_pending_uploads IS 'Files waiting for processing F058';

CREATE OR REPLACE VIEW audit.vw_data_residency_compliance AS
SELECT
    r.data_type,
    r.allowed_region_code,
    COUNT(s.*) as violations -- Ideally 0
FROM audit.data_residency_map r
LEFT JOIN audit.storage_locations s ON r.data_type = s.data_type AND s.region_code != r.allowed_region_code
GROUP BY r.data_type, r.allowed_region_code;
COMMENT ON VIEW audit.vw_data_residency_compliance IS 'Checks if data is in correct region F134';

CREATE OR REPLACE VIEW audit.vw_compliance_status AS
SELECT * FROM audit.compliance_certificates
WHERE status = 'VALID' AND expiry_date > CURRENT_DATE;
COMMENT ON VIEW audit.vw_compliance_status IS 'Current compliance status F150';


-- 6. Stored Procedures (P021 - P046)
-- ================================================================================

CREATE OR REPLACE PROCEDURE audit.sp_rotate_encryption_key()
LANGUAGE plpgsql
AS $$ DECLARE
    v_old_key_id UUID;
    v_new_key_id UUID;
BEGIN
    -- Select active key
    SELECT key_id INTO v_old_key_id FROM audit.encryption_keys WHERE status = 'ACTIVE' LIMIT 1;

    -- Create new key (Simulation)
    INSERT INTO audit.encryption_keys (key_alias, key_version, status, created_at, updated_at)
    VALUES ('master_key', (SELECT COALESCE(MAX(key_version), 0) + 1 FROM audit.encryption_keys), 'ACTIVE', NOW(), NOW())
    RETURNING key_id INTO v_new_key_id;

    -- Deprecate old key
    UPDATE audit.encryption_keys SET status = 'DEPRECATED', updated_at = NOW() WHERE key_id = v_old_key_id;

    -- Log rotation
    INSERT INTO audit.encryption_key_rotation_log (key_id, new_key_id, performed_by, timestamp, reason)
    VALUES (v_old_key_id, v_new_key_id, uuid_generate_v4(), NOW(), 'Scheduled Rotation');
END;
 $$;
COMMENT ON PROCEDURE audit.sp_rotate_encryption_key IS 'Rotates the active data encryption key F045';

CREATE OR REPLACE PROCEDURE audit.sp_cleanup_rate_limits()
LANGUAGE plpgsql
AS $$ BEGIN
    DELETE FROM audit.rate_limit_counters WHERE window_expiry < NOW();
END;
 $$;
COMMENT ON PROCEDURE audit.sp_cleanup_rate_limits IS 'Removes expired rate limit entries F025';

CREATE OR REPLACE PROCEDURE audit.sp_send_notifications()
LANGUAGE plpgsql
AS $$ DECLARE
    v_notif RECORD;
BEGIN
    FOR v_notif IN SELECT notif_id FROM audit.audit_notifications WHERE status = 'QUEUED' LIMIT 100
    LOOP
        -- Logic to send Email/SMS would go here
        UPDATE audit.audit_notifications
        SET status = 'SENT', sent_at = NOW(), updated_at = NOW()
        WHERE notif_id = v_notif.notif_id;
    END LOOP;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_send_notifications IS 'Sends queued notifications F038';

CREATE OR REPLACE PROCEDURE audit.sp_ban_auditor(p_auditor_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    UPDATE audit.auditor SET is_active = FALSE, updated_at = NOW() WHERE auditor_id = p_auditor_id;
    -- Revoke active sessions
    UPDATE audit.auditor_sessions SET status = 'TERMINATED', termination_reason = 'BANNED', updated_at = NOW()
    WHERE auditor_id = p_auditor_id AND status = 'ACTIVE';
END;
 $$;
COMMENT ON PROCEDURE audit.sp_ban_auditor IS 'Bans an auditor account F009';

CREATE OR REPLACE PROCEDURE audit.sp_analyze_query_performance(p_threshold_ms INTEGER)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.query_execution_stats (query_id, execution_time_ms, rows_scanned, buffer_pool_hit)
    SELECT
        q.query_id,
        EXTRACT(EPOCH FROM (q.updated_at - q.created_at))*1000 as duration,
        100, -- placeholder
        0.95 -- placeholder
    FROM audit.audit_query_history q
    WHERE EXTRACT(EPOCH FROM (q.updated_at - q.created_at))*1000 > p_threshold_ms;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_analyze_query_performance IS 'Analyzes slow queries F044';

CREATE OR REPLACE PROCEDURE audit.sp_process_file_upload(p_file_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Update status to PARSING
    UPDATE audit.audit_file_uploads SET status = 'PARSING' WHERE file_id = p_file_id;

    -- Mock OCR Process
    UPDATE audit.audit_file_uploads
    SET ocr_text = 'Extracted text...', status = 'READY', updated_at = NOW()
    WHERE file_id = p_file_id;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_process_file_upload IS 'OCR/Ingest uploaded files F058';

CREATE OR REPLACE PROCEDURE audit.sp_generate_synthetic_data(p_count INTEGER, p_distribution JSONB)
LANGUAGE plpgsql
AS $$ DECLARE
    i INTEGER;
BEGIN
    FOR i IN 1..p_count LOOP
        INSERT INTO audit.synthetic_transactions (amount, merchant_id, timestamp, category, generation_parameters)
        VALUES (random() * 1000, uuid_generate_v4(), NOW() - (random() * interval '1 year'), 'MISC', p_distribution);
    END LOOP;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_generate_synthetic_data IS 'Generates training data F064';

CREATE OR REPLACE PROCEDURE audit.sp_purge_old_locks()
LANGUAGE plpgsql
AS $$ BEGIN
    DELETE FROM audit.audit_locks WHERE auto_release_at < NOW();
END;
 $$;
COMMENT ON PROCEDURE audit.sp_purge_old_locks IS 'Removes stale locks F103';

CREATE OR REPLACE PROCEDURE audit.sp_tag_finding(p_finding_id UUID, p_tag_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.finding_tags_mapping (finding_id, tag_id, tagged_by)
    VALUES (p_finding_id, p_tag_id, uuid_generate_v4());
END;
 $$;
COMMENT ON PROCEDURE audit.sp_tag_finding IS 'Adds a tag to a finding F107';

CREATE OR REPLACE PROCEDURE audit.sp_explain_anomaly(p_anomaly_id UUID)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.anomaly_explanations (anomaly_id, text, generated_by_model)
    VALUES (p_anomaly_id, 'The transaction amount is significantly higher than the merchant average.', 'LLM-v1');
END;
 $$;
COMMENT ON PROCEDURE audit.sp_explain_anomaly IS 'Calls LLM to explain anomaly F035';

CREATE OR REPLACE PROCEDURE audit.sp_deprecate_api_version(p_version VARCHAR)
LANGUAGE plpgsql
AS $$ BEGIN
    UPDATE audit.api_versioning SET status = 'DEPRECATED', deprecation_date = CURRENT_DATE + INTERVAL '6 months' WHERE version = p_version;
END;
 $$;
COMMENT ON PROCEDURE audit.sp_deprecate_api_version IS 'Marks API version as deprecated F147';

CREATE OR REPLACE PROCEDURE audit.sp_register_ml_model(p_name VARCHAR, p_version VARCHAR)
LANGUAGE plpgsql
AS $$ BEGIN
    INSERT INTO audit.ml_model_versions (model_name, version, is_deployed)
    VALUES (p_name, p_version, FALSE);
END;
 $$;
COMMENT ON PROCEDURE audit.sp_register_ml_model IS 'Registers a new model version F132';

CREATE OR REPLACE PROCEDURE audit.sp_refresh_materialized_views()
LANGUAGE plpgsql
AS $$ BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY audit.mv_publication_impact; -- Assuming existence or placeholder
    NULL;
END;
 $$;


 -- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 3: Objects 101-150)
-- ================================================================================
-- Description: This script continues the database object creation for the Independent
-- Auditor Interface. It covers advanced analytics, security auditing, system
-- configuration, QA/Testing, and operational runbooks.
--
-- Scope: Database Objects T101 - T150.
-- ================================================================================

-- 4. DDL Statements (Tables T101 - T150)
-- ================================================================================

-- Table: T101 - query_execution_stats
-- Description: Detailed stats for query performance analysis.
-- Business Case: Deep Dive Performance Tuning. While high-level logs exist, this table captures deep statistics like buffer pool hits, disk reads, and specific operator costs. It allows Database Engineers to optimize the database at the micro-level, ensuring that the "Audit Data Freshness" KPI is met even during peak loads by identifying I/O bottlenecks.
-- KPIs: Buffer Pool Hit Ratio (>95%), Disk Read Count.
-- Feature Reference: F044, F084
CREATE TABLE IF NOT EXISTS audit.query_execution_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_id UUID NOT NULL, -- Links to T003
    execution_time_ms INTEGER NOT NULL,
    rows_scanned BIGINT NOT NULL,
    rows_returned BIGINT NOT NULL,
    buffer_pool_hit NUMERIC(3,2), -- Percentage
    disk_read_bytes BIGINT,
    plan_hash CHAR(64), -- Hash of the execution plan to identify plan regressions
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.query_execution_stats IS 'Granular performance metrics for database query optimization';

CREATE INDEX idx_query_stats_query ON audit.query_execution_stats(query_id, timestamp DESC);


-- Table: T102 - audit_task_queue
-- Description: Background job queue for async tasks.
-- Business Case: Asynchronous Task Management. Heavy operations like "Generate CSV for 10M rows" cannot be done in an HTTP request. This table serves as a queue for background workers. It supports prioritization (High/Low) and scheduling (Run at 2 AM). It ensures the web interface remains snappy while heavy lifting happens in the background.
-- KPIs: Task Latency, Queue Depth.
-- Feature Reference: F038, F004
CREATE TABLE IF NOT EXISTS audit.audit_task_queue (
    task_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    task_type VARCHAR(100) NOT NULL, -- EXPORT, EMAIL_SEND, REPORT_GEN
    payload_json JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED
    queued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10), -- 1 is highest
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    worker_node_id VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_task_queue IS 'Priority queue for asynchronous background processing tasks';

CREATE INDEX idx_task_queue_status ON audit.audit_task_queue(status, priority ASC, queued_at ASC);


-- Table: T103 - data_export_manifests
-- Description: List of files included in a specific export batch.
-- Business Case: Large Export Management. When an auditor requests "All 2023 Data", the result might be split across multiple files (part1.csv, part2.csv). This manifest lists every file in the batch, its checksum, and size. It allows the auditor or the system to verify that the download was complete and untampered.
-- KPIs: Export Integrity, Batch Success Rate.
-- Feature Reference: F037, F029
CREATE TABLE IF NOT EXISTS audit.data_export_manifests (
    manifest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    export_id UUID NOT NULL REFERENCES audit.report_exports(export_id),
    filename VARCHAR(255) NOT NULL,
    file_sequence INTEGER NOT NULL, -- 1, 2, 3...
    file_hash_sha256 CHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    storage_path TEXT NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_export_manifests IS 'Component listing for large multi-file data exports';

CREATE INDEX idx_manifest_export ON audit.data_export_manifests(export_id);


-- Table: T104 - audit_user_preferences
-- Description: UI preferences for auditors (Theme, Language, Timezone).
-- Business Case: Personalization. Auditors work globally. A user in Tokyo needs the dashboard in Japanese and JST, while a user in London needs English and GMT. This table stores these preferences to provide a localized, comfortable user experience, reducing cognitive load and errors.
-- KPIs: User Engagement, Localization Accuracy.
-- Feature Reference: F133
CREATE TABLE IF NOT EXISTS audit.audit_user_preferences (
    pref_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL UNIQUE,
    theme VARCHAR(20) DEFAULT 'LIGHT' CHECK (theme IN ('LIGHT', 'DARK', 'SYSTEM')),
    language_code CHAR(2) DEFAULT 'EN',
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    date_format VARCHAR(20) DEFAULT 'YYYY-MM-DD',
    time_format VARCHAR(10) DEFAULT '24H',
    density VARCHAR(20) DEFAULT 'COMFORTABLE', -- UI density
    notification_sound BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_user_preferences IS 'Stores user interface customization and localization settings';


-- Table: T105 - jurisdictional_tax_rates
-- Description: Historical and current tax rates per jurisdiction.
-- Business Case: Accurate Audit Calculations. Tax rates change (e.g., VAT standard rate drops from 20% to 19%). If an audit covers a period spanning this change, we need the historical rate for each transaction. This table stores time-series data for tax rates, ensuring the "Tax Liability" feature calculates the correct amount based on the transaction date.
-- KPIs: Calculation Accuracy (100%), Rate Freshness.
-- Feature Reference: F033, F100
CREATE TABLE IF NOT EXISTS audit.jurisdictional_tax_rates (
    rate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    jurisdiction_code CHAR(2) NOT NULL,
    tax_type VARCHAR(50) NOT NULL, -- 'VAT_STANDARD', 'VAT_REDUCED', 'CORPORATE'
    rate_percentage NUMERIC(5,4) NOT NULL,
    effective_start DATE NOT NULL,
    effective_end DATE, -- NULL if current
    legal_reference TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT chk_rate_dates CHECK (effective_end IS NULL OR effective_end > effective_start),
    CONSTRAINT chk_rate_positive CHECK (rate_percentage >= 0)
);
COMMENT ON TABLE audit.jurisdictional_tax_rates IS 'Time-series storage of tax rates for accurate historical calculations';

CREATE INDEX idx_tax_rate_jurisdiction_dates ON audit.jurisdictional_tax_rates(jurisdiction_code, tax_type, effective_start DESC);


-- Table: T106 - merkle_tree_nodes
-- Description: Nodes of the Merkle tree for transaction integrity.
-- Business Case: Cryptographic Proof. To prove data integrity without downloading everything, we use Merkle Trees. This table stores the nodes (Root, Branch, Leaf). If a single record is altered, the root hash changes. Auditors can verify the "Root Hash" published by the government against this tree to ensure the ledger hasn't been tampered with.
-- KPIs: Verification Speed (<500ms), Tree Integrity.
-- Feature Reference: F068
CREATE TABLE IF NOT EXISTS audit.merkle_tree_nodes (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tree_id UUID NOT NULL, -- Identifier for the specific tree (e.g., daily tree)
    node_hash CHAR(64) NOT NULL UNIQUE,
    parent_hash CHAR(64), -- NULL for root
    depth INTEGER NOT NULL CHECK (depth >= 0),
    is_leaf BOOLEAN DEFAULT FALSE,
    leaf_data_reference UUID, -- The transaction ID if this is a leaf

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.merkle_tree_nodes IS 'Storage structure for Merkle Trees enabling efficient data integrity verification';

CREATE INDEX idx_merkle_tree_id ON audit.merkle_tree_nodes(tree_id, depth);
CREATE INDEX idx_merkle_parent ON audit.merkle_tree_nodes(parent_hash);


-- Table: T107 - audit_session_ip_history
-- Description: History of IP addresses used by auditor sessions.
-- Business Case: Anomaly Detection. If an auditor usually logs in from Berlin and suddenly logs in from Moscow, that's a security risk. This table tracks the IP history. A "Travel Distance Algorithm" can query this to flag impossible travel events, preventing account takeover.
-- KPIs: Intrusion Detection Rate.
-- Feature Reference: F027, F088
CREATE TABLE IF NOT EXISTS audit.audit_session_ip_history (
    hist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    auditor_id UUID NOT NULL,
    ip_address INET NOT NULL,
    geo_location_country CHAR(2),
    geo_location_city VARCHAR(100),
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    isp VARCHAR(100),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_session_ip_history IS 'Geographic and network history of auditor sessions for security profiling';

CREATE INDEX idx_session_ip_auditor ON audit.audit_session_ip_history(auditor_id, timestamp DESC);


-- Table: T108 - compliance_gap_analysis
-- Description: Results of regulatory change impact analysis.
-- Business Case: Change Management. When a new regulation (e.g., "Digital Services Tax") is passed, we need to know what breaks. This table stores the analysis: which tables, which columns, and what logic needs to change. It acts as the roadmap for developers to implement compliance updates.
-- KPIs: Gap Identification Time, Implementation Velocity.
-- Feature Reference: F126
CREATE TABLE IF NOT EXISTS audit.compliance_gap_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id VARCHAR(100) NOT NULL, -- Reference to external law ID
    affected_tables TEXT[] NOT NULL,
    gap_description TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    remediation_plan TEXT,
    status VARCHAR(20) DEFAULT 'IDENTIFIED', -- IDENTIFIED, IN_PROGRESS, RESOLVED
    analysis_date DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_gap_analysis IS 'Assesses impact of regulatory changes on existing database schema and logic';


-- Table: T109 - audit_notification_templates
-- Description: Customizable templates for alert emails/SMS.
-- Business Case: Communication Flexibility. Marketing and Compliance teams need to update notification copy (e.g., "New VAT Rate Alert") without deploying code. This table stores the templates (Subject, Body, HTML) with placeholders (e.g., `{{merchant_name}}`), allowing dynamic content management.
-- KPIs: Template Update Latency.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_notification_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_name VARCHAR(255) NOT NULL,
    channel VARCHAR(20) NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'PUSH', 'WEBHOOK')),
    subject_line TEXT, -- For Email
    body_html TEXT,
    body_text TEXT, -- Fallback for SMS or non-HTML
    variables_json JSONB, -- e.g. [{"name": "merchant", "type": "string"}]
    language_code CHAR(2) DEFAULT 'EN',
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_notification_templates IS 'Stores dynamic content templates for system notifications';


-- Table: T110 - audit_session_activity
-- Description: High-frequency activity log (clicks, page views).
-- Business Case: User Experience (UX) Optimization. To improve the dashboard, we need to know which features are used and which are ignored. This high-volume table tracks every click and page view. Product Managers analyze this to redesign workflows (e.g., "Move this button here, it's clicked 1000 times a day").
-- KPIs: Feature Adoption Rate, User Flow Efficiency.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_session_activity (
    activity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID REFERENCES audit.auditor_sessions(session_id),
    auditor_id UUID NOT NULL,
    page_url TEXT NOT NULL,
    element_id VARCHAR(100), -- e.g., "btn_submit_tax_report"
    event_type VARCHAR(50) NOT NULL, -- CLICK, PAGE_VIEW, HOVER, FORM_SUBMIT
    referrer_url TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_session_activity IS 'Clickstream data for analytics and user experience improvement';

CREATE INDEX idx_session_activity_ts ON audit.audit_session_activity(timestamp DESC);
-- Note: In production, this would likely be partitioned by month.


-- Table: T111 - audit_suppliers
-- Description: List of external suppliers/contractors for auditing.
-- Business Case: Supply Chain Auditing. Merchants buy from suppliers. Sometimes suppliers are the ones evading tax. This table extends the audit scope to the Merchant's suppliers, allowing the system to flag a "Merchant" if they deal heavily with a "Blacklisted Supplier".
-- KPIs: Supply Chain Coverage.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.audit_suppliers (
    supplier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tin VARCHAR(100) NOT NULL, -- Tax Identification Number
    legal_name VARCHAR(255) NOT NULL,
    country_code CHAR(2) NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, BLACKLISTED
    risk_level audit.enum_risk_level,
    registration_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_suppliers IS 'Registry of external suppliers for supply chain risk analysis';


-- Table: T112 - supplier_verification
-- Description: KYB/KYC verification data for suppliers.
-- Business Case: Identity Assurance. We cannot blindly trust self-reported supplier data. This table stores the results of third-party checks (e.g., Dun & Bradstreet, government registries). It confirms that "Supplier A" actually exists and is not a shell company created just for fraud.
-- KPIs: Verification Success Rate.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.supplier_verification (
    verify_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    supplier_id UUID NOT NULL REFERENCES audit.audit_suppliers(supplier_id),
    verification_source VARCHAR(100) NOT NULL, -- e.g., 'DUNS', 'COMPANIES_HOUSE'
    verification_status VARCHAR(20) NOT NULL, -- VERIFIED, FAILED, PENDING
    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    confidence_score NUMERIC(3,2),
    external_ref_id VARCHAR(100), -- ID from external source
    details_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.supplier_verification_is 'Stores results of third-party identity checks on suppliers';


-- Table: T113 - api_contract_tests
-- Description: Stores results of automated API contract testing.
-- Business Case: CI/CD Quality Assurance. Before deploying code, we must ensure we haven't broken the API contract (e.g., changed a field name from 'amount' to 'total'). This table stores the results of automated tests (e.g., using Postman/Newman) run in the pipeline. A failure here blocks deployment.
-- KPIs: Test Pass Rate (>99%).
-- Feature Reference: F113
CREATE TABLE IF NOT EXISTS audit.api_contract_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint VARCHAR(255) NOT NULL,
    expected_status INTEGER NOT NULL,
    actual_status INTEGER NOT NULL,
    passed BOOLEAN NOT NULL,
    run_ts TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time_ms INTEGER,
    diff_json JSONB, -- Differences in response body
    build_id VARCHAR(100), -- Reference to CI/CD build

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.api_contract_tests IS 'Automated regression test results ensuring API stability during development';

CREATE INDEX idx_contract_tests_run ON audit.api_contract_tests(run_ts DESC);


-- Table: T114 - audit_data_masking_rules
-- Description: Specific rules for masking columns based on sensitivity.
-- Business Case: Dynamic Privacy Enforcement. Different users have different clearance. A "Tier 1" auditor might see the full name, but a "Tier 2" intern sees "J*** D***". This table defines the masking rules (Regex, Partial Hash) applied dynamically at the application layer or via database views.
-- KPIs: Masking Accuracy, Performance Overhead.
-- Feature Reference: F063, F054
CREATE TABLE IF NOT EXISTS audit.audit_data_masking_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    mask_function VARCHAR(50) NOT NULL, -- 'PARTIAL_MASK', 'HASH_SHA256', 'NULLIFY'
    mask_params JSONB, -- e.g. {"show_first": 1, "show_last": 1}
    allowed_roles TEXT[], -- Roles exempt from masking
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_data_masking_rules IS 'Defines dynamic data masking policies for PII columns based on user roles';


-- Table: T115 - audit_feedback_surveys
-- Description: User feedback on the audit platform functionality.
-- Business Case: Product Development. We need to know if auditors like the new features. This table stores survey responses (NPS scores, comments). It drives the product roadmap and helps identify pain points in the audit workflow.
-- KPIs: Net Promoter Score (NPS), Response Rate.
-- Feature Reference: F079
CREATE TABLE IF NOT EXISTS audit.audit_feedback_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    survey_type VARCHAR(50) NOT NULL, -- 'QUARTERLY_NPS', 'FEATURE_RELEASE'
    rating INTEGER CHECK (rating BETWEEN 1 AND 10),
    comments TEXT,
    sentiment_score NUMERIC(3,2), -- Derived from NLP on comments
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_feedback_surveys IS 'Collects user sentiment and feedback to guide platform improvements';


-- Table: T116 - audit_lock_resources
-- Description: Resources currently locked by an auditor.
-- Business Case: Distributed Concurrency Control. When User A is editing a specific Finding or Case, the system acquires a lock. This table holds that lock state. It prevents User B from overwriting User A's changes, supporting the "Real-Time Collaboration" feature by handling write-conflicts gracefully.
-- KPIs: Lock Wait Time, Conflict Rate.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_lock_resources (
    lock_resource_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- 'FINDING', 'CASE', 'TEMPLATE'
    resource_id UUID NOT NULL,
    locked_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    locked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until TIMESTAMPTZ NOT NULL, -- Auto-expiry to prevent deadlocks
    lock_token VARCHAR(255) NOT NULL UNIQUE, -- Used to unlock

    CONSTRAINT chk_lock_expiry CHECK (locked_until > locked_at)
);
COMMENT ON TABLE audit.audit_lock_resources IS 'Advisory locks preventing concurrent modification of audit resources';

CREATE INDEX idx_lock_resources_target ON audit.audit_lock_resources(resource_type, resource_id);


-- Table: T117 - forensic_snapshots
-- Description: Point-in-time snapshots for specific investigations.
-- Business Case: Evidence Preservation. Sometimes we need to freeze the state of the database exactly as it was when a crime was detected. This table manages snapshots (often logical exports or specific DB backups) created for forensic investigation, ensuring the "scene of the crime" isn't disturbed by ongoing system updates.
-- KPIs: Snapshot Creation Time, Restoration Accuracy.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.forensic_snapshots (
    snap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    investigation_id UUID NOT NULL,
    snapshot_timestamp TIMESTAMPTZ NOT NULL,
    storage_path TEXT NOT NULL, -- S3/Backup Path
    size_gb NUMERIC(10,2),
    status VARCHAR(20) DEFAULT 'CREATING', -- CREATING, AVAILABLE, CORRUPT
    checksum CHAR(64),
    retention_expiry DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.forensic_snapshots IS 'Manages point-in-time database states preserved for deep forensic analysis';


-- Table: T118 - audit_calculated_metrics
-- Description: Cached results of heavy calculations (e.g., VAT Gap).
-- Business Case: Dashboard Performance. Calculating the "National VAT Gap" involves scanning billions of rows. Doing this on the fly is impossible. This table stores the pre-calculated result (updated nightly), allowing dashboards to load instantly. It acts as a materialized view cache.
-- KPIs: Retrieval Latency (<100ms).
-- Feature Reference: F020
CREATE TABLE IF NOT EXISTS audit.audit_calculated_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL, -- 'NATIONAL_VAT_GAP_2023'
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    value NUMERIC(19,4) NOT NULL,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    parameters_json JSONB, -- Inputs used for calculation

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_calculated_metrics IS 'Cache for complex aggregate metrics required for executive dashboards';

CREATE UNIQUE INDEX idx_calc_metrics_unique ON audit.audit_calculated_metrics(metric_name, period_start, period_end);


-- Table: T119 - audit_api_contract_schema
-- Description: Stores OpenAPI/Swagger schema versions.
-- Business Case: API Governance and Documentation. We need to track exactly what the API promised at any given time. This table stores the full OpenAPI JSON spec for every version deployed. It allows us to generate documentation automatically and validate requests against the specific version the client is using.
-- KPIs: Schema Consistency.
-- Feature Reference: F057
CREATE TABLE IF NOT EXISTS audit.audit_api_contract_schema (
    schema_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(20) NOT NULL UNIQUE, -- e.g. 'v1.0', 'v2.1'
    spec_json JSONB NOT NULL, -- Full OpenAPI/Swagger JSON
    is_current BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_api_contract_schema_is 'Version control for API contracts and documentation specifications';


-- Table: T120 - audit_whitelist_ips
-- Description: IP whitelist for auditor access (network layer).
-- Business Case: Zero Trust Network Enforcement. As a security layer, we restrict access to known IP ranges (e.g., Tax Authority Office network). This table defines the whitelisted CIDR blocks. If a request comes from outside, the Firewall or API Gateway drops it before it even hits the application logic.
-- KPIs: Security Incident Reduction.
-- Feature Reference: F098
CREATE TABLE IF NOT EXISTS audit.audit_whitelist_ips (
    whitelist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID REFERENCES audit.auditor(auditor_id), -- NULL if global whitelist
    ip_range INET NOT NULL, -- e.g., '192.168.1.0/24'
    description TEXT,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_whitelist_ips IS 'Network-level access control lists restricting system access to specific IP ranges';


-- Table: T121 - audit_delegation
-- Description: Delegation of authority (temp access grants).
-- Business Case: Temporary Access. A Lead Auditor might go on leave and delegate their permissions to a substitute. This table records the delegation: "User A grants Read Access to User B for 2 weeks". It supports "Just-In-Time" (JIT) access principles, ensuring high privileges are only granted when needed.
-- KPIs: Delegation Compliance, Expiry Enforcement.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS audit.audit_delegation (
    delegation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    delegator_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    delegate_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    permission_scope TEXT[] NOT NULL, -- e.g. {'reports.read', 'finding.edit'}
    expires_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_delegation IS 'Manages temporary granting of permissions between auditors for coverage';


-- Table: T122 - audit_escalations
-- Description: Escalation path for unresolved findings.
-- Business Case: Workflow Management. If a finding isn't resolved within SLA, it must be escalated to a higher authority. This table logs the escalation event: "Finding 123 escalated from Tier 1 to Tier 2 due to SLA breach". It ensures accountability prevents findings from being ignored.
-- KPIs: Escalation Rate, SLA Adherence.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_escalations (
    escalation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES audit.audit_findings(finding_id),
    from_role VARCHAR(100) NOT NULL,
    to_role VARCHAR(100) NOT NULL,
    escalated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING_ACK', -- PENDING_ACK, ACKNOWLEDGED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_escalations IS 'Tracks the escalation of audit issues to higher authority levels';


-- Table: T123 - audit_data_lake_index
-- Description: Index of archived data in the Data Lake.
-- Business Case: Cold Data Discovery. Old data (5+ years) is moved to cheap storage (S3 Glacier) to save money. This table acts as the card catalog, pointing to where the data is and what it contains. It allows auditors to query old data without loading it back into the hot database.
-- KPIs: Archive Retrieval Time, Storage Cost Savings.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.audit_data_lake_index (
    lake_idx UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    s3_path TEXT NOT NULL,
    object_type VARCHAR(50) NOT NULL, -- 'TRANSACTIONS_2018', 'AUDIT_LOGS_2019'
    year INTEGER NOT NULL,
    month INTEGER NOT NULL,
    is_deleted BOOLEAN DEFAULT FALSE, -- Soft delete for data in the lake
    row_count BIGINT,
    compressed_size_bytes BIGINT,
    archived_at TIMESTAMPTZ NOT NULL
);
COMMENT ON TABLE audit.audit_data_lake_index IS 'Metastore for data archived in long-term cold storage solutions';

CREATE INDEX idx_lake_index_dates ON audit.audit_data_lake_index(year, month);


-- Table: T124 - audit_disaster_recovery_runbook
-- Description: DR procedures and execution logs.
-- Business Case: Operational Continuity. When the system crashes, panic ensues. This table stores the "Runbook"—the step-by-step instructions for recovery (e.g., "1. Stop Traffic", "2. Promote DB Replica"). It also logs *actual* drills to ensure the team knows how to use the runbook.
-- KPIs: RTO/RPO Compliance, Drill Success Rate.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS audit.audit_disaster_recovery_runbook (
    runbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    procedure_name VARCHAR(255) NOT NULL,
    description TEXT,
    instructions_jsonb NOT NULL, -- Structured steps
    last_executed TIMESTAMPTZ,
    last_execution_status VARCHAR(20),
    success_rate NUMERIC(3,2), -- Historical success of drills
    owner_team VARCHAR(100)
);
COMMENT ON TABLE audit.audit_disaster_recovery_runbook_is 'Procedural guides and logs for disaster recovery operations';


-- Table: T125 - audit_search_index
-- Description: Full-text index configuration.
-- Business Case: Search Optimization. The auditor interface has a "Smart Search". To make it fast, we use PostgreSQL Full Text Search (FTS). This table defines which columns are indexed and their weights (e.g., "Merchant Name" is more important than "Description"). It tunes the search relevance algorithm.
-- KPIs: Search Relevance (>85%).
-- Feature Reference: F122
CREATE TABLE IF NOT EXISTS audit.audit_search_index (
    index_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    weight CHAR(1) NOT NULL CHECK (weight IN ('A', 'B', 'C', 'D')), -- A is highest weight
    indexing_method VARCHAR(50) DEFAULT 'GIN', -- GIN, GIST
    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_search_index_is 'Configuration for full-text search weighting and indexing strategies';

CREATE UNIQUE INDEX idx_search_config ON audit.audit_search_index(table_name, column_name);


-- Table: T126 - audit_kpi_targets
-- Description: Target values for KPIs (SLAs).
-- Business Case: Performance Benchmarking. We need to know if the system is "Healthy". This table defines the targets (e.g., "Audit Latency < 10s"). The monitoring system queries this table to compare actuals vs targets and triggers alerts if SLAs are breached.
-- KPIs: SLA Compliance Rate.
-- Feature Reference: F006
CREATE TABLE IF NOT EXISTS audit.audit_kpi_targets (
    kpi_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    kpi_name VARCHAR(100) NOT NULL UNIQUE,
    target_value NUMERIC(19,4) NOT NULL,
    current_value NUMERIC(19,4), -- Updated periodically
    period VARCHAR(50) NOT NULL, -- 'ROLLING_24H', 'MONTHLY', 'QUARTERLY'
    operator VARCHAR(10) NOT NULL CHECK (operator IN ('<', '>', '<=', '>=')),
    last_calculated TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_kpi_targets IS 'Defines service level objectives (SLOs) and targets for system performance metrics';


-- Table: T127 - audit_role_hierarchy
-- Description: Defines hierarchy of auditor roles for approval flows.
-- Business Case: Approval Workflow Logic. "Tier 1" auditors need "Tier 2" approval for high-value findings. This table defines the hierarchy (Who reports to whom?). It allows the system to dynamically route approval requests up the chain of command without hardcoding names.
-- KPIs: Workflow Efficiency.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS audit.audit_role_hierarchy (
    hierarchy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_role VARCHAR(100) NOT NULL,
    child_role VARCHAR(100) NOT NULL,
    depth_level INTEGER NOT NULL, -- 1 for direct report, 2 for skip-level

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_role_hierarchy IS 'Defines the organizational hierarchy and approval routing paths for roles';


-- Table: T128 - audit_change_requests
-- Description: Requests for changes to audit rules or configs.
-- Business Case: Controlled Environments. Changing a tax rate or alert rule is dangerous. This table manages the "Change Request" (CR) workflow. A user proposes a change, it gets reviewed, approved, and then applied. This ensures no "cowboy" changes that could break compliance.
-- KPIs: Change Approval Time, Failed Change Rate.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS audit.audit_change_requests (
    cr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requested_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    change_type VARCHAR(50) NOT NULL, -- CONFIG_UPDATE, SCHEMA_CHANGE
    target_object VARCHAR(255) NOT NULL, -- table_name or config_key
    details_json NOT NULL, -- The proposed change (Old Value -> New Value)
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, IMPLEMENTED
    reviewed_by UUID REFERENCES audit.auditor(auditor_id),
    reviewed_at TIMESTAMPTZ,
    rejection_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_change_requests IS 'Workflow control for modifying system configurations and logic rules';


-- Table: T129 - audit_subscription_topics
-- Description: Kafka/WebSocket topics available for subscription.
-- Business Case: Real-Time Data Streaming. Auditors can subscribe to "topics" (streams of data). This table defines what topics are available (e.g., "High_Value_Transactions_DE"), their description, and who is allowed to subscribe. It drives the "Real-Time VAT Stream" feature.
-- KPIs: Subscription Success Rate.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.audit_subscription_topics (
    topic_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    access_level VARCHAR(50) NOT NULL, -- 'PUBLIC', 'INTERNAL', 'RESTRICTED'
    retention_hours INTEGER DEFAULT 24, -- How long messages stay in topic
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_subscription_topics IS 'Registry of real-time data streams available for auditor subscription';


-- Table: T130 - audit_user_subscriptions
-- Description: Junction: Users to Topics.
-- Business Case: User Preference Management. An auditor might want "VAT Alerts" but not "System Errors". This table links the Auditor to the specific Topics they are interested in. The notification engine reads this to determine who to alert.
-- KPIs: Alert Relevance.
-- Feature Reference: F001, F019
CREATE TABLE IF NOT EXISTS audit.audit_user_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    topic_id UUID NOT NULL REFERENCES audit.audit_subscription_topics(topic_id),
    filter_params JSONB, -- e.g. {"min_amount": 10000}
    subscribed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT chk_unique_subscription UNIQUE (auditor_id, topic_id)
);
COMMENT ON TABLE audit.audit_user_subscriptions_is 'Maps auditors to their specific real-time data stream subscriptions';


-- Table: T131 - audit_test_data_sets
-- Description: Definition of test datasets for QA.
-- Business Case: Automated Testing. To ensure new code doesn't break old features (regression), we need consistent test data. This table defines "Golden Sets" of data that the QA suite runs against every time we deploy.
-- KPIs: Test Coverage (>90%).
-- Feature Reference: F113
CREATE TABLE IF NOT EXISTS audit.audit_test_data_sets (
    dataset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    row_count INTEGER NOT NULL,
    created_for_release VARCHAR(100), -- e.g. 'v2.5.0'
    description TEXT,
    s3_location TEXT NOT NULL, -- Path to the CSV/SQL dump
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_test_data_sets IS 'Manages standardized data sets used for automated regression testing';


-- Table: T132 - audit_test_results
-- Description: Automated test execution results.
-- Business Case: Quality Assurance Gate. This table stores the pass/fail status of every test suite run. If a build fails, it fails here. It provides the history of code quality, allowing teams to track down when a bug was introduced.
-- KPIs: Build Success Rate, Test Execution Time.
-- Feature Reference: F113
CREATE TABLE IF NOT EXISTS audit.audit_test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_suite VARCHAR(100) NOT NULL,
    run_id VARCHAR(100) NOT NULL, -- Unique ID for the CI/CD run
    passed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    execution_time_seconds INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    build_url TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_test_results_is 'Historical results of automated test executions for quality tracking';

CREATE INDEX idx_test_results_ts ON audit.audit_test_results(timestamp DESC);


-- Table: T133 - audit_incident_tickets
-- Description: Support tickets related to the Audit module.
-- Business Case: Issue Tracking. If the system crashes or data looks wrong, auditors raise a ticket. This table tracks the lifecycle (Open -> In Progress -> Resolved). It ensures bugs are tracked and fixed, maintaining trust in the platform.
-- KPIs: Mean Time To Resolve (MTTR), Ticket Volume.
-- Feature Reference: F079
CREATE TABLE IF NOT EXISTS audit.audit_incident_tickets (
    ticket_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID REFERENCES audit.auditor(auditor_id),
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, ASSIGNED, RESOLVED, CLOSED
    assigned_to UUID REFERENCES audit.auditor(auditor_id),
    resolution TEXT,
    resolved_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_incident_tickets IS 'Tracks bug reports and system issues for the support and development teams';


-- Table: T134 - audit_roadmap_items
-- Description: Future features and roadmap tracking.
-- Business Case: Product Planning. This table stores the "Future of PARI". It lists features requested by auditors (e.g., "Dark Mode", "Mobile App") and tracks their status (Backlog, Planned, In Progress). It aligns engineering effort with user needs.
-- KPIs: Feature Delivery Velocity.
-- Feature Reference: F144
CREATE TABLE IF NOT EXISTS audit.audit_roadmap_items (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(255) NOT NULL,
    description TEXT,
    planned_quarter VARCHAR(10), -- '2023-Q4'
    status VARCHAR(20) DEFAULT 'BACKLOG', -- BACKLOG, PLANNED, IN_DEV, RELEASED
    assigned_to UUID REFERENCES audit.auditor(auditor_id),
    priority INTEGER CHECK (priority BETWEEN 1 AND 10),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_roadmap_items IS 'Product management backlog for future platform features';


-- Table: T135 - audit_third_party_integrations
-- Description: Config for 3rd party tools (Tableau, PowerBI).
-- Business Case: BI Ecosystem Integration. Auditors love Tableau. This table stores the OAuth tokens and workspace IDs required to push data from PARI to external dashboards. It allows the system to act as a data source for the auditor's preferred visualization tool.
-- KPIs: Connector Uptime.
-- Feature Reference: F071
CREATE TABLE IF NOT EXISTS audit.audit_third_party_integrations (
    integration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool_name VARCHAR(50) NOT NULL, -- 'TABLEAU', 'POWERBI', 'QLIK'
    api_key TEXT, -- Encrypted
    refresh_token TEXT, -- Encrypted
    workspace_id VARCHAR(255),
    owner_auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    last_synced_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_third_party_integrations IS 'Securely stores credentials for exporting data to external analytics tools';


-- Table: T136 - audit_custom_dimensions
-- Description: User-defined dimensions for analytics.
-- Business Case: Self-Service Analytics. Standard dimensions are "Date", "Merchant", "Amount". But an auditor might want "Chain vs. Independent". This table allows them to define a custom dimension (using a SQL expression) that they can then use in Pivot Tables without needing a developer.
-- KPIs: Dimension Creation Time.
-- Feature Reference: F028
CREATE TABLE IF NOT EXISTS audit.audit_custom_dimensions (
    dim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    name VARCHAR(100) NOT NULL,
    sql_expression TEXT NOT NULL, -- e.g. CASE WHEN type='X' THEN 'A' ELSE 'B' END
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE, -- Share with others?

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_custom_dimensions_is 'Allows users to define reusable calculated columns for data analysis';


-- Table: T137 - audit_data_dictionaries
-- Description: Business glossary for data terms.
-- Business Case: Data Literacy. "What is 'MCC'?" A new auditor might not know. This table acts as a glossary, defining terms (e.g., "MCC: Merchant Category Code") and linking them to specific tables/columns. It bridges the gap between Business jargon and Database schema.
-- KPIs: Definition Search Success.
-- Feature Reference: F010, F041
CREATE TABLE IF NOT EXISTS audit.audit_data_dictionaries (
    term_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    term_name VARCHAR(100) NOT NULL UNIQUE,
    definition TEXT NOT NULL,
    steward VARCHAR(100), -- Who owns this definition
    related_tables TEXT[], -- Links to tables
    acronym TEXT, -- Short form
    examples TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_data_dictionaries_is 'Business glossary linking terminology to technical schema elements';


-- Table: T138 - audit_audit_trail_meta
-- Description: Metadata about the audit trail itself (for integrity).
-- Business Case: Chain of Custody for Logs. Even the logs can be hacked. This table stores the "Hash of the Logs". It effectively hashes the content of the `auditor_logs` table (or its blocks). If a log is tampered with, this hash won't match the recalculated hash, alerting admins to a breach.
-- KPIs: Log Integrity (100%).
-- Feature Reference: F013
CREATE TABLE IF NOT EXISTS audit.audit_audit_trail_meta (
    meta_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trail_hash CHAR(64) NOT NULL, -- SHA-256 of the log block
    record_count INTEGER NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    last_verified TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    verification_status VARCHAR(20) DEFAULT 'VALID' -- VALID, CORRUPT, PENDING
);
COMMENT ON TABLE audit.audit_audit_trail_meta_is 'Cryptographic checkpoints ensuring the immutability of the audit logs themselves';

CREATE UNIQUE INDEX idx_trail_meta_period ON audit.audit_audit_trail_meta(period_start, period_end);


-- Table: T139 - audit_compliance_checklist
-- Description: Master checklist for compliance (e.g., SOC2, ISO27001).
-- Business Case: Regulatory Alignment. SOC2 requires specific controls (e.g., "Do you track who accessed data?"). This table maps the PARI features to these specific controls. It automates the generation of compliance reports for auditors (auditing the auditors).
-- KPIs: Compliance Percentage.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.audit_compliance_checklist (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    standard VARCHAR(50) NOT NULL, -- 'SOC2', 'ISO27001', 'GDPR'
    control_id VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    frequency VARCHAR(50), -- 'WEEKLY', 'QUARTERLY'
    related_feature_ids UUID[], -- Links to PARI features satisfying this

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_compliance_checklist_is 'Maps system capabilities to external regulatory framework controls';


-- Table: T140 - audit_compliance_evidence
-- Description: Evidence links for compliance checks.
-- Business Case: Audit Evidence Gathering. "We say we do X, prove it." This table links the Compliance Checklist Item to the actual proof (Screenshot of code, Log export, Config dump). It is the "Binder" for the compliance audit.
-- KPIs: Evidence Availability.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.audit_compliance_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    check_id UUID NOT NULL REFERENCES audit.audit_compliance_checklist(check_id),
    file_path TEXT NOT NULL,
    collected_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    date DATE NOT NULL DEFAULT CURRENT_DATE,
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_compliance_evidence_is 'Stores artifacts proving adherence to compliance controls';


-- Table: T141 - audit_email_queue
-- Description: Queue for outbound emails.
-- Business Case: Asynchronous Communication. Sending emails can be slow (5-10s). We don't want the user to wait. This table queues the email, and a background worker picks it up. It also handles retries if the mail server is down.
-- KPIs: Delivery Rate, Bounce Rate.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_email_queue (
    email_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    recipient VARCHAR(255) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    body TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, SENT, FAILED, BOUNCED
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    queued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMPTZ,
    bounce_reason TEXT
);
COMMENT ON TABLE audit.audit_email_queue IS 'Outbox queue for reliable email delivery';

CREATE INDEX idx_email_queue_status ON audit.audit_email_queue(status, attempts);


-- Table: T142 - audit_sms_queue
-- Description: Queue for outbound SMS (2FA).
-- Business Case: Security Alerts. For critical actions (Password Reset, Login from new IP), we send SMS. This table manages that queue. Since SMS costs money, we track delivery status to ensure we aren't paying for undelivered messages.
-- KPIs: Delivery Success, Cost Per SMS.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.audit_sms_queue (
    sms_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    phone_number VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    provider_id VARCHAR(50),
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, SENT, FAILED
    queued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMPTZ,
    cost_usd NUMERIC(10,4),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_sms_queue IS 'Queue for managing outgoing SMS notifications and 2FA codes';


-- Table: T143 - audit_provisioning_logs
-- Description: Logs of user provisioning/deprovisioning.
-- Business Case: Identity Management (IAM). When an auditor leaves the company, their access must be removed instantly. This table logs the sync events from the HR system (LDAP) to PARI. It acts as the source of truth for "Who has access right now?".
-- KPIs: Deprovisioning Speed (< 1 hour).
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.audit_provisioning_logs (
    prov_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    action VARCHAR(20) NOT NULL, -- CREATE, UPDATE, DEPROVISION, LOCK
    triggered_by VARCHAR(100) NOT NULL, -- 'SYSTEM_SYNC', 'ADMIN'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    details_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_provisioning_logs IS 'Tracks automated lifecycle events of user accounts from HR systems';


-- Table: T144 - audit_session_limit_config
-- Description: Config for session limits (duration, concurrent).
-- Business Case: Security Policy Enforcement. Company policy might be "Max 4 hours idle time" or "Max 2 concurrent sessions". This table stores these configurable limits, allowing Security Ops to tighten or loosen rules without code deployment.
-- KPIs: Policy Compliance Rate.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS audit.audit_session_limit_config (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id VARCHAR(100) NOT NULL,
    max_duration_min INTEGER NOT NULL,
    max_concurrent INTEGER NOT NULL,
    enforce_ip_lock BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_session_limit_config IS 'Defines session management policies per role for security enforcement';


-- Table: T145 - audit_api_clients
-- Description: Registered Machine-to-Machine clients.
-- Business Case: Service-to-Service Authentication. Other systems (like a Data Lake or Billing System) need to pull data from the Audit API. This table registers these "Machine Clients", managing their credentials and scopes (what they are allowed to access).
-- KPIs: API Client Success Rate.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS audit.audit_api_clients (
    client_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_name VARCHAR(255) NOT NULL,
    grant_type VARCHAR(50) NOT NULL, -- 'CLIENT_CREDENTIALS', 'AUTHORIZATION_CODE'
    redirect_uris TEXT[], -- For OAuth flows
    scopes TEXT[], -- e.g. {'read:reports', 'read:merchants'}
    owner_team VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_api_clients_is 'Registry for automated service accounts accessing the API';


-- Table: T146 - audit_client_credentials
-- Description: Hashed secrets for M2M clients.
-- Business Case: Credential Security. We never store passwords/secrets in plain text. This table stores the *hashed* version of the API Client secret. When a client tries to authenticate, we hash the provided secret and compare it to this value.
-- KPIs: Secret Hash Integrity.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS audit.audit_client_credentials (
    cred_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES audit.audit_api_clients(client_id),
    hashed_secret VARCHAR(255) NOT NULL, -- bcrypt
    salt VARCHAR(100) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_client_credentials_is 'Securely stores the hashed authentication secrets for API clients';


-- Table: T147 - audit_resource_tags
-- Description: Tags for resources (tables, reports).
-- Business Case: Flexible Metadata. Besides the rigid "Compliance Tag", users might want to tag resources with "Project X", "2023 Audit", or "High Priority". This table implements a generic "Key-Value" tagging system, allowing users to organize resources however they want.
-- KPIs: Tag Usage.
-- Feature Reference: F043
CREATE TABLE IF NOT EXISTS audit.audit_resource_tags (
    tag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- 'TABLE', 'VIEW', 'REPORT', 'CASE'
    resource_id UUID NOT NULL,
    tag_key VARCHAR(100) NOT NULL,
    tag_value VARCHAR(255),
    created_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_resource_tags_is 'Generic key-value tagging system for flexible resource categorization';

CREATE INDEX idx_resource_tags_target ON audit.audit_resource_tags(resource_type, resource_id);


-- Table: T148 - audit_audit_log_retention
-- Description: Overrides to default retention policies.
-- Business Case: Legal Hold. Sometimes a "Right to be Forgotten" request conflicts with a "Legal Hold" on an ongoing investigation. This table stores exceptions, explicitly saying "Do NOT delete logs for User X, even though the 7-year retention period is up."
-- KPIs: Legal Hold Compliance.
-- Feature Reference: F017
CREATE TABLE IF NOT EXISTS audit.audit_audit_log_retention (
    override_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_type VARCHAR(100) NOT NULL, -- 'AUDITOR_LOGS', 'TRANSACTIONS'
    entity_id UUID NOT NULL, -- ID of the specific entity to hold
    retention_years INTEGER NOT NULL,
    justification TEXT NOT NULL,
    requested_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approved_by UUID REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, CANCELLED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_audit_log_retention_is 'Exceptions to standard data retention policies for legal holds or investigations';


-- Table: T149 - audit_failover_test_results
-- Description: Results of DR drill tests.
-- Business Case: Disaster Readiness. We back up data, but do we know how to restore it? This table logs the results of periodic "Fire Drills". It tracks RPO (Data Loss) and RTO (Time to Restore). If these metrics get worse, we know our DR plan is failing.
-- KPIs: RTO < 15min, RPO < 5min.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS audit.audit_failover_test_results (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    drill_type VARCHAR(50) NOT NULL, -- 'FULL_SYSTEM', 'DB_ONLY'
    rpo_measured_seconds INTEGER NOT NULL,
    rto_measured_seconds INTEGER NOT NULL,
    passed BOOLEAN NOT NULL,
    run_date DATE NOT NULL DEFAULT CURRENT_DATE,
    notes TEXT,
    run_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_failover_test_results_is 'Records performance metrics of disaster recovery drills to validate system resilience';


-- Table: T150 - audit_penetration_test_results
-- Description: Results of pentests.
-- Business Case: Vulnerability Management. We hire "White Hat" hackers to try and break in. This table stores their findings (Severity Counts, Report Path). It tracks the lifecycle of a vulnerability from "Found" to "Fixed" to "Verified".
-- KPIs: Vulnerability Remediation Time.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.audit_penetration_test_results (
    pentest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor VARCHAR(100) NOT NULL, -- 'CROWDSTRIKE', 'KPMG'
    start_date DATE NOT NULL,
    end_date DATE,
    severity_counts JSONB NOT NULL, -- {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5}
    report_path TEXT,
    status VARCHAR(20) DEFAULT 'IN_PROGRESS', -- IN_PROGRESS, REPORT_SUBMITTED, REMEDIATION_DONE
    next_review_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_penetration_test_results_is 'Stores findings and remediation status of third-party security penetration tests';

-- End of Script Part 3 (Objects 101-150)

-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 4: Objects 151-200)
-- ================================================================================
-- Description: This script completes the database object creation for the Independent
-- Auditor Interface. It covers deep operational metrics, security scanning,
-- workflow orchestration, user analytics, and infrastructure monitoring.
--
-- Scope: Database Objects E020, T151 - T200.
-- ================================================================================

-- 3. Enums (Remaining from List)
-- ================================================================================

-- Enum: E020 - enum_iso_msg_type
-- Description: ISO 20022 Message Types.
-- Feature Reference: F010
CREATE TYPE audit.enum_iso_msg_type AS ENUM ('pain.001', 'pain.002', 'camt.053', 'acmt.001', 'pacs.008');
COMMENT ON TYPE audit.enum_iso_msg_type IS 'Standardized ISO 20022 financial message types supported by the system';


-- 4. DDL Statements (Tables T151 - T200)
-- ================================================================================

-- Table: T151 - audit_vulnerability_scan
-- Description: Results of dependency scans.
-- Business Case: Supply Chain Security. Modern applications rely on thousands of open-source libraries. Vulnerabilities like Log4j or Heartbleed can exist deep in these dependencies. This table stores the results of automated scanners (Snyk, OWASP Dependency Check) that run during the CI/CD pipeline, flagging libraries with known CVEs (Common Vulnerabilities and Exposures).
-- KPIs: Vulnerability Remediation Time, Critical CVE Count.
-- Feature Reference: F020
CREATE TABLE IF NOT EXISTS audit.audit_vulnerability_scan (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scanner_tool VARCHAR(100) NOT NULL, -- 'SNYK', 'DEPENDENCY_CHECK'
    scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    scan_report_path TEXT, -- Path to JSON report in S3

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_vulnerability_scan IS 'Stores results of security scans identifying vulnerabilities in software dependencies';


-- Table: T152 - audit_code_review_feedback
-- Description: Feedback from code reviews (CMMI).
-- Business Case: Quality Assurance and Knowledge Transfer. Before code merges, peers review it. This table captures structured feedback (e.g., "SQL Injection Risk", "Complexity Too High"). It quantifies code quality trends over time and helps CMMI maturity optimization by identifying recurring training needs for developers.
-- KPIs: Code Review Coverage, Defect Density.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS audit.audit_code_review_feedback (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id VARCHAR(100) NOT NULL, -- Pull Request ID
    reviewer VARCHAR(100) NOT NULL,
    comments TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO')),
    file_path TEXT,
    line_number INTEGER,
    review_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, ACKNOWLEDGED, FIXED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_code_review_feedback IS 'Records peer review feedback to track code quality and identify recurring issues';


-- Table: T153 - audit_release_notes
-- Description: Release notes for the platform.
-- Business Case: Change Communication. When a new version is deployed, auditors need to know what changed. This table stores release notes (Features, Bug Fixes, Breaking Changes). It populates the "What's New" modal in the UI, ensuring users are aware of new capabilities immediately.
-- KPIs: User Read Rate of Notes.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS audit.audit_release_notes (
    release_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(20) NOT NULL UNIQUE,
    release_date DATE NOT NULL DEFAULT CURRENT_DATE,
    notes_md TEXT NOT NULL, -- Markdown format
    highlights TEXT[], -- Bullet points for quick view
    is_published BOOLEAN DEFAULT FALSE,
    author_name VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_release_notes IS 'Publishes release documentation to keep users informed of platform updates';


-- Table: T154 - audit_feature_usage
-- Description: Granular usage tracking of UI features.
-- Business Case: Product Optimization. We track *everything* an auditor does in the UI (Clicking "Export", Opening "Graph View"). This high-volume table powers analytics that tell Product Managers which features are beloved and which are ignored (candidates for deprecation). It drives the roadmap.
-- KPIs: Daily Active Users (DAU), Feature Adoption %.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_feature_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    feature_name VARCHAR(255) NOT NULL, -- e.g. 'btn_vat_report'
    action VARCHAR(50) NOT NULL, -- CLICK, HOVER, DRAG_DROP
    page_url TEXT,
    ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    metadata_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_feature_usage IS 'Detailed telemetry of user interactions with the interface to guide product development';

CREATE INDEX idx_feature_usage_ts ON audit.audit_feature_usage(ts DESC);
-- Recommended Partitioning by month for production


-- Table: T155 - audit_onboarding_checklist
-- Description: Checklist for new auditor onboarding.
-- Business Case: Talent Management. New hires have a steep learning curve (Tax laws, tools). This table manages their onboarding checklist (e.g., "Complete GDPR Training", "Run First Mock Audit"). It ensures they are productive and compliant quickly.
-- KPIs: Time to Productivity, Onboarding Completion Rate.
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.audit_onboarding_checklist (
    step_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    task_name VARCHAR(255) NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMPTZ,
    due_date DATE,
    assigned_to_uuid UUID, -- Manager

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_onboarding_checklist_is 'Tracks the progress of new auditor training and compliance certification';


-- Table: T156 - audit_feedback_analysis
-- Description: Aggregated analysis of user feedback.
-- Business Case: Sentiment Analysis. Instead of reading thousands of comments, we use NLP to aggregate them. This table stores the results: "Sentiment Score", "Top Keywords" (e.g., "Slow", "Export Error"). It gives leadership a high-level view of user satisfaction.
-- KPIs: Sentiment Trend, Top Issue Categories.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.audit_feedback_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    total_comments INTEGER NOT NULL,
    sentiment_score NUMERIC(3,2), -- -1 to 1
    top_issues JSONB, -- [{"issue": "Latency", "count": 50}]
    analysis_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_feedback_analysis IS 'Stores AI-generated summaries of user feedback to track overall satisfaction';

CREATE UNIQUE INDEX idx_feedback_analysis_period ON audit.audit_feedback_analysis(period_start, period_end);


-- Table: T157 - audit_capacity_planning
-- Description: Forecasts for infrastructure capacity.
-- Business Case: FinOps and Scaling. We need to predict when we will run out of CPU or Storage. This table stores forecasts generated by time-series models (ARIMA). It allows DevOps to request budget and hardware months in advance, preventing outages.
-- KPIs: Forecast Accuracy (<10% error), Resource Utilization.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS audit.audit_capacity_planning (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_type VARCHAR(50) NOT NULL, -- 'CPU', 'STORAGE_IO', 'MEMORY'
    projected_value NUMERIC(19,4) NOT NULL,
    target_date DATE NOT NULL,
    confidence_interval VARCHAR(20), -- 'HIGH', 'MEDIUM'
    model_name VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_capacity_planning IS 'Forecasting data for proactive infrastructure scaling and budgeting';


-- Table: T158 - audit_cost_allocation
-- Description: Allocation of cloud costs to departments/auditors.
-- Business Case: Showback/Chargeback. Cloud billing is one big number. This table breaks it down: "Department A used $500 of compute", "Auditor B used $50 of S3 storage". It promotes responsible usage and helps allocate IT budgets fairly.
-- KPIs: Cost Per Audit, Cost Variance.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.audit_cost_allocation (
    alloc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    department VARCHAR(100) NOT NULL,
    cost_center VARCHAR(100),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    compute_cost NUMERIC(15,2) NOT NULL,
    storage_cost NUMERIC(15,2) NOT NULL,
    bandwidth_cost NUMERIC(15,2) NOT NULL,
    total_cost NUMERIC(15,2) GENERATED ALWAYS AS (compute_cost + storage_cost + bandwidth_cost) STORED,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_cost_allocation IS 'Breakdown of cloud infrastructure costs by department for financial management';

CREATE INDEX idx_cost_alloc_period ON audit.audit_cost_allocation(period_start, period_end);


-- Table: T159 - audit_service_level_objectives
-- Description: Definition of SLOs for the module.
-- Business Case: Reliability Engineering. We promise the Tax Authority "99.9% Uptime". This table defines the mathematical SLOs (e.g., "Error rate < 0.1% over rolling 30 days"). It is the source of truth for alerts.
-- KPIs: SLO Adherence.
-- Feature Reference: F006
CREATE TABLE IF NOT EXISTS audit.audit_service_level_objectives (
    slo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL UNIQUE,
    metric VARCHAR(100) NOT NULL, -- 'uptime', 'latency', 'error_rate'
    target_percent NUMERIC(5,2) NOT NULL, -- e.g. 99.90
    window VARCHAR(50) NOT NULL, -- 'rolling_30d', 'calendar_month'
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_service_level_objectives_is 'Defines the specific performance targets committed to by the service team';


-- Table: T160 - audit_slo_burn_rates
-- Description: Calculation of error budget burn.
-- Business Case: Reliability Monitoring. If we have 99.9% SLO, we have ~43 minutes of "Error Budget" per month. If we burn it all in the first week, we can't deploy new features (freeze code). This table calculates the burn rate.
-- KPIs: Error Budget Remaining.
-- Feature Reference: F006
CREATE TABLE IF NOT EXISTS audit.audit_slo_burn_rates (
    burn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_id UUID NOT NULL REFERENCES audit.audit_service_level_objectives(slo_id),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    burned_percent NUMERIC(5,2) NOT NULL, -- e.g., 12.50
    remaining_budget_seconds NUMERIC(10,2),
    status VARCHAR(20), -- 'HEALTHY', 'DEPLETED', 'AT_RISK'
    measured_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_slo_burn_rates_is 'Tracks consumption of the error budget to manage risk in deployments';

CREATE INDEX idx_slo_burn_slo_time ON audit.audit_slo_burn_rates(slo_id, window_start DESC);


-- Table: T161 - audit_incident_postmortems
-- Description: Records of incident postmortems (5 Whys).
-- Business Case: Learning from Failure. When an outage happens, we write a Postmortem. This table stores the "5 Whys" (Root Cause Analysis), lessons learned, and action items. It prevents the same mistake from happening twice.
-- KPIs: Postmortem Completion Rate (100%).
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS audit.audit_incident_postmortems (
    postmortem_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL, -- Link to T133
    incident_date DATE NOT NULL,
    summary TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    timeline_json JSONB NOT NULL, -- Timeline of events
    action_items TEXT[] NOT NULL,
    facilitator VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_incident_postmortems_is 'Documents root cause analysis of incidents to foster a blameless learning culture';


-- Table: T162 - audit_root_cause_analysis
-- Description: Detailed steps of RCA.
-- Business Case: Deep Dive Analysis. While T161 holds the summary, this table holds the detailed structured steps of the RCA (e.g., "Why 1: Server died. Why 2: Memory leak."). It allows structured querying of failure patterns.
-- KPIs: Analysis Depth.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS audit.audit_root_cause_analysis (
    rca_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    postmortem_id UUID NOT NULL REFERENCES audit.audit_incident_postmortems(postmortem_id),
    step_number INTEGER NOT NULL,
    question TEXT NOT NULL, -- 'Why did the database crash?'
    answer TEXT NOT NULL, -- 'Because OOM killer triggered'
    evidence_link TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_root_cause_analysis_is 'Stores structured Q&A steps of root cause analysis for incident review';


-- Table: T163 - audit_documentation_links
-- Description: Links to external/internal documentation.
-- Business Case: Knowledge Management. The UI has "Help" buttons. This table maps features to URLs (Confluence, GitBook, PDF). It ensures that "Help" links are always up to date and centralized, rather than hardcoded in the app.
-- KPIs: Link Validity.
-- Feature Reference: F057
CREATE TABLE IF NOT EXISTS audit.audit_documentation_links (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    category VARCHAR(100), -- 'USER_GUIDE', 'API_DOC', 'ARCHITECTURE'
    last_updated TIMESTAMPTZ,
    language CHAR(2) DEFAULT 'EN',

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_documentation_links IS 'Central repository for linking application features to help documentation';


-- Table: T164 - audit_faq
-- Description: Frequently asked questions.
-- Business Case: Self-Service Support. Reduces load on support tickets. This table stores FAQs displayed in the Help Center. It allows support teams to publish solutions to common problems (e.g., "How to export to CSV?") instantly.
-- KPIs: Deflection Rate (Tickets reduced).
-- Feature Reference: F111
CREATE TABLE IF NOT EXISTS audit.audit_faq (
    faq_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    order_index INTEGER NOT NULL,
    language CHAR(2) DEFAULT 'EN',
    category VARCHAR(100),
    view_count INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_faq_is 'Knowledge base of frequently asked questions to enable self-service user support';


-- Table: T165 - audit_announcements
-- Description: System announcements for auditors.
-- Business Case: Broadcast Communication. "System Maintenance Sunday at 2 AM". This table stores announcements that appear as banners in the UI. It ensures critical info is seen by everyone immediately.
-- KPIs: Announcement View Rate.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.audit_announcements (
    ann_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    start_date DATE NOT NULL DEFAULT CURRENT_DATE,
    end_date DATE NOT NULL,
    is_global BOOLEAN DEFAULT TRUE,
    target_roles TEXT[], -- If not global, who sees it?

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_announcements IS 'Manages temporary system-wide notices for scheduled maintenance or critical updates';


-- Table: T166 - audit_user_groups
-- Description: Groups of auditors for permissions/assignments.
-- Business Case: Role-Based Access Control (RBAC) Grouping. Instead of assigning permissions to 500 people individually, we assign to "Group: VAT Team". This table defines those groups, making user management efficient (add user to group -> they get permissions).
-- KPIs: Permission Assignment Efficiency.
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS audit.audit_user_groups (
    group_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    manager_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_user_groups_is 'Defines collections of auditors for simplified permission and workload management';


-- Table: T167 - audit_user_group_members
-- Description: Junction: Auditors to Groups.
-- Business Case: Many-to-Many Membership. An auditor can belong to "VAT Team" and "Emergency Response Team". This junction table enables flexible group memberships.
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS audit.audit_user_group_members (
    member_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES audit.audit_user_groups(group_id),
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_group_member UNIQUE (group_id, auditor_id)
);
COMMENT ON TABLE audit.audit_user_group_members_is 'Links auditors to organizational groups for role aggregation';

CREATE INDEX idx_group_members_auditor ON audit.audit_user_group_members(auditor_id);


-- Table: T168 - audit_workflow_steps
-- Description: Definition of steps in a workflow.
-- Business Case: Orchestration Logic. A workflow (e.g., "Audit Case") is a series of steps (Verify -> Investigate -> Approve). This table defines the blueprint of these steps, including which role is allowed to execute them.
-- KPIs: Workflow Consistency.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_workflow_steps (
    step_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_name VARCHAR(100) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    order_index INTEGER NOT NULL,
    assigned_role VARCHAR(100) NOT NULL, -- Who performs this step
    auto_assign BOOLEAN DEFAULT FALSE,
    due_date_offset_hours INTEGER, -- e.g. 24 hours from start

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_workflow_steps_is 'Blueprint definitions for the steps involved in audit business processes';


-- Table: T169 - audit_workflow_instance
-- Description: Running instance of a workflow.
-- Business Case: State Machine Runtime. When an audit case starts, we create an "Instance" of the workflow. This table tracks where we are in the process (Current Step), status, and who is working on it. It is the runtime representation of T168.
-- KPIs: Workflow Completion Time.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_workflow_instance (
    instance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_name VARCHAR(100) NOT NULL,
    current_step_id UUID REFERENCES audit.audit_workflow_steps(step_id),
    current_step_name VARCHAR(100), -- Denormalized for speed
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING', -- RUNNING, COMPLETED, CANCELLED
    started_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_workflow_instance_is 'Tracks the execution state of specific audit process instances';

CREATE INDEX idx_workflow_status ON audit.audit_workflow_instance(status, started_at DESC);


-- Table: T170 - audit_workflow_history
-- Description: History of step transitions in an instance.
-- Business Case: Audit Trail for Processes. We need to prove *when* a case moved from "Review" to "Approved". This table logs every state transition in a workflow instance, providing a complete history of the process lifecycle.
-- KPIs: Transition Latency.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.audit_workflow_history (
    hist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    instance_id UUID NOT NULL REFERENCES audit.audit_workflow_instance(instance_id),
    from_step VARCHAR(100),
    to_step VARCHAR(100) NOT NULL,
    actor_id UUID REFERENCES audit.auditor(auditor_id),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    comments TEXT
);
COMMENT ON TABLE audit.audit_workflow_history_is 'Chronological log of all state transitions within a workflow instance';

CREATE INDEX idx_workflow_hist_instance ON audit.audit_workflow_history(instance_id, timestamp DESC);


-- Table: T171 - audit_search_queries
-- Description: Logs of search queries for analytics.
-- Business Case: Search Optimization. What are auditors looking for? If everyone searches for "Fraud" but gets 0 results, we know we have a content gap. This table logs search terms and result counts to improve the search index and content strategy.
-- KPIs: Zero Results Rate, Search Success.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS audit.audit_search_queries (
    search_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    query_text TEXT NOT NULL,
    results_count INTEGER,
    filters_json JSONB,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_search_queries_is 'Logs search terms to identify content gaps and improve search relevance';

CREATE INDEX idx_search_queries_text ON audit.audit_search_queries USING gin(to_tsvector('english', query_text));


-- Table: T172 - audit_clickstream_events
-- Description: High-volume clickstream for UX analysis (Anonymized).
-- Business Case: Deep UX Research. Unlike T154 (Feature Usage), this is raw clickstream (X/Y coordinates, mouse paths). It helps UI designers understand if buttons are in the right place or if users are getting lost in the UI. Data is anonymized to respect privacy.
-- KPIs: Task Completion Time.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_clickstream_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL, -- Anonymized Session ID
    element_id VARCHAR(100), -- UI Element clicked
    event_type VARCHAR(50) NOT NULL, -- CLICK, SCROLL, HOVER
    page_url TEXT,
    ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    metadata_json JSONB -- X/Y coords, scroll depth
);
COMMENT ON TABLE audit.audit_clickstream_events_is 'High-volume anonymized interaction logs for deep user experience (UX) analysis';

-- Partitioning strongly recommended for production


-- Table: T173 - audit_a_b_tests
-- Description: Configuration of A/B tests for UI.
-- Business Case: Product Experimentation. Should the "Submit" button be Blue or Green? Does "Alert A" convert better than "Alert B"? This table defines active experiments and the percentage of traffic allocated to each variant.
-- KPIs: Statistical Significance, Conversion Rate.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_a_b_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    start_date DATE NOT NULL,
    end_date DATE,
    status VARCHAR(20) DEFAULT 'DESIGN', -- DESIGN, RUNNING, PAUSED, COMPLETED
    target_audience TEXT, -- e.g. 'AUDITORS_TIER_1'
    success_metric VARCHAR(100) -- e.g. 'EXPORT_CLICK_RATE'
);
COMMENT ON TABLE audit.audit_a_b_tests IS 'Manages the definition and lifecycle of user interface A/B experiments';


-- Table: T174 - audit_a_b_test_assignments
-- Description: Mapping of users to A/B test variants.
-- Business Case: Experiment Consistency. If User A sees "Variant A" today, they must see "Variant A" tomorrow. This table records the assignment of each user to a specific test variant, ensuring consistency during the experiment period.
-- KPIs: Assignment Consistency.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_a_b_test_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id UUID NOT NULL REFERENCES audit.audit_a_b_tests(test_id),
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    variant VARCHAR(50) NOT NULL, -- 'A', 'B', 'CONTROL'
    assigned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_test_user UNIQUE (test_id, user_id)
);
COMMENT ON TABLE audit.audit_a_b_test_assignments_is 'Ensures consistent experience for users participating in A/B tests';

CREATE INDEX idx_ab_test_user ON audit.audit_a_b_test_assignments(user_id);


-- Table: T175 - audit_a_b_test_results
-- Description: Aggregated results of A/B tests.
-- Business Case: Statistical Analysis. Did Variant B perform significantly better? This table aggregates the metrics (e.g., Total Clicks, Conversions) per variant, allowing Product Managers to calculate p-values and determine a winner.
-- KPIs: Statistical Confidence (>95%).
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_a_b_test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id UUID NOT NULL REFERENCES audit.audit_a_b_tests(test_id),
    variant VARCHAR(50) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(19,4) NOT NULL,
    sample_size INTEGER NOT NULL,
    calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_a_b_test_results_is 'Stores aggregated performance data for each variant in an experiment';

CREATE UNIQUE INDEX idx_ab_results_metric ON audit.audit_a_b_test_results(test_id, variant, metric_name);


-- Table: T176 - audit_error_catalog
-- Description: Catalog of known error codes and messages.
-- Business Case: Error Localization and User Support. Instead of showing "Error 500x", we map it to "Error: Network Timeout". This table catalogs all internal error codes, linking them to human-readable messages and troubleshooting steps, displayed to users or support staff.
-- KPIs: Error Resolution Time.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_error_catalog (
    error_code VARCHAR(50) PRIMARY KEY, -- 'AUTH_001', 'DB_TIMEOUT'
    message TEXT NOT NULL, -- User-facing message
    severity VARCHAR(20) NOT NULL, -- 'INFO', 'ERROR', 'CRITICAL'
    troubleshooting_url TEXT, -- Link to Confluence
    category VARCHAR(50), -- 'NETWORK', 'AUTH', 'VALIDATION'
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE audit.audit_error_catalog_is 'Standardized registry of error messages for consistent user communication';


-- Table: T177 - audit_error_logs
-- Description: Application error logs.
-- Business Case: Debugging. When the app crashes, this is the "Black Box". It stores stack traces, request IDs, and user context. Developers query this to fix bugs in the field.
-- KPIs: Error Volume, MTTR.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.audit_error_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    error_code VARCHAR(50) REFERENCES audit.audit_error_catalog(error_code),
    message TEXT NOT NULL,
    stack_trace TEXT,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    request_id UUID, -- HTTP Request ID
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    environment VARCHAR(20) DEFAULT 'PRODUCTION' -- DEV, STAGING, PROD
);
COMMENT ON TABLE audit.audit_error_logs_is 'Detailed logs of application exceptions for debugging and support';

CREATE INDEX idx_error_logs_ts ON audit.audit_error_logs(timestamp DESC);
CREATE INDEX idx_error_logs_code ON audit.audit_error_logs(error_code, timestamp DESC);


-- Table: T178 - audit_health_checks
-- Description: Results of periodic health checks.
-- Business Case: Uptime Monitoring. Automated pings (e.g., from Opsgenie or Datadog) hit this table's endpoint to say "I'm alive". It records the latency and status of every check.
-- KPIs: Availability %.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.audit_health_checks (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'PASS', 'FAIL', 'DEGRADED'
    latency_ms INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_health_checks_is 'Stores the results of synthetic monitoring checks to measure system availability';

CREATE INDEX idx_health_checks_service ON audit.audit_health_checks(service_name, timestamp DESC);


-- Table: T179 - audit_dependency_map
-- Description: Graph of service dependencies.
-- Business Case: Impact Analysis. If "Tax Calculator Service" goes down, who suffers? This table maps dependencies (A -> B -> C). It allows Ops to visualize the blast radius of a failure and identify single points of failure.
-- KPIs: Dependency Graph Completeness.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.audit_dependency_map (
    dep_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    upstream_service VARCHAR(100) NOT NULL, -- The provider
    downstream_service VARCHAR(100) NOT NULL, -- The consumer
    dependency_type VARCHAR(50) DEFAULT 'HTTP', -- 'HTTP', 'DB', 'QUEUE'
    is_critical BOOLEAN DEFAULT FALSE, -- If true, downstream breaks without upstream
    description TEXT
);
COMMENT ON TABLE audit.audit_dependency_map_is 'Maps the relationships between microservices to aid in architecture and failure analysis';


-- Table: T180 - audit_deployment_history
-- Description: History of deployments.
-- Business Case: Release Management. Who deployed what and when? This table logs every deployment (Git Commit SHA, Environment, Deployer). It is the first place to look when investigating "when did this bug appear?".
-- KPIs: Deployment Frequency.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS audit.audit_deployment_history (
    deploy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(50) NOT NULL,
    environment VARCHAR(20) NOT NULL, -- 'PRODUCTION', 'STAGING'
    deployed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) NOT NULL, -- 'SUCCESS', 'FAILED', 'ROLLBACK'
    finished_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    git_sha CHAR(40),
    build_url TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_deployment_history_is 'Tracks the history of software releases across environments';

CREATE INDEX idx_deploy_history_env ON audit.audit_deployment_history(environment, finished_at DESC);


-- Table: T181 - audit_rollback_history
-- Description: History of rollbacks.
-- Business Case: Safety Analysis. Why did we roll back? Was it a bad DB migration? This table records rollback events, allowing the team to analyze why a deployment failed and how long it took to revert.
-- KPIs: Rollback Rate.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS audit.audit_rollback_history (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deploy_id UUID NOT NULL REFERENCES audit.audit_deployment_history(deploy_id),
    reason TEXT NOT NULL,
    rolled_back_to_version VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    performed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_rollback_history_is 'Records events where a deployment was reverted to a previous version';


-- Table: T182 - audit_feature_flags_audit
-- Description: Audit log of feature flag changes.
-- Business Case: Governance. Feature flags are powerful but dangerous if misused. This table logs every change to a flag (Enabled -> Disabled, 10% -> 50%). It ensures accountability for who exposed a feature to whom.
-- KPIs: Flag Compliance.
-- Feature Reference: F054
CREATE TABLE IF NOT EXISTS audit.audit_feature_flags_audit (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_key VARCHAR(100) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    changed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    change_reason TEXT
);
COMMENT ON TABLE audit.audit_feature_flags_audit_is 'Immutable log of changes to feature flags for governance and compliance';

CREATE INDEX idx_ff_audit_flag ON audit.audit_feature_flags_audit(flag_key, ts DESC);


-- Table: T183 - audit_api_gateway_logs
-- Description: Raw logs from API Gateway.
-- Business Case: Traffic Analysis. Every request hits the gateway before the app. This table stores the raw logs (Path, Method, IP, User-Agent). It is used for analytics (e.g., "Which endpoints are most popular?") and security (e.g., "DDoS detection").
-- KPIs: Request Volume, Response Time.
-- Feature Reference: F057
CREATE TABLE IF NOT EXISTS audit.audit_api_gateway_logs (
    gw_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id UUID,
    path TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER,
    client_ip INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_api_gateway_logs_is 'Ingests high-volume HTTP traffic logs for analytics and security monitoring';

-- Note: High write volume. Partitioning is required.


-- Table: T184 - audit_throttling_events
-- Description: Events where throttling was applied.
-- Business Case: Abuse Prevention. If a user tries to download 1TB of data or sends 1000 req/sec, we throttle them. This table logs those events. It helps distinguish between legitimate heavy users and malicious attackers.
-- KPIs: Throttle Rate.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.audit_throttling_events (
    throttle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    limit_type VARCHAR(50) NOT NULL, -- 'RATE_LIMIT', 'QUOTA_EXCEEDED'
    attempted_rate NUMERIC(10,2),
    limit_value NUMERIC(10,2),
    ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_throttling_events_is 'Logs when rate limiting policies are triggered to identify abuse or misconfiguration';

CREATE INDEX idx_throttle_user ON audit.audit_throttling_events(user_id, ts DESC);


-- Table: T185 - audit_cache_invalidation
-- Description: Log of cache invalidation commands.
-- Business Case: Cache Coherence. Caches speed things up, but they can get stale (e.g., Merchant Name changes). This table logs invalidation events ("Clear cache for Merchant 123"). It helps debug cases where users see old data.
-- KPIs: Cache Miss Rate.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.audit_cache_invalidation (
    inv_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_key TEXT NOT NULL, -- Pattern like 'merchant_*' or specific key
    trigger_reason VARCHAR(100) NOT NULL, -- 'UPDATE', 'MANUAL', 'TTL'
    invalidated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    triggered_by UUID REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.audit_cache_invalidation_is 'Tracks cache clearing events to troubleshoot stale data issues';

CREATE INDEX idx_cache_inv_key ON audit.audit_cache_invalidation(cache_key);


-- Table: T186 - audit_db_migration_history
-- Description: History of DB schema migrations.
-- Business Case: Schema Versioning. The DB evolves. This table lists every migration script (Up/Down) that has been applied. It ensures all environments (Dev, Stage, Prod) are in sync and allows rollback by running the "Down" script.
-- KPIs: Migration Success Rate.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS audit.audit_db_migration_history (
    migration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    script_name VARCHAR(255) NOT NULL UNIQUE,
    checksum CHAR(64) NOT NULL, -- SHA of the script file
    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INTEGER,
    success BOOLEAN NOT NULL
);
COMMENT ON TABLE audit.audit_db_migration_history_is 'Tracks the application of database schema changes for version control';


-- Table: T187 - audit_backup_verification
-- Description: Logs of backup integrity checks.
-- Business Case: DR Confidence. Taking a backup isn't enough; we must be able to *restore* it. This table logs periodic "Restore Drills" where we verify the checksum of the backup.
-- KPIs: Backup Integrity (100%).
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.audit_backup_verification (
    verify_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id UUID NOT NULL, -- Links to T086
    checksum_verified BOOLEAN NOT NULL,
    verification_method VARCHAR(50), -- 'SHA_COMPARE', 'PARTIAL_RESTORE'
    verified_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    restore_test_success BOOLEAN
);
COMMENT ON TABLE audit.audit_backup_verification_is 'Records integrity checks performed on database backups to ensure recoverability';


-- Table: T188 - audit_replication_lag
-- Description: Metrics for DB replication lag.
-- Business Case: High Availability (HA) Monitoring. The Primary DB replicates to Standbys. If Lag > 5 mins, we risk losing data if Primary fails. This table tracks the lag in seconds/bytes.
-- KPIs: Replication Lag (< 5s).
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.audit_replication_lag (
    lag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_db VARCHAR(100) NOT NULL,
    replica_db VARCHAR(100) NOT NULL,
    lag_seconds INTEGER NOT NULL,
    lag_bytes BIGINT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_replication_lag_is 'Monitors the delay in data replication between database instances';

CREATE INDEX idx_rep_lag_ts ON audit.audit_replication_lag(timestamp DESC);


-- Table: T189 - audit_connection_pool
-- Description: Real-time stats of DB connection pools.
-- Business Case: Resource Monitoring. Connection pools are expensive. If all are "Active", new requests wait. This table tracks pool stats (Active, Idle, Waiting) to alert Ops before the app hangs.
-- KPIs: Pool Utilization (< 80%).
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.audit_connection_pool (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,
    active_connections INTEGER NOT NULL,
    idle_connections INTEGER NOT NULL,
    waiting_count INTEGER DEFAULT 0,
    max_connections INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_connection_pool_is 'Time-series tracking of database connection pool utilization';


-- Table: T190 - audit_table_size_stats
-- Description: History of table sizes (disk usage).
-- Business Case: Storage Planning. Some tables grow faster than others. This table tracks the physical disk size of every table weekly. It helps predict when we need to add storage or archive data.
-- KPIs: Disk Usage Growth Rate.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_table_size_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    schema_name VARCHAR(100) NOT NULL,
    size_mb NUMERIC(10,2) NOT NULL,
    row_count BIGINT,
    timestamp DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(table_name, timestamp)
);
COMMENT ON TABLE audit.audit_table_size_stats_is 'Historical tracking of database table storage consumption for capacity planning';


-- Table: T191 - audit_index_size_stats
-- Description: History of index sizes.
-- Business Case: Performance Tuning. Indexes speed up reads but consume disk and slow down writes. This table tracks index size. If an index grows faster than the table, it might be bloated and needs rebuilding.
-- KPIs: Index Bloat.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_index_size_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    index_name VARCHAR(255) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    size_mb NUMERIC(10,2) NOT NULL,
    timestamp DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(index_name, timestamp)
);
COMMENT ON TABLE audit.audit_index_size_stats_is 'Monitors the disk usage of indexes to detect bloat or fragmentation';


-- Table: T192 - audit_lock_waits
-- Description: History of database lock waits.
-- Business Case: Concurrency Performance. If Transaction A locks a row, and Transaction B waits for 10 seconds, that's a "Lock Wait". High lock waits indicate contention or slow transactions. This table logs these waits to help DBAs optimize queries.
-- KPIs: Avg Lock Wait Time (< 100ms).
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_lock_waits (
    wait_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_id UUID, -- The waiting query
    blocked_by_query_id UUID,
    lock_type VARCHAR(50) NOT NULL, -- 'ExclusiveLock', 'RowShareLock'
    relation VARCHAR(100), -- Table name
    wait_duration_ms INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_lock_waits_is 'Captures events where database queries were blocked by locks to identify bottlenecks';


-- Table: T193 - audit_deadlocks
-- Description: Log of deadlock events.
-- Business Case: Critical Bug Fixing. A Deadlock (A waits for B, B waits for A) causes a transaction to fail. This table logs the victim query and the winning query, providing the data needed to rewrite code and prevent the cycle.
-- KPIs: Deadlock Count.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_deadlocks (
    deadlock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    victim_query TEXT NOT NULL,
    winning_query TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_deadlocks_is 'Captures fatal deadlock events requiring immediate code remediation';


-- Table: T194 - audit_long_running_txns
-- Description: Log of transactions exceeding duration threshold.
-- Business Case: Resource Management. Long transactions hold locks and bloat the WAL (Write Ahead Log). This table logs any transaction running > 5 mins (or threshold). It prevents a single query from degrading the whole system.
-- KPIs: Long Transaction Count.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_long_running_txns (
    txn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    duration_sec INTEGER NOT NULL,
    query_text TEXT,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    start_ts TIMESTAMPTZ NOT NULL,
    state VARCHAR(50), -- 'active in transaction'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_long_running_txns_is 'Identifies transactions holding locks for too long, risking system stability';


-- Table: T195 - audit_materialized_view_stats
-- Description: Refresh stats for MVs.
-- Business Case: MV Performance. Materialized Views (MVs) are great for performance, but refreshing them can be heavy. This table tracks how long each MV takes to refresh. If refresh time > SLA, we know the MV needs optimization.
-- KPIs: MV Refresh Time.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.audit_materialized_view_stats (
    mv_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mv_name VARCHAR(255) NOT NULL,
    last_refresh TIMESTAMPTZ NOT NULL,
    duration_ms INTEGER NOT NULL,
    data_freshness_sec INTEGER, -- Staleness
    row_count BIGINT
);
COMMENT ON TABLE audit.audit_materialized_view_stats_is 'Monitors the performance and freshness of materialized views';


-- Table: T196 - audit_partition_stats
-- Description: Stats for table partitions.
-- Business Case: Partition Management. We partition tables by date. If one partition has 10x the data of others (Skew), queries become slow. This table tracks row count per partition to identify skew.
-- KPIs: Data Skew Ratio.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.audit_partition_stats (
    part_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    partition_key VARCHAR(100) NOT NULL, -- e.g. '2023-10-01'
    row_count BIGINT NOT NULL,
    size_mb NUMERIC(10,2),
    timestamp DATE NOT NULL DEFAULT CURRENT_DATE
);
COMMENT ON TABLE audit.audit_partition_stats_is 'Analyzes data distribution across table partitions to detect imbalance';


-- Table: T197 - audit_data_skew
-- Description: Analysis of data skew across partitions.
-- Business Case: Performance Diagnostics. This table stores the *result* of a skew analysis (e.g., "Partition A has 90% of data"). It alerts developers to fix the partitioning strategy.
-- KPIs: Skew Factor.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_data_skew (
    skew_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    partition_key VARCHAR(100) NOT NULL,
    skew_ratio NUMERIC(5,2) NOT NULL, -- > 1.0 indicates skew
    recommendation TEXT,
    analyzed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_data_skew_is 'Identifies performance bottlenecks caused by uneven data distribution';


-- Table: T198 - audit_query_plan_cache
-- Description: Stats on query plan cache hits/misses.
-- Business Case: CPU Efficiency. Planning a query is CPU intensive. Caching the plan saves CPU. This table tracks the "Hit Ratio" of the plan cache. Low hit ratio suggests high variability in queries (dynamic SQL) which might need optimization.
-- KPIs: Plan Cache Hit Ratio (>90%).
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_query_plan_cache (
    cache_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash CHAR(64) NOT NULL,
    plan_hash CHAR(64) NOT NULL,
    hit_count BIGINT DEFAULT 0,
    last_hit TIMESTAMPTZ
);
COMMENT ON TABLE audit.audit_query_plan_cache_is 'Tracks the efficiency of the database query planner cache';


-- Table: T199 - audit_temp_file_usage
-- Description: Usage of temporary space (sort/hash).
-- Business Case: Memory/Disk Management. Complex queries (Sort, Hash Join) spill to disk if they don't fit in RAM (work_mem). This table tracks temp file usage. High usage means we need more RAM or better indexes.
-- KPIs: Temp File Bytes.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_temp_file_usage (
    temp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id BIGINT,
    operation VARCHAR(50), -- 'Sort', 'HashJoin'
    size_bytes BIGINT NOT NULL,
    table_name VARCHAR(100),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_temp_file_usage_is 'Monitors disk spilling to identify queries exceeding memory allocations';


-- Table: T200 - audit_wal_statistics
-- Description: Write-Ahead Log statistics.
-- Business Case: Transaction Throughput. The WAL is where all changes go before hitting the main data files. Monitoring WAL size and rotation speed helps tune `checkpoint_segments` and `wal_buffers`.
-- KPIs: WAL Throughput, Checkpoint Duration.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.audit_wal_statistics (
    wal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wal_size_mb NUMERIC(10,2) NOT NULL,
    wal_rotation_count INTEGER NOT NULL,
    checkpoint_lag_sec INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_wal_statistics_is 'Tracks the volume and rotation frequency of transaction logs to tune I/O performance';

CREATE INDEX idx_wal_stats_ts ON audit.audit_wal_statistics(timestamp DESC);

-- End of Script Part 4 (Objects E020, T151-T200)
-- All 200 Tables have been generated with enhancements and documentation.

-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 5: Objects 201-250)
-- ================================================================================
-- Description: This script continues the database object creation for the Independent
-- Auditor Interface, extending into Mobile support, advanced ML Ops, deep
-- forensics, and granular system administration.
--
-- Scope: Database Objects T201 - T250.
-- Note: The initial list provided in the prompt extended to T200. This script
-- logically extrapolates the remaining requirements (T201-T250) based on the
-- comprehensive feature set (F001-F150) and the architectural needs of a
-- large-scale audit system (Mobile, ML, Blockchain, Globalization).
-- ================================================================================

-- 4. DDL Statements (Tables T201 - T250)
-- ================================================================================

-- Table: T201 - mobile_device_info
-- Description: Registration and metadata for auditor mobile devices.
-- Business Case: Mobile Security and Policy Enforcement. As auditors move to field work (F052), we must manage their devices. This table stores device fingerprints, OS versions, and security posture (Jailbreak status). It allows the Mobile Device Management (MDM) system to enforce policies like "Must have PIN" or "Must be encrypted". If a device is compromised, this table blocks its API keys.
-- KPIs: Device Compliance Rate, MDM Enrollment.
-- Feature Reference: F052, F098
CREATE TABLE IF NOT EXISTS audit.mobile_device_info (
    device_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    device_name VARCHAR(100) NOT NULL,
    device_type VARCHAR(50) CHECK (device_type IN ('IOS', 'ANDROID', 'TABLET')),
    os_version VARCHAR(50),
    app_version VARCHAR(20), -- PARI App Version
    is_jailbroken BOOLEAN DEFAULT FALSE,
    is_encrypted BOOLEAN DEFAULT TRUE,
    last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    token_hash CHAR(64), -- Hash of the push token for lookup

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.mobile_device_info IS 'Registers and manages security posture of auditor mobile devices';

CREATE INDEX idx_mobile_auditor ON audit.mobile_device_info(auditor_id);


-- Table: T202 - mobile_push_tokens
-- Description: Stores push notification tokens for mobile devices.
-- Business Case: Real-Time Field Communication. When a high-value transaction occurs or a finding is assigned, the auditor needs to know *now*. This table maps Device IDs to APNS (Apple) or FCM (Google) tokens. It ensures that notifications are routed to the correct physical device currently in the auditor's pocket, enabling instant response.
-- KPIs: Push Delivery Success Rate.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS audit.mobile_push_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES audit.mobile_device_info(device_id),
    provider VARCHAR(20) NOT NULL CHECK (provider IN ('APNS', 'FCM', 'HMS')), -- Huawei
    token_text TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_registered TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.mobile_push_tokens IS 'Stores provider-specific tokens for routing push notifications to mobile apps';

CREATE INDEX idx_push_active ON audit.mobile_push_tokens(is_active);


-- Table: T203 - mobile_offline_queue
-- Description: Queue for actions taken while offline.
-- Business Case: Offline Capability. Field auditors often enter secure facilities with no internet. They create findings or take notes offline. This table stores these pending actions as soon as the device reconnects. It acts as a sync buffer, ensuring no data is lost during connectivity gaps, using CRDTs (Conflict-Free Replicated Data Types) logic to merge changes.
-- KPIs: Sync Conflict Rate (<1%), Data Loss Rate (0%).
-- Feature Reference: F052, F090
CREATE TABLE IF NOT EXISTS audit.mobile_offline_queue (
    queue_item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES audit.mobile_device_info(device_id),
    action_type VARCHAR(50) NOT NULL, -- 'CREATE_FINDING', 'ADD_COMMENT', 'UPLOAD_PHOTO'
    payload_json JSONB NOT NULL,
    local_timestamp TIMESTAMPTZ NOT NULL,
    server_sync_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SYNCED, CONFLICT
    sync_attempt_count INTEGER DEFAULT 0,
    last_sync_attempt TIMESTAMPTZ,
    conflict_resolution JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.mobile_offline_queue IS 'Sync queue for actions taken by auditors while offline';

CREATE INDEX idx_offline_queue_status ON audit.mobile_offline_queue(server_sync_status, sync_attempt_count);


-- Table: T204 - ml_anomaly_score_history
-- Description: Time-series storage of ML anomaly scores.
-- Business Case: Model Performance Forensics. When a fraud model flags a transaction as "90% suspicious", we need to know if that score is trending up or down over time. This table stores the historical scores of entities. If a merchant's risk score jumps from 0.1 to 0.8 in a week, it triggers a manual review, even if the score itself hasn't hit the "Critical" threshold yet.
-- KPIs: Score Trend Velocity, Prediction Lag.
-- Feature Reference: F012, F074
CREATE TABLE IF NOT EXISTS audit.ml_anomaly_score_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- MERCHANT, WALLET, SUPPLIER
    model_name VARCHAR(100) NOT NULL,
    score NUMERIC(5,4) NOT NULL, -- The probability/risk score
    feature_contributions JSONB, -- e.g. {"volatility": 0.4, "network": 0.6}
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ml_anomaly_score_history IS 'Stores historical ML risk scores to detect trend anomalies and model drift';

CREATE INDEX idx_score_history_entity ON audit.ml_anomaly_score_history(entity_id, calculated_at DESC);


-- Table: T205 - ml_model_drift_alerts
-- Description: Alerts triggered when model performance degrades.
-- Business Case: Continuous Model Retraining (CMMI). Fraud patterns change. A model trained on 2022 data might fail in 2023. This table logs "Drift Alerts" generated when the input data distribution (e.g., average transaction amount) changes significantly from the training data. It triggers the automated retraining pipeline (F132) before the model becomes useless.
-- KPIs: Drift Detection Latency, False Drift Rate.
-- Feature Reference: F132, T093
CREATE TABLE IF NOT EXISTS audit.ml_model_drift_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    drift_metric VARCHAR(100) NOT NULL, -- 'KL_DIVERGENCE', 'POPULATION_STABILITY_INDEX'
    threshold_value NUMERIC(10,4) NOT NULL,
    actual_value NUMERIC(10,4) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, RETRAINING, RESOLVED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ml_model_drift_alerts IS 'Monitors data distribution changes to trigger proactive model retraining';

CREATE INDEX idx_drift_status ON audit.ml_model_drift_alerts(status, detected_at DESC);


-- Table: T206 - blockchain_block_header
-- Description: Stores blockchain block headers for verification.
-- Business Case: Ledger Integrity Anchor. The PARI system relies on a blockchain (M01) for immutability. To verify that our database (M06) matches the blockchain truth, we store Block Headers (Hash, Timestamp, Parent Hash). Periodically, we calculate the Merkle Root of our DB tables and compare it to this Block Header. A mismatch indicates data tampering.
-- KPIs: Hash Consistency, Block Sync Latency.
-- Feature Reference: F051, F068
CREATE TABLE IF NOT EXISTS audit.blockchain_block_header (
    block_number BIGINT PRIMARY KEY,
    block_hash CHAR(64) NOT NULL UNIQUE,
    parent_block_hash CHAR(64),
    miner_address CHAR(42),
    timestamp TIMESTAMPTZ NOT NULL,
    transaction_count INTEGER NOT NULL,
    size_bytes BIGINT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.blockchain_block_header IS 'Anchors audit data to the blockchain ledger for cryptographic verification';

CREATE INDEX idx_blockchain_ts ON audit.blockchain_block_header(timestamp DESC);


-- Table: T207 - smart_contract_abi
-- Description: Stores ABI definitions for smart contracts.
-- Business Case: Dynamic Interaction. We don't hardcode smart contract interactions. This table stores the Application Binary Interface (ABI) JSON for every contract we monitor. It allows the system to dynamically decode function calls and events (e.g., 'transfer(address,uint256)') without code changes, ensuring we can audit any new contract deployed on the network.
-- KPIs: ABI Parsing Success, Coverage.
-- Feature Reference: F051
CREATE TABLE IF NOT EXISTS audit.smart_contract_abi (
    abi_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(42) UNIQUE NOT NULL,
    abi_json JSONB NOT NULL,
    contract_name VARCHAR(255),
    verified BOOLEAN DEFAULT FALSE,
    source_explorer VARCHAR(100), -- Etherscan, Blockscout
    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.smart_contract_abi IS 'Stores ABI definitions to dynamically decode blockchain transaction data';


-- Table: T208 - cross_jurisdiction_rate_map
-- Description: Maps tax rates for transactions involving two regions.
-- Business Case: Cross-Border Commerce Logic. A digital service might be sold by a company in Germany to a consumer in France. Which VAT rate applies? Standard domestic tables (T105) don't solve this. This table stores the matrix of "Origin -> Destination" rates and rules (e.g., EU One-Stop Shop), ensuring correct tax calculation for global trade.
-- KPIs: Tax Calculation Accuracy, Rule Match Rate.
-- Feature Reference: F033, F100
CREATE TABLE IF NOT EXISTS audit.cross_jurisdiction_rate_map (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    origin_country CHAR(2) NOT NULL,
    destination_country CHAR(2) NOT NULL,
    service_type VARCHAR(50) NOT NULL, -- 'DIGITAL_SERVICES', 'PHYSICAL_GOODS'
    tax_rate NUMERIC(5,4) NOT NULL,
    reverse_charge BOOLEAN DEFAULT FALSE, -- Is liability reversed?
    legal_basis TEXT, -- EU VAT Directive Article
    effective_date DATE NOT NULL,
    expiry_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_cross_dates CHECK (expiry_date IS NULL OR expiry_date > effective_date)
);
COMMENT ON TABLE audit.cross_jurisdiction_rate_map IS 'Complex mapping for international trade tax liabilities and reverse charges';

CREATE UNIQUE INDEX idx_cross_jur_map ON audit.cross_jurisdiction_rate_map(origin_country, destination_country, service_type);


-- Table: T209 - escalation_sla_matrix
-- Description: Defines SLAs for escalation based on finding severity.
-- Business Case: Workflow Automation. Not all findings are equal. A "Critical" finding must be escalated to the Head of Tax Authority within 1 hour. This table defines the SLA Matrix: "If Severity = X, Escalate to Role Y within Z minutes". It drives the automated workflow engine (F107) to ensure high-priority risks get immediate attention.
-- KPIs: SLA Compliance Rate (>99%), Escalation Latency.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.escalation_sla_matrix (
    matrix_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    target_role VARCHAR(100) NOT NULL,
    escalation_deadline_minutes INTEGER NOT NULL,
    notification_channel VARCHAR(50), -- EMAIL, SMS, PAGER
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.escalation_sla_matrix IS 'Defines service level agreement rules for automatic escalation of audit findings';


-- Table: T210 - auditor_skill_certifications
-- Description: Tracks professional certifications of auditors.
-- Business Case: Resource Planning and Compliance. To audit VAT, one needs specific certifications (e.g., Certified Fraud Examiner, CPA). This table tracks which auditors hold which valid certs. The system can then route cases intelligently ("Only a CFE can handle this complex fraud case") and ensure legal compliance of the audit team itself.
-- KPIs: Certification Validity, Skill Coverage.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.auditor_skill_certifications (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    certification_name VARCHAR(255) NOT NULL,
    issuing_body VARCHAR(255) NOT NULL, -- AICPA, ACCA, etc.
    certificate_number VARCHAR(100),
    issue_date DATE NOT NULL,
    expiry_date DATE,
    verified_document_path TEXT, -- Proof

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor_skill_certifications IS 'Registry of professional qualifications enabling role-based task routing';

CREATE INDEX idx_skill_auditor ON audit.auditor_skill_certifications(auditor_id);


-- Table: T211 - knowledge_base_articles
-- Description: Articles for internal support/knowledge base.
-- Business Case: Self-Service Efficiency. Reducing support ticket volume is key. This table stores rich-text articles, guides, and FAQs. The integrated "Smart Search" (F094) queries this table to give auditors instant answers without waiting for an email response from support.
-- KPIs: Deflection Rate, Article Utility.
-- Feature Reference: F111, F163
CREATE TABLE IF NOT EXISTS audit.knowledge_base_articles (
    article_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    body_html TEXT NOT NULL,
    category VARCHAR(100),
    tags TEXT[],
    language CHAR(2) DEFAULT 'EN',
    author_id UUID NOT NULL,
    view_count INTEGER DEFAULT 0,
    helpful_count INTEGER DEFAULT 0,
    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'PUBLISHED', -- DRAFT, PUBLISHED, ARCHIVED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.knowledge_base_articles IS 'Repository of support documentation and guides for auditor self-service';

CREATE INDEX idx_kb_category ON audit.knowledge_base_articles(category, status);


-- Table: T212 - kb_search_relevance
-- Description: Logs search results on Knowledge Base.
-- Business Case: Search Optimization. We need to know if the "Smart Search" is actually helping. This table logs what users searched for, which article was clicked (if any), and the search result score. This data feeds back into the search ranking algorithm (learning to rank), ensuring the "Deflection Rate" improves over time.
-- KPIs: Search Click-Through Rate (CTR).
-- Feature Reference: F094, F111
CREATE TABLE IF NOT EXISTS audit.kb_search_relevance (
    search_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_query TEXT NOT NULL,
    article_clicked UUID REFERENCES audit.knowledge_base_articles(article_id),
    result_rank INTEGER, -- Was it the 1st, 2nd, 10th result?
    clicked BOOLEAN DEFAULT FALSE,
    search_ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.kb_search_relevance IS 'Logs interaction with knowledge base to train search ranking algorithms';


-- Table: T213 - ui_theme_configurations
-- Description: Custom UI themes for whitelabeling/client branding.
-- Business Case: B2B White-Labeling. Large clients (e.g., a National Bank) might want the Auditor Interface to look like *their* system. This table stores CSS variables, logos, and color palettes. It allows the platform to render differently based on the client's domain, supporting white-label licensing models.
-- KPIs: Theme Consistency, Load Time Impact.
-- Feature Reference: F070
CREATE TABLE IF NOT EXISTS audit.ui_theme_configurations (
    theme_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    theme_name VARCHAR(100) NOT NULL,
    client_id UUID, -- NULL for default PARI theme
    logo_url TEXT,
    primary_color_hex CHAR(7),
    secondary_color_hex CHAR(7),
    custom_css TEXT,
    font_family VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.ui_theme_configurations IS 'Stores branding assets and styles for white-label implementations';


-- Table: T214 - i18n_translations
-- Description: Internationalization strings for UI.
-- Business Case: Global Accessibility. PARI operates across 24+ countries (F076). This table stores every UI string in every supported language (EN, ES, DE, FR...). It enables instant switching of languages without code deployment and ensures legal terms are translated correctly by professional linguists.
-- KPIs: Translation Coverage (%), Update Latency.
-- Feature Reference: F076
CREATE TABLE IF NOT EXISTS audit.i18n_translations (
    translation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_name VARCHAR(255) NOT NULL, -- e.g. 'nav_home', 'error_404'
    language_code CHAR(2) NOT NULL,
    value TEXT NOT NULL,
    context TEXT, -- Helps translators understand usage
    last_verified TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_translation UNIQUE (key_name, language_code)
);
COMMENT ON TABLE audit.i18n_translations IS 'Database-driven localization system for multi-language support';


-- Table: T215 - external_api_throttles
-- Description: Throttling limits for external Tax Authority APIs.
-- Business Case: External API Governance. We cannot spam the Spanish Tax Agency (SII) or they will ban our IP. This table manages dynamic throttling for *outbound* calls. It tracks "Remaining Quota" per minute/hour and queues requests if we are hitting the limit, preventing service disruption.
-- KPIs: Throttle Success Rate, External API Uptime.
-- Feature Reference: F010
CREATE TABLE IF NOT EXISTS audit.external_api_throttles (
    throttle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    connector_id UUID NOT NULL REFERENCES audit.national_tax_connectors(connector_id),
    limit_window VARCHAR(20) NOT NULL, -- 'MINUTE', 'HOUR', 'DAY'
    max_requests INTEGER NOT NULL,
    current_requests INTEGER DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    wait_until TIMESTAMPTZ, -- If throttled, when to retry

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.external_api_throttles IS 'Manages rate limits for outbound calls to prevent blacklisting by external services';


-- Table: T216 - ingestion_error_patterns
-- Description: Aggregated patterns of errors during data ingestion.
-- Business Case: Supplier Quality Management. Instead of just logging "Error", this table aggregates patterns. e.g., "Supplier X sends 'Invalid VAT Format' 50 times a day". It allows us to automatically reach out to the supplier or block their feed, preventing the ingestion pipeline from clogging with bad data.
-- KPIs: Error Pattern Detection Time, Supplier Quality Score.
-- Feature Reference: F083, T145
CREATE TABLE IF NOT EXISTS audit.ingestion_error_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_system VARCHAR(100) NOT NULL, -- e.g., 'MERCHANT_API_X'
    error_type VARCHAR(100) NOT NULL, -- e.g., 'JSON_PARSE_ERROR', 'SCHEMA_VIOLATION'
    occurrence_count BIGINT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20), -- LOW, MEDIUM, HIGH (impacts volume)
    mitigation_status VARCHAR(20) -- DETECTED, CONTACTED, RESOLVED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ingestion_error_patterns IS 'Aggregates repeated data errors to identify systemic supplier issues';

CREATE INDEX idx_ingest_pattern_source ON audit.ingestion_error_patterns(source_system, error_type);


-- Table: T217 - data_quality_anomalies
-- Description: Logs of specific data quality rule failures.
-- Business Case: Audit Trail for Quality. While T033 tracks *metrics*, this table logs the *events*. "Row 543 in 'Sales' table failed 'Not Null' check for 'Invoice ID'". It provides the specific evidence needed to contact the data owner and ask for a correction file.
-- KPIs: Anomaly Resolution Time.
-- Feature Reference: F040
CREATE TABLE IF NOT EXISTS audit.data_quality_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    primary_key_value UUID, -- Identifier of the bad row
    rule_name VARCHAR(100) NOT NULL, -- e.g. 'VAT_RANGE_CHECK'
    expected_value JSONB,
    actual_value JSONB,
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, ACKNOWLEDGED, FIXED
    assigned_to UUID,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_quality_anomalies IS 'Detailed log of individual records failing data quality validation rules';

CREATE INDEX idx_dq_status ON audit.data_quality_anomalies(status, detected_at DESC);


-- Table: T218 - auditor_training_records
-- Description: Tracks training courses taken by auditors.
-- Business Case: Compliance and Skill Development. Auditors must complete "Anti-Money Laundering 101" annually. This table tracks course progress, quiz scores, and completion status. It feeds into the "Onboarding Checklist" (F069) and ensures the team maintains professional licensure.
-- KPIs: Training Completion Rate, Average Score.
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.auditor_training_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    course_id UUID NOT NULL, -- Links to LMS
    course_name VARCHAR(255) NOT NULL,
    enrollment_date DATE NOT NULL DEFAULT CURRENT_DATE,
    completion_date DATE,
    status VARCHAR(20) NOT NULL, -- ENROLLED, IN_PROGRESS, COMPLETED, FAILED
    score NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor_training_records IS 'Tracks continuing education and compliance training for audit staff';


-- Table: T219 - training_completion_certs
-- Description: Stores PDFs of completion certificates.
-- Business Case: Proof of Training. When an auditor finishes a course, they get a PDF. This table stores the reference to that S3 file. It allows auditors to download their own certificates for personal records or HR reviews, and allows Admins to verify them during audits.
-- KPIs: Certificate Availability.
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.training_completion_certs (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    training_record_id UUID NOT NULL REFERENCES audit.auditor_training_records(record_id),
    file_path TEXT NOT NULL, -- S3 Path
    issued_by UUID NOT NULL, -- System or Instructor
    issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    valid_until DATE

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.training_completion_certs IS 'Stores generated certificates for completed training courses';


-- Table: T220 - email_reputation_tracking
-- Description: Tracks domain reputation to avoid spam filters.
-- Business Case: Deliverability Assurance. If "noreply@pariaudit.com" gets flagged as spam, critical VAT alerts won't reach tax authorities. This table monitors the IP and Domain reputation scores from external providers. If reputation drops, it alerts Ops to rotate IPs or warm up new domains.
-- KPIs: Email Deliverability Rate (>98%).
-- Feature Reference: F019, T141
CREATE TABLE IF NOT EXISTS audit.email_reputation_tracking (
    reputation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sending_domain VARCHAR(255) NOT NULL,
    sending_ip INET,
    reputation_score INTEGER CHECK (reputation_score BETWEEN 0 AND 100),
    provider VARCHAR(100), -- Google Postmaster, Microsoft SNDS
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.email_reputation_tracking IS 'Monitors sending reputation to ensure high email deliverability';

CREATE INDEX idx_email_rep_domain ON audit.email_reputation_tracking(sending_domain, checked_at DESC);


-- Table: T221 - sms_cost_centers
-- Description: Allocates SMS costs to specific departments or cases.
-- Business Case: Financial Accountability. SMS costs money (especially for international verification). This table attributes the cost of every SMS sent (via T142) to a specific "Cost Center" or "Case ID". It allows Finance to bill the correct department or client for the usage, rather than absorbing it into general IT overhead.
-- KPIs: Cost Allocation Accuracy.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS audit.sms_cost_centers (
    allocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sms_id UUID NOT NULL REFERENCES audit.audit_sms_queue(sms_id),
    cost_center_code VARCHAR(50) NOT NULL,
    cost_amount NUMERIC(10,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    allocated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sms_cost_centers IS 'Attributes SMS messaging costs to specific cost centers for financial tracking';

CREATE INDEX idx_sms_cost_sms ON audit.sms_cost_centers(sms_id);


-- Table: T222 - backup_restore_drills
-- Description: Logs practice restore operations.
-- Business Case: Disaster Recovery Confidence. A backup is useless if you can't restore it. This table logs scheduled "Drills" where we restore a backup to a sandbox environment, verify a specific query, and then destroy it. It proves that the Disaster Recovery (DR) plan actually works when needed.
-- KPIs: Drill Success Rate, Restore Speed.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.backup_restore_drills (
    drill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id UUID NOT NULL REFERENCES audit.audit_backup_manifest(backup_id),
    drill_date DATE NOT NULL DEFAULT CURRENT_DATE,
    drill_type VARCHAR(50) NOT NULL, -- 'POINT_IN_TIME', 'FULL_RESTORE'
    target_instance VARCHAR(100), -- Sandbox DB name
    status VARCHAR(20) DEFAULT 'STARTED', -- STARTED, RESTORED, VERIFIED, FAILED
    restore_duration_seconds INTEGER,
    verification_query_passed BOOLEAN,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.backup_restore_drills IS 'Logs scheduled disaster recovery tests to validate restore procedures';


-- Table: T223 - vacuum_maintenance_history
-- Description: Logs of VACUUM operations.
-- Business Case: Database Performance (Anti-Bloat). In PostgreSQL, deleting rows leaves "dead tuples" (bloat). VACUUM cleans this. This table logs every VACUUM run, how much space was reclaimed, and how long it took. It helps DBAs tune the `autovacuum` settings to balance performance vs I/O.
-- KPIs: Bloat Reclaimed, Maintenance Window Adherence.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS audit.vacuum_maintenance_history (
    vacuum_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation_type VARCHAR(20) NOT NULL, -- VACUUM, VACUUM_FULL, ANALYZE
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    dead_tuples_removed BIGINT,
    index_scans INTEGER,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.vacuum_maintenance_history IS 'Tracks maintenance operations that reclaim disk space and update statistics';

CREATE INDEX idx_vacuum_table ON audit.vacuum_maintenance_history(table_name, started_at DESC);


-- Table: T224 - query_plan_archive
-- Description: Long-term storage of EXPLAIN ANALYZE results.
-- Business Case: Historical Performance Analysis. Query plans change as data grows. T084 stores recent logs, but this table stores the *full JSON plan* for historical analysis. We can compare a plan from 6 months ago to today to see if a new index caused a "Seq Scan" to turn into an "Index Scan", quantifying the impact of optimization.
-- KPIs: Plan Stability Score.
-- Feature Reference: T084
CREATE TABLE IF NOT EXISTS audit.query_plan_archive (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash CHAR(64) NOT NULL,
    plan_json JSONB NOT NULL, -- Full EXPLAIN ANALYZE output
    captured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rows_planned BIGINT,
    total_cost NUMERIC(20,4),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.query_plan_archive IS 'Archives detailed execution plans for long-term performance trend analysis';

CREATE INDEX idx_plan_archive_hash ON audit.query_plan_archive(query_hash, captured_at DESC);


-- Table: T225 - auditor_billable_hours
-- Description: Tracks time for billing internal departments.
-- Business Case: Internal Cost Recovery. The Audit Module (M06) might charge the "Tax Department" or "Fraud Unit" for server time used. This table logs how many hours (or compute units) each auditor spent on cases, allowing generation of internal invoices based on usage.
-- KPIs: Tracking Accuracy, Revenue Recovery.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.auditor_billable_hours (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    case_id UUID REFERENCES audit.audit_workload(case_id),
    date DATE NOT NULL,
    hours_worked NUMERIC(5,2) NOT NULL,
    activity_type VARCHAR(100),
    billing_code VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.auditor_billable_hours IS 'Tracks audit activity time for internal cost allocation and billing';


-- Table: T226 - third_party_service_logs
-- Description: Logs of interactions with Tableau, PowerBI, etc.
-- Business Case: Integration Debugging. When an auditor connects their Tableau Desktop to PARI, what queries do they run? This table logs the queries coming in via OData/JDBC connectors. It helps identify "Expensive Queries" generated by BI tools that might be slowing down the production database.
-- KPIs: BI Query Latency.
-- Feature Reference: F071, T135
CREATE TABLE IF NOT EXISTS audit.third_party_service_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(50) NOT NULL, -- TABLEAU, POWERBI, QLIK
    user_id UUID NOT NULL,
    query_text TEXT,
    rows_returned BIGINT,
    execution_time_ms INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.third_party_service_logs IS 'Monitors query activity from external BI tools to protect performance';

CREATE INDEX idx_3p_service_ts ON audit.third_party_service_logs(timestamp DESC);


-- Table: T227 - compliance_framework_requirements
-- Description: Detailed breakdown of compliance standards.
-- Business Case: Granular Compliance Mapping. "SOC2" is a high-level standard. This table breaks it down into specific requirements (e.g., "CC3.1: Access Control"). It links these requirements to PARI features (e.g., "MFA Enabled"). This automated mapping is crucial for passing external audits quickly.
-- KPIs: Requirement Coverage, Audit Prep Time.
-- Feature Reference: F150, T139
CREATE TABLE IF NOT EXISTS audit.compliance_framework_requirements (
    req_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_name VARCHAR(50) NOT NULL, -- SOC2, ISO27001, GDPR
    requirement_code VARCHAR(100) NOT NULL, -- e.g. "GDPR-Art-32"
    description TEXT NOT NULL,
    control_mapping UUID[], -- Links to T139
    status VARCHAR(20) DEFAULT 'NOT_IMPLEMENTED', -- IMPLEMENTED, PARTIAL, NOT_APPLICABLE

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_framework_requirements IS 'Maps external compliance standards to internal technical controls';


-- Table: T228 - audit_sampling_results
-- Description: Records which transactions/items were picked in a random sample.
-- Business Case: Statistical Audit Evidence. When we perform an audit via "Statistical Sampling" (F083), we must prove the sample was random. This table records the specific IDs (Transaction IDs) selected by the RNG algorithm. This evidence proves that we didn't cherry-pick specific transactions to target a merchant.
-- KPIs: Sample Randomness Verification.
-- Feature Reference: F083
CREATE TABLE IF NOT EXISTS audit.audit_sampling_results (
    sample_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id UUID NOT NULL REFERENCES audit.audit_workload(case_id),
    sampled_entity_id UUID NOT NULL, -- The TX ID or Merchant ID
    stratum VARCHAR(100), -- The "Bucket" it was drawn from
    selection_weight NUMERIC(10,4), -- Probability of being selected
    selected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_sampling_results_is 'Stores the specific entities selected for statistical audit verification';

CREATE INDEX idx_sampling_audit ON audit.audit_sampling_results(audit_id);


-- Table: T229 - statistical_sampling_pools
-- Description: Definition of sampling pools and strata.
-- Business Case: Audit Design. Before sampling, we define the "Universe" (e.g., "All TX > 10k in 2023"). This table defines those pools and "Strata" (sub-groups, e.g., "North", "South") to ensure representative sampling. It stores the parameters of the audit design.
-- KPIs: Sample Representativeness.
-- Feature Reference: F083
CREATE TABLE IF NOT EXISTS audit.statistical_sampling_pools (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(255) NOT NULL,
    target_population_query TEXT NOT NULL, -- SQL defining the universe
    sample_size INTEGER NOT NULL,
    confidence_level NUMERIC(3,2), -- e.g. 0.95
    margin_of_error NUMERIC(3,2),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.statistical_sampling_pools_is 'Defines the parameters for statistical sampling audit designs';


-- Table: T230 - peer_group_benchmark_metrics
-- Description: Storage of benchmark values for peer groups.
-- Business Case: Performance Analytics. To compare Merchant A to "Peers" (F022), we need the numbers for the Peers. This table stores the aggregated metrics (Avg Revenue, Avg VAT) for the peer group, calculated periodically. It serves as the baseline for the Peer Group Benchmarking feature.
-- KPIs: Benchmark Freshness.
-- Feature Reference: F022
CREATE TABLE IF NOT EXISTS audit.peer_group_benchmark_metrics (
    benchmark_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_definition_id UUID NOT NULL, -- ID of the logic defining the group
    metric_name VARCHAR(100) NOT NULL,
    aggregate_value NUMERIC(19,4) NOT NULL, -- Mean/Median
    sample_size INTEGER NOT NULL, -- How many peers in the group?
    calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.peer_group_benchmark_metrics IS 'Stores aggregated baselines for peer comparison analytics';


-- Table: T231 - dynamic_risk_factor_weights
-- Description: Configurable weights for ML risk models.
-- Business Case: Explainable AI. A black-box model says "Risk: High". This table allows Risk Analysts to adjust the *weights* of factors visible to the user. e.g., "Increase weight of 'Late Filing' factor". It allows business logic to be injected into the ML model without retraining, making the risk score more interpretable.
-- KPIs: Model Transparency, User Trust.
-- Feature Reference: F056
CREATE TABLE IF NOT EXISTS audit.dynamic_risk_factor_weights (
    weight_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    factor_name VARCHAR(100) NOT NULL, -- 'VOLUME', 'LATENESS', 'DISPUTES'
    weight NUMERIC(5,4) NOT NULL DEFAULT 1.0,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.dynamic_risk_factor_weights IS 'Allows manual tuning of ML model factors for transparency';


-- Table: T232 - geofencing_rule_logs
-- Description: Alerts when devices enter/exit geofences.
-- Business Case: Security and Asset Protection. Auditors shouldn't take sensitive devices into high-risk areas or competitor offices. This table logs alerts when a mobile device (F052) crosses a Geofence boundary defined in T032, triggering automated security protocols like remote wipe or camera disable.
-- KPIs: Geofence Violation Rate.
-- Feature Reference: F032
CREATE TABLE IF NOT EXISTS audit.geofencing_rule_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES audit.mobile_device_info(device_id),
    fence_id UUID NOT NULL,
    event_type VARCHAR(20) NOT NULL, -- ENTER, EXIT
    location_lat NUMERIC(9,6),
    location_long NUMERIC(9,6),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.geofencing_rule_logs_is 'Security logs for mobile devices crossing virtual geographic boundaries';

CREATE INDEX idx_geofence_device ON audit.geofencing_rule_logs(device_id, timestamp DESC);


-- Table: T233 - auditor_travel_manifest
-- Description: Official logs of auditor travel for security.
-- Business Case: Travel Risk Management. When auditors travel internationally, risk increases. This table logs official travel plans (from HR systems). If an audit attempt is made from London while the auditor is officially in New York, it triggers a "Impossible Travel" security alert.
-- KPIs: Manifest Accuracy, Fraud Detection.
-- Feature Reference: F107, T107
CREATE TABLE IF NOT EXISTS audit.auditor_travel_manifest (
    manifest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    origin_city VARCHAR(100),
    destination_city VARCHAR(100) NOT NULL,
    destination_country CHAR(2) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    purpose VARCHAR(100), -- 'AUDIT', 'CONFERENCE', 'TRAINING'
    status VARCHAR(20) DEFAULT 'APPROVED', -- APPROVED, CANCELLED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor_travel_manifest_is 'Tracks auditor travel to validate login locations and manage risk';


-- Table: T234 - meeting_minutes
-- Description: Records of audit team meetings.
-- Business Case: Knowledge Retention. Key decisions are made in audit meetings ("Close this case", "Contact this witness"). This table stores the minutes, action items, and attendees. It links these decisions to specific audit cases, ensuring the rationale for a decision is documented months later during a legal review.
-- KPIs: Action Item Tracking.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS audit.meeting_minutes (
    minutes_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_title VARCHAR(255) NOT NULL,
    case_ids UUID[], -- Linked cases
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    location VARCHAR(255), -- Physical or Virtual Link
    attendee_ids UUID[] NOT NULL,
    minutes_text TEXT,
    action_items_json JSONB, -- Structured action items

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.meeting_minutes IS 'Documents decisions and action items from audit team meetings';


-- Table: T235 - file_encryption_metadata
-- Description: Keys for client-side file encryption.
-- Business Case: Zero-Trust Data Exchange. When auditors download sensitive reports, we might encrypt them with a key only they possess. This table stores the metadata of such encrypted files (Encryption Method, Key Version, Recipient) so the file can be validated upon re-upload or audit.
-- KPIs: Decryption Success Rate.
-- Feature Reference: F045, F030
CREATE TABLE IF NOT EXISTS audit.file_encryption_metadata (
    enc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES audit.report_exports(export_id),
    algorithm VARCHAR(50) NOT NULL, -- 'AES-256-GCM'
    key_version INTEGER NOT NULL,
    recipient_auditor_id UUID REFERENCES audit.auditor(auditor_id),
    wrapped_key TEXT NOT NULL, -- Key encrypted with Auditor's Public Key
    encryption_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.file_encryption_metadata IS 'Manages keys for zero-trust encrypted file exchanges';


-- Table: T236 - s3_bucket_inventory
-- Description: List of all objects in archive/Data Lake.
-- Business Case: Storage Governance. We need to know exactly what's sitting in S3 to manage costs (T158). This table is an inventory of the Data Lake (T123), updated periodically by a crawler. It identifies "Abandoned Files" or "Duplicate Data" that can be deleted to save money.
-- KPIs: Inventory Accuracy (% of files listed), Cost Savings.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.s3_bucket_inventory (
    inventory_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bucket_name VARCHAR(255) NOT NULL,
    object_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    last_modified TIMESTAMPTZ,
    storage_class VARCHAR(50), -- STANDARD, GLACIER, DEEP_ARCHIVE
    is_encrypted BOOLEAN DEFAULT TRUE,
    last_scanned TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_s3_object UNIQUE (bucket_name, object_key)
);
COMMENT ON TABLE audit.s3_bucket_inventory IS 'Comprehensive inventory of cold storage assets for cost and lifecycle management';

CREATE INDEX idx_s3_last_mod ON audit.s3_bucket_inventory(last_modified DESC);


-- Table: T237 - data_lake_query_audit
-- Description: Logs queries run against the Data Lake.
-- Business Case: Cold Data Security. Querying historical archives (S3) via Athena/Presto is expensive and sensitive. This table logs every query run against the Data Lake, tracking cost (T158) and user access. It ensures that "Cold Data" isn't accessed inappropriately or without cost approval.
-- KPIs: Query Cost per User, Lake Access Compliance.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.data_lake_query_audit (
    lake_query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_engine VARCHAR(50) NOT NULL, -- 'ATHENA', 'PRESTO', 'REDSHIFT'
    query_text TEXT NOT NULL,
    auditor_id UUID REFERENCES audit.auditor(auditor_id),
    data_scanned_gb NUMERIC(10,2),
    duration_seconds INTEGER,
    cost_usd NUMERIC(10,4),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_lake_query_audit IS 'Audits access and cost of queries against the archived data lake';


-- Table: T238 - serverless_function_logs
-- Description: Logs for AWS Lambda/Azure Functions.
-- Business Case: Microservices Observability. PARI uses serverless functions for async tasks (T046, T102). Since they aren't always running, standard DB logs miss them. This table receives JSON logs from CloudWatch/Log Insights, centralizing them for debugging "Serverless" workflows.
-- KPIs: Function Error Rate, Cold Start Time.
-- Feature Reference: F097, T046
CREATE TABLE IF NOT EXISTS audit.serverless_function_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    function_name VARCHAR(100) NOT NULL,
    invocation_id VARCHAR(100) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL, -- SUCCESS, ERROR, TIMEOUT
    memory_mb INTEGER,
    duration_ms INTEGER,
    error_message TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.serverless_function_logs IS 'Centralizes logs from ephemeral serverless compute resources';

CREATE INDEX idx_serverless_func_time ON audit.serverless_function_logs(function_name, timestamp DESC);


-- Table: T239 - api_gateway_configuration
-- Description: Configuration of API routes and policies.
-- Business Case: API Management. This table stores the "Routers" configuration. e.g., "Route /v1/audit to Service A". It acts as the source of truth for the API Gateway (Kong/AWS API GW), allowing configuration changes via SQL (Control Plane) rather than editing YAML files (Data Plane).
-- KPIs: Config Deployment Time.
-- Feature Reference: F057, F025
CREATE TABLE IF NOT EXISTS audit.api_gateway_configuration (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    route_path VARCHAR(255) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    methods TEXT[] NOT NULL, -- {GET, POST}
    plugins_enabled JSONB, -- e.g. {"rate-limit": {minute: 100}}
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.api_gateway_configuration_is 'Manages the routing and policy configuration of the API Gateway';


-- Table: T240 - webhook_retry_queue
-- Description: Queue for failed webhooks.
-- Business Case: Guaranteed Delivery. If a webhook (T035) to Slack/Teams fails (server down), we can't just lose the alert. This table holds the failed payload and implements exponential backoff retry logic (wait 1s, 2s, 4s...). It ensures notifications eventually arrive.
-- KPIs: Webhook Recovery Rate (>99%).
-- Feature Reference: F038
CREATE TABLE IF NOT EXISTS audit.webhook_retry_queue (
    retry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_webhook_id UUID NOT NULL REFERENCES audit.notification_webhooks(webhook_id),
    payload_json JSONB NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    next_retry_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    max_retries INTEGER DEFAULT 5,
    status VARCHAR(20) DEFAULT 'PENDING' -- PENDING, SUCCESS, FAILED
);
COMMENT ON TABLE audit.webhook_retry_queue IS 'Manages retries for failed external webhook notifications to guarantee delivery';

CREATE INDEX idx_webhook_retry_time ON audit.webhook_retry_queue(next_retry_at);


-- Table: T241 - batch_job_dependency_graph
-- Description: Defines dependencies between batch jobs.
-- Business Case: Orchestration Logic. Job B cannot start until Job A finishes. This table defines the Directed Acyclic Graph (DAG) of dependencies for Batch Jobs (T042). The scheduler queries this table to determine the execution order, ensuring data dependencies are met.
-- KPIs: Dependency Resolution Latency.
-- Feature Reference: F092
CREATE TABLE IF NOT EXISTS audit.batch_job_dependency_graph (
    dep_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_job_id UUID NOT NULL REFERENCES audit.batch_jobs(job_id),
    child_job_id UUID NOT NULL REFERENCES audit.batch_jobs(job_id),
    dependency_type VARCHAR(50) DEFAULT 'SUCCESS_FINISH' -- SUCCESS_FINISH, DATA_AVAILABILITY
);
COMMENT ON TABLE audit.batch_job_dependency_graph IS 'Defines execution order dependencies for batch processing jobs';


-- Table: T242 - cron_execution_history
-- Description: Log of every cron trigger event.
-- Business Case: Scheduling Audit. Why didn't the daily report run? This table logs the "Tick" event of the cron scheduler (T068). It records if the cron fired, if it found jobs to run, and if the scheduler itself had any errors. It distinguishes between "Scheduler failed" and "Job failed".
-- KPIs: Scheduler Uptime.
-- Feature Reference: F092
CREATE TABLE IF NOT EXISTS audit.cron_execution_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schedule_id UUID NOT NULL REFERENCES audit.audit_schedules(schedule_id),
    expected_run_time TIMESTAMPTZ NOT NULL,
    actual_run_time TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL, -- TRIGGERED, SKIPPED, ERROR
    jobs_spawned INTEGER DEFAULT 0,
    error_message TEXT
);
COMMENT ON TABLE audit.cron_execution_history IS 'Audits the execution of the scheduler itself to differentiate between task and infrastructure errors';


-- Table: T243 - system_alert_subscriptions
-- Description: Who gets Ops/System alerts.
-- Business Case: Incident Response Management. When the database CPU hits 90%, who gets paged? This table maps "Alert Types" (e.g., "High CPU", "Disk Space Low") to lists of auditor emails/phone numbers (Ops Team, On-Call Dev). It ensures the right people are woken up at night.
-- KPIs: Alert Engagement Time.
-- Feature Reference: F097, F019
CREATE TABLE IF NOT EXISTS audit.system_alert_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    severity_threshold VARCHAR(20) NOT NULL, -- CRITICAL, WARNING
    subscriber_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    delivery_method VARCHAR(20) NOT NULL, -- EMAIL, SMS, PAGER
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.system_alert_subscriptions_is 'Routes system health alerts to the appropriate on-call personnel';


-- Table: T244 - incident_command_center
-- Description: Status of "War Room" during major incidents.
-- Business Case: Incident Coordination. During a major outage (P1 Incident), we establish a "War Room". This table stores the state: Active, Who is Commander, What is the current focus. It provides a single source of truth for the status page and for incoming stakeholders, preventing confusion.
-- KPIs: Incident Transparency.
-- Feature Reference: F018, T161
CREATE TABLE IF NOT EXISTS audit.incident_command_center (
    war_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES audit.audit_incident_tickets(ticket_id),
    status VARCHAR(20) NOT NULL, -- ACTIVE, MONITORING, RESOLVED
    commander_id UUID REFERENCES audit.auditor(auditor_id),
    current_focus TEXT,
    bridge_link TEXT, -- Zoom/Teams link
    last_update TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.incident_command_center_is 'Manages the operational state of major incident response efforts';


-- Table: T245 - emergency_contact_list
-- Description: Non-system contacts for emergency.
-- Business Case: Disaster Recovery. If the PARI platform is down, we can't use the system to find the phone number of the DBA. This table stores a static, highly available list of emergency contacts (DBA, CTO, Vendor Support) printed out or cached locally for use during total outages.
-- KPIs: Contact Information Accuracy.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS audit.emergency_contact_list (
    contact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role VARCHAR(100) NOT NULL, -- 'DBA_LEAD', 'CLOUD_PROVIDER'
    name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50) NOT NULL,
    email VARCHAR(255),
    priority INTEGER CHECK (priority BETWEEN 1 AND 10),
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.emergency_contact_list_is 'Fallback contact information for disaster recovery scenarios';


-- Table: T246 - vendor_security_posture
-- Description: Scores of vendor/merchant security.
-- Business Case: Supply Chain Risk. We audit merchants, but we also care about *their* security. If a merchant stores passwords in plain text, they are a breach risk to PARI's connection. This table stores their security score (based on third-party scans or questionnaires) to decide integration limits.
-- KPIs: Vendor Security Score.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS audit.vendor_security_posture (
    posture_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL, -- Links to T021 or T111
    scan_date DATE NOT NULL,
    score CHAR(1) CHECK (score IN ('A', 'B', 'C', 'D', 'F')),
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_vulnerabilities INTEGER DEFAULT 0,
    certification_standard VARCHAR(100), -- 'SOC2', 'ISO27001'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.vendor_security_posture IS 'Tracks security ratings of third-party vendors to manage supply chain risk';


-- Table: T247 - cyber_threat_intel
-- Description: Feeds of Indicators of Compromise (IoC).
-- Business Case: Proactive Threat Hunting. We don't wait to be hacked. This table ingests "Threat Intel" feeds (lists of bad IPs, Malware hashes) from commercial providers. If an auditor session (T001) logs in from a "Bad IP", we terminate it immediately.
-- KPIs: Threat Feed Freshness.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS audit.cyber_threat_intel (
    intel_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_type VARCHAR(50) NOT NULL, -- 'BAD_IP', 'MALWARE_HASH', 'DOMAIN'
    indicator_value TEXT NOT NULL, -- e.g. "192.168.1.1" or "sha256:..."
    source_feed VARCHAR(100) NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE audit.cyber_threat_intel_is 'Stores indicators of compromise for proactive security blocking';

CREATE INDEX idx_threat_active ON audit.cyber_threat_intel(threat_type, indicator_value) WHERE is_active = TRUE;


-- Table: T248 - ml_feature_importance
-- Description: Tracks which features matter most to the model.
-- Business Case: Explainable AI (XAI) & Data Engineering. Why did the model flag this transaction? This table stores the global "Feature Importance" scores (e.g., "Amount" is 40% important, "Time" is 10%). It helps Data Engineers know which data to focus on cleaning and helps Auditors understand the model.
-- KPIs: Feature Stability.
-- Feature Reference: T092, F012
CREATE TABLE IF NOT EXISTS audit.ml_feature_importance (
    importance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    feature_name VARCHAR(100) NOT NULL,
    importance_score NUMERIC(5,4) NOT NULL,
    calculation_method VARCHAR(50), -- 'SHAP', 'PERMUTATION'
    calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ml_feature_importance IS 'Ranks input features by their influence on the ML model predictions';

CREATE INDEX idx_feat_imp_model ON audit.ml_feature_importance(model_id, importance_score DESC);


-- Table: T249 - feature_engineering_steps
-- Description: Logs steps taken to create ML features.
-- Business Case: Data Science Reproducibility. Creating a "Feature" (e.g., "Avg Tx over 30 days") involves complex SQL logic. This table stores the recipe (SQL snippet, parameters) used to create the feature in T092. If a model drifts, we can trace exactly back to the SQL logic used to build its inputs.
-- KPIs: Engineering Transparency.
-- Feature Reference: T092
CREATE TABLE IF NOT EXISTS audit.feature_engineering_steps (
    step_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    raw_source_table VARCHAR(100) NOT NULL,
    transformation_sql TEXT NOT NULL,
    parameters_json JSONB,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.feature_engineering_steps_is 'Versioned recipes for the creation of machine learning features';


-- Table: T250 - daily_financial_balances
-- Description: Daily closing balances for accounts.
-- Business Case: Financial Reconciliation. The core ledger (M01) runs continuously, but for audit, we often need "Daily Closing Balances". This table stores the snapshot of totals per account at midnight. It provides a stable point-in-time reference for generating balance sheets and tax reports, unaffected by subsequent real-time transactions.
-- KPIs: Balance Accuracy, Closing Latency.
-- Feature Reference: F033, F014
CREATE TABLE IF NOT EXISTS audit.daily_financial_balances (
    balance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    account_id VARCHAR(100) NOT NULL, -- General Ledger Account
    currency CHAR(3) NOT NULL,
    closing_balance NUMERIC(19,4) NOT NULL,
    debit_total NUMERIC(19,4) NOT NULL,
    credit_total NUMERIC(19,4) NOT NULL,
    business_date DATE NOT NULL,
    calculated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_account_date UNIQUE (account_id, currency, business_date)
);
COMMENT ON TABLE audit.daily_financial_balances IS 'Stores end-of-day financial snapshots for audit reconciliation';

CREATE INDEX idx_fin_balance_date ON audit.daily_financial_balances(business_date DESC);

-- End of Script Part 5 (Objects 201-250)
-- Completes the logical database schema extension for the PARI M06 module.


-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 6: Objects 251-350)
-- ================================================================================
-- Description: This script completes the database object creation for the Independent
-- Auditor Interface. It covers advanced forensics, complex compliance scenarios,
-- geopolitical risk management, talent analytics, and deep financial reconciliation.
--
-- Scope: Database Objects T251 - T350.
-- ================================================================================

-- 4. DDL Statements (Tables T251 - T350)
-- ================================================================================

-- Table: T251 - forensic_chain_analysis
-- Description: Stores deep trace analysis of fund movement across blockchain hops.
-- Business Case: Complex Money Laundering Detection. Criminals layer transactions to hide origins. Simple graph edges (T017) show direct links, but this table stores the results of recursive analysis (Chain Reaction). It tracks "Source of Funds" through 10+ hops, enabling auditors to prove that clean money entered and dirty money exited, satisfying strict AML reporting requirements.
-- KPIs: Analysis Depth, Trace Accuracy.
-- Feature Reference: F002, F051
CREATE TABLE IF NOT EXISTS audit.forensic_chain_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    seed_tx_hash CHAR(64) NOT NULL, -- The starting transaction
    entity_id UUID NOT NULL, -- The subject wallet/merchant
    hop_depth INTEGER NOT NULL,
    total_volume_traced NUMERIC(19,4) NOT NULL,
    final_destination_type VARCHAR(50), -- 'EXCHANGE', 'MIXER', 'GAMBLING'
    risk_indicators TEXT[],
    analysis_status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, COMPLETED, TIMEOUT
    analyst_id UUID REFERENCES audit.auditor(auditor_id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.forensic_chain_analysis IS 'Stores results of recursive blockchain tracing for complex money laundering forensics';

CREATE INDEX idx_forensic_entity ON audit.forensic_chain_analysis(entity_id, completed_at);


-- Table: T252 - consensus_mechanism_logs
-- Description: Logs of blockchain consensus events and validator sets.
-- Business Case: Ledger Integrity Assurance. To trust the blockchain, we must trust the consensus. This table records which validators proposed blocks and voted for them. If a specific validator (potentially compromised) consistently votes against the majority, it flags a consensus failure risk. It ensures the data source (M01) remains decentralized and secure.
-- KPIs: Consistency Score, Validator Uptime.
-- Feature Reference: F051
CREATE TABLE IF NOT EXISTS audit.consensus_mechanism_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    block_number BIGINT NOT NULL,
    block_hash CHAR(64) NOT NULL,
    proposer_address VARCHAR(42),
    validator_set JSONB NOT NULL, -- List of validating nodes
    gas_used BIGINT,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.consensus_mechanism_logs IS 'Audits the consensus process to ensure blockchain decentralization and integrity';

CREATE INDEX idx_consensus_block ON audit.consensus_mechanism_logs(block_number);


-- Table: T253 - smart_contract_event_emissions
-- Description: Detailed logs of specific events emitted by smart contracts.
-- Business Case: granular Audit Trails. While T080 logs general events, this table is a high-fidelity store of *decoded* events (e.g., `Approval(address,uint256)`). It stores the arguments in a structured format (JSONB) so auditors can query "Show me all Approvals > $1M" without parsing raw logs. It bridges the gap between low-level EVM data and high-level audit queries.
-- KPIs: Decoding Accuracy, Ingestion Latency.
-- Feature Reference: F051
CREATE TABLE IF NOT EXISTS audit.smart_contract_event_emissions (
    emission_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(42) NOT NULL,
    event_signature VARCHAR(100) NOT NULL, -- e.g. "Approval(address,uint256)"
    tx_hash CHAR(66) NOT NULL,
    log_index INTEGER NOT NULL,
    args_json JSONB NOT NULL, -- Structured arguments
    timestamp TIMESTAMPTZ NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.smart_contract_event_emissions IS 'High-fidelity structured storage of decoded smart contract events for queryable auditing';

CREATE INDEX idx_emission_contract ON audit.smart_contract_event_emissions(contract_address, timestamp DESC);


-- Table: T254 - cryptographic_key_usage
-- Description: Tracks which key signed which document/report.
-- Business Case: Non-Repudiation Evidence. When a tax report is signed (F130), we need to prove *which* private key was used at that exact time. This table links a specific Key Version (T059) to a specific Report ID, creating a cryptographic chain of custody that holds up in court better than a simple user ID.
-- KPIs: Key Binding Accuracy, Signing Verification Time.
-- Feature Reference: F045, F130
CREATE TABLE IF NOT EXISTS audit.cryptographic_key_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL REFERENCES audit.encryption_keys(key_id),
    document_id UUID NOT NULL, -- Report ID, Finding ID, etc.
    document_hash CHAR(64) NOT NULL,
    signature_payload TEXT, -- The actual signature blob
    signed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    purpose VARCHAR(50), -- 'REPORT_SIGNING', 'AUTHENTICATION'
    revoked_at TIMESTAMPTZ, -- If key was revoked after signing

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cryptographic_key_usage IS 'Links digital signatures to specific cryptographic key versions for legal non-repudiation';

CREATE INDEX idx_key_usage_doc ON audit.cryptographic_key_usage(document_id);


-- Table: T255 - digital_asset_custody
-- Description: Tracks custody of digital assets/tokens (if applicable).
-- Business Case: Asset Control. If the PARI system handles digital assets (e.g., stablecoins for tax payments), we must track custody. This table records "Address A holds 1000 USDC on behalf of Merchant B". It ensures that funds aren't lost or stolen during the transition between hot wallets and cold storage.
-- KPIs: Custody Balance Match, Asset Safety.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.digital_asset_custody (
    custody_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_address VARCHAR(42) NOT NULL,
    owner_merchant_id UUID NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- 'USDC', 'EUROC'
    balance NUMERIC(19,4) NOT NULL,
    last_sync_block BIGINT,
    custody_type VARCHAR(20) NOT NULL, -- 'HOT_WALLET', 'COLD_VAULT', 'ESCROW'
    is_frozen BOOLEAN DEFAULT FALSE,
    freeze_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.digital_asset_custody IS 'Tracks holdings and custody status of digital assets used within the platform';


-- Table: T256 - audit_trail_pruning_log
-- Description: Logs of data deletion for GDPR compliance.
-- Business Case: Right to be Forgotten Execution. GDPR requires data to be deleted. Simply deleting a row isn't enough; we must prove we deleted it everywhere (backups, logs, archives). This table logs the execution of a pruning job, listing exactly which tables and which rows were purged, providing the legal "Certificate of Deletion".
-- KPIs: Pruning Completeness, Compliance Verification.
-- Feature Reference: F099, F017
CREATE TABLE IF NOT EXISTS audit.audit_trail_pruning_log (
    prune_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES audit.dsr_requests(request_id),
    tables_affected TEXT[] NOT NULL,
    rows_deleted_total INTEGER NOT NULL,
    backup_shard_id UUID, -- If backup exists, mark it for deletion too
    executed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verification_hash CHAR(64) -- Hash of the operation report

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_trail_pruning_log IS 'Immutable record of data deletion activities to satisfy GDPR Right to be Forgotten';


-- Table: T257 - compliance_report_templates
-- Description: Configurable templates for ISO/SOC reports.
-- Business Case: Audit Automation. Generating a 50-page ISO 27001 report is hard. This table stores configurable templates (Docx/ODT) with dynamic placeholders ({{control_count}}, {{passed_tests}}). The system injects data into these templates to generate professional compliance reports in seconds, not days.
-- KPIs: Report Generation Speed, Template Reusability.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.compliance_report_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_name VARCHAR(255) NOT NULL,
    standard VARCHAR(50) NOT NULL, -- 'ISO27001', 'SOC2_TYPE2'
    version VARCHAR(20) NOT NULL,
    file_format VARCHAR(20), -- 'DOCX', 'HTML', 'PDF'
    template_binary BYTEA, -- The file content
    placeholder_schema JSONB, -- Definition of required variables
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.compliance_report_templates IS 'Stores document templates for automated generation of compliance reports';


-- Table: T258 - external_system_handshakes
-- Description: Logs of API handshakes with external banks/tax auths.
-- Business Case: Interoperability Audit. We need to prove we successfully connected to the Spanish Tax Agency (SII) at a specific time. This table logs the TLS handshake details, certificates exchanged, and initial auth token exchange. It provides a "Network-level" audit trail for external integrations.
-- KPIs: Handshake Success Rate, Protocol Compliance.
-- Feature Reference: F010
CREATE TABLE IF NOT EXISTS audit.external_system_handshakes (
    handshake_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    connector_id UUID NOT NULL REFERENCES audit.national_tax_connectors(connector_id),
    remote_ip INET,
    remote_tls_version VARCHAR(20),
    remote_tls_cipher VARCHAR(100),
    remote_cert_subject TEXT,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    latency_ms INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.external_system_handshakes IS 'Network-level audit of secure connections to external financial and tax systems';


-- Table: T259 - data_pipeline_heartbeat
-- Description: Monitoring the pulse of data ingestion from M05.
-- Business Case: Real-time Health. The Audit Module depends on M05 (Exchange Hub). If M05 stops sending data, M06 is flying blind. This table acts as a watchdog, recording the timestamp of the last received data packet per stream. A "Missed Heartbeat" triggers a P1 alert.
-- KPIs: Stream Uptime, Data Freshness.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.data_pipeline_heartbeat (
    stream_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    stream_name VARCHAR(100) NOT NULL, -- e.g. 'TX_STREAM_GERMANY'
    source_module VARCHAR(50) NOT NULL, -- 'M05', 'M03'
    last_message_ts TIMESTAMPTZ,
    messages_last_minute INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'HEALTHY', -- HEALTHY, LAGGING, STALLED
    lag_seconds INTEGER, -- Calculated difference between now and last_message_ts

    -- Audit Columns
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_pipeline_heartbeat IS 'Real-time watchdog monitoring incoming data streams from core exchange modules';

CREATE INDEX idx_pipeline_status ON audit.data_pipeline_heartbeat(status, updated_at DESC);


-- Table: T260 - anomaly_suppression_rules
-- Description: Rules to suppress known false positives.
-- Business Case: Noise Reduction. Fraud models often flag legitimate recurring behavior as anomalous (e.g., a payroll run). Instead of flooding the `suspicious_activities` (T013) table, auditors can define suppression rules here. "If pattern = 'Payday' and < 10:00 AM, ignore". This sharpens the focus on genuine threats.
-- KPIs: Alert Precision, Noise Ratio.
-- Feature Reference: F132, T013
CREATE TABLE IF NOT EXISTS audit.anomaly_suppression_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_description TEXT NOT NULL,
    suppression_logic_json JSONB NOT NULL, -- Logic to match the event
    reason TEXT,
    created_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    is_active BOOLEAN DEFAULT TRUE,
    suppression_count BIGINT DEFAULT 0, -- Metrics to see how useful the rule is

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.anomaly_suppression_rules IS 'Manages rules to filter out known false positives from anomaly detection alerts';


-- Table: T261 - tenant_isolation_policies
-- Description: Defining strict data segregation for multi-tenancy.
-- Business Case: Multi-Tenancy Security. PARI might be hosted as a SaaS for different governments. This table enforces "Tenant Isolation". It defines which Schema/Tables belong to which Tenant ID, and Row-Level Security (RLS) policies that the system automatically applies to prevent cross-tenant data leakage.
-- KPIs: Isolation Violation Count (0).
-- Feature Reference: F003
CREATE TABLE IF NOT EXISTS audit.tenant_isolation_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id VARCHAR(100) NOT NULL, -- e.g., 'GOV_FRANCE'
    schema_name VARCHAR(100) NOT NULL,
    rls_policy_name VARCHAR(100), -- Postgres Policy Name
    enforcement_level VARCHAR(20) DEFAULT 'STRICT', -- STRICT, MODERATE, DISABLED
    created_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.tenant_isolation_policies IS 'Defines Row-Level Security (RLS) rules for multi-tenant data segregation';


-- Table: T262 - fx_rate_history
-- Description: Historical FX rates for currency conversion.
-- Business Case: Accurate Reconciliation. An audit might span a period where EUR/USD fluctuated from 1.0 to 1.2. To report the correct value in the base currency (USD), we need a historical time-series of FX rates. This table feeds the "Cross-Border Settlement" and "Tax Liability" calculations to ensure financial accuracy.
-- KPIs: Rate Accuracy, Latency.
-- Feature Reference: F123, F008
CREATE TABLE IF NOT EXISTS audit.fx_rate_history (
    rate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    base_currency CHAR(3) NOT NULL, -- USD
    quote_currency CHAR(3) NOT NULL, -- EUR
    exchange_rate NUMERIC(15,8) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- ECB, FED
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_fx_rate UNIQUE (base_currency, quote_currency, timestamp)
);
COMMENT ON TABLE audit.fx_rate_history IS 'Time-series storage of foreign exchange rates for accurate multi-currency audit calculations';

CREATE INDEX idx_fx_rates_time ON audit.fx_rate_history(quote_currency, timestamp DESC);


-- Table: T263 - sanction_list_updates
-- Description: Tracking when sanction lists (OFAC, UN) were updated.
-- Business Case: AML Responsiveness. Sanctions lists change daily (new oligarchs added). This table logs the "Update Version" and "Checksum" of every list we ingest. If we fail to ingest an update because of an error, we know exactly which version we missed and can re-download it immediately to avoid compliance violations.
-- KPIs: Update Freshness, Version Sync Success.
-- Feature Reference: F026, T030
CREATE TABLE IF NOT EXISTS audit.sanction_list_updates (
    update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    list_name VARCHAR(100) NOT NULL, -- 'OFAC_SDN', 'UN_CONSOLIDATED'
    source_url TEXT,
    download_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    record_count INTEGER NOT NULL,
    file_checksum CHAR(64) NOT NULL,
    ingestion_status VARCHAR(20) DEFAULT 'SUCCESS' -- SUCCESS, FAILED, PARTIAL

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sanction_list_updates IS 'Tracks ingestion versions of external sanctions lists to ensure AML compliance data is current';

CREATE INDEX idx_sanction_update_time ON audit.sanction_list_updates(download_timestamp DESC);


-- Table: T264 - political_exposure_risks
-- Description: Tracking risk associated with political regions.
-- Business Case: Geopolitical Risk Management. Auditing entities in high-risk regions (War zones, Sanctioned areas) requires extra scrutiny. This table maps regions to risk scores and "News Headlines" (via NLP). If a merchant starts transacting heavily with a region where a coup just happened, the system auto-flags them.
-- KPIs: Risk Detection Speed.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.political_exposure_risks (
    risk_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    region_code CHAR(2) OR CHAR(3) NOT NULL, -- ISO 2 or 3 letter code
    risk_score INTEGER CHECK (risk_score BETWEEN 1 AND 100),
    risk_level VARCHAR(20), -- LOW, ELEVATED, SEVERE, CRITICAL
    news_summary TEXT, -- AI generated summary of recent news
    last_assessed TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.political_exposure_risks IS 'Stores geopolitical risk assessments by region to flag high-value transaction monitoring';


-- Table: T265 - regulatory_deadline_calendar
-- Description: Calendar of upcoming tax/legal deadlines.
-- Business Case: Proactive Compliance. Missing a filing deadline is a critical failure. This table maintains a calendar of all regulatory deadlines (VAT Returns, Annual Audits, Filing periods) based on jurisdiction. It triggers "Countdown" alerts in the UI and workflow systems to ensure auditors never miss a date.
-- KPIs: Deadline Adherence (100%).
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.regulatory_deadline_calendar (
    deadline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    jurisdiction_code CHAR(2) NOT NULL,
    deadline_type VARCHAR(50) NOT NULL, -- 'VAT_RETURN', 'ANNUAL_FILING'
    description TEXT,
    due_date DATE NOT NULL,
    is_recurring BOOLEAN DEFAULT FALSE,
    recurrence_pattern VARCHAR(50), -- 'YEARLY', 'QUARTERLY'
    notification_sent BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.regulatory_deadline_calendar IS 'Central calendar managing all regulatory filing and reporting deadlines';

CREATE INDEX idx_deadline_date ON audit.regulatory_deadline_calendar(due_date);


-- Table: T266 - audit_program_schedule
-- Description: Scheduling the annual audit plan.
-- Business Case: Audit Planning. Audits aren't random; they follow a "Audit Plan" (Which merchant, when, which team). This table stores the master schedule for the year/fiscal period. It ensures that resource allocation (T146, T267) aligns with the strategic plan set by the Audit Committee.
-- KPIs: Plan Adherence, Coverage %.
-- Feature Reference: F039, F146
CREATE TABLE IF NOT EXISTS audit.audit_program_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    audit_type VARCHAR(50) NOT NULL, -- 'FULL_AUDIT', 'SPOT_CHECK', 'FORENSIC'
    planned_start_date DATE NOT NULL,
    planned_end_date DATE NOT NULL,
    priority VARCHAR(20) CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'MANDATORY')),
    assigned_team_id UUID REFERENCES audit.audit_user_groups(group_id),
    status VARCHAR(20) DEFAULT 'PLANNED', -- PLANNED, IN_PROGRESS, COMPLETED, DEFERRED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_program_schedule IS 'Master plan defining the timeline and resource allocation for audit engagements';

CREATE INDEX idx_audit_plan_dates ON audit.audit_program_schedule(planned_start_date, status);


-- Table: T267 - resource_allocation_matrix
-- Description: Allocating auditors to regions/sectors.
-- Business Case: Capacity Management. We have 100 auditors and 50 sectors. Who goes where? This table provides a "Matrix" of allocation (e.g., "Team A: Retail", "Team B: Tech"). It prevents over-allocation (burnout) and under-allocation (missed audits).
-- KPIs: Utilization Rate (80-90%).
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS audit.resource_allocation_matrix (
    allocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    target_sector VARCHAR(100), -- MCC Group
    target_region CHAR(2), -- Jurisdiction
    allocation_percentage INTEGER CHECK (allocation_percentage BETWEEN 0 AND 100),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    is_primary_assignment BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.resource_allocation_matrix IS 'Defines how auditor time is distributed across different sectors and regions';


-- Table: T268 - audit_methodology_library
-- Description: Storing standard audit procedures (steps).
-- Business Case: Standardization (CMMI). How do we audit "Cash Withdrawal"? This table stores the "Methodology" (Step 1: Check logs, Step 2: Verify CCTV...). It guides auditors through the process, ensuring that every auditor follows the same high-quality procedure for a given type of investigation.
-- KPIs: Procedure Adherence.
-- Feature Reference: F039
CREATE TABLE IF NOT EXISTS audit.audit_methodology_library (
    method_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'FRAUD', 'VAT', 'COMPLIANCE'
    risk_focus VARCHAR(50),
    steps_json JSONB NOT NULL, -- Structured steps array
    required_skills TEXT[],
    estimated_hours NUMERIC(5,2),
    version VARCHAR(20) NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_methodology_library IS 'Standard Operating Procedures (SOP) library ensuring consistent audit execution';


-- Table: T269 - continuous_control_testing
-- Description: Results of automated control testing.
-- Business Case: Continuous Auditing. Instead of checking "Is Password Policy On?" once a year, we run this test daily. This table stores the results of automated control testing scripts. It provides a real-time "Compliance Scorecard" (F150) that is always current, not just based on a point-in-time audit.
-- KPIs: Control Failure Rate, Test Frequency.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.continuous_control_testing (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_name VARCHAR(255) NOT NULL,
    control_type VARCHAR(50) NOT NULL, -- 'ITGC', 'AUTOMATED'
    test_query TEXT NOT NULL, -- SQL logic to check control
    expected_result TEXT, -- e.g., '0 ROWS'
    actual_result TEXT,
    passed BOOLEAN NOT NULL,
    tested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    variance_explanation TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.continuous_control_testing IS 'Stores results of daily automated tests to validate internal controls are functioning';

CREATE INDEX idx_control_test_date ON audit.continuous_control_testing(tested_at DESC);


-- Table: T270 - compliance_gap_heatmap
-- Description: Visual representation of compliance gaps.
-- Business Case: Risk Visualization. This table aggregates compliance gaps (T108) by region and category to generate a "Heatmap". It answers "Where is our biggest risk?". Red cells in the dashboard tell managers where to focus their remediation efforts immediately.
-- KPIs: Risk Reduction Velocity.
-- Feature Reference: F126, T108
CREATE TABLE IF NOT EXISTS audit.compliance_gap_heatmap (
    heatmap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    region_code CHAR(2),
    compliance_category VARCHAR(100), -- 'DATA_PRIVACY', 'ACCESS_CONTROL'
    gap_score INTEGER CHECK (gap_score BETWEEN 0 AND 100), -- 0 = Perfect, 100 = Broken
    calculated_at DATE NOT NULL DEFAULT CURRENT_DATE,
    top_finding_summary TEXT

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_gap_heatmap IS 'Aggregated metrics for visualizing compliance risk across different domains';

CREATE UNIQUE INDEX idx_heatmap_unique ON audit.compliance_gap_heatmap(region_code, compliance_category, calculated_at);


-- Table: T271 - third_party_risk_ownership
-- Description: Tracking beneficial ownership for AML.
-- Business Case: Ultimate Beneficial Owner (UBO) Checks. Who actually owns the shell company? This table traces ownership up the chain (Company A -> Company B -> Person X). If Person X is a Politically Exposed Person (PEP), the entire chain is risky. It enables UBO reporting required by AMLD IV.
-- KPIs: Ownership Depth, PEP Detection.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.third_party_risk_ownership (
    ownership_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL, -- The Merchant/Supplier
    parent_entity_id UUID, -- The Owner (Company or Person)
    ownership_percentage NUMERIC(5,2) NOT NULL,
    entity_type VARCHAR(50), -- 'COMPANY', 'INDIVIDUAL', 'TRUST'
    is_pep BOOLEAN DEFAULT FALSE, -- Politically Exposed Person
    pep_details JSONB, -- Role, Country, etc.
    verified BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.third_party_risk_ownership IS 'Maps corporate ownership structures to identify Ultimate Beneficial Owners and PEPs';

CREATE INDEX idx_ownership_entity ON audit.third_party_risk_ownership(entity_id);


-- Table: T272 - audit_evidence_chain
-- Description: Cryptographic chain of evidence hashes.
-- Business Case: Evidence Integrity. An investigation might take months. We need to prove that the "Evidence.zip" we have on Day 90 is the same one created on Day 1. This table creates a hash chain of every piece of evidence added to the locker (T065). Any change to the evidence breaks the hash chain.
-- KPIs: Evidence Integrity (100%).
-- Feature Reference: F065
CREATE TABLE IF NOT EXISTS audit.audit_evidence_chain (
    chain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES audit.audit_workload(case_id),
    sequence_number INTEGER NOT NULL,
    previous_hash CHAR(64), -- Hash of previous step
    current_hash CHAR(64) NOT NULL,
    evidence_ids UUID[] NOT NULL, -- IDs of items in this step
    added_by UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_evidence_chain IS 'Creates a cryptographic link for evidence ensuring files are not tampered with during investigation';

CREATE INDEX idx_evidence_chain_case ON audit.audit_evidence_chain(case_id, sequence_number);


-- Table: T273 - legal_hold_requests
-- Description: Requests to preserve data (Legal Hold).
-- Business Case: Litigation Support. When a lawsuit is filed, we must stop all data deletion for relevant users, even if retention policies (T005) say to delete. This table logs "Legal Hold" requests, overriding retention policies to preserve evidence. It is the master switch for data preservation during legal proceedings.
-- KPIs: Hold Implementation Time.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.legal_hold_requests (
    hold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_reference VARCHAR(255) NOT NULL, -- Court Case #
    scope TEXT NOT NULL, -- 'All data related to Merchant X'
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, RELEASED, EXPIRED
    requested_by UUID NOT NULL,
    legal_team_contact VARCHAR(255),
    requested_date DATE NOT NULL DEFAULT CURRENT_DATE,
    release_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.legal_hold_requests IS 'Manages litigation holds to suspend data retention policies for relevant entities';

CREATE INDEX idx_legal_hold_status ON audit.legal_hold_requests(status, release_date);


-- Table: T274 - audit_opinion_letters
-- Description: Storing generated legal opinion text.
-- Business Case: Professional Output. Audits culminate in an "Opinion Letter". This table stores the text of these letters (or links to them). It version controls them, tracking changes from "Draft" to "Final" to "Signed", ensuring the final output is legally binding and correct.
-- KPIs: Draft Iterations, Approval Time.
-- Feature Reference: F047
CREATE TABLE IF NOT EXISTS audit.audit_opinion_letters (
    letter_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_case_id UUID NOT NULL REFERENCES audit.audit_workload(case_id),
    opinion_type VARCHAR(100) NOT NULL, -- 'UNQUALIFIED', 'QUALIFIED', 'ADVERSE'
    content_text TEXT,
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, REVIEW, FINAL
    approved_by UUID REFERENCES audit.auditor(auditor_id),
    final_pdf_path TEXT,
    issued_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_opinion_letters IS 'Tracks the drafting and approval lifecycle of formal audit opinion letters';


-- Table: T275 - stakeholder_communication_log
-- Description: Logs of comms with regulators/stakeholders.
-- Business Case: Audit Trail of Dialogue. When a Tax Authority asks a question via email, we must record it. This table logs all inbound and outbound communications related to specific audits. It prevents "He said, she said" disputes and provides a single timeline of the audit engagement.
-- KPIs: Response SLA, Communication Accuracy.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.stakeholder_communication_log (
    comm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_case_id UUID REFERENCES audit.audit_workload(case_id),
    stakeholder_name VARCHAR(255) NOT NULL,
    direction VARCHAR(20) NOT NULL, -- INBOUND, OUTBOUND
    channel VARCHAR(50) NOT NULL, -- EMAIL, MEETING, LETTER
    subject TEXT,
    body_text TEXT,
    sent_by UUID REFERENCES audit.auditor(auditor_id),
    sent_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    attachment_paths TEXT[]

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.stakeholder_communication_log IS 'Chronological record of all interactions with external regulators and stakeholders';

CREATE INDEX idx_comm_case ON audit.stakeholder_communication_log(audit_case_id, sent_at DESC);


-- Table: T276 - audit_adjustment_entries
-- Description: Accounting adjustments made during audit.
-- Business Case: Correcting the Ledger. If an audit finds a missing invoice of 10k, an adjustment is made. This table records these "Audit Adjustments" that flow back to the core ledger (M01/M05). It ensures that the "Audited Financials" match the "Ledger Financials" eventually.
-- KPIs: Adjustment Count, Adjustment Value.
-- Feature Reference: F033
CREATE TABLE IF NOT EXISTS audit.audit_adjustment_entries (
    adjustment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_finding_id UUID REFERENCES audit.audit_findings(finding_id),
    account_code VARCHAR(50) NOT NULL,
    debit_amount NUMERIC(19,4) DEFAULT 0,
    credit_amount NUMERIC(19,4) DEFAULT 0,
    description TEXT NOT NULL,
    posted_to_ledger BOOLEAN DEFAULT FALSE,
    posted_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_adjustment_entries IS 'Records financial adjustments required to reconcile audit findings with the general ledger';


-- Table: T277 - audit_workpaper_index
-- Description: Linking to physical/digital workpapers.
-- Business Case: Workpaper Management. An audit is supported by "Workpapers" (spreadsheets, photos). This table indexes these files, linking them to specific findings. It ensures that the evidence supporting the "Opinion Letter" (T274) is organized and retrievable.
-- KPIs: Workpaper Coverage.
-- Feature Reference: F065
CREATE TABLE IF NOT EXISTS audit.audit_workpaper_index (
    workpaper_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id UUID REFERENCES audit.audit_findings(finding_id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    file_type VARCHAR(50), -- 'EXCEL', 'PDF', 'IMAGE'
    file_path TEXT NOT NULL,
    prepared_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    reviewed_by UUID REFERENCES audit.auditor(auditor_id),
    date_prepared DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_workpaper_index IS 'Catalog of supporting documentation (workpapers) for audit findings';

CREATE INDEX idx_workpaper_finding ON audit.audit_workpaper_index(finding_id);


-- Table: T278 - reviewer_notes
-- Description: Private notes for reviewers.
-- Business Case: Review Process. A Senior Reviewer needs to leave notes for the Junior Auditor that are not visible to the Merchant. This table stores private feedback, guidance, and queries related to specific findings, facilitating the "Review and Supervise" step of the audit lifecycle.
-- KPIs: Review Cycle Time.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS audit.reviewer_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id UUID REFERENCES audit.audit_findings(finding_id),
    reviewer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    target_auditor_id UUID REFERENCES audit.auditor(auditor_id),
    note_text TEXT NOT NULL,
    is_private BOOLEAN DEFAULT TRUE, -- Only visible to reviewer
    note_type VARCHAR(50) DEFAULT 'FEEDBACK', -- FEEDBACK, QUERY, APPROVAL
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.reviewer_notes IS 'Private communication channel between reviewers and preparers during audit execution';


-- Table: T279 - sign_off_authority
-- Description: List of authorized signatories.
-- Business Case: Authorization Matrix. Only specific people can sign the final report (T274) or Compliance Certificate (T079). This table defines who these people are, their role (Partner, Director), and their delegation limits. It enforces "Four-Eyes Principle" for high-risk audits.
-- KPIs: Delegation Validity.
-- Feature Reference: F130
CREATE TABLE IF NOT EXISTS audit.sign_off_authority (
    authority_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL, -- 'PARTNER', 'DIRECTOR', 'COMPLIANCE_OFFICER'
    signature_image_url TEXT, -- Path to PNG of signature
    is_active BOOLEAN DEFAULT TRUE,
    scope TEXT, -- e.g., 'EU_REGION_ONLY', 'LIMIT_1M'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sign_off_authority IS 'Registry of authorized personnel permitted to sign off on official audit reports';


-- Table: T280 - audit_report_versioning
-- Description: Detailed versioning of reports.
-- Business Case: Change Management. While T062 tracks versions generally, this table stores the *delta* (diff) between versions. It records exactly which section changed, what was added, and what was removed. This is crucial for understanding how the audit conclusion evolved over time.
-- KPIs: Version Granularity.
-- Feature Reference: F062
CREATE TABLE IF NOT EXISTS audit.audit_report_versioning (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID NOT NULL REFERENCES audit.tax_reports(report_id),
    version_number INTEGER NOT NULL,
    changed_sections JSONB NOT NULL, -- { "exec_summary": "changed", "figures": "updated"}
    change_summary TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_report_versioning IS 'Stores detailed change logs between sequential versions of audit reports';

CREATE INDEX idx_report_ver_report ON audit.audit_report_versioning(report_id, version_number);


-- Table: T281 - nlp_sentiment_analysis
-- Description: Sentiment analysis of auditor feedback.
-- Business Case: Cultural Health. Analyzing text feedback (T115) for "Sentiment" (Positive/Negative). This table stores the calculated score per feedback item. It helps HR identify unhappy teams or systemic issues with specific modules (e.g., "Everyone hates the VAT Report Generator").
-- KPIs: Sentiment Trend, Engagement.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.nlp_sentiment_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_id UUID NOT NULL, -- Link to T115
    sentiment_score NUMERIC(3,2) CHECK (sentiment_score BETWEEN -1.0 AND 1.0),
    sentiment_label VARCHAR(20), -- 'POSITIVE', 'NEGATIVE', 'NEUTRAL'
    key_phrases TEXT[], -- ["difficult", "slow", "great"]
    model_version VARCHAR(50),
    analyzed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.nlp_sentiment_analysis IS 'Results of Natural Language Processing on user feedback to gauge satisfaction';


-- Table: T282 - predictive_model_accuracy
-- Description: Tracking accuracy of predictive models.
-- Business Case: Model Performance Decay. The "Merchant Bankruptcy Prediction" (F112) model might be 90% accurate today, but drop to 80% next year. This table tracks model accuracy over time against ground truth (did the merchant actually go bankrupt?). It triggers retraining when accuracy drops.
-- KPIs: Prediction Accuracy.
-- Feature Reference: F112, T093
CREATE TABLE IF NOT EXISTS audit.predictive_model_accuracy (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    evaluation_date DATE NOT NULL DEFAULT CURRENT_DATE,
    ground_truth_count INTEGER NOT NULL, -- How many predictions we can verify
    correct_predictions INTEGER NOT NULL,
    accuracy_percentage NUMERIC(5,2),
    precision_score NUMERIC(5,2),
    recall_score NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.predictive_model_accuracy IS 'Monitors ongoing performance of predictive models to detect decay';

CREATE INDEX idx_model_acc_date ON audit.predictive_model_accuracy(model_id, evaluation_date DESC);


-- Table: T283 - forecasting_variance
-- Description: Variance between forecast and actual.
-- Business Case: Planning Feedback. We forecasted "Tax Revenue" for Q1. Now Q1 is over. How accurate was the forecast? This table compares Forecast (F114) vs Actual (T118). High variance indicates the model needs tuning or external factors (e.g., new law) changed the game.
-- KPIs: Variance %.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS audit.forecasting_variance (
    variance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    forecast_id UUID NOT NULL, -- Link to T157 or similar
    actual_value NUMERIC(19,4) NOT NULL,
    forecasted_value NUMERIC(19,4) NOT NULL,
    variance_percent NUMERIC(5,2),
    variance_direction VARCHAR(10), -- 'UNDER', 'OVER'
    calculated_at DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.forecasting_variance IS 'Measures deviation of forecasts from actuals to improve planning models';


-- Table: T284 - machine_learning_experiments
-- Description: Tracking A/B testing of ML models.
-- Business Case: Model Improvement. We have "Model A" (Random Forest) and "Model B" (XGBoost). We route 10% of traffic to B in production. This table tracks the "Experiment". It records which model handled which request and the outcome. If B is better, we promote it.
-- KPIs: Model Lift, Conversion Rate.
-- Feature Reference: F132, T093
CREATE TABLE IF NOT EXISTS audit.machine_learning_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_name VARCHAR(255) NOT NULL,
    challenger_model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    champion_model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    traffic_split_percentage NUMERIC(3,2) NOT NULL, -- 10.0
    start_date DATE NOT NULL,
    end_date DATE,
    winner VARCHAR(50), -- 'CHALLENGER', 'CHAMPION', 'INCONCLUSIVE'
    significance_level NUMERIC(3,2) -- Statistical p-value

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.machine_learning_experiments_is 'Controls A/B testing of machine learning models in production';

CREATE INDEX idx_exp_active ON audit.machine_learning_experiments(start_date, end_date);


-- Table: T285 - data_drift_indicators
-- Description: KPIs indicating data drift.
-- Business Case: Drift Alerting. A single table to summarize drift metrics (Population Stability Index, KL Divergence) across all features. It acts as a "Red Dashboard" for Data Scientists. If 3 features drift > threshold, a big red light flashes.
-- KPIs: Drift Threshold Breaches.
-- Feature Reference: T205
CREATE TABLE IF NOT EXISTS audit.data_drift_indicators (
    indicator_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    feature_name VARCHAR(100),
    drift_metric VARCHAR(50) NOT NULL, -- 'PSI', 'KL_DIVERGENCE'
    current_value NUMERIC(10,4) NOT NULL,
    threshold_value NUMERIC(10,4) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'STABLE', 'WARNING', 'DRIFTED'
    measured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_drift_indicators IS 'Summarizes statistical drift of features to trigger retraining alerts';


-- Table: T286 - feature_engineering_registry
-- Description: Central registry of ML features.
-- Business Case: Feature Management. To avoid "Feature Spaghetti", we register every feature here. "Feature X: Definition, SQL to calculate, Owner". When a source system changes a column name, we update it here, and all dependent models know to re-calculate.
-- KPIs: Feature Lineage Coverage.
-- Feature Reference: T092
CREATE TABLE IF NOT EXISTS audit.feature_engineering_registry (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    source_tables TEXT[] NOT NULL,
    calculation_logic TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DEPRECATED
    last_updated TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.feature_engineering_registry IS 'Central catalog of all features used by machine learning models for dependency management';


-- Table: T287 - model_inference_latency
-- Description: Tracking speed of model inference.
-- Business Case: Real-time UX. Fraud checks happen at API gateway. If the model takes 500ms, the UI hangs. This table tracks P50 and P99 latency of model inference calls. It tells us when we need to optimize the model code or scale the GPU cluster.
-- KPIs: Inference P99 (< 100ms).
-- Feature Reference: F074
CREATE TABLE IF NOT EXISTS audit.model_inference_latency (
    latency_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    request_id UUID,
    inference_time_ms INTEGER NOT NULL,
    input_size_bytes INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.model_inference_latency IS 'Tracks latency of model predictions to ensure real-time performance';

CREATE INDEX idx_inf_latency_ts ON audit.model_inference_latency(model_id, timestamp DESC);


-- Table: T288 - audit_trail_rehydration_logs
-- Description: Logs of rehydrating archived logs.
-- Business Case: Archive Restoration. When an auditor opens a case from 2019, the system must "Rehydrate" the logs from Glacier (T123) back to Hot storage (T002) for searching. This table logs that process. It ensures we don't accidentally delete the hot copy or rehydrate twice.
-- KPIs: Rehydration Speed.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.audit_trail_rehydration_logs (
    rehydration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES audit.audit_workload(case_id),
    date_range_start DATE NOT NULL,
    date_range_end DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, RESTORING, READY, ERROR
    requested_by UUID NOT NULL,
    bytes_rehydrated BIGINT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_trail_rehydration_logs IS 'Logs the restoration of cold audit data to hot storage for active investigation';


-- Table: T289 - cold_storage_tiering
-- Description: Tracking data moving to colder tiers.
-- Business Case: Cost Optimization. Hot storage (SSD) is expensive. Cold (Tape/S3 Glacier) is cheap. This table tracks the migration of data from Hot -> Warm -> Cold. It ensures data moves according to policy (T005) to minimize costs while meeting retrieval SLAs.
-- KPIs: Tiering Compliance, Cost Savings.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.cold_storage_tiering (
    tiering_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    object_id UUID NOT NULL,
    source_tier VARCHAR(50) NOT NULL, -- HOT, WARM
    destination_tier VARCHAR(50) NOT NULL, -- COLD, ARCHIVE
    move_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, MOVING, COMPLETED
    scheduled_date DATE NOT NULL,
    completed_date DATE,
    cost_impact_usd NUMERIC(10,2), -- Estimated savings

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cold_storage_tiering IS 'Manages lifecycle of data moving through storage tiers to optimize costs';


-- Table: T290 - archive_compatibility_check
-- Description: Checking if old archives are readable.
-- Business Case: Data Longevity. Formats change (e.g., Parquet v1 to v2). Can we still read data from 5 years ago? This table logs periodic "Compatibility Checks". If an archive fails to read, it flags it for migration before the bit-rot becomes total loss.
-- KPIs: Archive Readability.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS audit.archive_compatibility_check (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    archive_id UUID NOT NULL REFERENCES audit.audit_data_lake_index(lake_idx),
    check_date DATE NOT NULL DEFAULT CURRENT_DATE,
    is_readable BOOLEAN NOT NULL,
    error_details TEXT,
    schema_version_detected VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.archive_compatibility_check IS 'Validates that long-term archives remain readable as data formats evolve';


-- Table: T291 - system_deprecation_schedule
-- Description: Scheduling removal of old features.
-- Business Case: Lifecycle Management. "API v1" is deprecated. When do we turn it off? This table schedules the "Kill Date". It provides a timeline for clients (Tax Authorities) to migrate off the old version before support ends.
-- KPIs: Decommissioning Adherence.
-- Feature Reference: F147
CREATE TABLE IF NOT EXISTS audit.system_deprecation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(255) NOT NULL,
    component_type VARCHAR(50), -- 'API_VERSION', 'FEATURE', 'DATABASE_COLUMN'
    deprecation_date DATE NOT NULL,
    sunset_date DATE NOT NULL,
    migration_guide_url TEXT,
    affected_clients TEXT[],
    status VARCHAR(20) DEFAULT 'PLANNED' -- PLANNED, IN_PROGRESS, COMPLETED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.system_deprecation_schedule IS 'Tracks the end-of-life timeline for deprecated system components';


-- Table: T292 - feature_adoption_metrics
-- Description: Metrics on how features are adopted.
-- Business Case: Product Management. We built "Graph Analysis". Is anyone using it? This table aggregates adoption (DAU, WAU) per feature. Low adoption might mean the feature is hard to use, hidden, or unnecessary. It drives the roadmap decision: Improve or Kill.
-- KPIs: Adoption Rate (% of users).
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.feature_adoption_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(255) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    total_users INTEGER,
    active_users INTEGER, -- Used feature at least once
    power_users INTEGER, -- Used feature > 10 times
    adoption_rate NUMERIC(3,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.feature_adoption_metrics IS 'Quantifies usage of new features to determine product success or failure';


-- Table: T293 - user_journey_mapping
-- Description: Mapping user flows in UI.
-- Business Case: UX Optimization. How do users get from Login to Export? This table stores "Step 1 -> Step 2" flows. It identifies "Drop-off points" (where users exit the app) and "Circular paths" (users getting lost), informing UX redesigns to make the auditor more efficient.
-- KPIs: Funnel Conversion Rate.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.user_journey_mapping (
    journey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    session_id UUID,
    start_step VARCHAR(100) NOT NULL,
    end_step VARCHAR(100),
    steps_sequence TEXT[] NOT NULL, -- e.g. ['login', 'dashboard', 'search', 'export']
    journey_duration_seconds INTEGER,
    completed BOOLEAN DEFAULT FALSE,
    timestamp DATE NOT NULL DEFAULT CURRENT_DATE
);
COMMENT ON TABLE audit.user_journey_mapping IS 'Analyzes the sequence of user actions to optimize interface flows';


-- Table: T294 - ui_accessibility_audits
-- Description: Ensuring UI is accessible (WCAG).
-- Business Case: Inclusivity & Compliance. The UI must meet WCAG 2.1 AA standards (contrast, screen reader support). This table stores automated audit results of the UI (e.g., "Button X has low contrast"). It ensures the platform is usable by auditors with disabilities and avoids legal liability.
-- KPIs: WCAG Violation Count.
-- Feature Reference: F133
CREATE TABLE IF NOT EXISTS audit.ui_accessibility_audits (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    page_url TEXT NOT NULL,
    component_id VARCHAR(255),
    wcag_level VARCHAR(10) NOT NULL, -- 'A', 'AA', 'AAA'
    violation_type VARCHAR(100), -- 'CONTRAST', 'MISSING_ALT_TEXT'
    severity VARCHAR(20), -- 'CRITICAL', 'SERIOUS', 'MODERATE'
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, FIXED
    fixed_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.ui_accessibility_audits IS 'Automated checks ensuring user interface meets accessibility standards';

CREATE INDEX idx_a11y_status ON audit.ui_accessibility_audits(status, severity);


-- Table: T295 - personalization_engines
-- Description: ML engines for personalized UI.
-- Business Case: Adaptive UI. "Smart Search" (F094) should learn that User A always searches for "VAT" and User B for "Fraud". This table stores the *model* (the weights/coefficients) for personalization algorithms. It tailors the search ranking and dashboard layout to the individual's habits.
-- KPIs: Personalization Lift (CTR).
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.personalization_engines (
    engine_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    engine_type VARCHAR(50) NOT NULL, -- 'SEARCH_RANK', 'DASHBOARD_LAYOUT'
    model_json JSONB NOT NULL, -- Weights/Preferences
    last_trained_at TIMESTAMPTZ,
    training_data_points INTEGER,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.personalization_engines IS 'Stores ML models that adapt the user interface to individual auditor behavior';


-- Table: T296 - content_delivery_network_logs
-- Description: Logs of CDN hits.
-- Business Case: Performance Audit. Static assets (JS, CSS, Images) are served via CDN. This table logs cache hit/miss ratios and latency per region. If a region has high miss latency, we might need to provision a new CDN Edge Location there.
-- KPIs: Cache Hit Ratio, Byte Volume.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.content_delivery_network_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_path TEXT NOT NULL,
    edge_location VARCHAR(100), -- e.g., 'Frankfurt', 'New York'
    cache_status VARCHAR(20) NOT NULL, -- HIT, MISS, DYNAMIC
    bytes_served BIGINT,
    latency_ms INTEGER,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.content_delivery_network_logs IS 'Monitors CDN performance to optimize load times for global users';

CREATE INDEX idx_cdn_resource ON audit.content_delivery_network_logs(resource_path, timestamp DESC);


-- Table: T297 - api_gateway_rate_limiting
-- Description: Detailed rate limiting per IP.
-- Business Case: Granular Throttling. T055 has counters. This table has the *history*. "User X from IP Y hit limit 5000 times in Jan". It helps identify persistent abusers or legitimate heavy users who need a dedicated limit increase.
-- KPIs: Throttle Persistence.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.api_gateway_rate_limiting (
    limit_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address INET NOT NULL,
    endpoint VARCHAR(255),
    limit_type VARCHAR(50) NOT NULL, -- 'QPS', 'QPM'
    limit_value INTEGER NOT NULL,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.api_gateway_rate_limiting IS 'Historical log of throttling events to identify abusive IP addresses';

CREATE INDEX idx_rate_limit_ip ON audit.api_gateway_rate_limiting(ip_address, triggered_at DESC);


-- Table: T298 - waf_firewall_logs
-- Description: Web Application Firewall logs.
-- Business Case: Security Defense. The WAF sits in front of the API Gateway. It blocks SQLi, XSS, etc. This table logs *blocked* requests. We analyze these to tune rules (reduce false positives) and identify active attack campaigns against the platform.
-- KPIs: Block Count, False Positive Rate.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.waf_firewall_logs (
    waf_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_ip INET NOT NULL,
    attack_type VARCHAR(50) NOT NULL, -- 'SQL_INJECTION', 'XSS', 'DDOS'
    blocked_payload TEXT,
    rule_id VARCHAR(100),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.waf_firewall_logs IS 'Logs requests blocked by Web Application Firewall for security analysis';

CREATE INDEX idx_waf_attack ON audit.waf_firewall_logs(attack_type, timestamp DESC);


-- Table: T299 - bot_detection_signals
-- Description: Detecting bot traffic.
-- Business Case: Account Protection. Competitors or scrapers might script the UI. This table stores signals (Mouse movement, Click patterns) that identify bots. If a user is flagged as a bot, we force a CAPTCHA or block them to protect account creation and data scraping.
-- KPIs: Bot Detection Rate.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.bot_detection_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    ip_address INET,
    score NUMERIC(3,2) NOT NULL, -- 0 to 1 (Human to Bot)
    triggers TEXT[], -- ["High_Request_Rate", "No_Mouse_Move"]
    action_taken VARCHAR(50), -- 'ALLOWED', 'CAPTCHA', 'BLOCKED'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.bot_detection_signals_is 'Stores behavioral signals to identify and block automated bot traffic';

CREATE INDEX idx_bot_score ON audit.bot_detection_signals(score DESC);


-- Table: T300 - sql_injection_attempts
-- Description: Logging SQL injection attempts.
-- Business Case: Security Audit. Despite WAF, some attempts might slip or be internal. This table logs *any* query string that looks like SQL Injection (`' OR '1'='1`). It is the "Hacker's Diary" for the security team to analyze attack vectors.
-- KPIs: SQLi Frequency.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.sql_injection_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_ip INET,
    user_id UUID REFERENCES audit.auditor(auditor_id),
    payload_snippet TEXT,
    attack_vector VARCHAR(50), -- 'UNION_BASED', 'BOOLEAN_BASED'
    blocked BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sql_injection_attempts IS 'Logs SQL injection attempts detected by the security layer';

CREATE INDEX idx_sql_inj_ip ON audit.sql_injection_attempts(source_ip, timestamp DESC);


-- Table: T301 - password_policy_enforcement
-- Description: Enforcing password complexity.
-- Business Case: Identity Security. Users hate complex passwords, but they are necessary. This table logs password change events and whether they met the policy (Length, Special Char, History Check). It ensures "Weak Passwords" are rejected and tracks compliance of the policy.
-- KPIs: Policy Reject Rate.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.password_policy_enforcement (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    attempted_password_hash CHAR(64),
    policy_version VARCHAR(20),
    is_compliant BOOLEAN NOT NULL,
    failure_reasons TEXT[], -- ['Too Short', 'No Special Char']
    action_taken VARCHAR(50), -- 'REJECTED', 'ACCEPTED', 'FORCE_RESET'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.password_policy_enforcement IS 'Audits password compliance and rejection reasons to enforce identity security';


-- Table: T302 - session_hijacking_alerts
-- Description: Alerting on session hijacking.
-- Business Case: Account Takeover (ATO) Detection. If a Session ID is used from Frankfurt and then 2 seconds later from Tokyo, that's hijacking. This table logs these "Impossible Travel" events, instantly killing the session and alerting the user to change their password.
-- KPIs: Hijack Detection Time.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.session_hijacking_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    original_ip INET NOT NULL,
    suspicious_ip INET NOT NULL,
    distance_km INTEGER NOT NULL,
    travel_time_seconds INTEGER NOT NULL,
    action_taken VARCHAR(50) NOT NULL, -- 'TERMINATED', 'NOTIFIED_USER'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.session_hijacking_alerts IS 'Records suspicious session jumps indicating potential account takeover';

CREATE INDEX idx_hijack_session ON audit.session_hijacking_alerts(session_id);


-- Table: T303 - privilege_escalation_logs
-- Description: Logging privilege escalations.
-- Business Case: Insider Threat Monitoring. An auditor suddenly giving themselves "Admin" rights is a red flag. This table logs all privilege changes, especially "Escalation" events (JIT). It feeds the Insider Risk program to catch employees abusing access.
-- KPIs: Unauthorized Escalation Count.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS audit.privilege_escalation_logs (
    escalation_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    previous_role VARCHAR(100),
    new_role VARCHAR(100),
    escalation_method VARCHAR(50) NOT NULL, -- 'JIT', 'MANUAL_ADMIN', 'SCRIPT'
    justification TEXT,
    authorized_by UUID REFERENCES audit.auditor(auditor_id),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.privilege_escalation_logs IS 'Detailed log of role changes to detect unauthorized privilege escalation';

CREATE INDEX idx_escal_user_time ON audit.privilege_escalation_logs(user_id, timestamp DESC);


-- Table: T304 - data_exfiltration_monitoring
-- Description: Monitoring large data exports.
-- Business Case: DLP (Data Loss Prevention). We want auditors to work, but we don't want them stealing the whole DB. This table monitors *volume* of exports. If User A exports 10GB in one day, we lock their account and notify security. It balances legitimate needs with security.
-- KPIs: Exfiltration Block Rate.
-- Feature Reference: F048
CREATE TABLE IF NOT EXISTS audit.data_exfiltration_monitoring (
    monitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    export_id UUID REFERENCES audit.report_exports(export_id),
    bytes_exported BIGINT NOT NULL,
    rolling_24h_total BIGINT GENERATED ALWAYS AS (
        (SELECT COALESCE(SUM(bytes_exported) OVER (PARTITION BY user_id ORDER BY timestamp ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0)
    ) STORED,
    threshold_limit BIGINT NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'ALLOWED', 'BLOCKED', 'FLAGGED'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.data_exfiltration_monitoring IS 'Tracks export volumes per user to detect potential data theft';

CREATE INDEX idx_exfil_user ON audit.data_exfiltration_monitoring(user_id, timestamp DESC);


-- Table: T305 - insider_threat_indicators
-- Description: KPIs for insider threat (UBA).
-- Business Case: Insider Risk Program. User Behavior Analytics (UBA) generates a risk score. This table stores the *indicators* that built up that score (e.g., "Logins at 3 AM", "Accessed 5 sensitive files"). It allows security analysts to drill down into *why* a user is flagged.
-- KPIs: High Risk User Count.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.insider_threat_indicators (
    indicator_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    indicator_name VARCHAR(100) NOT NULL,
    risk_score_contribution NUMERIC(5,2) NOT NULL,
    observed_value NUMERIC(19,4), -- e.g., "Logins: 5" vs Avg 1
    baseline_value NUMERIC(19,4),
    severity VARCHAR(20), -- 'LOW', 'MEDIUM', 'HIGH'
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.insider_threat_indicators IS 'Breakdown of behavioral anomalies contributing to user risk scores';

CREATE INDEX idx_uba_user ON audit.insider_threat_indicators(user_id, timestamp DESC);


-- Table: T306 - dormant_account_tracking
-- Description: Tracking inactive accounts.
-- Business Case: Security Hygiene. Dormant accounts are prime targets for hijackers. This table tracks last login. If > 90 days, it flags the account for forced password reset or disablement. It reduces the attack surface.
-- KPIs: Dormant Account Count.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS audit.dormant_account_tracking (
    tracking_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    last_login_date DATE,
    days_inactive INTEGER,
    status VARCHAR(20), -- 'ACTIVE', 'WARNING', 'DISABLED'
    last_action_taken VARCHAR(100), -- 'EMAIL_SENT', 'ACCOUNT_LOCKED'
    checked_at DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(user_id, checked_at)
);
COMMENT ON TABLE audit.dormant_account_tracking IS 'Identifies and manages inactive accounts to reduce security risk';


-- Table: T307 - compliance_training_assignments
-- Description: Assigning mandatory compliance training.
-- Business Case: Compliance HR. New laws require training. This table assigns specific training courses (T218) to specific users or groups. It tracks who has completed what, ensuring the firm is legally certified to operate.
-- KPIs: Training Completion %.
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.compliance_training_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    training_id UUID NOT NULL REFERENCES audit.audit_training_records(training_id),
    due_date DATE NOT NULL,
    assigned_by UUID REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'ASSIGNED', -- ASSIGNED, IN_PROGRESS, COMPLETED
    completed_at DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_training_assignments IS 'Manages mandatory training assignments for regulatory compliance';


-- Table: T308 - certification_expiry_alerts
-- Description: Alerting on expiring certs.
-- Business Case: Credential Management. Auditors have CPAs, CFEs. Merchants have Import Licenses. This table monitors the expiry dates of all relevant certifications stored in T210, T021. It sends alerts 90, 60, 30 days out to prevent lapses in qualifications.
-- KPIs: Lapse Rate (Target 0%).
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.certification_expiry_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL, -- 'AUDITOR', 'MERCHANT', 'SYSTEM'
    entity_id UUID NOT NULL,
    certification_name VARCHAR(255) NOT NULL,
    expiry_date DATE NOT NULL,
    alert_sent_90 BOOLEAN DEFAULT FALSE,
    alert_sent_60 BOOLEAN DEFAULT FALSE,
    alert_sent_30 BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) -- 'ACTIVE', 'EXPIRED'
);
COMMENT ON TABLE audit.certification_expiry_alerts IS 'Monitors and alerts on approaching expiration dates for professional and system certificates';

CREATE INDEX idx_cert_expiry ON audit.certification_expiry_alerts(expiry_date, status);


-- Table: T309 - audit_quality_assurance_scores
-- Description: Scoring quality of audits performed.
-- Business Case: Audit Quality. Not all audits are equal. This table scores the quality of the audit *work* (Was documentation complete? Was logic sound?). It is used for reviewer performance metrics and for identifying auditors who need retraining.
-- KPIs: Average Audit Quality Score.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_quality_assurance_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id UUID NOT NULL REFERENCES audit.audit_workload(case_id),
    reviewer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    preparer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    dimension_1_score NUMERIC(3,2), -- Documentation
    dimension_2_score NUMERIC(3,2), -- Logic
    dimension_3_score NUMERIC(3,2), -- Timeliness
    overall_score NUMERIC(3,2),
    feedback TEXT,
    reviewed_at DATE NOT NULL DEFAULT CURRENT_DATE
);
COMMENT ON TABLE audit.audit_quality_assurance_scores IS 'Stores peer review scores to assess and improve the quality of audit execution';


-- Table: T310 - client_satisfaction_surveys
-- Description: Surveys sent to merchants/clients.
-- Business Case: Client Experience. We audit merchants, but are *we* doing a good job? This table manages surveys sent to external clients (Merchants) regarding their experience with the audit process. High satisfaction is crucial for the platform's reputation.
-- KPIs: Client CSAT Score.
-- Feature Reference: F115
CREATE TABLE IF NOT EXISTS audit.client_satisfaction_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    audit_id UUID REFERENCES audit.audit_workload(case_id),
    sent_date DATE NOT NULL,
    responded_date DATE,
    rating INTEGER CHECK (rating BETWEEN 1 AND 10),
    nps_score INTEGER CHECK (nps_score BETWEEN -100 AND 100),
    comments TEXT,
    status VARCHAR(20) DEFAULT 'SENT', -- SENT, RESPONDED, DECLINED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.client_satisfaction_surveys IS 'Measures merchant satisfaction with the audit process to improve service quality';


-- Table: T311 - audit_fee_schedule
-- Description: Calculating audit fees.
-- Business Case: Commercialization. If audits are paid services (e.g., for non-Tax Authority clients), we need to bill. This table defines the Fee Schedule (Hourly Rate, Flat Fee, Expenses) and applies it to the Audit Plan (T266) to generate invoices.
-- KPIs: Billing Accuracy.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.audit_fee_schedule (
    fee_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    engagement_id UUID NOT NULL, -- Link to T266 or Contract
    fee_type VARCHAR(50) NOT NULL, -- 'HOURLY_RATE', 'FIXED_FEE', 'EXPENSE_REIMBURSEMENT'
    rate_value NUMERIC(10,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    unit VARCHAR(20), -- 'PER_HOUR', 'PER_DAY', 'TOTAL'
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_fee_schedule IS 'Defines pricing models for generating audit invoices for external clients';


-- Table: T312 - invoice_generation_queue
-- Description: Generating invoices for services.
-- Business Case: Billing Automation. At the end of a billing cycle, this table queues up the generation of PDF invoices based on the Fee Schedule (T311) and Time Logs (T225). It ensures that clients receive accurate, itemized bills for audit services rendered.
-- KPIs: Invoice Generation Success Rate.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.invoice_generation_queue (
    queue_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_id UUID NOT NULL, -- Merchant or Org
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, GENERATING, SENT, FAILED
    total_amount NUMERIC(19,4),
    currency CHAR(3),
    pdf_path TEXT,
    generated_at TIMESTAMPTZ,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.invoice_generation_queue IS 'Automates the creation and dispatch of service invoices to clients';


-- Table: T313 - payment_processing_logs
-- Description: Logs of payment gateway interactions.
-- Business Case: Revenue Assurance. When a client pays, we talk to Stripe/Adyen. This table logs the success/failure of payment intents. It matches incoming bank transfers to open invoices to close them out.
-- KPIs: Payment Reconciliation Match Rate.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.payment_processing_logs (
    payment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    invoice_id UUID REFERENCES audit.invoice_generation_queue(queue_id),
    gateway_provider VARCHAR(50) NOT NULL, -- 'STRIPE', 'ADYEN'
    transaction_id VARCHAR(255), -- Provider Transaction ID
    amount NUMERIC(19,4) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'INITIATED', 'SUCCEEDED', 'FAILED', 'REFUNDED'
    failure_reason TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.payment_processing_logs_is 'Tracks interaction with payment providers to ensure revenue is collected';


-- Table: T314 - revenue_recognition_schedule
-- Description: Scheduling revenue recognition.
-- Business Case: Accounting Standards (IFRS 15). Revenue cannot be recognized immediately if the service is over a year. This table defines the schedule for recognizing revenue (e.g., "Recognize 1/12th every month"). It ensures financial statements are legally compliant.
-- KPIs: RevRec Compliance.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.revenue_recognition_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    engagement_id UUID NOT NULL,
    total_value NUMERIC(19,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    recognition_frequency VARCHAR(50), -- 'MONTHLY', 'QUARTERLY'
    next_recognition_date DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.revenue_recognition_schedule IS 'Manages deferred revenue recognition schedules for long-term audit contracts';


-- Table: T315 - cost_center_balances
-- Description: Tracking cost center spend.
-- Business Case: Financial Control. PARI has internal cost centers (R&D, Sales, Infrastructure). This table tracks internal spend against budget (F157). It ensures we don't overspend on, say, cloud computing for the "Audit" module.
-- KPIs: Budget Variance.
-- Feature Reference: F158
CREATE TABLE IF NOT EXISTS audit.cost_center_balances (
    balance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cost_center_code VARCHAR(50) NOT NULL,
    fiscal_year INTEGER NOT NULL,
    budgeted_amount NUMERIC(15,2) NOT NULL,
    actual_spend NUMERIC(15,2) NOT NULL,
    committed_spend NUMERIC(15,2),
    remaining_budget NUMERIC(15,2) GENERATED ALWAYS AS (budgeted_amount - actual_spend - committed_spend) STORED,
    variance_percent NUMERIC(5,2) GENERATED ALWAYS AS (((actual_spend - budgeted_amount) / budgeted_amount) * 100) STORED,

    -- Audit Columns
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cost_center_balances IS 'Tracks actual spend vs budget for internal financial governance';

CREATE UNIQUE INDEX idx_cost_center_year ON audit.cost_center_balances(cost_center_code, fiscal_year);


-- Table: T316 - budget_variance_tracking
-- Description: Tracking budget vs actual.
-- Business Case: Variance Analysis. Why did we overspend? This table records variance entries (Account, Budgeted, Actual, Variance, Explanation). It provides the narrative behind the numbers in T315 for management review.
-- KPIs: Explanation Coverage.
-- Feature Reference: F158
CREATE TABLE IF NOT EXISTS audit.budget_variance_tracking (
    variance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cost_center_code VARCHAR(50) NOT NULL,
    fiscal_year INTEGER NOT NULL,
    account_code VARCHAR(50) NOT NULL,
    budgeted_amount NUMERIC(15,2) NOT NULL,
    actual_amount NUMERIC(15,2) NOT NULL,
    variance_amount NUMERIC(15,2) NOT NULL,
    explanation TEXT,
    manager_id UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.budget_variance_tracking_is 'Records detailed explanations for budget variances to drive financial accountability';


-- Table: T317 - capital_expenditure_logs
-- Description: CapEx logging.
-- Business Case: Asset Management. Buying new servers or software licenses is Capital Expenditure (CapEx). This table logs CapEx requests and approvals. It ensures we have a fixed asset register and that CapEx is aligned with the long-term strategy.
-- KPIs: CapEx Approval Cycle Time.
-- Feature Reference: F157
CREATE TABLE IF NOT EXISTS audit.capital_expenditure_logs (
    capex_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_category VARCHAR(100), -- 'HARDWARE', 'SOFTWARE', 'INFRASTRUCTURE'
    requested_amount NUMERIC(15,2) NOT NULL,
    approved_amount NUMERIC(15,2),
    justification TEXT NOT NULL,
    request_date DATE NOT NULL DEFAULT CURRENT_DATE,
    approved_by UUID REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, ACQUIRED
    depreciation_years INTEGER,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.capital_expenditure_logs IS 'Manages approval and tracking of capital expenditure requests';


-- Table: T318 - operational_expenses
-- Description: OpEx logging.
-- Business Case: P&L Management. Monthly bills (SaaS, Utilities, Rent) are Operational Expenses. This table tracks recurring monthly expenses. It feeds into the Profit & Loss statement and helps identify cost cutting opportunities.
-- KPIs: OpEx Trend.
-- Feature Reference: F157
CREATE TABLE IF NOT EXISTS audit.operational_expenses (
    opex_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    expense_category VARCHAR(100) NOT NULL, -- 'AWS', 'OFFICE_RENT', 'SOFTWARE_LICENSES'
    vendor_name VARCHAR(255) NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    expense_date DATE NOT NULL,
    cost_center_code VARCHAR(50),
    invoice_id UUID,
    is_recurring BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.operational_expenses IS 'Records monthly operational expenses for profit and loss analysis';

CREATE INDEX idx_opex_date ON audit.operational_expenses(expense_date DESC);


-- Table: T319 - financial_forecasting_models
-- Description: Models for financial forecasting.
-- Business Case: Strategic Planning. We need to predict next year's revenue and costs. This table stores the parameters and results of financial forecasting models (ARIMA, etc.). It supports the Board in setting long-term goals.
-- KPIs: Forecast Accuracy.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS audit.financial_forecasting_models (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    forecast_type VARCHAR(50) NOT NULL, -- 'REVENUE', 'OP_EX', 'HEAD_COUNT'
    target_period DATE NOT NULL,
    predicted_value NUMERIC(19,4) NOT NULL,
    lower_bound NUMERIC(19,4),
    upper_bound NUMERIC(19,4),
    confidence_interval NUMERIC(3,2),
    model_version VARCHAR(20),
    generated_at DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.financial_forecasting_models_is 'Stores predictive financial models for strategic business planning';


-- Table: T320 - audit_resource_utilization
-- Description: Utilization of auditor hours vs capacity.
-- Business Case: Capacity Management. We bill clients by the hour (T225). We also have a fixed supply of hours (Team size * 40 weeks). This table compares Billable Hours vs Capacity. Utilization < 80% means we are overstaffed; > 100% means we are overbooked.
-- KPIs: Utilization Rate (Target 80-90%).
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS audit.audit_resource_utilization (
    utilization_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    capacity_hours NUMERIC(8,2) NOT NULL,
    billable_hours NUMERIC(8,2) NOT NULL,
    internal_hours NUMERIC(8,2) DEFAULT 0,
    training_hours NUMERIC(8,2) DEFAULT 0,
    total_utilization NUMERIC(5,2) GENERATED ALWAYS AS ((billable_hours + internal_hours + training_hours) / capacity_hours * 100) STORED,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_resource_utilization_is 'Analyzes how auditor time is utilized across client, internal, and training work';

CREATE UNIQUE INDEX idx_resource_util_period ON audit.audit_resource_utilization(auditor_id, period_start, period_end);


-- Table: T321 - skill_demand_forecasting
-- Description: Forecasting demand for specific skills.
-- Business Case: Workforce Planning. We foresee a need for "Crypto-Forensic Experts" next year based on the audit pipeline (T266). This table matches skill demand to the talent pool (T210) to trigger recruitment or training (T218) plans.
-- KPIs: Skill Gap Analysis.
-- Feature Reference: F116, T210
CREATE TABLE IF NOT EXISTS audit.skill_demand_forecasting (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    skill_name VARCHAR(100) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    demand_hours NUMERIC(8,2) NOT NULL,
    current_supply_hours NUMERIC(8,2),
    deficit_hours NUMERIC(8,2) GENERATED ALWAYS AS (demand_hours - current_supply_hours) STORED,
    action_plan VARCHAR(20), -- 'HIRE', 'TRAIN', 'OUTSOURCE'
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.skill_demand_forecasting_is 'Predicts future skill requirements to guide recruitment and training strategies';


-- Table: T322 - recruitment_pipeline
-- Description: Tracking hiring of auditors.
-- Business Case: Talent Acquisition. Filling an open role takes months. This table tracks candidates through the pipeline (Applied -> Interview -> Offer -> Hired). It provides metrics for "Time to Hire" and "Offer Acceptance Rate".
-- KPIs: Time to Fill.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.recruitment_pipeline (
    candidate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'APPLIED', 'SCREENING', 'INTERVIEW', 'OFFER', 'HIRED', 'REJECTED'
    applied_date DATE NOT NULL DEFAULT CURRENT_DATE,
    stage_entered_at TIMESTAMPTZ,
    source VARCHAR(100), -- 'LINKEDIN', 'REFERRAL', 'AGENCY'
    recruiter_id UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.recruitment_pipeline IS 'Manages the lifecycle of candidates applying for auditor positions';


-- Table: T323 - auditor_performance_reviews
-- Description: Storing performance review data.
-- Business Case: Talent Development. Annual performance reviews (1-5 scale). This table stores the ratings, self-assessment, and manager's notes. It links to the Bonus/Promotion process and identifies high performers (T310).
-- KPIs: Review Completion Rate.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.auditor_performance_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    review_period VARCHAR(20) NOT NULL, -- 'Q1', 'Q2', 'Q3', 'Q4'
    year INTEGER NOT NULL,
    overall_rating INTEGER CHECK (overall_rating BETWEEN 1 AND 5),
    self_rating INTEGER,
    manager_feedback TEXT,
    goals_set TEXT[],
    goals_achieved TEXT[],
    reviewer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    completed_at DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.auditor_performance_reviews_is 'Stores formal performance review data for HR management and progression';


-- Table: T324 - succession_planning
-- Description: Planning for key role succession.
-- Business Case: Business Continuity. What if the Head of Audit leaves? This table identifies "Key Roles" and their potential successors. It identifies gaps in the "Bench Strength" and triggers training for successors (T218).
-- KPIs: Readiness Level.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.succession_planning (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_role_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    successor_id UUID REFERENCES audit.auditor(auditor_id),
    readiness_level VARCHAR(20) CHECK (readiness_level IN ('READY', '1_YEAR', '2_YEARS', 'NO_SUCCESSOR')),
    gap_analysis TEXT, -- What training is needed?
    last_reviewed DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.succession_planning IS 'Identifies and prepares successors for critical audit roles';


-- Table: T325 - knowledge_sharing_sessions
-- Description: Logs of knowledge sharing sessions.
-- Business Case: Knowledge Management. "Brown Bags", "Tech Talks". This table records sessions where auditors share expertise (e.g., "How to spot Shell Companies"). It links to the artifacts (slides, recording) created, capturing tribal knowledge.
-- KPIs: Knowledge Sharing Frequency.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS audit.knowledge_sharing_sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    presenter_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    topic_category VARCHAR(100) NOT NULL,
    session_date DATE NOT NULL DEFAULT CURRENT_DATE,
    duration_minutes INTEGER,
    attendees UUID[], -- Array of Auditor IDs
    recording_url TEXT,
    slides_url TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.knowledge_sharing_sessions IS 'Catalogs internal training sessions to preserve and disseminate expert knowledge';


-- Table: T326 - mentorship_programs
-- Description: Managing mentor/mentee pairs.
-- Business Case: Talent Development. Junior auditors need guidance. This table matches Mentors with Mentees. It tracks goals and check-ins, ensuring the onboarding process (T069) is supported personally.
-- KPIs: Mentee Satisfaction.
-- Feature Reference: F069
CREATE TABLE IF NOT EXISTS audit.mentorship_programs (
    program_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mentor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    mentee_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    start_date DATE NOT NULL,
    end_date DATE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, PAUSED, COMPLETED
    goals_summary TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.mentorship_programs_is 'Manages mentor-mentee relationships to accelerate skill transfer';


-- Table: T327 - audit_culture_metrics
-- Description: Metrics on organizational culture.
-- Business Case: Organizational Health. eNPS, Burnout Rate, Diversity. This table aggregates HR metrics related to the Audit Organization. It provides a dashboard for Leadership to monitor the "Health of the Firm", not just the P&L.
-- KPIs: eNPS, Turnover Rate.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.audit_culture_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL, -- 'E_NPS', 'TURNOVER_RATE', 'DIVERSITY_INDEX'
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    metric_value NUMERIC(10,2) NOT NULL,
    change_percent NUMERIC(5,2),
    trend VARCHAR(10), -- 'IMPROVING', 'STABLE', 'DECLINING'
    calculated_at DATE NOT NULL DEFAULT CURRENT_DATE
);
COMMENT ON TABLE audit.audit_culture_metrics_is 'Aggregates HR metrics to monitor the health and culture of the audit organization';


-- Table: T328 - employee_net_promoter_score
-- Description: eNPS for auditors.
-- Business Case: Employee Engagement. The "Ultimate Question": "Would you recommend this firm as a place to work?". This table stores eNPS survey results. It is a leading indicator of retention; a drop in eNPS precedes a wave of resignations.
-- KPIs: eNPS Score.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.employee_net_promoter_score (
    nps_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    survey_date DATE NOT NULL DEFAULT CURRENT_DATE,
    score INTEGER CHECK (score BETWEEN 0 AND 10),
    promoter BOOLEAN GENERATED ALWAYS AS (score >= 9) STORED,
    passive BOOLEAN GENERATED ALWAYS AS (score BETWEEN 7 AND 8) STORED,
    detractor BOOLEAN GENERATED ALWAYS AS (score <= 6) STORED
);
COMMENT ON TABLE audit.employee_net_promoter_score_is 'Stores employee feedback to calculate eNPS and predict retention risk';


-- Table: T329 - learning_and_dev_records
-- Description: L&D attendance/records.
-- Business Case: Skill Inventory. Apart from mandatory compliance training (T307), auditors attend external conferences or courses. This table is the full transcript of an auditor's education. It helps in matching staff to specialized cases.
-- KPIs: L&D Hours per FTE.
-- Feature Reference: F218
CREATE TABLE IF NOT EXISTS audit.learning_and_dev_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    course_title VARCHAR(255) NOT NULL,
    provider VARCHAR(255),
    start_date DATE NOT NULL,
    end_date DATE,
    credits_earned NUMERIC(5,2),
    cost NUMERIC(10,2),
    certificate_path TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.learning_and_dev_records IS 'Comprehensive record of all educational activities for auditors';


-- Table: T330 - talent_pool_analytics
-- Description: Analytics on available talent.
-- Business Case: Resource Optimization. We have 100 people. What are they good at? This table aggregates skills, certifications, and experience levels into a "Talent Matrix". It helps the Resource Manager (T267) pick the right team for the right job.
-- KPIs: Skill Coverage.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.talent_pool_analytics (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    primary_sector VARCHAR(100), -- 'BANKING', 'TECH', 'RETAIL'
    skill_tags TEXT[], -- ['FORENSICS', 'VAT', 'AML']
    availability_hours_next_week INTEGER,
    utilization_rate NUMERIC(3,2),
    last_updated DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.talent_pool_analytics_is 'Aggregated view of skills and availability to optimize resource allocation';


-- Table: T331 - audit_methodology_updates
-- Description: Tracking changes to methodology.
-- Business Case: Continuous Improvement. Audit methodologies change (e.g., "New approach to Crypto Fraud"). This table tracks versioning of the Methodology Library (T268). It ensures everyone is using the latest playbook.
-- KPIs: Methodology Version Consistency.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.audit_methodology_updates (
    update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    method_id UUID NOT NULL REFERENCES audit.audit_methodology_library(method_id),
    version VARCHAR(20) NOT NULL,
    changes_summary TEXT,
    updated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approved_by UUID REFERENCES audit.auditor(auditor_id),
    approved_at DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.audit_methodology_updates_is 'Tracks version history of audit methodology documents to ensure standardization';


-- Table: T332 - regulatory_commentary
-- Description: Internal commentary on regs.
-- Business Case: Interpretation of Law. Laws are vague. This table stores internal interpretations and "Legal Opinions" from the legal team on how to apply a specific regulation (e.g., "Does this apply to DAOs?"). It creates a secondary source of truth for guidance.
-- KPIs: Commentary Access Rate.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.regulatory_commentary (
    commentary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id VARCHAR(100) NOT NULL, -- Reference to T096 or External
    topic VARCHAR(255) NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    legal_opinion TEXT NOT NULL,
    provided_by_legal_team BOOLEAN DEFAULT TRUE,
    effective_date DATE NOT NULL,
    is_superseded BOOLEAN DEFAULT FALSE,
    superseded_by UUID REFERENCES audit.regulatory_commentary(commentary_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.regulatory_commentary IS 'Internal guidance interpreting complex regulations for operational consistency';


-- Table: T333 - lobbying_activity_tracker
-- Description: Tracking lobbying/engagement.
-- Business Case: Government Relations. If the PARI platform wants a law changed, we might lobby for it. This table tracks interactions with policymakers, meetings, and draft bill reviews. It ensures a coordinated approach to regulatory influence.
-- KPIs: Engagement Count.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.lobbying_activity_tracker (
    activity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_maker_name VARCHAR(255) NOT NULL,
    office VARCHAR(255),
    date_of_contact DATE NOT NULL,
    meeting_type VARCHAR(50), -- 'FORMAL_MEETING', 'COFFEE', 'ROUND_TABLE'
    topic_discussed TEXT NOT NULL,
    position_influence VARCHAR(50), -- 'SUPPORT', 'OPPOSE', 'NEUTRAL'
    next_steps TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.lobbying_activity_tracker_is 'Tracks engagement with policymakers and regulatory bodies to influence legislation';


-- Table: T334 - public_policy_impact_assessment
-- Description: Assessing impact of public policy.
-- Business Case: Strategic Risk. A government announces "New Digital Services Tax". How does that hit us? This table assesses the impact of new public policies on the PARI business model, users, or compliance burden. It drives strategy adaptation.
-- KPIs: Impact Assessment Speed.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS audit.public_policy_impact_assessment (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_title VARCHAR(255) NOT NULL,
    policy_date DATE NOT NULL,
    affected_module VARCHAR(50), -- 'M01', 'M06', 'ALL'
    impact_level VARCHAR(20), -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    financial_impact_num NUMERIC(15,2),
    operational_impact TEXT,
    mitigation_plan TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.public_policy_impact_assessment IS 'Evaluates the effect of new public policies on platform operations';


-- Table: T335 - geopolitical_risk_factors
-- Description: Risk factors based on geography.
-- Business Case: Regional Risk. Beyond sanctions, countries have risks like "Currency instability", "Expropriation risk", "Hyperinflation". This table stores these risk factors per country. It adjusts the "Risk Score" of transactions/merchants operating in that region automatically.
-- KPIs: Risk Model Sensitivity.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.geopolitical_risk_factors (
    factor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2) NOT NULL,
    factor_name VARCHAR(100) NOT NULL, -- 'CORRUPTION', 'POLITICAL_STABILITY'
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    weight NUMERIC(3,2) NOT NULL, -- Importance of this factor
    description TEXT,
    last_updated TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.geopolitical_risk_factors_is 'Provides inputs for calculating dynamic risk scores based on country-level instability';

CREATE INDEX idx_geo_risk_country ON audit.geopolitical_risk_factors(country_code);


-- Table: T336 - sanitary_phyto_sanctions
-- Description: Sanctions related to phyto-sanitary.
-- Business Case: Niche Compliance. For merchants trading in goods (Food, Plants), we need to check for Phyto-Sanitary Certificates and Sanctions. This table integrates with specific agricultural databases to block trade of banned goods.
-- KPIs: Phyto-Sanction Compliance.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS audit.sanitary_phyto_sanctions (
    sanction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    species_name VARCHAR(255) NOT NULL,
    banned_from_country CHAR(2),
    ban_reason TEXT, -- 'PEST', 'DISEASE'
    ban_start_date DATE NOT NULL,
    ban_end_date,
    regulatory_body VARCHAR(255), -- 'USDA', 'EFSA'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sanitary_phyto_sanctions IS 'Tracks trade bans on specific agricultural goods to prevent regulatory violations';


-- Table: T337 - trade_embargo_monitoring
-- Description: Monitoring trade embargoes.
-- Business Case: Macro-Compliance. "No trade with Country X". This table monitors active trade embargoes. If a transaction (T008) is detected involving an embargoed jurisdiction, it triggers a critical block and alert to Compliance Officer.
-- KPIs: Embargo Violation Count (0).
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS audit.trade_embargo_monitoring (
    embargo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_country CHAR(2) NOT NULL,
    embargo_type VARCHAR(50) NOT NULL, -- 'FULL', 'ARMS', 'FINANCIAL'
    issuing_authority VARCHAR(255), -- 'UN', 'EU', 'US'
    reference_url TEXT,
    effective_date DATE NOT NULL,
    lifted_date DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.trade_embargo_monitoring_is 'Tracks active trade embargoes to prevent illegal cross-border transactions';

CREATE INDEX idx_embargo_country ON audit.trade_embargo_monitoring(target_country);


-- Table: T338 - dual_use_goods_monitoring
-- Description: Monitoring dual-use goods.
-- Business Case: Dual-Use Goods (DUG). Technology that can be used for both civilian and military purposes (e.g., semiconductors, encryption tech). This table maps HS Codes (Harmonized System) to DUG status. It ensures we don't facilitate the export of restricted technologies.
-- KPIs: DUG Export Count.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.dual_use_goods_monitoring (
    good_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hs_code VARCHAR(10) NOT NULL, -- Harmonized System Code
    description TEXT NOT NULL,
    control_regime VARCHAR(50) NOT NULL, -- 'EAR', 'WASSSENAAR'
    license_required BOOLEAN DEFAULT TRUE,
    end_user_certificate_required BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.dual_use_goods_monitoring_is 'Classifies goods by their dual-use nature to enforce export control compliance';


-- Table: T339 - military_end_user_certificates
-- Description: Military end-user checks.
-- Business Case: Military End-User (MEU). Even if the goods aren't DUG, if the buyer is the military, we might need a license. This table stores references to known MEU entities or flags entities for verification.
-- KPIs: MEU Identification Rate.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.military_end_user_certificates (
    meu_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_name VARCHAR(255) NOT NULL,
    country_code CHAR(2) NOT NULL,
    listed_on VARCHAR(50), -- 'US_ENTITY_LIST', 'EU_MEU_LIST'
    certificate_required BOOLEAN DEFAULT TRUE,
    status VARCHAR(20), -- 'VERIFIED', 'PENDING_VERIFICATION', 'UNKNOWN'
    last_checked DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.military_end_user_certificates_is 'Monitors entities to identify potential military end-users for export control';


-- Table: T340 - export_control_classification
-- Description: Classifying exports for control.
-- Business Case: Trade Compliance. For every export transaction or data exchange, we need to classify it (ECCN - Export Control Classification Number). This table stores the classification result, linking the transaction to the specific legal control (e.g., '5A002 - Information Security').
-- KPIs: Classification Accuracy.
-- Feature Reference: F008
CREATE TABLE IF NOT EXISTS audit.export_control_classification (
    classification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
    eccn_code VARCHAR(20), -- Export Control Classification Number
    control_regime VARCHAR(50),
    license_exception_number VARCHAR(100),
    classification_date DATE NOT NULL DEFAULT CURRENT_DATE,
    classified_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.export_control_classification_is 'Records the application of export control classifications to specific transactions';


-- Table: T341 - customs_clearance_logs
-- Description: Logs of customs clearance.
-- Business Case: Physical Trade. Physical goods moving across borders must clear customs. This table logs the Clearance Number and Status. It connects the digital transaction to the physical movement proof.
-- KPIs: Clearance Success Rate.
-- Feature Reference: F008
CREATE TABLE IF NOT EXISTS audit.customs_clearance_logs (
    clearance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    shipment_id UUID NOT NULL,
    port_of_entry CHAR(5),
    customs_declaration_number VARCHAR(100),
    clearance_status VARCHAR(20) NOT NULL, -- 'CLEARED', 'HELD', 'SEIZED'
    clearance_date DATE,
    duties_paid NUMERIC(15,2),
    vat_paid NUMERIC(15,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.customs_clearance_logs_is 'Tracks the customs clearance status for physical goods linked to transactions';


-- Table: T342 - free_trade_zone_usage
-- Description: Tracking FTZ usage.
-- Business Case: Tax Optimization. Moving goods through a Free Trade Zone (FTZ) might defer taxes. This table tracks which transactions were routed through FTZs. It is essential for proving the tax deferral or exemption status to authorities.
-- KPIs: FTZ Savings Captured.
-- Feature Reference: F100
CREATE TABLE IF NOT EXISTS audit.free_trade_zone_usage (
    ftz_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
    ftz_code CHAR(10) NOT NULL,
    entry_date DATE NOT NULL,
    exit_date DATE,
    tax_deferred_amount NUMERIC(15,2),
    tax_exemption_claimed BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.free_trade_zone_usage_is 'Tracks utilization of Free Trade Zones to manage tax deferrals and exemptions';


-- Table: T343 - transfer_pricing_documentation
-- Description: Docs for transfer pricing.
-- Business Case: Cross-Border Tax. Large multinationals use "Transfer Pricing" to shift profits. Tax authorities require documentation proving "Arm's Length Principle". This table stores the TP Study file references linked to related entities.
-- KPIs: TP Documentation Availability.
-- Feature Reference: F100
CREATE TABLE IF NOT EXISTS audit.transfer_pricing_documentation (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_group_id UUID NOT NULL, -- Group of companies involved
    transaction_type VARCHAR(50), -- 'ROYALTY', 'LOAN', 'SERVICE_FEE'
    fiscal_year INTEGER NOT NULL,
    tp_method VARCHAR(100), -- 'CUP', 'TNMM'
    documentation_path TEXT NOT NULL, -- Link to PDF study
    local_file_number VARCHAR(100),
    status VARCHAR(20), -- 'SUBMITTED', 'ACCEPTED', 'AUDITED'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.transfer_pricing_documentation IS 'Stores Transfer Pricing study documentation for cross-border tax compliance';


-- Table: T344 - permanent_establishment_records
-- Description: PE records.
-- Business Case: Tax Liability. Multinationals must be taxed on "Permanent Establishment" (PE) basis. This table identifies where an entity has a PE (Office, Fixed Place of Business) for tax purposes. It prevents companies from hiding profits in low-tax jurisdictions without substance.
-- KPIs: PE Identification Accuracy.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.permanent_establishment_records (
    pe_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    pe_type VARCHAR(50), -- 'OFFICE', 'FACTORY', 'WAREHOUSE'
    address TEXT NOT NULL,
    employees_count INTEGER,
    is_significant_pe BOOLEAN DEFAULT FALSE, -- Does it create significant economic presence?
    substance_test_result TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.permanent_establishment_records_is 'Identifies Permanent Establishments to determine correct tax jurisdiction for entities';


-- Table: T345 - tax_treaty_benefits
-- Description: Tracking treaty benefits.
-- Business Case: Double Taxation Avoidance. Country A and B have a tax treaty. A payment from A->B might suffer WHT (Withholding Tax). If a Certificate of Residency (CoR) is presented, the rate drops. This table tracks applied treaty benefits.
-- KPIs: WHT Recovery.
-- Feature Reference: F100
CREATE TABLE IF NOT EXISTS audit.tax_treaty_benefits (
    benefit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
    source_country CHAR(2) NOT NULL,
    destination_country CHAR(2) NOT NULL,
    treaty_article VARCHAR(100), -- e.g., 'Article 11 - Interest'
    standard_wht_rate NUMERIC(5,2) NOT NULL,
    treaty_rate NUMERIC(5,2) NOT NULL,
    certificate_id UUID, -- Link to CoR
    savings_amount NUMERIC(15,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.tax_treaty_benefits IS 'Records the application of tax treaties to reduce withholding tax on payments';


-- Table: T346 - tax_haven_monitoring
-- Description: Monitoring transactions to tax havens.
-- Business Case: Base Erosion & Profit Shifting (BEPS). Profits moving to "Tax Havens" (0% tax) is a red flag. This table flags transactions or entities interacting with jurisdictions on the EU Blacklist or Global High-Risk list.
-- KPIs: Haven Risk Exposure.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.tax_haven_monitoring (
    monitoring_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    haven_jurisdiction_code CHAR(2) NOT NULL,
    transaction_count INTEGER,
    volume_moved NUMERIC(19,4),
    risk_score INTEGER, -- Based on volume and haven type
    is_blacklisted_jurisdiction BOOLEAN DEFAULT TRUE,
    monitored_period_start DATE NOT NULL,
    monitored_period_end DATE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.tax_haven_monitoring_is 'Tracks fund flows to high-risk jurisdictions to identify potential tax evasion patterns';


-- Table: T347 - base_erosion_profit_shifting
-- Description: Detecting BEPS.
-- Business Case: BEPS Action Plan. "Base Erosion" involves shifting profits away from where value is created. This table stores indicators of BEPS: e.g., "Interest expenses > Benchmark", "Intangibles transferred to low-tax entity".
-- KPIs: BEPS Indicator Count.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS audit.base_erosion_profit_shifting (
    beps_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    beps_action NUMBER CHECK (beps_action BETWEEN 1 AND 12), -- Actions 1-12
    indicator_name VARCHAR(255) NOT NULL,
    trigger_value NUMERIC(15,2),
    benchmark_value NUMERIC(15,2),
    variance_percentage NUMERIC(5,2),
    fiscal_year INTEGER NOT NULL,
    status VARCHAR(20), -- 'FLAGGED', 'UNDER_REVIEW', 'SUBSTANTIATED'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.base_erosion_profit_shifting IS 'Stores indicators consistent with Base Erosion and Profit Shifting under BEPS Action 4';


-- Table: T348 - country_by_country_reporting
-- Description: CbCR reporting data.
-- Business Case: CbCR Transparency. Multinationals must report tax paid in each country (Country-by-Country Reporting). This table aggregates the data required for the local file of the CbCR report.
-- KPIs: CbCR Completeness.
-- Feature Reference: F100
CREATE TABLE IF NOT EXISTS audit.country_by_country_reporting (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    fiscal_year INTEGER NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    revenue NUMERIC(15,2),
    profit_before_tax NUMERIC(15,2),
    tax_paid NUMERIC(15,2),
    tax_accrued NUMERIC(15,2),
    capital_employed NUMERIC(15,2),
    employees INTEGER,
    status VARCHAR(20), -- 'CALCULATED', 'SUBMITTED'
    submission_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.country_by_country_reporting IS 'Aggregates financial data for Country-by-Country Reporting (CbCR) compliance';


-- Table: T349 - master_file_interchange_agreements
-- Description: MFIA agreements.
-- Business Case: Exchange of Information. Competent Authorities (tax bodies) exchange data via MFIA. This table logs the existence of these agreements and the scope of information exchange. It validates if we are legally allowed to send/receive data to/from a specific country.
-- KPIs: Data Exchange Coverage.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.master_file_interchange_agreements (
    mfia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_country CHAR(2) NOT NULL,
    agreement_type VARCHAR(50), -- 'AUTOMATIC', 'ON_REQUEST', 'SPONTANEOUS'
    covered_taxes TEXT[],
    data_scope TEXT,
    effective_date DATE NOT NULL,
    expiry_date DATE,
    last_renewal_date DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.master_file_interchange_agreements_is 'Manages legal frameworks for tax data exchange with other jurisdictions';


-- Table: T350 - global_minimum_tax_tracking
-- Description: Tracking Global Minimum Tax (Pillar Two).
-- Business Case: GloBE Rules (Pillar Two). Multinationals must pay a minimum tax (e.g., 15%) globally. This table calculates the Effective Tax Rate (ETR) per entity and compares it to the Global Minimum Tax (GMT) rate to determine top-up tax owed.
-- KPIs: ETR vs GMT Variance.
-- Feature Reference: F100
CREATE TABLE IF NOT EXISTS audit.global_minimum_tax_tracking (
    tracking_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    fiscal_year INTEGER NOT NULL,
    global_revenue NUMERIC(15,2) NOT NULL,
    profit_before_gmt NUMERIC(15,2) NOT NULL,
    gmt_rate NUMERIC(5,2) NOT NULL, -- e.g., 15.00
    effective_tax_rate NUMERIC(5,2) NOT NULL, -- Actual ETR
    top_up_tax_due NUMERIC(15,2), -- Additional tax owed
    excess_credits NUMERIC(15,2),
    status VARCHAR(20), -- 'CALCULATED', 'FINALIZED'

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.global_minimum_tax_tracking IS 'Calculates top-up tax liabilities under Pillar Two Global Minimum Tax rules';

-- End of Script Part 6 (Objects 251-350)
-- Completes the exhaustive database schema for PARI M06.

-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 7: Objects 351-450)
-- ================================================================================
-- Description: This script continues the database object creation for the Independent
-- Auditor Interface. It covers advanced forensics, ESG compliance,
-- blockchain depth, next-gen security, AI-driven operations, and governance.
--
-- Scope: Database Objects T351 - T450.
-- ================================================================================

-- 4. DDL Statements (Tables T351 - T450)
-- ================================================================================

-- Table: T351 - transaction_reconstruction_jobs
-- Description: Stores asynchronous jobs to reconstruct broken transaction chains.
-- Business Case: Advanced Data Recovery. In high-volume systems (M05), occasional gaps in event streams occur due to network partitions or buffer overflows. Before auditors can rely on the data, we must "reconstruct" the missing transactions from ledger snapshots or peer logs. This table manages these heavy re-indexing jobs, ensuring that "Audit Data Freshness" (KPI) is maintained even after infrastructure hiccups.
-- KPIs: Reconstruction Success Rate, Reconstruction Speed.
-- Feature Reference: F001, F119
CREATE TABLE IF NOT EXISTS audit.transaction_reconstruction_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gap_start TIMESTAMP WITH TIME ZONE NOT NULL,
    gap_end TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RECONSTRUCTING', 'VERIFIED', 'FAILED')),
    estimated_records_count INTEGER,
    actual_records_recovered INTEGER DEFAULT 0,
    source_strategy VARCHAR(50), -- PEER_LOGS, STATEMENT, CHECKPOINT_REPLAY
    initiated_by UUID REFERENCES audit.auditor(auditor_id),
    error_log TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.transaction_reconstruction_jobs IS 'Manages asynchronous jobs to fix gaps in transaction event streams for audit integrity';

CREATE INDEX idx_recon_status ON audit.transaction_reconstruction_jobs(status, created_at DESC);


-- Table: T352 - heuristic_pattern_library
-- Description: Stores manually curated heuristics for anomaly detection.
-- Business Case: Knowledge Management for Fraud. While ML models (T092) learn patterns, they struggle with novel techniques or very specific "Red Flags". This table stores human-curated heuristics (e.g., "If Merchant A sends to Blacklisted B, escalate immediately"). It provides a fallback mechanism that is more agile than retraining models and allows domain experts to inject intelligence.
-- KPIs: Heuristic True Positive Rate, Coverage.
-- Feature Reference: F025, F013
CREATE TABLE IF NOT EXISTS audit.heuristic_pattern_library (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'CIRCULAR_TRADE', 'SHELL_COMPANY', 'TIMING_ANOMALY'
    logic_expression TEXT NOT NULL, -- SQL or JSON logic expression
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence_score NUMERIC(3,2), -- 0 to 1
    created_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    last_triggered TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.heuristic_pattern_library IS 'Repository of expert-curated rules to detect specific fraud patterns ML might miss';

CREATE INDEX idx_heuristic_cat ON audit.heuristic_pattern_library(category, is_active);


-- Table: T353 - esg_audit_metrics
-- Description: Tracks Environmental, Social, and Governance metrics.
-- Business Case: ESG Compliance & Green IT. Global financial systems are increasingly scrutinized for their environmental impact. This table tracks the "Carbon Footprint" of running the PARI audit system (e.g., KWH consumed, CO2 generated by data centers). It enables the platform to report on its own sustainability and offsets carbon usage.
-- KPIs: Carbon Offset Target, Energy Efficiency (PUE).
-- Feature Reference: F132, F047
CREATE TABLE IF NOT EXISTS audit.esg_audit_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporting_period_start DATE NOT NULL,
    reporting_period_end DATE NOT NULL,
    energy_kwh NUMERIC(15,2) NOT NULL,
    carbon_tonnes_emitted NUMERIC(15,4),
    carbon_tonnes_offset NUMERIC(15,4) DEFAULT 0,
    net_carbon_tonnes NUMERIC(15,4) GENERATED ALWAYS AS (carbon_tonnes_emitted - carbon_tonnes_offset) STORED,
    data_center_region VARCHAR(100) NOT NULL,
    renewable_energy_percentage NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.esg_audit_metrics IS 'Tracks environmental impact metrics of the audit infrastructure for ESG reporting';


-- Table: T354 - carbon_offset_purchases
-- Description: Records the purchase of carbon credits.
-- Business Case: Carbon Neutrality Strategy. To achieve "Net Zero" status, the platform buys Carbon Offsets (credits). This table records these purchases (Provider, Amount, Certification), creating an auditable trail of how we achieved our green targets. It validates that "Net Carbon" calculation in T353 is backed by real purchases.
-- KPIs: Offset Purchase Completion Rate.
-- Feature Reference: T353
CREATE TABLE IF NOT EXISTS audit.carbon_offset_purchases (
    purchase_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_name VARCHAR(255) NOT NULL,
    tonnage_purchased NUMERIC(15,4) NOT NULL,
    price_per_tonne NUMERIC(10,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    certificate_number VARCHAR(255) NOT NULL,
    purchase_date DATE NOT NULL DEFAULT CURRENT_DATE,
    vintage_year INTEGER, -- Year the emission occurred
    retirement_date DATE, -- When offset is retired
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, RETIRED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.carbon_offset_purchases_is 'Records transactions for purchasing carbon credits to offset infrastructure emissions';


-- Table: T355 - layer2_solution_tracking
-- Description: Monitors scaling solutions (e.g., Rollups, Polygon).
-- Business Case: Blockchain Scalability Monitoring. M01 (Core Chain) might be expensive (High Gas). PARI might utilize "Layer 2" (L2) scaling solutions (Rollups) for cheaper transactions. This table tracks transactions bridged from L1 to L2, verifying that the rollup finality matches the main chain root hash. It prevents fraud on the L2 layer.
-- KPIs: Bridge Finality Confirmation, Gas Savings.
-- Feature Reference: F001, F051
CREATE TABLE IF NOT EXISTS audit.layer2_solution_tracking (
    bridge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    layer1_tx_hash CHAR(66) NOT NULL, -- Transaction on Main Chain
    layer2_tx_hash CHAR(66) NOT NULL, -- Transaction on Rollup Chain
    solution_name VARCHAR(50) NOT NULL, -- 'POLYGON', 'ARBITRUM', 'OPTIMISM'
    bridge_address VARCHAR(42) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, CHALLENGED, CONFIRMED
    confirmed_at TIMESTAMP WITH TIME ZONE,
    gas_saved_num_units BIGINT, -- Amount of Layer 1 gas saved
    verification_link TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.layer2_solution_tracking IS 'Tracks transactions moved to Layer 2 scaling solutions to verify finality and cost savings';

CREATE INDEX idx_l2_solution_status ON audit.layer2_solution_tracking(status, confirmed_at DESC);


-- Table: T356 - cross_chain_bridge_monitoring
-- Description: Monitors assets moving across independent blockchains.
-- Business Case: Cross-Chain Compliance. Assets might move from Ethereum to Solana. Tax authorities care about the asset, not the chain. This table monitors "Bridges", mapping the burn event (Source Chain) to the mint event (Destination Chain). It ensures we can track the lifecycle of a taxable event regardless of which network it is currently on.
-- KPIs: Bridge Event Verification Rate.
-- Feature Reference: F001, F051
CREATE TABLE IF NOT EXISTS audit.cross_chain_bridge_monitoring (
    bridge_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_chain VARCHAR(50) NOT NULL,
    destination_chain VARCHAR(50) NOT NULL,
    source_tx_hash CHAR(66) NOT NULL,
    destination_tx_hash CHAR(66) NOT NULL,
    asset_id CHAR(42) NOT NULL, -- Token Contract Address
    amount NUMERIC(19,4) NOT NULL,
    bridge_fee_amount NUMERIC(19,4),
    bridge_address VARCHAR(42),
    monitored_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cross_chain_bridge_monitoring IS 'Monitors asset transfers across different blockchain bridges to ensure tax continuity';


-- Table: T357 - ai_policy_generator_logs
-- Description: Logs policies drafted by AI (LLMs).
-- Business Case: Regulatory Automation. New laws are complex (hundreds of pages). AI can draft compliance policies instantly. This table logs these AI-generated policies, tracking which LLM version generated it, who reviewed it, and the approval status. It accelerates compliance adoption while keeping a human in the loop for safety.
-- KPIs: Policy Drafting Speed, Human Revision Rate.
-- Feature Reference: F096, F136
CREATE TABLE IF NOT EXISTS audit.ai_policy_generator_logs (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id VARCHAR(100) NOT NULL, -- Link to T108 or External Law
    ai_model_version VARCHAR(50) NOT NULL, -- e.g., 'GPT-4-Turbo'
    generated_content TEXT NOT NULL,
    confidence_score NUMERIC(3,2),
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, UNDER_REVIEW, APPROVED, REJECTED
    reviewer_comments TEXT,
    approved_by UUID REFERENCES audit.auditor(auditor_id),
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.ai_policy_generator_logs_is 'Tracks AI-drafted compliance policies through the human review workflow';


-- Table: T358 - hardware_security_module_inventory
-- Description: Inventory of Hardware Security Modules (HSMs, TPMs).
-- Business Case: Root of Trust Hardware. We store critical keys in Hardware Security Modules (HSMs) or Trusted Platform Modules (TPMs) in user devices. This table tracks the inventory of these chips, their firmware versions, and security status. A compromised HSM is a "Game Over" event, so this table is crucial for alerting.
-- KPIs: Firmware Up-to-Date Rate, HSM Health.
-- Feature Reference: F045, F088
CREATE TABLE IF NOT EXISTS audit.hardware_security_module_inventory (
    hsm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_serial VARCHAR(100) NOT NULL UNIQUE,
    module_type VARCHAR(50) NOT NULL, -- 'HSM', 'TPM', 'TEE'
    manufacturer VARCHAR(100) NOT NULL,
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DECOMMISSIONED, COMPROMISED
    owner_auditor_id UUID REFERENCES audit.auditor(auditor_id),
    location VARCHAR(100), -- Datacenter, Office
    last_seen_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.hardware_security_module_inventory_is 'Manages the lifecycle and health of hardware security modules for key protection';


-- Table: T359 - hardware_integrity_verification
-- Description: Logs verifying hardware hasn't been tampered.
-- Business Case: Physical Security. How do we know an HSM in a remote office hasn't been swapped for a malicious clone? This table logs the results of "Attestation" protocols (remote physical check of module serial/boot hash). It ensures the Root of Trust extends to the physical world.
-- KPIs: Attestation Success Rate.
-- Feature Reference: F088, F045
CREATE TABLE IF NOT EXISTS audit.hardware_integrity_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hsm_id UUID NOT NULL REFERENCES audit.hardware_security_module_inventory(hsm_id),
    verification_method VARCHAR(50) NOT NULL, -- 'REMOTE_ATTESTATION', 'FIRMWARE_AUDIT'
    boot_hash_hex CHAR(64),
    is_passed BOOLEAN NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    performed_by UUID REFERENCES audit.auditor(auditor_id),
    failure_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.hardware_integrity_verification IS 'Stores results of physical and firmware checks to ensure hardware modules have not been tampered with';


-- Table: T360 - predictive_maintenance_schedules
-- Description: Schedules maintenance before failures occur.
-- Business Case: Predictive Ops. Instead of fixing a server when it crashes, we fix it when we predict it *will* crash. This table schedules maintenance tasks (Storage Replacement, RAM Upgrade) generated by predictive models analyzing hardware metrics (T189, T190). It increases uptime and prevents data loss.
-- KPIs: Predicted Failure Prevention Rate.
-- Feature Reference: F114, F119
CREATE TABLE IF NOT EXISTS audit.predictive_maintenance_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id VARCHAR(100) NOT NULL, -- Server Name, DB Cluster ID
    prediction_model_id UUID REFERENCES audit.ml_model_versions(model_id),
    predicted_failure_date TIMESTAMP WITH TIME ZONE NOT NULL,
    recommended_action TEXT NOT NULL,
    scheduled_maintenance_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'SCHEDULED', -- SCHEDULED, COMPLETED, CANCELLED
    completed_by UUID REFERENCES audit.auditor(auditor_id),
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.predictive_maintenance_schedules_is 'Manages proactive maintenance tasks triggered by predictive models to prevent infrastructure failure';


-- Table: T361 - graph_neural_network_inference
-- Description: Stores outputs from Graph Neural Networks (GNN).
-- Business Case: Next-Gen Fraud Detection. Traditional ML looks at rows. GNNs look at the *Graph* structure (who pays whom). This table stores the "Embeddings" and predictions from GNN models. It is much more effective at spotting "Money Laundering Rings" (F002) than tabular models.
-- KPIs: GNN Inference Latency, AUC Score.
-- Feature Reference: F012, F002
CREATE TABLE IF NOT EXISTS audit.graph_neural_network_inference (
    inference_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    entity_id UUID NOT NULL, -- The Merchant/Wallet being analyzed
    graph_embedding BYTEA, -- The vector representation of the graph structure
    fraud_probability NUMERIC(3,2) NOT NULL,
    top_feature_contributor TEXT, -- e.g., "Circular_Link_A-B"
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.graph_neural_network_inference_is 'Stores results of Graph Neural Network analysis for detecting complex network fraud';


-- Table: T362 - credit_bureau_integration
-- Description: Tracks integration with external credit bureaus.
-- Business Case: Enhanced KYC/KYB. Public credit scores (Equifax, Dun & Bradstreet) are good signals for merchant reliability. This table stores the results of external credit checks linked to our internal merchant IDs. It augments our internal risk models (T012) with validated financial history.
-- KPIs: Credit Refresh Rate, API Cost.
-- Feature Reference: F021, F026
CREATE TABLE IF NOT EXISTS audit.credit_bureau_integration (
    integration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL, -- Merchant ID
    provider_name VARCHAR(50) NOT NULL, -- 'DUNS', 'EXPERIAN'
    credit_score INTEGER,
    limit_amount NUMERIC(15,2),
    check_date DATE NOT NULL DEFAULT CURRENT_DATE,
    report_number VARCHAR(100),
    integration_status VARCHAR(20), -- SUCCESS, NOT_FOUND, ERROR
    raw_response_json JSONB,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.credit_bureau_integration_is 'Stores external credit ratings to enhance internal risk assessments of merchants';


-- Table: T363 - edge_device_processing_stats
-- Description: Stats from edge nodes (local servers).
-- Business Case: Edge Computing. To reduce latency and bandwidth costs, some processing happens "at the edge" (e.g., in tax authority's data center). This table reports performance stats from these edge nodes back to the central M06 system, ensuring the distributed architecture performs within SLAs.
-- KPIs: Edge Latency P95, Sync Lag.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS audit.edge_device_processing_stats (
    stats_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_node_id VARCHAR(100) NOT NULL,
    processed_count INTEGER NOT NULL,
    avg_latency_ms INTEGER,
    cpu_utilization NUMERIC(5,2),
    memory_utilization NUMERIC(5,2),
    last_heartbeat TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_freshness_lag_seconds INTEGER,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.edge_device_processing_stats IS 'Aggregates performance metrics from edge computing nodes to ensure low-latency auditing';


-- Table: T364 - rpa_bot_execution_logs
-- Description: Logs execution of Robotic Process Automation (RPA) bots.
-- Business Case: Digital Labor. Auditors shouldn't do data entry. We use RPA bots to scrape external tax websites or fill Excel forms. This table logs the success/failure and steps of these bots. It treats bots as "Digital Employees" that must be audited and optimized.
-- KPIs: Bot Success Rate, Steps Correctness.
-- Feature Reference: F092, F002
CREATE TABLE IF NOT EXISTS audit.rpa_bot_execution_logs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bot_name VARCHAR(100) NOT NULL, -- 'SCRAPER_VAT_DE', 'EXCEL_FILLER'
    target_system VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- SUCCESS, PARTIAL_SUCCESS, FAILURE
    total_steps INTEGER,
    steps_failed INTEGER DEFAULT 0,
    screenshot_path TEXT,
    error_message TEXT,
    triggered_by UUID REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.rpa_bot_execution_logs_is 'Tracks the execution and results of RPA bots automating repetitive audit tasks';

CREATE INDEX idx_rpa_bot_time ON audit.rpa_bot_execution_logs(start_time DESC);


-- Table: T365 - board_material_generation
-- Description: Tracks generation of materials for Board Meetings.
-- Business Case: Governance Reporting. The Board needs high-level summaries (Revenue, Risk, Litigation). This table logs the generation of slide decks (PPT/PDF) for Board meetings, linking them to the underlying data. It ensures Board decisions are based on verified, accurate data.
-- KPIs: Material Generation Time, Accuracy.
-- Feature Reference: F150, T234
CREATE TABLE IF NOT EXISTS audit.board_material_generation (
    material_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_title VARCHAR(255) NOT NULL,
    meeting_date DATE NOT NULL,
    format VARCHAR(20) NOT NULL, -- 'PPT', 'PDF', 'DECK'
    generated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    file_path TEXT,
    version INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, FINAL, ARCHIVED
    approved_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.board_material_generation_is 'Manages the creation and versioning of documents for corporate Board meetings';


-- Table: T366 - audit_committee_minutes
-- Description: Stores minutes of the Audit Committee.
-- Business Case: Governance Oversight. An "Audit Committee" provides independent oversight. This table stores the minutes and decisions of these committees. It ensures that major decisions (like Firing an auditor or Approving an Audit Plan) are documented with strict governance.
-- KPIs: Committee Attendance, Decision Clarity.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.audit_committee_minutes (
    minutes_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_date DATE NOT NULL DEFAULT CURRENT_DATE,
    committee_name VARCHAR(100) NOT NULL,
    quorum_met BOOLEAN NOT NULL,
    attendees_uuids UUID[] NOT NULL,
    decisions_made TEXT[], -- List of decisions
    resolution_references TEXT[], -- References to other docs (T011, T274)
    chair_person_uuid UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    file_path TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_committee_minutes_is 'Official record of decisions made by the Audit Committee for governance oversight';


-- Table: T367 - sentinel_event_detection
-- Description: Stores advanced anomaly events from Sentinel systems.
-- Business Case: Advanced Threat Detection. "Sentinel" systems monitor for subtle patterns like "Impossible Time", "Geolocation Velocity", or "User Behavior Analytics (UBA) anomalies". This table stores high-fidelity alerts from these systems that standard ML might miss, providing a defense-in-depth security posture.
-- KPIs: False Positive Rate, Detection Time.
-- Feature Reference: F088, T305
CREATE TABLE IF NOT EXISTS audit.sentinel_event_detection (
    sentinel_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL, -- 'IMPOSSIBLE_TRAVEL', 'INSIDER_THREAT', 'DATA_EXFILTRATION'
    source_entity_id UUID NOT NULL,
    confidence_score NUMERIC(3,2) NOT NULL,
    trigger_data JSONB NOT NULL, -- The raw data causing the alert
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    investigation_status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CLOSED, FALSE_POSITIVE
    assigned_to UUID REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.sentinel_event_detection IS 'Stores security alerts from advanced behavioral and heuristic analysis engines';

CREATE INDEX idx_sentinel_status ON audit.sentinel_event_detection(investigation_status, detected_at DESC);


-- Table: T368 - quantum_resistance_migration
-- Description: Tracks migration to quantum-resistant algorithms.
-- Business Case: Future-Proofing. Quantum computers can break RSA/ECC. This table tracks the migration of our encryption (T059) and digital signatures (T254) from "Pre-Quantum" (RSA-2048) to "Post-Quantum" (Dilithium, Kyber) algorithms. It ensures long-term data confidentiality as hardware advances.
-- KPIs: Quantum Readiness Percentage.
-- Feature Reference: F045, T090
CREATE TABLE IF NOT EXISTS audit.quantum_resistance_migration (
    migration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_type VARCHAR(50) NOT NULL, -- 'ENCRYPTION_KEY', 'SIGNING_ALGORITHM'
    old_algorithm VARCHAR(50) NOT NULL, -- e.g., 'RSA_2048'
    new_algorithm VARCHAR(50) NOT NULL, -- e.g., 'CRYSTALS_KYBER_DILITHIUM'
    target_id UUID REFERENCES audit.encryption_keys(key_id),
    migration_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'PLANNED', -- PLANNED, IN_PROGRESS, VERIFIED, ROLLED_BACK
    verified_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.quantum_resistance_migration_is 'Tracks the transition to cryptographic algorithms secure against quantum computer attacks';


-- Table: T369 - privacy_budget_auctions
-- Description: Experimental framework for trading privacy budget.
-- Business Case: Incentivizing Privacy. If a researcher wants to query sensitive data (high epsilon), they must "buy" epsilon budget from others who aren't using theirs. This table records these "Privacy Budget Auctions" (Smart Contract based), creating a market for differential privacy access.
-- KPIs: Market Efficiency, Budget Utilization.
-- Feature Reference: F043, F051
CREATE TABLE IF NOT EXISTS audit.privacy_budget_auctions (
    auction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auction_start TIMESTAMP WITH TIME ZONE NOT NULL,
    auction_end TIMESTAMP WITH TIME ZONE NOT NULL,
    contract_address CHAR(42), -- Ethereum contract address
    epsilon_amount NUMERIC(10,4) NOT NULL, -- Total epsilon in auction
    winner_address CHAR(42),
    winning_bid_amount NUMERIC(19,4),
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, CLOSED, CANCELLED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.privacy_budget_auctions_is 'Records blockchain-based auctions for trading privacy budget (Epsilon) for data access';


-- Table: T370 - regulatory_simulation_results
-- Description: Stores results of simulating new regulations.
-- Business Case: Impact Assessment. Before a new law (e.g., "Ban Crypto Payments") passes, we simulate it. This table stores the impact of the simulation on our transaction volume, tax collection, and compliance costs. It allows us to provide data-driven feedback to policymakers.
-- KPIs: Simulation Accuracy, Prediction Horizon.
-- Feature Reference: F096, T144
CREATE TABLE IF NOT EXISTS audit.regulatory_simulation_results (
    simulation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(255) NOT NULL,
    proposed_regulation TEXT NOT NULL,
    simulated_start_date DATE NOT NULL,
    simulated_end_date DATE NOT NULL,
    impact_on_revenue NUMERIC(15,2), -- Projected change
    impact_on_compliance_cost NUMERIC(15,2),
    user_behavior_change VARCHAR(50), -- e.g., 'MIGRATE_TO_CASH'
    confidence_interval NUMERIC(3,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.regulatory_simulation_results_is 'Stores outcomes of economic simulations of proposed regulatory changes';


-- Table: T371 - synthetic_data_marketplace
-- Description: Marketplace for trading synthetic datasets.
-- Business Case: Data Monetization. Synthetic data (T061) has value. Researchers and developers might buy it to train their models. This table lists "Products" (datasets) for sale, price, and access terms. It turns a compliance tool into a potential revenue stream for the organization.
-- KPIs: Dataset Sales Revenue, Buyer Satisfaction.
-- Feature Reference: F064, T061
CREATE TABLE IF NOT EXISTS audit.synthetic_data_marketplace (
    listing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_name VARCHAR(255) NOT NULL,
    description TEXT,
    row_count BIGINT NOT NULL,
    fidelity_score NUMERIC(3,2), -- How real is it?
    price_amount NUMERIC(10,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    license_type VARCHAR(50), -- 'COMMERCIAL', 'RESEARCH_ONLY'
    expiry_date DATE,
    seller_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.synthetic_data_marketplace_is 'Marketplace for monetizing high-fidelity synthetic datasets generated for training';


-- Table: T372 - automated_legal_clause_inserter
-- Description: Logs insertion of legal clauses into contracts.
-- Business Case: Contract Automation. Merchant agreements, vendor contracts, and audit engagement letters often need standard legal clauses (e.g., "Force Majeure", "Governing Law"). This table logs the automatic insertion of these clauses by an AI/NLP engine, ensuring every contract generated is legally compliant.
-- KPIs: Clause Inclusion Accuracy.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.automated_legal_clause_inserter (
    insertion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_type VARCHAR(100) NOT NULL, -- 'AUDIT_ENGAGEMENT', 'VENDOR_AGREEMENT'
    jurisdiction_code CHAR(2) NOT NULL,
    clause_name VARCHAR(255) NOT NULL,
    clause_text TEXT NOT NULL,
    target_section VARCHAR(100),
    detected_from_reference VARCHAR(255), -- Link to Legal DB
    inserted_by VARCHAR(100), -- AI or Human
    inserted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.automated_legal_clause_inserter_is 'Logs automatic insertion of standard legal clauses into contracts to ensure compliance';


-- Table: T373 - dynamic_data_labeling
-- Description: Tracks crowdsourced labeling of data for ML.
-- Business Case: Human-in-the-Loop ML. ML models need labeled data (e.g., "Is this Fraud? Yes/No"). This table manages tasks where humans (Auditors) label batches of data to train the models. It supports an "Active Learning" loop where models query what they are unsure of, and humans label it.
-- KPIs: Labeling Throughput, Quality Agreement.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.dynamic_data_labeling (
    labeling_task_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_batch_id UUID NOT NULL,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    data_type VARCHAR(50) NOT NULL, -- 'TRANSACTION', 'ENTITY'
    assigned_to UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'ASSIGNED', -- ASSIGNED, IN_PROGRESS, COMPLETED
    items_labeled INTEGER DEFAULT 0,
    items_total INTEGER NOT NULL,
    quality_score NUMERIC(3,2), -- Check consistency
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.dynamic_data_labeling_is 'Manages tasks for humans to label data to improve supervised machine learning models';

CREATE INDEX idx_labeling_status ON audit.dynamic_data_labeling(status, assigned_to);


-- Table: T374 - federated_learning_contribution
-- Description: Tracks contributions to a global federated model.
-- Business Case: Collaborative AI without Data Sharing. Maybe 5 countries use PARI. We can train a global fraud model without sharing private data (Federated Learning). This table tracks the contribution metrics (data points, gradients) from each partner, ensuring fairness and attributing value correctly.
-- KPIs: Contribution Validity, Model Performance Gain.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.federated_learning_contribution (
    contribution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    global_model_id UUID NOT NULL,
    participant_jurisdiction CHAR(2) NOT NULL,
    training_round INTEGER NOT NULL,
    data_points_contributed BIGINT NOT NULL,
    gradient_checksum CHAR(64), -- Integrity of the update
    performance_improvement NUMERIC(3,2), -- Lift score for this partner
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.federated_learning_contribution_is 'Tracks data contributions from partners to a centralized federated learning model for fraud detection';


-- Table: T375 - algorithmic_audit_trails
-- Description: Verifying the fairness and logic of algorithms.
-- Business Case: Algorithmic Accountability. We audit people, but we must also "Audit the Algo". This table logs the decision logic path (Feature X > 5 AND Feature Y < 2) used by ML models to make decisions. If a model denies a loan, this table explains *why* mathematically, proving no discrimination.
-- KPIs: Logic Explainability, Audit Verification Time.
-- Feature Reference: F035, F150
CREATE TABLE IF NOT EXISTS audit.algorithmic_audit_trails (
    trail_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    prediction_id UUID NOT NULL, -- The specific event
    input_features JSONB NOT NULL, -- The 'X' vector
    decision_boundary NUMERIC(10,4), -- Threshold used
    feature_contributions JSONB NOT NULL, -- {feature: weight}
    explanation TEXT,
    fairness_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.algorithmic_audit_trails_is 'Detailed log of algorithmic decision paths to ensure transparency, fairness, and accountability';


-- Table: T376 - digital_twin_audit_data
-- Description: Data for creating a Digital Twin of the audit process.
-- Business Case: Predictive Simulation. A "Digital Twin" is a virtual replica of the real-world process. This table holds the dynamic data (current workload, active alerts, staff availability) used to simulate "What happens to our delivery date if we lose 2 auditors?". It enables proactive management.
-- KPIs: Twin Synchronization Accuracy.
-- Feature Reference: F116, F150
CREATE TABLE IF NOT EXISTS audit.digital_twin_audit_data (
    twin_update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    simulation_scenario_id UUID NOT NULL,
    state_key VARCHAR(255) NOT NULL, -- e.g., 'CURRENT_CASES_OPEN'
    state_value JSONB NOT NULL,
    confidence_interval_high NUMERIC(15,2),
    confidence_interval_low NUMERIC(15,2),
    captured_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.digital_twin_audit_data_is 'Stores state snapshots for building a digital twin of the audit operation for predictive modeling';


-- Table: T377 - cognitive_biometric_auth
-- Description: Continuous authentication via behavioral patterns.
-- Business Case: Zero Trust Security. Passwords are static; behavior is dynamic. This table stores "Cognitive Biometrics" (Keystroke dynamics, Mouse movement patterns) captured during a session. If the user's behavior deviates significantly (indicating hijacking), the session is terminated.
-- KPIs: False Rejection Rate (FRR).
-- Feature Reference: F009, F088
CREATE TABLE IF NOT EXISTS audit.cognitive_biometric_auth (
    biometric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    metric_type VARCHAR(50) NOT NULL, -- 'KEYSTROKE_RHYTHM', 'MOUSE_ACCELERATION'
    sample_data JSONB NOT NULL, -- Encrypted vectors
    is_anomalous BOOLEAN NOT NULL,
    confidence_score NUMERIC(3,2),
    triggered_action VARCHAR(50), -- 'NONE', 'WARN_USER', 'TERMINATE_SESSION'
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cognitive_biometric_auth_is 'Stores behavioral biometric signals for continuous authentication and anomaly detection';

CREATE INDEX idx_bio_session ON audit.cognitive_biometric_auth(session_id);


-- Table: T378 - zero_knowledge_proof_verification
-- Description: Verifies Zero-Knowledge Proofs (zk-SNARKs).
-- Business Case: Privacy Assurance. Merchants submit zk-SNARKs to prove they have enough collateral or revenue without revealing the exact number. This table logs the *verification* of these proofs (validating the crypto proof), checking that the logic holds while keeping the data hidden.
-- KPIs: Proof Verification Speed (<200ms), Validity.
-- Feature Reference: F035, F023
CREATE TABLE IF NOT EXISTS audit.zero_knowledge_proof_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proof_type VARCHAR(50) NOT NULL, -- 'INCOME_PROOF', 'SOLVENCY_PROOF'
    submitter_id UUID NOT NULL,
    proof_hash CHAR(64) NOT NULL,
    smart_contract_address CHAR(42),
    verification_result BOOLEAN NOT NULL,
    gas_used BIGINT,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT
);
COMMENT ON TABLE audit.zero_knowledge_proof_verification_is 'Stores results of verifying Zero-Knowledge proofs without accessing underlying sensitive data';


-- Table: T379 - supply_chain_interoperability
-- Description: ISO 20022 based supply chain tracking.
-- Business Case: Full Supply Chain Audit. We track payment, but not the goods. This table ingests ISO 20022 "Traceability" messages (apts, dmst) from merchants' logistics partners. It links the Financial Flow (T014) to the Physical Flow (Logistics), creating a "Digital Twin" of the supply chain.
-- KPIs: Message Processing Rate, Traceability Coverage.
-- Feature Reference: F001, T096
CREATE TABLE IF NOT EXISTS audit.supply_chain_interoperability (
    supply_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    product_batch_id VARCHAR(100) NOT NULL,
    product_code VARCHAR(100) NOT NULL,
    logistics_provider VARCHAR(255) NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- 'PACKED', 'SHIPPED', 'DELIVERED'
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    location_geo_lat NUMERIC(9,6),
    location_geo_long NUMERIC(9,6),
    message_type VARCHAR(20) CHECK (message_type IN ('APTS', 'DMST'))
    message_xml_path TEXT
);
COMMENT ON TABLE audit.supply_chain_interoperability_is 'Ingests ISO 20022 supply chain messages to correlate financial transactions with physical goods movement';


-- Table: T380 - custodial_wallet_audit
-- Description: Auditing third-party custodial wallets.
-- Business Case: DeFi Risk Analysis. Users might interact via a "Custodial Wallet" (Coinbase) which pools funds. This table tracks the balance and transactions of these custodial wallets (via API), allowing auditors to assess if the custodial provider is a risk to the platform's liquidity.
-- KPIs: Custodial Balance Difference, API Latency.
-- Feature Reference: F001, T255
CREATE TABLE IF NOT EXISTS audit.custodial_wallet_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_provider VARCHAR(50) NOT NULL,
    wallet_address VARCHAR(100) NOT NULL,
    balance_snapshot NUMERIC(19,4) NOT NULL,
    last_tx_hash CHAR(66),
    api_verified BOOLEAN DEFAULT FALSE,
    api_latency_ms INTEGER,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.custodial_wallet_audit_is 'Monitors balances of third-party custodial wallets interacting with the platform to assess liquidity risk';


-- Table: T381 - decentralized_identity_verification
-- Description: Verifying Decentralized Identities (DIDs).
-- Business Case: KYC for Web3. Users use DIDs (did:ethr). This table stores the verification status of these DIDs (trust anchors, credential issuance). It replaces manual KYC checks with automated cryptographic verification of decentralized identity proofs.
-- KPIs: Verification Success Rate.
-- Feature Reference: F098, T088
CREATE TABLE IF NOT EXISTS audit.decentralized_identity_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    did_identifier VARCHAR(255) NOT NULL, -- Decentralized ID
    trust_anchor VARCHAR(255) NOT NULL, -- e.g., 'Polygon_ID', 'Sovrin'
    credential_type VARCHAR(100), -- e.g., 'Passport', 'AgeVerification'
    issuer_did VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE,
    is_valid BOOLEAN NOT NULL,
    verification_details JSONB
);
COMMENT ON TABLE audit.decentralized_identity_verification_is 'Stores verification status of Decentralized Idententities to validate Web3 user profiles';


-- Table: T382 - tokenized_real_world_asset_audit
-- Description: Auditing Real World Assets (RWA) represented as tokens.
-- Business Case: Asset Tokenization. Real Estate or Gold is tokenized on chain. This table links the "Token ID" to the "Physical Asset" data (Location, Appraiser ID). It allows auditors to verify that the token actually represents a real asset in the real world.
-- KPIs: Asset Verification Success.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.tokenized_real_world_asset_audit (
    rwa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_id CHAR(42) NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- 'REAL_ESTATE', 'COMMODITY'
    asset_identifier VARCHAR(255) NOT NULL, -- Deed or Serial Number
    location_address TEXT NOT NULL,
    appraised_value NUMERIC(19,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    appraiser_name VARCHAR(255),
    last_verified DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.tokenized_real_world_asset_audit_is 'Links blockchain tokens to real-world physical assets to prevent asset-backed token fraud';


-- Table: T383 - nft_kyc_registry
-- Description: Checks if NFT holders are KYC'd.
-- Business Case: NFT Compliance. NFTs can be money laundering tools (Art wash trading). This table tracks which Wallet/Holder has passed KYC verification. If an NFT is transferred to an un-KYC'd wallet, it flags an alert for high-value art sales.
-- KPIs: KYC Coverage of Transactions.
-- Feature Reference: F026, F382
CREATE TABLE IF NOT EXISTS audit.nft_kyc_registry (
    registry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_address VARCHAR(42) NOT NULL,
    nft_collection_address CHAR(42) NOT NULL,
    kyc_level VARCHAR(50), -- 'NONE', 'SOLO', 'INSTITUTIONAL'
    verified_by VARCHAR(100), -- 'IDENTITY_PROTOCOL', 'EXCHANGE'
    verification_date DATE NOT NULL DEFAULT CURRENT_DATE,
    is_blacklisted BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.nft_kyc_registry_is 'Maps NFT holders to KYC status to detect transfers to unverified wallets';


-- Table: T384 - dao_proposal_votes
-- Description: Auditing DAO governance votes.
-- Business Case: DAO Oversight. A Decentralized Autonomous Organization (DAO) might hold treasury funds. This table records the voting history of proposals (Who voted what). It allows auditors to ensure that funds aren't being syphoned by a 51% attack or malicious actors.
-- KPIs: Voter Turnout, Proposal Validity.
-- Feature Reference: F021, F001
CREATE TABLE IF NOT EXISTS audit.dao_proposal_votes (
    vote_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proposal_id VARCHAR(100) NOT NULL,
    voter_address CHAR(42) NOT NULL,
    vote_option VARCHAR(50) NOT NULL, -- 'FOR', 'AGAINST', 'ABSTAIN'
    voting_weight BIGINT NOT NULL, -- Token weight
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    block_number BIGINT
);
COMMENT ON TABLE audit.dao_proposal_votes IS 'Records voting activity in DAOs to audit treasury disbursement and governance';

CREATE INDEX idx_dao_proposal ON audit.dao_proposal_votes(proposal_id, timestamp DESC);


-- Table: T385 - smart_contract_lifecycle_audit
-- Description: Full lifecycle audit of a smart contract.
-- Business Case: Contract Auditability. A smart contract has a life: Dev -> Testnet Deploy -> Mainnet Deploy -> Upgrade -> Sunset. This table links the Source Code (Hash) to the Deployed Address, tracking every stage. It proves that the code running on Mainnet is the code we audited.
-- KPIs: Lifecycle Verification Time.
-- Feature Reference: F001, T207
CREATE TABLE IF NOT EXISTS audit.smart_contract_lifecycle_audit (
    lifecycle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,
    stage VARCHAR(20) NOT NULL, -- 'DEV', 'AUDITED', 'DEPLOYED_TESTNET', 'DEPLOYED_MAINNET', 'UPGRADED'
    source_code_hash CHAR(64), -- IPFS hash of source
    deployed_address CHAR(42),
    auditor_uuid UUID REFERENCES audit.auditor(auditor_id),
    audit_report_path TEXT,
    stage_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.smart_contract_lifecycle_audit_is 'Tracks the development and deployment stages of smart contracts to ensure audit compliance';


-- Table: T386 - gas_price_optimization_recommendations
-- Description: Suggestions for minimizing gas costs.
-- Business Case: Cost Savings. Gas prices fluctuate. A transaction that costs $5 at 2 PM might cost $1 at 4 AM. This table tracks our recommendations for batching or delaying transactions to save money. It allows us to calculate the "Gas Efficiency" of our operations.
-- KPIs: Savings Achieved.
-- Feature Reference: F001, F158
CREATE TABLE IF NOT EXISTS audit.gas_price_optimization_recommendations (
    rec_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_tx_hash CHAR(66) NOT NULL,
    recommended_action VARCHAR(50) NOT NULL, -- 'DELAY', 'USE_L2', 'BATCH'
    estimated_gas_units NUMERIC(10,4) NOT NULL,
    estimated_cost_usd NUMERIC(10,2),
    suggested_execution_timestamp TIMESTAMP WITH TIME ZONE,
    accepted BOOLEAN DEFAULT FALSE,
    accepted_by UUID REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.gas_price_optimization_recommendations_is 'Stores optimization suggestions to reduce blockchain gas transaction costs';


-- Table: T387 - orphan_block_detection
-- Description: Logging detection of orphaned blocks.
-- Business Case: Chain Integrity. Sometimes miners produce blocks that are "Orphans" (not part of the main chain). This table logs the detection of these orphans. We need to ensure that no valid transactions were trapped in these discarded blocks.
-- KPIs: Orphan Block Count.
-- Feature Reference: F001, T206
CREATE TABLE IF NOT EXISTS audit.orphan_block_detection (
    orphan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    block_hash CHAR(64) NOT NULL,
    block_number BIGINT NOT NULL,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    re_orged_into_block_hash CHAR(66) -- The block that replaced it
);
COMMENT ON TABLE audit.orphan_block_detection_is 'Stores detection logs of orphaned blocks to ensure no transactions are lost during chain reorganizations';


-- Table: T388 - validator_slashing_events
-- Description: Recording validator slashing events.
-- Business Case: Consensus Risk. In Proof-of-Stake, validators act maliciously and get "Slashed" (funds burned). This table logs these events. If a validator associated with our infrastructure (or an exchange we use) is slashed, it's a critical financial event for us.
-- KPIs: Slashing Events.
-- Feature Reference: T206, T002
CREATE TABLE IF NOT EXISTS audit.validator_slashing_events (
    slashing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    validator_address VARCHAR(42) NOT NULL,
    reason VARCHAR(255) NOT NULL, -- 'DOUBLE_SIGN', 'DOWNTIME'
    amount_slashed NUMERIC(19,4) NOT NULL,
    block_number BIGINT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.validator_slashing_events_is 'Logs events where blockchain validators are penalized for malicious activity';


-- Table: T389 - cross_domain_sso_logs
-- Description: Logs of Single Sign-On (SSO) attempts.
-- Business Case: Identity Federation. Users log in via Okta/Auth0. This table logs the SAML/OIDC assertion details (Attributes received, Session ID). It creates a reliable audit trail of who accessed which apps using the federated identity, crucial for compliance.
-- KPIs: SSO Success Rate.
-- Feature Reference: F009, F098
CREATE TABLE IF NOT EXISTS audit.cross_domain_sso_logs (
    sso_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    identity_provider VARCHAR(100) NOT NULL, -- 'OKTA', 'AZURE_AD'
    saml_response_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    relay_state_uuid UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiration TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE audit.cross_domain_sso_logs_is 'Stores tokens and session details from federated identity providers for user login auditing';


-- Table: T390 - just_in_time_access_grants
-- Description: Logs Just-In-Time (JIT) access grants.
-- Business Case: Principle of Least Privilege. Users don't have permanent "Admin" rights. They request a "Privilege Elevation" for 1 hour. This table logs every JIT grant: Who requested, Why, Who approved, and when. It provides a tighter control loop than static roles.
-- KPIs: JIT Revocation Speed.
-- Feature Reference: F127, F018
CREATE TABLE IF NOT EXISTS audit.just_in_time_access_grants (
    grant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requester_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approver_id UUID REFERENCES audit.auditor(auditor_id),
    requested_role VARCHAR(100) NOT NULL,
    justification TEXT NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    access_token_id UUID REFERENCES audit.session_tokens(token_id)
);
COMMENT ON TABLE audit.just_in_time_access_grants IS 'Logs temporary privilege escalations to enforce dynamic access control policies';


-- Table: T391 - insider_trading_detection
-- Description: Logs of specific ML model for insider trading.
-- Business Case: Market Abuse. If an auditor has access to a "Sensitive Company" (Merger target), and we see them buying stock 1 day before the announcement, that's insider trading. This table logs the alerts from this specialized ML model, separating it from general fraud to handle specific compliance needs.
-- KPIs: Alert Precision.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.insider_trading_detection (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    target_entity VARCHAR(255) NOT NULL, -- The Stock/Merchant
    trigger_event_type VARCHAR(50), -- 'UNUSUAL_VOLUME', 'PRICE_RAMP', 'OPTION_PURCHASE'
    confidence_score NUMERIC(3,2) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reported_to_regulator VARCHAR(20), -- 'SEC', 'FCA', 'NONE'
    case_status VARCHAR(20) DEFAULT 'FLAGGED'
);
COMMENT ON TABLE audit.insider_trading_detection_is 'Stores alerts detecting potential market abuse based on privileged information access';


-- Table: T392 - market_manipulation_signals
-- Description: Logs detection of wash trading/spoofing.
-- Business Case: Market Integrity. "Wash Trading" (buying and selling to yourself) creates fake volume. This table logs signals of this manipulation detected on DEXes (Decentralized Exchanges). It ensures the trading data we use for audits is clean and not manipulated by washers.
-- KPIs: Wash Trade Detection Rate.
-- Feature Reference: F002, F393
CREATE TABLE IF NOT EXISTS audit.market_manipulation_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_pair VARCHAR(20) NOT NULL, -- ETH/USD
    detection_type VARCHAR(50) NOT NULL, -- 'WASH_TRADE', 'SPOOFING', 'LAYERING'
    involved_addresses TEXT[] NOT NULL,
    volume_affected NUMERIC(19,4),
    signal_strength NUMERIC(3,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.market_manipulation_signals_is 'Logs detection of market manipulation techniques in decentralized exchange pools';


-- Table: T393 - liquidity_pool_monitoring
-- Description: Monitoring AMM (Automated Market Maker) pools.
-- Business Case: Liquidity Risk. Many tokens use AMM pools (Uniswap) for price. A "Rug Pull" drains the pool. This table monitors the liquidity depth and token prices in major pools associated with our platform, alerting if liquidity drops below a safe threshold.
-- KPIs: Liquidity Volatility, Health Score.
-- Feature Reference: F001, F394
CREATE TABLE IF NOT EXISTS audit.liquidity_pool_monitoring (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_address CHAR(42) NOT NULL,
    token_a CHAR(42) NOT NULL,
    token_b CHAR(42) NOT NULL,
    reserve_token_a NUMERIC(19,4),
    reserve_token_b NUMERIC(19,4),
    price_token_a NUMERIC(19,4),
    observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    health_status VARCHAR(20) -- 'HEALTHY', 'RISK', 'CRITICAL'
);
COMMENT ON TABLE audit.liquidity_pool_monitoring_is 'Tracks real-time depth and value of liquidity pools to detect rug pulls or liquidity crises';


-- Table: T394 - stablecoin_peg_monitoring
-- Description: Monitoring if Stablecoins are actually pegged.
-- Business Case: Reserve Risk. We accept USDC, USDT, etc. If they "De-Peg" (become worth $0.90), we lose money. This table constantly monitors the off-chain reserves (Bank accounts, T-Bills) to ensure 1:1 backing exists for every token in our system.
-- KPIs: Peg Variance (<0.01%).
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.stablecoin_peg_monitoring (
    peg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    stablecoin_name VARCHAR(50) NOT NULL, -- 'USDT', 'USDC'
    target_currency CHAR(3) NOT NULL, -- USD
    peg_value NUMERIC(10,4) NOT NULL, -- e.g., 1.01
    last_audit_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auditor_name VARCHAR(255),
    reserve_adequate BOOLEAN DEFAULT TRUE,
    deviation_percent NUMERIC(5,2)
);
COMMENT ON TABLE audit.stablecoin_peg_monitoring_is 'Continuously audits reserves backing stablecoins to detect loss of peg';


-- Table: T395 - oracle_failover_logs
-- Description: Logs switching between data oracles.
-- Business Case: Reliability of Truth. Smart contracts often need "External Data" (Price of Gold, Weather, Forex) via Oracles (Chainlink). If Chainlink fails, we switch to a backup. This table logs the Failover event, ensuring we know which data source we were using at any specific time.
-- KPIs: Oracle Availability, Failover Time.
-- Feature Reference: F001, T259
CREATE TABLE IF NOT EXISTS audit.oracle_failover_logs (
    failover_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    oracle_provider VARCHAR(50) NOT NULL, -- 'CHAINLINK', 'BAND_PROTOCOL'
    data_feed_name VARCHAR(100) NOT NULL,
    from_provider VARCHAR(50),
    to_provider VARCHAR(50),
    reason VARCHAR(255),
    switch_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    validation_success BOOLEAN
);
COMMENT ON TABLE audit.oracle_failover_logs_is 'Records events where external data sources fail over to backup providers to ensure system reliability';


-- Table: T396 - flash_loan_detection
-- Description: Detecting Flash Loans on chain.
-- Business Case: Smart Contract Risk. "Flash Loans" (Borrow A -> Sell A -> Buy Back -> Repay) manipulate markets. This table logs the detection of these rapid transactions. If a large merchant uses Flash Loans to arbitrage VAT, it flags a specific AML risk.
-- KPIs: Loan Detection Speed.
-- Feature Reference: F001, F088
CREATE TABLE IF NOT EXISTS audit.flash_loan_detection (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tx_hash CHAR(66) NOT NULL,
    borrower_address CHAR(42) NOT NULL,
    lender_pool_address CHAR(42) NOT NULL,
    asset_amount NUMERIC(19,4) NOT NULL,
    profit_amount NUMERIC(19,4),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_confirmed BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE audit.flash_loan_detection_is 'Detects instantaneous uncollateralized loans used for arbitrage or manipulation';

CREATE INDEX idx_flash_tx ON audit.flash_loan_detection(tx_hash);


-- Table: T397 - sandwich_attack_detection
-- Description: Detecting MEV Sandwich attacks.
-- Business Case: Transaction Ordering Risk. A "Sandwich Attack" places a tx before yours and after yours to manipulate the price. This table logs these detection events. If we see our tax payment being sandwiched, it confirms we might be overpaying, triggering an automated retry or investigation.
-- KPIs: Front-Running Detection Rate.
-- Feature Reference: F001, F088
CREATE TABLE IF NOT EXISTS audit.sandwich_attack_detection (
    attack_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    victim_tx_hash CHAR(66) NOT NULL, -- Our tx
    front_runner_tx_hash CHAR(66) NOT NULL,
    back_runner_tx_hash CHAR(66) NOT NULL,
    gas_used_by_attacker NUMERIC(10,4),
    extra_gas_paid_by_victim NUMERIC(10,4),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.sandwich_attack_detection_is 'Detects MEV sandwich attacks targeting our transactions to analyze price impact';


-- Table: T398 - mev_blocker_conflicts
-- Description: Logs MEV blockers (Flashbots, etc.).
-- Business Case: Infrastructure Competition. MEV Blockers (searchers who profit from ordering txs) congest the network. This table logs interactions with or blockage by known MEV bots. It helps us decide if we need to raise our Gas Price to ensure tx inclusion.
-- KPIs: Inclusion Failure Rate.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS audit.mev_blocker_conflicts (
    conflict_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tx_hash CHAR(66) NOT NULL,
    blocker_signature CHAR(132) NOT NULL,
    gas_price_offered NUMERIC(10,4) NOT NULL,
    our_gas_price NUMERIC(10,4) NOT NULL,
    conflict_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.mev_blocker_conflicts_is 'Logs conflicts with MEV searchers to optimize gas strategy for transaction inclusion';


-- Table: T399 - dark_pool_monitoring
-- Description: Monitoring dark pools (private transactions).
-- Business Case: AML for Privacy Coins. Dark Pools (e.g., RenBridge, Tornado Cash) hide transaction graphs. Criminals love them. This table monitors known dark pool addresses. If a merchant receives funds from a dark pool address, it is a major risk signal for AML.
-- KPIs: Dark Pool Volume Tracking.
-- Feature Reference: F025, F399
CREATE TABLE IF NOT EXISTS audit.dark_pool_monitoring (
    pool_address CHAR(42) NOT NULL,
    pool_type VARCHAR(50) NOT NULL, -- 'MIXER', 'SPLITTER', 'PELATOR'
    monitored_since TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    volume_last_24h NUMERIC(19,4),
    associated_addresses TEXT[],
    risk_level VARCHAR(20) DEFAULT 'HIGH', -- HIGH, SEVERE
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(pool_address)
);
COMMENT ON TABLE audit.dark_pool_monitoring_is 'Monitors privacy-enhancing tools (Dark Pools) for potential illicit money flow';


-- Table: T400 - mempool_transaction_classification
-- Description: Classifying unconfirmed transactions in mempool.
-- Business Case: Pre-TX Filtering. Before a tx is confirmed, it's in the "Mempool". Fraudsters might try to double-spend. This table pulls pending txs and classifies them using ML (Is this a Double Spend?). We can warn users to cancel/ignore the tx before it confirms.
-- KPIs: Classification Accuracy.
-- Feature Reference: F001, F088
CREATE TABLE IF NOT EXISTS audit.mempool_transaction_classification (
    class_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tx_hash CHAR(66) NOT NULL,
    nonce BIGINT NOT NULL,
    predicted_outcome VARCHAR(50) NOT NULL, -- 'SUCCESS', 'FAIL_DOUBLE_SPEND', 'FAIL_NONCE'
    confidence_score NUMERIC(3,2),
    classified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    was_correct BOOLEAN -- Filled once tx confirms/rejects
);
COMMENT ON TABLE audit.mempool_transaction_classification_is 'Classifies unconfirmed transactions in the memory pool to predict failure before confirmation';


-- Table: T401 - privacy_enhancing_technology_logs
-- Description: Logs usage of ZKP, Homomorphic, etc.
-- Business Case: Data Privacy Tech. We don't just mask data; we might use "Zero Knowledge Proofs" or "Secure Multi-Party Computation (SMPC)". This table logs which PETs (Privacy Enhancing Technologies) were used to process a specific query, proving we are using state-of-the-art privacy.
-- KPIs: PET Usage Rate, Performance Overhead.
-- Feature Reference: F004, T378
CREATE TABLE IF NOT EXISTS audit.privacy_enhancing_technology_logs (
    pet_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_id UUID NOT NULL REFERENCES audit.audit_query_history(query_id),
    technology_type VARCHAR(50) NOT NULL, -- 'ZKP', 'HOMOMORPHIC', 'TE'
    parameters_json JSONB NOT NULL,
    execution_time_ms INTEGER,
    privacy_budget_consumed NUMERIC(5,4),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.privacy_enhancing_technology_logs_is 'Tracks the use of advanced cryptographic privacy techniques for specific audit queries';


-- Table: T402 - secure_multiparty_computation_logs
-- Description: Logs SMPC sessions.
-- Business Case: Collaborative Computation. Multiple parties want to find the average VAT collection without seeing each other's data. SMPC allows "Compute sum" without revealing inputs. This table logs the setup and result hashes of SMPC sessions, ensuring data cannot be extracted from the protocol.
-- KPIs: SMPC Session Validity.
-- Feature Reference: F004, F401
CREATE TABLE IF NOT EXISTS audit.secure_multiparty_computation_logs (
    smpc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    computation_type VARCHAR(50) NOT NULL, -- 'SUM', 'AVERAGE', 'COUNT'
    participant_ids UUID[] NOT NULL,
    result_hash CHAR(64),
    execution_time_ms INTEGER,
    security_protocol VARCHAR(100), -- 'SPDZ', 'BGW'
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.secure_multiparty_computation_logs_is 'Records execution of Secure Multi-Party Computation protocols to validate privacy guarantees';


-- Table: T403 - threshold_secret_sharing_logs
-- Description: Logs sharing of secrets via Trusted Execution Environments (TEEs).
-- Business Case: Hardware-Level Security. We might need to process data inside a TEE (enclave) using a secret (decryption key) provided by the owner. The key is "sealed" (Threshold Secret Sharing). This table logs the decryption/usage events, ensuring the secret was not extracted from the enclave improperly.
-- KPIs: Secret Leakage (Zero).
-- Feature Reference: F045, F402
CREATE TABLE IF NOT EXISTS audit.threshold_secret_sharing_logs (
    tee_session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL,
    encrypted_secret_hash CHAR(64),
    user_uuid UUID NOT NULL,
    operation_type VARCHAR(50) NOT NULL, -- 'DECRYPT', 'COMPUTE'
    tee_hash_proof CHAR(64),
    status VARCHAR(20) NOT NULL, -- 'ALLOWED', 'REJECTED'
    execution_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.threshold_secret_sharing_logs_is 'Logs operations involving sealed secrets in Trusted Execution Environments';


-- Table: T404 - verifiable_credentials_registry
-- Description: Stores Verifiable Credentials (VCs).
-- Business Case: Portable Credentials. A VC is like a digital vaccination certificate or university degree. This table holds the hash of the VCs, DID, and revocation status. We use this to verify that an auditor is actually "Certified Chartered Accountant" without asking the university for the 100th time.
-- KPIs: VC Verification Speed, Revocation Coverage.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.verifiable_credentials_registry (
    vc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    holder_did VARCHAR(255) NOT NULL,
    credential_type VARCHAR(100) NOT NULL, -- 'DEGREE', 'CPA', 'LICENSE'
    issuer_did VARCHAR(255) NOT NULL,
    credential_hash CHAR(64) NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    valid_from DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_until DATE NOT NULL,
    linked_auditor_id UUID REFERENCES audit.auditor(auditor_id) -- Optional, if known
);
COMMENT ON TABLE audit.verifiable_credentials_registry_is 'Stores cryptographic proofs of Verifiable Credentials for automated validity checking';


-- Table: T405 - decentralized_storage_redundancy
-- Description: Tracks redundancy of data in decentralized storage (IPFS).
-- Business Case: Data Availability. We might store audit logs in IPFS. Files get "Pinned" by different nodes. This table tracks which "CIDs" (Content IDs) are pinned to how many nodes, ensuring we meet our durability guarantee (e.g., stored across 6 continents).
-- KPIs: Replication Factor.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.decentralized_storage_redundancy (
    redundancy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_cid CHAR(64) NOT NULL,
    ipfs_gateway VARCHAR(255) NOT NULL, -- e.g., ipfs.io
    file_size_bytes BIGINT,
    pin_count INTEGER DEFAULT 0,
    unique_peers INTEGER DEFAULT 0,
    last_verified TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.decentralized_storage_redundancy_is 'Monitors replication of files in IPFS to ensure data availability';


-- Table: T406 - content_addressable_storage_monitoring
-- Description: Monitoring CAS (Content Addressable Storage).
-- Business Case: Data Integrity. CAS (e.g., MinIO, Swarm) dedupes data based on Content Hash. This table monitors the "Bucket Health" and ensures that no data is corrupted. If an object hash doesn't match, we trigger a repair from the Redundancy system (T405).
-- KPIs: Object Integrity (>99.99%).
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS audit.content_addressable_storage_monitoring (
    bucket_id VARCHAR(255) NOT NULL,
    object_name VARCHAR(255) NOT NULL,
    expected_hash CHAR(64) NOT NULL,
    current_hash CHAR(64),
    size_bytes BIGINT,
    is_corrupted BOOLEAN NOT NULL DEFAULT FALSE,
    last_scan TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.content_addressable_storage_monitoring_is 'Verifies integrity of objects stored in Content Addressable Storage systems';


-- Table: T407 - immutable_worm_compliance_check
-- Description: Checking WORM (Write Once Read Many) status.
-- Business Case: Legal Holds. We must prove to regulators that data is immutable once written. This table runs periodic checks (e.g., via AWS Macie) to verify that the bucket has Object Lock enabled and Versioning disabled. It generates a "Compliance Certificate" proving data hasn't been tampered with.
-- KPIs: WORM Compliance Score (100%).
-- Feature Reference: F030, F119
CREATE TABLE IF NOT EXISTS audit.immutable_worm_compliance_check (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bucket_name VARCHAR(255) NOT NULL,
    lock_enabled BOOLEAN NOT NULL,
    versioning_enabled BOOLEAN, -- Should be False
    last_checked TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN GENERATED ALWAYS AS (lock_enabled AND NOT versioning_enabled) STORED,
    certification_id UUID REFERENCES audit.compliance_certificates(cert_id)
);
COMMENT ON TABLE audit.immutable_worm_compliance_check_is 'Verifies configuration of storage buckets to ensure Write Once Read Many (WORM) compliance';


-- Table: T408 - cognitive_security_ops_monitoring
-- Description: SOAR/CSOC operational monitoring.
-- Business Case: Security Response. The "Cognitive Security" layer monitors alerts. We need to know if the ops team is responding fast enough. This table aggregates metrics like Mean Time to Respond (MTTR), Mean Time to Contain (MTTC) for security incidents, ensuring the incident response process is efficient.
-- KPIs: MTTR, MTTC.
-- Feature Reference: T161, F133
CREATE TABLE IF NOT EXISTS audit.cognitive_security_ops_monitoring (
    ops_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_id UUID REFERENCES audit.sentinel_event_detection(sentinel_id),
    detection_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    triage_timestamp TIMESTAMP WITH TIME ZONE,
    acknowledged_timestamp TIMESTAMP WITH TIME ZONE,
    resolved_timestamp TIMESTAMP WITH TIME ZONE,
    mttr_minutes INTEGER, -- Mean Time To Respond
    mttc_minutes INTEGER, -- Mean Time To Contain
    assigned_to UUID REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.cognitive_security_ops_monitoring_is 'Measures the performance of the security operations center in responding to and containing threats';


-- Table: T409 - threat_intelligence_feed_subscriptions
-- Description: Subscriptions to external Threat Intel feeds.
-- Business Case: Intelligence Sharing. We subscribe to Threat Intel providers (e.g., IBM X-Force, Mandiant). This table tracks which "Feeds" we are subscribed to and the topics of interest. If a new C2 (Command & Control) indicator is published for our region, we ingest it.
-- KPIs: Feed Latency, Threat Match Rate.
-- Feature Reference: T263, F088
CREATE TABLE IF NOT EXISTS audit.threat_intelligence_feed_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_name VARCHAR(100) NOT NULL,
    feed_name VARCHAR(255) NOT NULL, -- e.g., 'APT28_INDICATORS'
    feed_type VARCHAR(50) NOT NULL, -- 'JSON', 'STIX', 'RSS'
    subscription_key VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_successful_pull TIMESTAMP WITH TIME ZONE,
    subscribed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.threat_intelligence_feed_subscriptions_is 'Manages active subscriptions to external threat intelligence data feeds for proactive defense';


-- Table: T410 - cyber_risk_insurance_policies
-- Description: Policies for Cyber Risk Insurance.
-- Business Case: Risk Transfer. We buy "Cyber Risk Insurance" to cover breach costs. This table stores the policy details (Limit, Premium, Deductible) and tracks claims against it. It allows us to calculate the Net Risk Exposure and determine if we need to increase limits.
-- KPIs: Claim Frequency, Coverage Adequacy.
-- Feature Reference: F150, T133
CREATE TABLE IF NOT EXISTS audit.cyber_risk_insurance_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    insurer_name VARCHAR(255) NOT NULL,
    policy_number VARCHAR(100) NOT NULL,
    coverage_limit_usd NUMERIC(15,2) NOT NULL,
    premium_amount_usd NUMERIC(15,2) NOT NULL,
    deductible_usd NUMERIC(15,2),
    policy_start_date DATE NOT NULL,
    policy_end_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, LAPSED, CANCELLED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.cyber_risk_insurance_policies_is 'Manages cyber insurance policies and claims to transfer financial risk';


-- Table: T411 - incident_simulation_drills
-- Description: Records "War Gaming" simulations.
-- Business Case: Readiness Testing. We simulate attacks (Ransomware, DDOS) to see if our defenses hold up. This table logs the "Drill" - what we simulated, did we stop it, and what we learned. It proves to auditors (or insurance companies) that we are secure.
-- KPIs: Drill Participation, "Win/Loss" Ratio.
-- Feature Reference: F119, T244
CREATE TABLE IF NOT EXISTS audit.incident_simulation_drills (
    drill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(255) NOT NULL, -- 'RANSOMWARE', 'ACCOUNT_TAKEOVER'
    execution_date DATE NOT NULL DEFAULT CURRENT_DATE,
    red_team VARCHAR(100) NOT NULL, -- Internal SOC
    blue_team VARCHAR(100) NOT NULL, -- Operations Team
    result VARCHAR(20) NOT NULL, -- SUCCESS, FAILED, PARTIAL_SUCCESS
    lessons_learned TEXT,
    duration_minutes INTEGER,
    organized_by UUID NOT NULL REFERENCES audit.auditor(auditor_id)
);
COMMENT ON TABLE audit.incident_simulation_drills_is 'Records results of war gaming drills to test incident response readiness';


-- Table: T412 - reputation_system_scores
-- Description: Tracking reputation scores of entities.
-- Business Case: Identity Reputation. "Reputation" systems assign a score to wallets or companies based on their history. This table stores this reputation score (0-100). If a Merchant uses a wallet with Low Reputation, we increase the merchant's risk score (T012) by association.
-- KPIs: Reputation Correlation.
-- Feature Reference: F025
CREATE TABLE IF NOT EXISTS audit.reputation_system_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL, -- 'WALLET', 'MERCHANT'
    entity_identifier VARCHAR(255) NOT NULL,
    reputation_source VARCHAR(50) NOT NULL, -- 'DARCHE', 'UNISWAP'
    score INTEGER CHECK (score BETWEEN 0 AND 100),
    contributing_factors JSONB,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.reputation_system_scores_is 'Stores reputation scores from external block-chain and web-of-trust sources for risk assessment';

CREATE INDEX idx_reputation_entity ON audit.reputation_system_scores(entity_type, entity_identifier);


-- Table: T413 - credential_stuffing_detection
-- Description: Detecting credential stuffing attacks.
-- Business Case: Account Takeover Prevention. Attackers try passwords from leaks on thousands of sites at once (Stuffing). This table logs attempts to login using "Known Leaked" passwords. It allows us to block the IP immediately and force a password reset for the user.
-- KPIs: Stuffing Block Rate.
-- Feature Reference: F300, F088
CREATE TABLE IF NOT EXISTS audit.credential_stuffing_detection (
    stuffing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    leaked_password_hash CHAR(64) NOT NULL, -- The leaked hash
    attempted_password_hash CHAR(64) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    attempt_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE audit.credential_stuffing_detection IS 'Detects and blocks login attempts using credentials from known data breaches';


-- Table: T414 - api_abuse_prevention_botnet
-- Description: Botnet for API Abuse Prevention.
-- Business Case: Anti-Botnet. Attackers use botnets to scrape our API. To stop them, we might maintain a "Honeypot" (trap). This table tracks known botnet IPs and the "Signal" we put on them to trap them.
-- KPIs: Botnet IPs Identified.
-- Feature Reference: F088, T184
CREATE TABLE IF NOT EXISTS audit.api_abuse_prevention_botnet (
    botnet_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_range INET NOT NULL, -- e.g., 10.0.0.0/24
    discovered_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    threat_level VARCHAR(20) NOT NULL, -- 'LOW', 'HIGH', 'CRITICAL'
    source VARCHAR(255), -- e.g., 'HONEY_POT'
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DISABLED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.api_abuse_prevention_botnet_is 'Manages known malicious IP ranges and botnets to prevent API abuse and scraping';


-- Table: T415 - honeypot_token_traps
-- Description: Logging tokens planted in honeypots.
-- Business Case: Deception. We leak fake "API Keys" or "Auth Tokens" into breaches to see if bad actors use them. This table logs the creation of these Honeypot Tokens. When one is used, it's a guaranteed detection of a bad actor.
-- KPIs: Honeypot Hits.
-- Feature Reference: F414
CREATE TABLE IF NOT EXISTS audit.honeypot_token_traps (
    trap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_type VARCHAR(50) NOT NULL, -- 'API_KEY', 'JWT', 'COOKIE'
    value_hash CHAR(64) NOT NULL,
    planted_in_breach VARCHAR(255) NOT NULL,
    planted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    first_used TIMESTAMP WITH TIME ZONE,
    used_count INTEGER DEFAULT 0,
    source_ip INET,
    notes TEXT
);
COMMENT ON TABLE audit.honeypot_token_traps_is 'Tracks fake credentials leaked to trap attackers and identify malicious actors';


-- Table: T416 - deception_technology_logs
-- Description: Logs using fake data to deceive attackers.
-- Business Case: Active Defense. If an attacker SQL Injects, we might return fake data to confuse them. This table logs the generation of this "Deception Data" so we can analyze which parts of the database structure the attacker is interested in.
-- KPIs: Deception Success.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.deception_technology_logs (
    deception_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    attacker_session_id UUID NOT NULL, -- Linked to T001
    trigger_event VARCHAR(100) NOT NULL, -- 'SQL_INJECTION', 'USER_ENUM'
    fake_data_payload JSONB NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    detection_status VARCHAR(20) -- DETECTED, IGNORED
);
COMMENT ON TABLE audit.deception_technology_logs_is 'Logs the injection of fake data into attacker sessions to mislead and identify them';


-- Table: T417 - active_directory_synchronization_logs
-- Description: Logs of AD/LDAP synchronization.
-- Business Case: Identity Governance. The Master Directory (AD) is the source of truth for users. This table logs the sync events (User Created, User Deleted, Role Change) from AD to PARI. It ensures an auditor who is disabled in AD is immediately disabled here.
-- KPIs: Sync Latency, Success Rate.
-- Feature Reference: F009, F143
CREATE TABLE IF NOT EXISTS audit.active_directory_synchronization_logs (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_user_id VARCHAR(100) NOT NULL, -- sAMAccountName
    internal_user_id UUID REFERENCES audit.auditor(auditor_id),
    action_type VARCHAR(50) NOT NULL, -- 'CREATE', 'UPDATE', 'DELETE', 'DISABLE'
    attributes_changed JSONB, -- What fields changed?
    sync_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SUCCESS, ERROR
    sync_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT
);
COMMENT ON TABLE audit.active_directory_synchronization_logs_is 'Tracks synchronization events from Active Directory to maintain user identity status';


-- Table: T418 - privilege_access_management_lifecycle
-- Description: PAM Lifecycle of a specific access right.
-- Business Case: Lifecycle Management. A manager requests "Access to Production Data". This table tracks the request -> Approval -> Provision -> Review -> Revoke cycle. It is a sub-audit of permissions, ensuring privileges don't linger after an employee transfers.
-- KPIs: Review Cycle Time.
-- Feature Reference: F127, F418
CREATE TABLE IF NOT EXISTS audit.privilege_access_management_lifecycle (
    pam_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    requestor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approver_id UUID REFERENCES audit.auditor(auditor_id),
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    approved_at TIMESTAMP WITH TIME ZONE,
    provisioned_at TIMESTAMP WITH TIME ZONE,
    review_date DATE, -- Date to review if still needed
    revocation_date DATE,
    status VARCHAR(20) DEFAULT 'REQUESTED', -- REQUESTED, APPROVED, PROVISIONED, REVOKED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.privilege_access_management_lifecycle_is 'Manages the full lifecycle of privilege access requests to ensure temporary access is revoked';


-- Table: T419 - remote_session_termination_logs
-- Description: Logs forced remote session terminations.
-- Business Case: Emergency Controls. If a device is lost or a user reports theft, we must kill their session immediately. This table logs the execution of "Kill Switch" commands, sending signals to revoke tokens and close connections.
-- KPIs: Termination Latency (<5s).
-- Feature Reference: F027, F098
CREATE TABLE IF NOT EXISTS audit.remote_session_termination_logs (
    termination_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    termination_reason VARCHAR(100) NOT NULL, -- 'DEVICE_LOST', 'THEFT', 'ADMIN_ACTION'
    initiated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL
);
COMMENT ON TABLE audit.remote_session_termination_logs_is 'Logs remote execution of session termination commands for lost or stolen devices';


-- Table: T420 - lost_device_wipe_commands
-- Description: Queues commands to wipe data from lost devices.
-- Business Case: Data Protection. When a device is lost, we can't rely on the user deleting it. This table queues an "Erase Command" to be sent to the device (via MDM) the next time it connects, wiping corporate data and cached credentials.
-- KPIs: Wipe Execution Success.
-- Feature Reference: F098, F419
CREATE TABLE IF NOT EXISTS audit.lost_device_wipe_commands (
    wipe_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES audit.mobile_device_info(device_id),
    wipe_scope TEXT[] NOT NULL, -- 'CONTACTS', 'COOKIES', 'CACHE'
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, SENT, FAILED, SUCCESS
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    failure_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.lost_device_wipe_commands_is 'Queues remote data erasure commands for lost or decommissioned mobile devices';


-- Table: T421 - geo_velocity_check_alerts
-- Description: Alerts for impossible travel speeds.
-- Business Case: Travel Rule Violation. A user logs in from London. 5 minutes later, they log in from Tokyo. That's "Geo-Velocity" (impossible travel). This table logs these alerts, which are a sign of shared credentials or session hijacking.
-- KPIs: Geo-Velocity Detection Rate.
-- Feature Reference: F027, F107
CREATE TABLE IF NOT EXISTS audit.geo_velocity_check_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    prev_ip INET NOT NULL,
    curr_ip INET NOT NULL,
    distance_km NUMERIC(10,2) NOT NULL,
    time_elapsed_minutes NUMERIC(10,2) NOT NULL,
    max_allowed_km NUMERIC(10,2), -- e.g., 2000 km
    is_impossible BOOLEAN GENERATED ALWAYS AS (distance_km > max_allowed_km) STORED,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    action_taken VARCHAR(50), -- 'CHALLENGE_USER', 'TERMINATE_SESSION'
    resolved BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE audit.geo_velocity_check_alerts_is 'Detects logins from geographically impossible locations indicating session hijacking';


-- Table: T422 - biometric_template_versioning
-- Description: Managing versions of biometric templates.
-- Business Case: Biometric Refresh. Biometric models (for voice or face) need to be retrained (enrolled) over time as users change slightly. This table tracks the version of the biometric template used for each user, ensuring we don't use an old model to verify a user's new voice.
-- KPIs: Model Refresh Cycle.
-- Feature Reference: F088
CREATE TABLE IF NOT EXISTS audit.biometric_template_versioning (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    biometric_type VARCHAR(50) NOT NULL, -- 'FACE', 'VOICE', 'BEHAVIOR'
    template_version INTEGER NOT NULL,
    enrollment_status VARCHAR(20), -- 'ENROLLING', 'ACTIVE', 'UPGRADING'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    last_verified_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE audit.biometric_template_versioning_is 'Manages the versioning of biometric templates to ensure accurate biometric authentication';


-- Table: T423 - behavioral_biometric_tuning
-- Description: Records tuning of behavioral models.
-- Business Case: Model Accuracy. Behavioral Biometrics (typing speed, mouse movement) drifts. If a user gets a new chair or mouse, the model starts rejecting them. This table logs when an "Auto-Tune" (Re-enrollment) is requested by the system to adjust the model to the user's new baseline.
-- KPIs: Re-enrollment Success Rate.
-- Feature Reference: F377
CREATE TABLE IF NOT EXISTS audit.behavioral_biometric_tuning (
    tuning_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    reason_for_tuning VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COLLECTING_DATA, COMPLETE
    start_date DATE NOT NULL DEFAULT CURRENT_DATE,
    completion_date DATE,
    model_version_after INTEGER,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.behavioral_biometric_tuning_is 'Tracks adjustments to behavioral biometric models to maintain low false rejection rates';


-- Table: T424 - continuous_authentication_risk_score
-- Description: CAR (Continuous Authentication Risk) Score.
-- Business Case: Dynamic Risk. The risk of a session isn't static. It combines: Geo-Velocity (T421), Typing Rhythm (T377), Device Freshness (T358) into a "CAR Score". If the score drops below a threshold, we challenge the user (MFA). This table stores the historical score.
-- KPIs: CAR Score Volatility.
-- Feature Reference: F009, T421
CREATE TABLE IF NOT EXISTS audit.continuous_authentication_risk_score (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100) NOT NULL, -- 0 is risky, 100 is safe
    geo_velocity_score INTEGER NOT NULL,
    behavioral_score INTEGER NOT NULL,
    device_integrity_score INTEGER NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.continuous_authentication_risk_score_is 'Stores a composite risk score for authentication to dynamically adjust security challenges';


-- Table: T425 - access_review_board_meetings
-- Description: Logs meetings of the Access Review Board.
-- Business Case: Governance. The "Access Review Board" decides who gets access to what. This table logs the meetings, attendees, and decisions (Approve/Deny). It provides a high-level audit of who has power in the system.
-- KPIs: Review Completion Rate.
-- Feature Reference: F127, F418
CREATE TABLE IF NOT EXISTS audit.access_review_board_meetings (
    meeting_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_date DATE NOT NULL DEFAULT CURRENT_DATE,
    scheduled_start TIMESTAMP WITH TIME ZONE,
    scheduled_end TIMESTAMP WITH TIME ZONE,
    chairperson_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    attendee_ids UUID[] NOT NULL,
    agenda_items TEXT[],
    decisions_made TEXT[], -- JSON or Text summary
    meeting_minutes_file_path TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.access_review_board_meetings_is 'Records proceedings of the board responsible for granting high-level access rights';


-- Table: T426 - complaint_management_system
-- Description: Tracking user/merchant complaints.
-- Business Case: Issue Resolution. Auditors might make mistakes or be rude. Merchants can complain. This table tracks these complaints, the investigation, and the outcome. It is used to train auditors and identify toxic employees.
-- KPIs: Complaint Resolution Time.
-- Feature Reference: F115, F310
CREATE TABLE IF NOT EXISTS audit.complaint_management_system (
    complaint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    complainant_type VARCHAR(50) NOT NULL, -- 'MERCHANT', 'AUDITOR', 'PARTNER'
    complainant_id UUID, -- ID of person or entity
    subject_auditor_id UUID REFERENCES audit.auditor(auditor_id),
    description TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, RESOLVED, DISMISSED
    investigation_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.complaint_management_system IS 'Tracks and manages lifecycle of complaints from stakeholders regarding audit quality';


-- Table: T427 - whistleblower_case_management
-- Description: Secure reporting of misconduct.
-- Business Case: Ethical Integrity. Employees or users need to report fraud or misconduct anonymously. This table manages these "Whistleblower" cases. It guarantees anonymity to the reporter while ensuring the investigation is logged and resolved.
-- KPIs: Case Confidentiality Score.
-- Feature Reference: F018, F132
CREATE TABLE IF NOT EXISTS audit.whistleblower_case_management (
    case_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporter_id UUID, -- Can be NULL or an anonymous ID
    report_type VARCHAR(100) NOT NULL, -- 'FRAUD', 'HARASSMENT', 'SECURITY_BREACH'
    allegations_summary TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'NEW', -- NEW, REVIEW, ACTIONED
    assigned_team_id UUID REFERENCES audit.audit_user_groups(group_id),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'SEVERE')),
    case_file_path TEXT, -- Encrypted storage for evidence
    opened_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE audit.whistleblower_case_management_is 'Manages secure anonymous reporting of misconduct ensuring whistleblower protection and case tracking';


-- Table: T428 - incident_manager_case_files
-- Description: Managing files associated with incident cases.
-- Business Case: Evidence Organization. An incident has many files (Logs, Screenshots, Chat logs). This table organizes them, preventing files from being lost and ensuring the "Incident Manager" has everything in one place.
-- KPIs: File Access Count.
-- Feature Reference: F161, T288
CREATE TABLE IF NOT EXISTS audit.incident_manager_case_files (
    file_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES audit.incident_tickets(ticket_id),
    file_name VARCHAR(255) NOT NULL,
    description TEXT,
    storage_path TEXT NOT NULL,
    file_hash CHAR(64) NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    uploaded_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    is_public BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE audit.incident_manager_case_files_is 'Stores and indexes files attached to incident management cases for quick retrieval';


-- Table: T429 - root_cause_analysis_tree
-- Description: Tree structure for "5 Whys".
-- Business Case: Deep RCA. "Why did the system crash?" "Why was there an error?". This table stores the hierarchical analysis (Root Cause -> Intermediate Causes -> Symptoms). It allows us to query "All crashes caused by Root Cause A".
-- KPIs: Tree Depth.
-- Feature Reference: F162, T429
CREATE TABLE IF NOT EXISTS audit.root_cause_analysis_tree (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES audit.incident_tickets(ticket_id),
    parent_node_id UUID REFERENCES audit.root_cause_analysis_tree(node_id), -- Self-referential for tree
    node_type VARCHAR(50) NOT NULL, -- 'ROOT', 'INTERMEDIATE', 'SYMPTOM'
    question TEXT NOT NULL, -- "Why?"
    answer TEXT NOT NULL, -- "Because..."
    category VARCHAR(100) NOT NULL,
    investigator_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.root_cause_analysis_tree_is 'Stores hierarchical "5 Whys" analysis to determine root causes of incidents';

CREATE INDEX idx_rca_incident ON audit.root_cause_analysis_tree(incident_id);


-- Table: T430 - lessons_learned_repository
-- Description: Repository of "Lessons Learned".
-- Business Case: Knowledge Retention. "We made a mistake and fixed it. How do we ensure we don't make it again?". This table stores "Lessons Learned" extracted from incidents and post-mortems (T161), tagged by category. It feeds into training (T218) and documentation (F163).
-- KPIs: Lesson Relevance/Usage.
-- Feature Reference: F161, F218
CREATE TABLE IF NOT EXISTS audit.lessons_learned_repository (
    lesson_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    category VARCHAR(100) NOT NULL, -- 'CODE', 'PROCESS', 'TOOL'
    title VARCHAR(255) NOT NULL,
    trigger_event VARCHAR(255), -- Which incident caused this?
    lesson_text TEXT NOT NULL,
    mitigation_action TEXT NOT NULL,
    approved_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approved_date DATE NOT NULL DEFAULT CURRENT_DATE,
    tags TEXT[],
    is_applicable BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE audit.lessons_learned_repository_is 'Stores actionable insights from incidents to prevent recurrence of errors';


-- Table: T431 - corrective_action_tracker
-- Description: Tracker for Corrective Actions (CAT).
-- Business Case: Remediation Management. Fixing the problem (Root Cause) requires tasks. This table tracks these "Corrective Actions" (Buy software, Change Policy, Train Staff). It assigns owners and due dates, ensuring the fix is actually implemented.
-- KPIs: Action Overdue Count.
-- Feature Reference: F162, F430
CREATE TABLE IF NOT EXISTS audit.corrective_action_tracker (
    action_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID REFERENCES audit.incident_tickets(ticket_id),
    root_cause_node_id UUID REFERENCES audit.root_cause_analysis_tree(node_id),
    action_description TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, IN_PROGRESS, VERIFIED, CLOSED
    due_date DATE NOT NULL,
    completion_date DATE,
    evidence_path TEXT, -- Link to T428
    verification_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.corrective_action_tracker_is 'Tracks remediation tasks required to fix root causes identified in incidents';


-- Table: T432 - process_optimization_proposals
-- Description: Kaizen (Continuous Improvement) proposals.
-- Business Case: Operational Efficiency. Employees have ideas to improve the audit process. This table manages the "Idea" to "Implementation" flow. It encourages a culture of Kaizen, where small improvements are constantly made.
-- KPIs: Kaizen Savings (% cost saved/time saved).
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.process_optimization_proposals (
    proposal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proposer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    process_name VARCHAR(100) NOT NULL,
    current_problem TEXT NOT NULL,
    proposed_solution TEXT NOT NULL,
    estimated_savings_usd NUMERIC(15,2),
    estimated_time_savings_hours NUMERIC(10,2),
    status VARCHAR(20) DEFAULT 'PROPOSED', -- PROPOSED, APPROVED, IMPLEMENTING, COMPLETE
    implemented_by UUID REFERENCES audit.auditor(auditor_id),
    implemented_at DATE,
    actual_savings_usd NUMERIC(15,2),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.process_optimization_proposals_is 'Manages Kaizen proposals for process improvement and tracks realized savings';


-- Table: T433 - quality_improvement_projects
-- Description: QIP (Quality Improvement Projects).
-- Business Case: Strategic Quality. Unlike small optimizations (T432), QIPs are major projects (e.g., "Upgrade to New Audit Platform"). This table tracks these larger projects, spanning months and cross-functional teams.
-- KPIs: Project Success Rate (On Time/On Budget).
-- Feature Reference: F116, F150
CREATE TABLE IF NOT EXISTS audit.quality_improvement_projects (
    qip_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,
    project_sponsor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    budget_amount NUMERIC(15,2),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'PLANNING', -- PLANNING, ACTIVE, ON_HOLD, CLOSED
    progress_percentage INTEGER CHECK (progress_percentage BETWEEN 0 AND 100),
    risk_score INTEGER, -- Project Risk
    project_manager_id UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.quality_improvement_projects_is 'Manages cross-functional quality improvement projects to enhance overall audit platform maturity';


-- Table: T434 - audit_committee_charter
-- Description: Governance Charter for the Audit Committee.
-- Business Case: Governance Framework. The Committee needs rules (Quorum, Voting Rights). This table stores the "Charter" document. If we add a new member, we check if this table limits the number of auditors. It ensures we always operate within our governance framework.
-- KPIs: Charter Compliance (100%).
-- Feature Reference: F150, T366
CREATE TABLE IF NOT EXISTS audit.audit_committee_charter (
    charter_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    charter_name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,
    effective_date DATE NOT NULL DEFAULT CURRENT_DATE,
    charter_json JSONB NOT NULL, -- The full text or JSON rules
    approved_by_id UUID REFERENCES audit.auditor(auditor_id),
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.audit_committee_charter_is 'Stores the governance charter and rules defining the operation of the Audit Committee';


-- Table: T435 - internal_audit_findings
-- Description: Findings from internal audits of the system.
-- Business Case: Eating our own dog food. We audit others, but we also audit ourselves (System Audit). This table stores findings from internal audits of the PARI M06 module itself (e.g., "Audit Logs not retained long enough"). It ensures our compliance claims are backed by internal evidence.
-- KPIs: Internal Audit Closure Rate.
-- Feature Reference: F150, F139
CREATE TABLE IF NOT EXISTS audit.internal_audit_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    internal_audit_id UUID NOT NULL, -- Link to Audit Plan
    reviewer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    control_id UUID REFERENCES audit.continuous_control_testing(test_id),
    observation TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    remediation_plan TEXT,
    due_date DATE,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, IN_PROGRESS, RESOLVED,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.internal_audit_findings_is 'Stores findings from internal audits of the M06 system to ensure compliance with our own standards';


-- Table: T436 - compliance_officer_assignments
-- Description: Assignments for DPOs and Compliance Officers.
-- Business Case: Accountability. Data Privacy is serious. This table maps specific datasets (e.g., "EU PII") to the "Compliance Officer" responsible for it. It ensures there is a named human responsible for every piece of sensitive data, satisfying GDPR accountability.
-- KPIs: Assignment Coverage (% of datasets covered).
-- Feature Reference: F150, T115
CREATE TABLE IF NOT EXISTS audit.compliance_officer_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    officer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    data_domain VARCHAR(255) NOT NULL, -- e.g., 'EU_AUDIT_LOGS', 'ALL_EMAILS'
    jurisdiction_code CHAR(2) NOT NULL,
    responsibilities TEXT,
    effective_date DATE NOT NULL DEFAULT CURRENT_DATE,
    end_date DATE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, ON_LEAVE, REVOKED

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.compliance_officer_assignments_is 'Assigns Data Protection Officers to specific data domains to ensure GDPR accountability';


-- Table: T437 - privacy_impact_assessments
-- Description: Logs Data Protection Impact Assessments (DPIAs).
-- Business Case: Risk Analysis. Before we launch a new feature or share data, we must do a DPIA. This table logs the assessment: What data is involved? What is the likelihood of harm? What are the mitigation measures? It is a legal requirement under GDPR.
-- KPIs: DPIA Approval Time.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.privacy_impact_assessments (
    dpia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,
    dpia_lead_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    data_categories_affected TEXT[] NOT NULL,
    likelihood_of_harm VARCHAR(20) CHECK (likelihood_of_harm IN ('NONE', 'LOW', 'MEDIUM', 'HIGH')),
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, SUBMITTED, APPROVED
    submission_date DATE,
    approval_date DATE
);
COMMENT ON TABLE audit.privacy_impact_assessments_is 'Stores the analysis and approval of potential privacy impacts for new projects or features';


-- Table: T438 - consent_revocation_logs
-- Description: Logs revocation of user consent.
-- Business Case: Right to Revoke Consent. Users might consent to "Marketing Emails", then revoke it. This table logs every revocation event, propagating the "Do Not Sell" command to the Marketing system and ensuring we stop using that data immediately.
-- KPIs: Revocation Propagation Time.
-- Feature Reference: F150, T115
CREATE TABLE IF NOT EXISTS audit.consent_revocation_logs (
    revocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    consent_type VARCHAR(100) NOT NULL, -- 'MARKETING_EMAIL', 'ANALYTICS', 'COOKIES'
    user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    propagation_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED, FAILED
    downstream_systems TEXT[], -- Which systems did we notify?
    failure_reason TEXT
);
COMMENT ON TABLE audit.consent_revocation_logs_is 'Tracks the revocation of user consent and the propagation of that signal to downstream systems';


-- Table: T439 - cookie_tracking_logs
-- Description: Logs web browser cookies for audit.
-- Business Case: Tracking User Journey. Auditors use a Web App (Frontend). This table logs the lifecycle of the `session_id` cookie (set, verify, expire). It helps reconstruct user sessions for debugging "Why did the user crash?" and detects replay attacks.
-- KPIs: Cookie Validity.
-- Feature Reference: F116, F444
CREATE TABLE IF NOT EXISTS audit.cookie_tracking_logs (
    cookie_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    cookie_value TEXT NOT NULL,
    action VARCHAR(20) NOT NULL, -- 'SET', 'READ', 'EXPIRE'
    ip_address INET NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.cookie_tracking_logs_is 'Logs state changes of web cookies to reconstruct user web sessions for security';


-- Table: T440 - pixel_tracking_logs
-- Description: Logs invisible tracking pixels.
-- Business Case: Open Rates. We embed transparent 1x1 pixels in emails (e.g., "Did you open this audit report?"). This table logs the "Fire" event when the pixel loads. It helps measure the effectiveness of our communication.
-- KPIs: Email Open Rate.
-- Feature Reference: F116, F141
CREATE TABLE IF NOT EXISTS audit.pixel_tracking_logs (
    pixel_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_id VARCHAR(100) NOT NULL,
    user_id UUID, -- May be hash if email is external
    email_subject TEXT,
    client_ip INET,
    user_agent TEXT,
    opened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.pixel_tracking_logs_is 'Records loading of tracking pixels to measure marketing and email engagement';


-- Table: T441 - beacon_frames
-- Description: Logging "Beacons" (Web Beacons) activity.
-- Business Case: Website Performance. Beacons are scripts that send telemetry. This table logs the event data (User ID, Page Scroll, Time on Page). It feeds into T293 (User Journey Mapping) to optimize the frontend.
-- KPIs: Page Load Time, Engagement.
-- Feature Reference: F116, T293
CREATE TABLE IF NOT EXISTS audit.beacon_frames (
    beacon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    page_url TEXT NOT NULL,
    user_id UUID,
    event_name VARCHAR(100) NOT NULL, -- 'page_view', 'scroll'
    event_value NUMERIC(10,2), -- e.g., scroll depth
    client_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    server_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.beacon_frames_is 'Detailed telemetry data sent by web beacons to analyze user interface interaction';


-- Table: T442 - fingerprinting_algorithm_updates
-- Description: Managing versions of device fingerprinting algo.
-- Business Case: Tech Refresh. Fingerprinting algorithms change (v1 to v2) to evade bot adaptations. This table tracks the active version of the algorithm used to identify devices (T223). If we upgrade, we might see "New Device" patterns for everyone temporarily.
-- KPIs: Algo Performance.
-- Feature Reference: F027, T088
CREATE TABLE IF NOT EXISTS audit.fingerprinting_algorithm_updates (
    algo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_number INTEGER NOT NULL,
    fingerprint_type VARCHAR(50) NOT NULL, -- 'BROWSER', 'DEVICE'
    accuracy_score NUMERIC(3,2), -- How often does it mis-ID?
    parameters_json JSONB NOT NULL,
    deployed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.fingerprinting_algorithm_updates_is 'Stores version history of device fingerprinting algorithms to manage device identification accuracy';


-- Table: T443 - device_attribution_analysis
-- Description: Linking multiple devices to a single user ID.
-- Business Case: Multi-Device Users. An auditor has a laptop, a phone, and a tablet. This table links these `fingerprint_ids` (T223) to a single `user_id`. It allows us to map the "Attacker" across devices, preventing them from fragmenting their attack to evade detection.
-- KPIs: Linkage Confidence Score.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS audit.device_attribution_analysis (
    attribution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    primary_user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    linked_device_id UUID REFERENCES audit.mobile_device_info(device_id),
    confidence_score NUMERIC(3,2) NOT NULL, -- How sure are we this is the same person?
    linkage_method VARCHAR(100), -- 'MANUAL', 'HEURISTIC', 'ALGO'
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_DATE,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'CANDIDATE' -- CANDIDATE, CONFIRMED, REJECTED
);
COMMENT ON TABLE audit.device_attribution_analysis_is 'Links multiple devices to a single user profile to track user activity across platforms';


-- Table: T444 - session_replay_attack_detection
-- Description: Detecting replay of session tokens.
-- Business Case: Session Hijack Detection. If an attacker captures a `session_token` and reuses it, the session ID will be the same, but the IP might change. This table detects anomalies in the session lifecycle (same ID, different Geo), flagging the attack.
-- KPIs: Replay Detection Rate.
-- Feature Reference: F009, F421
CREATE TABLE IF NOT EXISTS audit.session_replay_attack_detection (
    replay_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES audit.auditor_sessions(session_id),
    expected_ip_range INET, -- e.g., 192.168.1.0/24
    detected_ip INET NOT NULL,
    distance_km NUMERIC(10,2),
    action_taken VARCHAR(50), -- 'BLOCKED', 'ALLOWED'
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.session_replay_attack_detection_is 'Detects usage of captured session tokens from different locations to prevent session hijacking';


-- Table: T445 - brute_force_attack_patterns
-- Description: Analyzing patterns of brute force attempts.
-- Business Case: Security Analytics. We block brute force (T300). This table analyzes the *patterns* (Usernames used, User Agent strings) of the attackers. If we see a pattern (e.g., always trying 'admin'), we can block the IP range proactively.
-- KPIs: Pattern Identification Speed.
-- Feature Reference: F300, F088
CREATE TABLE IF NOT EXISTS audit.brute_force_attack_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_type VARCHAR(50) NOT NULL, -- 'USERNAME_SEQUENTIAL', 'COMMON_PASSWORD'
    description TEXT NOT NULL,
    ip_prefix VARCHAR(100), -- e.g., '203.0.113'
    user_agent_signature VARCHAR(255),
    attack_count INTEGER NOT NULL,
    first_seen DATE NOT NULL DEFAULT CURRENT_DATE,
    last_seen DATE NOT NULL DEFAULT CURRENT_DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE audit.brute_force_attack_patterns_is 'Analyzes aggregated data from brute force attacks to identify attacker patterns and block ranges';


-- Table: T446 - credential_stuffing_attempts
-- Description: Logging specific stuffing attempts.
-- Business Case: Attack Documentation. While T413 detects general stuffing, this table records the specific *attempts*. It ties an attempt to a specific "Breach Database" version. It provides evidence for law enforcement if the attacker is caught.
-- KPIs: Stuffing Volume.
-- Feature Reference: T413, F088
CREATE TABLE IF NOT EXISTS audit.credential_stuffing_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_user_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    breach_source VARCHAR(100) NOT NULL, -- e.g., 'COLLECTION_1', 'LEAKED_SITES'
    detected_by VARCHAR(50), -- 'RULE_ENGINE', 'HONEYPOT'
    used_password VARCHAR(255), -- Obfuscated for privacy
    attempt_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_successful BOOLEAN NOT NULL -- Did the attacker get in?
);
COMMENT ON TABLE audit.credential_stuffing_attempts_is 'Detailed log of individual credential stuffing attempts to track attacker methodologies';


-- Table: T447 - data_poisoning_incidents
-- Description: Logs poisoning of ML training data.
-- Business Case: Model Sabotage. Attackers inject bad data into our datasets (e.g., labeling fraud as non-fraud) to break our ML models. This table logs detection of "Poisoned Data". We need to remove this data from T092 (Feature Store) to retrain the model.
-- KPIs: Poisoned Data Volume Detected.
-- Feature Reference: F132, T088
CREATE TABLE IF NOT EXISTS audit.data_poisoning_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_type VARCHAR(100) NOT NULL, -- 'TRANSACTION', 'ENTITY_PROFILE'
    suspected_poisoner_id UUID REFERENCES audit.auditor(auditor_id),
    poisoning_method VARCHAR(255) NOT NULL, -- 'LABEL_FLIP', 'BACKDOOR_INJECTION'
    affected_model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    records_count INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'DETECTED', -- DETECTED, INVESTIGATING, REMEDIATED
    remediation_plan TEXT,

    -- Audit Columns
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.data_poisoning_incidents_is 'Logs detection of malicious data insertion into ML training sets to prevent model degradation';


-- Table: T448 - model_inversion_attack_logs
-- Description: Logs attempts to invert model predictions.
-- Business Case: Adversarial Machine Learning. Attackers query a model to extract its weights. This table logs detections of Model Inversion attacks (where the gradient or output is probed). It forces us to upgrade to more robust architectures (like SMPC).
-- KPIs: Inversion Attack Detection Rate.
-- Feature Reference: T375
CREATE TABLE IF NOT EXISTS audit.model_inversion_attack_logs (
    inversion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    attacker_ip INET,
    query_count INTEGER NOT NULL,
    suspicious_queries JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'DETECTED', -- DETECTED, BLOCKED, FALSE_POSITIVE
    mitigation_action TEXT
);
COMMENT ON TABLE audit.model_inversion_attack_logs_is 'Logs probing attacks against ML models intended to extract internal parameters or predictions';


-- Table: T449 - adversarial_example_generation
-- Description: Generating examples to harden models.
-- Business Case: Defense Generation. To defend against attacks (T447, T448), we need "Adversarial Examples" (inputs that cause the model to fail). This table logs the generation of these examples for "Red Teaming" the ML models to make them robust.
-- KPIs: Red Teaming Accuracy.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS audit.adversarial_example_generation (
    example_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    generator_type VARCHAR(100), -- 'GENETIC_ALGORITHM', 'GAN'
    original_input JSONB,
    perturbation_json JSONB, -- What was changed?
    target_class VARCHAR(50), -- The new, 'wrong' label
    confidence NUMERIC(3,2),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    used_in_retraining BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE audit.adversarial_example_generation_is 'Stores synthetic data created to test and improve model robustness against adversarial attacks';


-- Table: T450 - synthetic_training_data_generator
-- Description: Generating the synthetic data.
-- Business Case: Data Augmentation. We use "Generative Adversarial Networks" (GANs) to create fake data that looks like real data (T061). This table stores the configuration (Parameters) and results of these generation jobs, allowing us to create unlimited training data without exposing real user privacy.
-- KPIs: Generation Speed (Rows/sec).
-- Feature Reference: T064
CREATE TABLE IF NOT EXISTS audit.synthetic_training_data_generator (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_table_name VARCHAR(100) NOT NULL, -- 'ANONYMIZED_EVENTS'
    generator_model_id VARCHAR(100), -- 'GAN_V4', 'VAE'
    parameters_json JSONB NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    rows_generated BIGINT,
    file_path TEXT, -- Location of generated CSV/Parquet
    fidelity_score NUMERIC(3,2), -- How real does it look?
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, COMPLETED, FAILED
    error_message TEXT
);
COMMENT ON TABLE audit.synthetic_training_data_generator_is 'Tracks the execution of synthetic data generation jobs for ML training and testing';

CREATE INDEX idx_gen_status ON audit.synthetic_training_data_generator(status, start_time DESC);

-- End of Script Part 7 (Objects 351-450)
-- Completes exhaustive database schema for PARI M06.

-- ================================================================================
-- PARI System - Module M06: Independent Auditor Interface
-- PostgreSQL Database Schema Script (Part 8: Objects 451-550)
-- ================================================================================
-- Description: This script concludes the database object creation for the Independent
-- Auditor Interface. It focuses on complex global trade compliance, advanced
-- risk management, AI governance, quantum readiness, and ESG tracking.
--
-- Scope: Database Objects T451 - T550.
-- ================================================================================

-- 4. DDL Statements (Tables T451 - T550)
-- ================================================================================

-- Table: T451 - sanctions_master_registry
-- Description: Central registry for global sanctions lists (OFAC, UN, EU).
-- Business Case: Sanctions Compliance. Different countries maintain their own lists (OFAC SDN, EU Consolidated, UN Security Council). This table acts as a "Master Index" or "Golden Copy", aggregating entity names and statuses from various sources into a unified view. It ensures that if a merchant is sanctioned in *any* list, the PARI system blocks the transaction immediately.
-- KPIs: Sanctions Coverage Rate, False Positive Rate < 0.1%.
-- Feature Reference: F026, F098
CREATE TABLE IF NOT EXISTS audit.sanctions_master_registry (
    registry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- INDIVIDUAL, ENTITY, VESSEL, AIRCRAFT
    primary_name VARCHAR(255), -- Full Legal Name
    date_of_birth DATE,
    nationality_code CHAR(2),
    unique_identifier VARCHAR(255) NOT NULL, -- Passport Number, etc.
    source_list VARCHAR(50) NOT NULL, -- 'OFAC_US', 'EU_CONSOLIDATED'
    sanction_type VARCHAR(100), -- 'TERRORISM', 'WEAPONS'
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, REINSTATED
    effective_date DATE,
    revoked_date DATE,
    reason_for_removal TEXT,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.sanctions_master_registry IS 'Unified master registry of global sanctions lists to enforce automated blocking of sanctioned entities';

CREATE INDEX idx_sanctions_entity ON audit.sanctions_master_registry(entity_name);
CREATE INDEX idx_sanctions_status ON audit.sanctions_master_registry(status);


-- Table: T452 - sanctions_exemptions
-- Description: Sanctions list exemptions for humanitarian aid.
-- Business Case: Humanitarian Exceptions. Sanctions generally prohibit all transactions. However, food, medicine, and humanitarian aid are often exempt. This table stores these specific exemptions, allowing legitimate aid organizations to transact without triggering false positive blocks, while documenting the legal basis for the exemption.
-- KPIs: Exemption Approvals Rate.
-- Feature Reference: F026, F338
CREATE TABLE IF NOT EXISTS audit.sanctions_exemptions (
    exemption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_name VARCHAR(255) NOT NULL,
    exemption_type VARCHAR(100) NOT NULL, -- 'HUMANITARIAN_AID', 'MEDICAL_SUPPLY'
    sanction_list_id UUID REFERENCES audit.sanctions_master_registry(registry_id),
    jurisdiction_code CHAR(2) NOT NULL,
    legal_basis TEXT NOT NULL, -- Reference to UN Resolution
    exemption_start_date DATE NOT NULL DEFAULT CURRENT_DATE,
    exemption_end_date DATE NOT NULL,
    approval_document_path TEXT, -- Proof of entitlement
    status VARCHAR(20) NOT NULL DEFAULT 'APPROVED', -- APPROVED, UNDER_REVIEW, REVOKED
    reviewer_comments TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.sanctions_exemptions IS 'Stores approved exemptions to sanctions lists for humanitarian or medical purposes';

CREATE INDEX idx_exemptions_entity ON audit.sanctions_exemptions(entity_name);


-- Table: T453 - export_licensing_authority
-- Description: Tracks licenses for exporting dual-use goods.
-- Business Case: Dual-Use Control. Exporting "Dual-Use Goods" (cryptography components, missiles) often requires a specific government license (e.g., from DGFT in EU). This table stores the details of these licenses (License Number, Scope, Validity Period). It enables the system to verify that a transaction involving a dual-use item has a valid export license before allowing it.
-- KPIs: License Validity Check Rate.
-- Feature Reference: F338, F334
CREATE TABLE IF NOT EXISTS audit.export_licensing_authority (
    license_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    license_number VARCHAR(100) NOT NULL UNIQUE,
    issuing_authority VARCHAR(255) NOT NULL, -- 'DGFT', 'US_BIS'
    issuing_jurisdiction_code CHAR(2) NOT NULL, -- EU, US, UK
    control_category_code VARCHAR(100) NOT NULL, -- Dual-Use category code
    license_holder_name VARCHAR(255) NOT NULL,
    effective_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    renewal_date DATE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, REVOKED
    document_path TEXT, -- Link to license PDF

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    updated_by UUID NOT NULL
);
COMMENT ON TABLE audit.export_licensing_authority IS 'Tracks validity and scope of licenses required for exporting controlled technology items';

CREATE INDEX idx_export_license_number ON audit.export_licensing_authority(license_number);


-- Table: T454 - customs_tariff_tracking
-- Description: Tracks customs duty and tariff rates.
-- Business Case: Accurate Customs Valuation. Import duties vary by product origin and HS Code. This table stores the applicable customs duties for specific HS Codes to ensure that VAT/GST collected and reported matches the actual duty paid at the border. It detects discrepancies between the tax reported by the merchant and the duty paid at the border.
-- KPIs: Tariff Accuracy (100%).
-- Feature Reference: F338, F342
CREATE TABLE IF NOT EXISTS audit.customs_tariff_tracking (
    tariff_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hs_code VARCHAR(20) NOT NULL, -- Harmonized System Code
    originating_country_code CHAR(2) NOT NULL,
    destination_country_code CHAR(2) NOT NULL,
    effective_date DATE NOT NULL,
    duty_percentage NUMERIC(5,2) NOT NULL,
    vat_applicable BOOLEAN DEFAULT TRUE,
    description TEXT,
    regulatory_reference VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.customs_tariff_tracking IS 'Stores customs duty rates and tariff changes for cross-border trade auditing and reconciliation';

CREATE UNIQUE INDEX idx_tariff_hc_code ON audit.customs_tariff_tracking(hs_code, originating_country_code, destination_country_code);


-- Table: T455 - trade_agreement_compliance
-- Description: Verifying documents for international trade agreements.
-- Business Case: Trade Compliance. Large international trade often falls under free trade agreements (e.g., NAFTA, RCEP). This table manages the metadata and verification status of these agreements. It ensures that merchants are claiming tax exemptions or preferential rates (via T209) are actually covered by a valid legal document on file.
-- KPIs: Agreement Verification Success Rate.
-- Feature Reference: F338, F209
CREATE TABLE IF NOT EXISTS audit.trade_agreement_compliance (
    agreement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    agreement_type VARCHAR(100) NOT NULL, -- 'BILATERAL', 'PREFERENTIAL', 'FREE_TRADE_AGREEMENT'
    partner_countries JSONB NOT NULL, -- Array of country codes
    agreement_reference_number VARCHAR(100) NOT NULL UNIQUE,
    expiry_date DATE,
    proof_of_origin_path TEXT, -- Link to legal PDF
    status VARCHAR(20) DEFAULT 'PENDING_VERIFICATION', -- PENDING_VERIFICATION, VALID, EXPIRED, REVOKED
    verified_by UUID REFERENCES audit.auditor(auditor_id),
    verified_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.trade_agreement_compliance IS 'Stores legal documentation and verification status for preferential trade agreements and tax treaties';


-- Table: T456 - customs_declaration_monitoring
-- Description: Monitoring customs declarations (Single Window).
-- Business Case: Compliance Assurance. "Single Window" systems (like NCTS in EU) receive customs declarations. This table logs the reception and processing of these declarations. It verifies that the data PARI receives from the blockchain (M01) matches the declaration sent to the customs authority, identifying discrepancies in real-time.
-- KPIs: Discrepancy Detection Rate.
-- Feature Reference: F338, F344
CREATE TABLE IF NOT EXISTS audit.customs_declaration_monitoring (
    declaration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    mrn_number VARCHAR(100) NOT NULL, -- Movement Reference Number
    declaration_type VARCHAR(50) NOT NULL, -- IMPORT, EXPORT, TRANSIT
    submitter_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    goods_description TEXT,
    total_value NUMERIC(19,4),
    currency_code CHAR(3),
    customs_processing_status VARCHAR(20) DEFAULT 'RECEIVED', -- RECEIVED, PROCESSING, ACKNOWLEDGED
    matched_ledger_tx_hash CHAR(66), -- Hash of matching transaction in PARI

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE audit.customs_declaration_monitoring IS 'Monitors the lifecycle of customs declarations to ensure data integrity between PARI ledger and external customs authorities';


-- Table: T457 - non_tariff_barriers
-- Description: Tracking non-tariff barriers to trade.
-- Business Case: Protectionism Analysis. Some countries impose quotas or tariffs not based on HS codes but on political grounds (Non-Tariff Barriers). This table logs these barriers. It helps auditors analyze the *structural* challenges to trade, identifying hidden costs or protectionist measures affecting global supply chains.
-- KPIs: Barrier Coverage Map.
-- Feature Reference: F338, F353
CREATE TABLE IF NOT EXISTS audit.non_tariff_barriers (
    barrier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    barrier_name VARCHAR(255) NOT NULL,
    target_country_code CHAR(2) NOT NULL,
    source_country_code CHAR(2),
    barrier_type VARCHAR(50) NOT NULL, -- 'QUOTA', 'EMBARGO', 'LICENSING_REQUIREMENT'
    estimated_impact_score INTEGER CHECK (estimated_impact_score BETWEEN 1 AND 100),
    description TEXT,
    start_date DATE NOT NULL DEFAULT CURRENT_DATE,
    end_date DATE,
    is_active BOOLEAN DEFAULT TRUE,
    related_regulation TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.non_tariff_barriers IS 'Stores information on non-tariff barriers and protectionist policies to analyze impact on trade flows';


-- Table: T458 - origin_certification_tracking
-- Description: Tracking certification of country of origin.
-- Business Case: Rules of Origin. Products must prove where they were made ("Rules of Origin"). This table tracks the certificates (C/O, EUR.1) provided for specific products. It ensures that claims of "Made in Italy" for a product are backed by a valid, tracked certificate.
-- KPIs: Certification Validity Date.
-- Feature Reference: F348
CREATE TABLE IF NOT EXISTS audit.origin_certification_tracking (
    certificate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    product_id UUID NOT NULL,
    origin_country_code CHAR(2) NOT NULL,
    certification_type VARCHAR(100) NOT NULL, -- 'EUR1_COO', 'C_O'
    certificate_number VARCHAR(255) NOT NULL,
    certifying_body VARCHAR(255), -- Issuer of the certificate
    issue_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'VALID', -- VALID, REVOKED, EXPIRED
    verified_by UUID REFERENCES audit.auditor(auditor_id),
    document_storage_path TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.origin_certification_tracking IS 'Stores tracking of "Rules of Origin" certifications to validate product claims for customs and tariff purposes';


-- Table: T459 - multilateral_trade_pacts
-- Description: Storing details of bilateral/multilateral trade pacts.
-- Business Case: Treaty Management. Trade pacts (e.g., USMCA) change tariff structures. This table stores the specific articles and rates of these pacts. It allows the tariff system (T454) to automatically apply the correct rate (Treaty Rate vs MFN Rate) if a trade pact is active between the two countries involved.
-- KPIs: Pact Application Accuracy.
-- Feature Reference: F338, T345
CREATE TABLE IF NOT EXISTS audit.multilateral_trade_pacts (
    pact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pact_name VARCHAR(255) NOT NULL,
    partner_countries JSONB NOT NULL, -- ['US', 'CA', 'MX']
    effective_date DATE NOT NULL,
    base_tariff_rate NUMERIC(5,2) NOT NULL,
    mfn_rate NUMERIC(5,2), -- Most Favored Nation Rate
    pact_status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, ABANDONED
    regulatory_link TEXT, -- URL to treaty text
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.multilateral_trade_pacts IS 'Manages details of trade agreements and their preferential rates to override standard tariffs automatically';


-- Table: T460 - regional_trade_disputes
-- Description: Tracking disputes over customs/tariff classifications.
-- Business Case: Dispute Resolution. A merchant might classify a product as "Textile" (zero tax) but customs thinks it's "Carpets" (20% tax). This table tracks the lifecycle of such disputes, including the evidence provided and the final ruling. It prevents revenue leakage and overpayment while a dispute is ongoing.
-- KPIs: Resolution Cycle Time.
-- Feature Reference: F338
CREATE TABLE IF NOT EXISTS audit.regional_trade_disputes (
    dispute_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    declaration_id UUID REFERENCES audit.customs_declaration_monitoring(declaration_id),
    contested_item_description TEXT,
    dispute_status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, UNDER_INVESTIGATION, ADJUDICATED, RESOLVED
    merchant_evidence_path TEXT,
    customs_evidence_path TEXT,
    monetary_amount_disputed NUMERIC(19,4),
    final_tariff_rate NUMERIC(5,2), -- Agreed rate
    currency_code CHAR(3),
    resolved_by UUID REFERENCES audit.auditor(auditor_id),
    resolution_date DATE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.regional_trade_disputes IS 'Tracks disputes regarding customs classifications and tariff valuations to resolve discrepancies with authorities';

CREATE INDEX idx_dispute_status ON audit.regional_trade_disputes(status);


-- Table: T461 - supply_chain_finance_inquiry
-- Description: Logging requests for supply chain financing data.
-- Business Case: Financing Risk Assessment. Merchants use trade finance. This table logs the "Inquiry" made to these financiers (Banks). It helps auditors assess the liquidity risk of the merchant, ensuring they aren't about to go bankrupt despite high sales volume, which would disrupt the supply chain.
-- KPIs: Inquiry Response Time.
-- Feature Reference: F321
CREATE TABLE IF NOT EXISTS audit.supply_chain_finance_inquiry (
    inquiry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    financier_id VARCHAR(100) NOT NULL,
    merchant_id UUID NOT NULL,
    inquiry_date DATE NOT NULL DEFAULT CURRENT_DATE,
    response_date DATE,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, RESPONDED, DECLINED
    credit_limit_offered NUMERIC(19,4),
    collateral_offered NUMERIC(19,4),
    response_summary TEXT,
    conducted_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.supply_chain_finance_inquiry IS 'Tracks inquiries made to supply chain financiers to assess merchant liquidity risk';

CREATE INDEX idx_inquiry_status ON audit.supply_chain_finance_inquiry(status);


-- Table: T462 - supply_chain_audit_trails
-- Description: Audit trails for supply chain due diligence.
-- Business Case: Supply Chain Integrity. We audit the goods flow. This table stores the trail for a specific supplier's audit (Did they verify the source? Did we check the transport?). It ensures that goods sold by our merchants are ethically sourced and compliant.
-- KPIs: Audit Completion Rate.
-- Feature Reference: T321, F021
CREATE TABLE IF NOT EXISTS audit.supply_chain_audit_trails (
    trail_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    supplier_id UUID NOT NULL,
    audit_date DATE NOT NULL DEFAULT CURRENT_DATE,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    audit_score INTEGER CHECK (audit_score BETWEEN 0 AND 100), -- A risk/compliance score
    findings_summary JSONB, -- {"Child Labor": "Pass", "Conflict Minerals": "High Risk"}
    corrective_action_plan TEXT,
    status VARCHAR(20) DEFAULT 'COMPLETED', -- SCHEDULED, IN_PROGRESS, COMPLETED
    next_review_date DATE,
    evidence_files_path TEXT[], -- Array of links to documents

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.supply_chain_audit_trails IS 'Stores the results of supply chain due diligence audits to track vendor compliance over time';


-- Table: T463 - supplier_factoring_data
-- Description: Invoices and rates from suppliers for factoring.
-- Business Case: Supply Chain Cost Analysis. Factoring companies lend against invoices. This table stores the invoices received from suppliers (T321) and the agreed factoring rates. It allows the audit system to reconcile the cost of goods sold (T014) with the payments actually made to factoring firms, identifying hidden margins or kickbacks.
-- KPIs: Discrepancy Amount.
-- Feature Reference: T321
CREATE TABLE IF NOT EXISTS audit.supplier_factoring_data (
    factoring_data_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    supplier_id UUID NOT NULL,
    invoice_number VARCHAR(100) NOT NULL,
    invoice_date DATE NOT NULL,
    amount_due NUMERIC(19,4) NOT NULL,
    currency_code CHAR(3) NOT NULL,
    due_date DATE NOT NULL,
    factoring_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    proof_of_payment_path TEXT,
    pares_amount NUMERIC(19,4), -- Amount paid by merchant
    variance_amount NUMERIC(19,4) GENERATED ALWAYS AS (amount_due - pares_amount) STORED,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.supplier_factoring_data IS 'Stores invoices and factoring rates to validate cost of goods sold and reconcile payments to suppliers';


-- Table: T464 - logistics_provider_monitoring
-- Description: Monitoring logistics providers in the chain.
-- Business Case: Logistics Compliance. We need to know if goods moved legally. This table monitors the performance and compliance status of logistics providers (Truckers, Shipping Lines). It flags high-risk providers (high delay, customs seizures) that might jeopardize the merchant's ability to deliver.
-- KPIs: Delivery Punctuality.
-- Feature Reference: T321, F344
CREATE TABLE IF NOT EXISTS audit.logistics_provider_monitoring (
    provider_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_name VARCHAR(255) NOT NULL,
    service_level VARCHAR(50), -- 'STANDARD', 'EXPRESSED'
    region CHAR(2),
    on_time_delivery_rate NUMERIC(5,2), -- Percentage
    average_delivery_days NUMERIC(5,2),
    seizure_incident_count INTEGER DEFAULT 0,
    last_reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, UNDER_REVIEW, BANNED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.logistics_provider_monitoring IS 'Tracks performance and compliance metrics of logistics providers to identify supply chain bottlenecks';


-- Table: T465 - third_party_risk_scoring
-- Description: Aggregating risk signals from various third-party APIs.
-- Business Case: Comprehensive Risk Profiling. We use external data (Dun & Bradstreet, LexisNexis). This table pulls scores from these vendors and calculates a consolidated "Third-Party Risk Score" for a merchant. It allows us to see the risk landscape of a merchant beyond just their internal transaction data.
-- KPIs: Score Correlation.
-- Feature Reference: F362
CREATE TABLE IF NOT EXISTS audit.third_party_risk_scoring (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    score_date DATE NOT NULL DEFAULT CURRENT_DATE,
    credit_bureau_score INTEGER CHECK (credit_bureau_score BETWEEN 0 AND 100),
    sanctions_hit_count INTEGER DEFAULT 0,
    adr_watchlist_count INTEGER DEFAULT 0,
    media_sentiment_score NUMERIC(5,2), -- Derived from NLP
    proprietary_data_vendor_score NUMERIC(5,2),
    consolidated_risk_level VARCHAR(20) GENERATED ALWAYS AS (
        CASE
            WHEN credit_bureau_score > 80 OR sanctions_hit_count > 0 THEN 'CRITICAL'
            WHEN credit_bureau_score > 60 OR adr_watchlist_count > 0 THEN 'HIGH'
            WHEN credit_bureau_score > 40 THEN 'MEDIUM'
            ELSE 'LOW'
        END
    ) STORED,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.third_party_risk_scoring IS 'Aggregates risk signals from external providers like credit bureaus and watchlists into a unified merchant risk score';


-- Table: T466 - vendor_debt_collection
-- Description: Tracking recovery of debt owed to merchants.
-- Business Case: Asset Protection. Merchants buy goods on credit. This table tracks the recovery of that debt. It is separate from the internal accounting ledger (T316) to ensure that collection efforts are documented and audited, preventing accusations of harassment or preferential treatment.
-- KPIs: Collection Success Rate.
-- Feature Reference: F321
CREATE TABLE IF NOT EXISTS audit.vendor_debt_collection (
    debt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    creditor_id VARCHAR(100) NOT NULL,
    merchant_id UUID NOT NULL,
    invoice_reference VARCHAR(255),
    outstanding_amount NUMERIC(19,4) NOT NULL,
    currency_code CHAR(3),
    age_days INTEGER, -- Days since last payment
    collection_status VARCHAR(20) DEFAULT 'NEW', -- NEW, ASSIGNED, IN_COLLECTION, WRITTEN_OFF
    last_collection_date DATE,
    collection_agent_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    recovery_cost_percentage NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.vendor_debt_collection IS 'Tracks the recovery of outstanding debts owed to merchants to protect platform assets and ensure fair collection practices';


-- Table: T467 - insolvency_watchlist
-- Description: List of companies undergoing insolvency.
-- Business Case: Counterparty Risk. Dealing with a company entering insolvency is a huge risk. This table lists entities that are actively in insolvency proceedings or administration. Transactions with these entities are flagged for extreme scrutiny and holdbacks, protecting the system from "Loss Given Default".
-- KPIs: Watchlist Update Latency.
-- Feature Reference: F362
CREATE TABLE IF NOT EXISTS audit.insolvency_watchlist (
    watchlist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_name VARCHAR(255) NOT NULL UNIQUE,
    entity_type VARCHAR(50) NOT NULL, -- 'LIMITED_LIABILITY', 'ADMINISTRATION'
    jurisdiction_code CHAR(2) NOT NULL,
    insolvency_date DATE NOT NULL DEFAULT CURRENT_DATE,
    official_case_number VARCHAR(100),
    court_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, CLOSED, DISCHARGED
    risk_level VARCHAR(20) DEFAULT 'CRITICAL', -- HIGH, MEDIUM, LOW
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.insolvency_watchlist IS 'Maintains a watchlist of entities undergoing insolvency to prevent losses to failed counterparties';


-- Table: T468 - market_abuse_detection
-- Description: Algorithms for detecting market manipulation.
-- Business Case: Market Integrity. Bad actors might use "Spoofing" (fake buys to increase price) or "Wash Trading" to hide profits. This table logs the detection of these events. It identifies patterns consistent with artificial manipulation, prompting alerts for regulatory bodies or exchange audits.
-- KPIs: Wash Trade Detection Rate.
-- Feature Reference: F392
CREATE TABLE IF NOT EXISTS audit.market_abuse_detection (
    abuse_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    detection_id UUID NOT NULL, -- Links to an internal ML model or heuristic
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    entity_pair VARCHAR(255) NOT NULL, -- e.g., "TokenA-TokenB"
    market_exchange VARCHAR(100), -- Binance, CoinGecko, Uniswap
    abuse_type VARCHAR(100) NOT NULL, -- SPOOFING, WASH_TRADE, LAYERING
    evidence_data JSONB,
    transaction_hashes CHAR(66)[],
    estimated_profit_loss NUMERIC(19,4),
    action_taken VARCHAR(50), -- ALERT_ONLY, ACCOUNT_FREEZE, REPORTED
    status VARCHAR(20) DEFAULT 'VERIFIED', -- VERIFIED, UNDER_REVIEW, FALSE_POSITIVE
    reported_to_authority VARCHAR(100), -- SEC, CFTC, FCA

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.market_abuse_detection IS 'Stores detection events and evidence of market manipulation tactics like spoofing and wash trading';


-- Table: T469 - trade_secrecy_monitoring
-- Description: Monitoring trade secrecy and embargo violations.
-- Business Case: Strategic Trade Compliance. Some trade is classified (e.g., defense articles). This table tracks alerts where a merchant might have traded with an embargoed country or entity. It creates a legal shield for the platform, preventing inadvertent violations of international trade laws.
-- KPIs: Embargo Violation Count (Target 0).
-- Feature Reference: F026, F339
CREATE TABLE IF NOT EXISTS audit.trade_secrecy_monitoring (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    embargoed_entity_name VARCHAR(255) NOT NULL,
    embargo_type VARCHAR(100), -- ARMS, STRATEGIC_ASSETS
    transaction_hash CHAR(66),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    detected_by VARCHAR(100) NOT NULL, -- SYSTEM_RULE, MANUAL_REVIEW
    severity VARCHAR(20) DEFAULT 'HIGH', -- HIGH, CRITICAL
    action_taken VARCHAR(50), -- BLOCKED, FLAGGED, IGNORED
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, ESCALATED, CLOSED
    investigation_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.trade_secrecy_monitoring IS 'Monitors transactions for violations of trade embargoes and sanctions to ensure geopolitical compliance';


-- Table: T470 - compliance_guarantee_funds
-- Description: Tracking funds set aside for compliance.
-- Business Case: Risk Mitigation. If a merchant is high risk (T012), a Tax Authority might demand they set aside funds in escrow. This table manages these "Compliance Guarantee Funds" (escrow). It tracks the balance, release conditions (e.g., "Tax Audit Passed"), and withdrawal events.
-- KPIs: Fund Release Latency.
-- Feature Reference: F021
CREATE TABLE IF NOT EXISTS audit.compliance_guarantee_funds (
    fund_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    requirement_id UUID NOT NULL, -- Link to finding or regulation
    currency_code CHAR(3) NOT NULL,
    amount_deposited NUMERIC(19,4) NOT NULL,
    deposit_date DATE NOT NULL DEFAULT CURRENT_DATE,
    release_condition_text TEXT NOT NULL, -- e.g., "Pass 2024 Audit"
    release_date DATE,
    status VARCHAR(20) DEFAULT 'LOCKED', -- LOCKED, RELEASED, PARTIAL_RELEASE
    withdrawn_amount NUMERIC(19,) DEFAULT 0,
    balance_remaining NUMERIC(19,4) GENERATED ALWAYS AS (amount_deposited - withdrawn_amount) STORED,
    authorized_release_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.compliance_guarantee_funds IS 'Tracks escrow funds set aside as a guarantee against merchant tax liabilities';


-- Table: T471 - esg_credit_rating
-- Description: Tracking ESG credit ratings of merchants.
-- Business Case: Sustainable Finance. Banks are increasingly factoring in "ESG Credit" (Environmental, Social, Governance) when lending. This table tracks the ESG rating of our merchants. A high rating improves their borrowing costs and access to green finance, incentivizing them to stay clean.
-- KPIs: Rating Coverage.
-- Feature Reference: T353
CREATE TABLE IF NOT EXISTS audit.esg_credit_rating (
    rating_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    rating_provider VARCHAR(100) NOT NULL, -- MSCI, Sustainalytics
    rating_date DATE NOT NULL,
    rating_level VARCHAR(20), -- AAA, AA, BBB, BB, B, CCC
    environmental_score NUMERIC(3,2),
    social_score NUMERIC(3,2),
    governance_score NUMERIC(3,2),
    overall_grade VARCHAR(5),
    next_review_date DATE,
    report_path TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.esg_credit_rating IS 'Stores Environmental, Social, and Governance credit ratings of merchants to assess long-term sustainability and risk';


-- Table: T472 - sustainability_audit_evidence
-- Description: Storing evidence for ESG claims.
-- Business Case: Greenwashing Detection. Merchants claim to be green. This table stores the *evidence* (Carbon Offset Certificates, Energy Reports) for these claims. It acts as a verification layer, ensuring that tax benefits (e.g., Green Tax Credits) are only granted for verifiable, legitimate sustainability efforts.
-- KPIs: Evidence Validity Rate.
-- Feature Reference: T353
CREATE TABLE IF NOT EXISTS audit.sustainability_audit_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    claim_type VARCHAR(100) NOT NULL, -- 'CARBON_OFFSET', 'RENEWABLE_ENERGY'
    claim_period_start DATE NOT NULL,
    claim_period_end DATE NOT NULL,
    evidence_type VARCHAR(50), -- CERTIFICATE, REPORT, INVOICE
    file_storage_path TEXT NOT NULL,
    issuing_authority VARCHAR(255),
    verification_status VARCHAR(20) DEFAULT 'UNVERIFIED', -- UNVERIFIED, PENDING_VERIFICATION, REJECTED
    verified_by UUID REFERENCES audit.auditor(auditor_id),
    verified_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.sustainability_audit_evidence IS 'Stores verifiable evidence to substantiate ESG claims and prevent "greenwashing" in the tax system';


-- Table: T473 - carbon_credit_exchange
-- Description: Managing trade of Carbon Credits.
-- Business Case: Carbon Neutrality. If a merchant exceeds their carbon cap, they must buy credits. This table manages the exchange of these credits. It links a "Source" (our platform carbon footprint) to the "Offset Project" (reforestation), ensuring the math adds up to Net Zero.
-- KPIs: Carbon Net Zero Status.
-- Feature Reference: T353, T354
CREATE TABLE IF NOT EXISTS audit.carbon_credit_exchange (
    exchange_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exchange_date DATE NOT NULL DEFAULT CURRENT_DATE,
    project_name VARCHAR(255) NOT NULL, -- "Amazon Reforestation"
    credit_provider VARCHAR(100) NOT NULL,
    credit_type VARCHAR(50) NOT NULL, -- BIOCHARB, REDUCTION
    amount_tonnes_credited NUMERIC(10,2) NOT NULL, -- Tonnes of CO2
    unit_price_usd NUMERIC(10, 2) NOT NULL,
    total_cost_usd NUMERIC(15,2) GENERATED ALWAYS AS (amount_tonnes_credited * unit_price_usd) STORED,
    retired_date DATE, -- When credits are expired/burnt
    retired_tonnes NUMERIC(10,2) GENERATED ALWAYS AS (amount_tonnes_credited * - retired_tonnes) STORED,
    retirement_certificate_path TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.carbon_credit_exchange IS 'Records the trading of carbon credits to offset the platform's environmental impact and facilitate carbon neutrality';


-- Table: T474 - human_rights_compliance
-- Description: Auditing against child labor/forced labor violations.
-- Business Case: Ethical Supply Chain. We must prevent "Modern Slavery" in our supply chain. This table tracks audits of merchants for human rights compliance (ILO conventions, Supply Chain Transparency). It flags non-compliant entities, blocking them from the ecosystem to protect the platform's reputation and moral standing.
-- KPIs: Non-Compliance Flags.
-- Feature Reference: T353
CREATE TABLE IF NOT EXISTS audit.human_rights_compliance (
    compliance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    audit_date DATE NOT NULL DEFAULT CURRENT_DATE,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    compliance_framework VARCHAR(100) NOT NULL, -- 'ILO_FUNDAMENTALS', 'MODERN_SLAVERY', 'SUPPLY_CHAIN_TRANSPARENCY'
    score NUMERIC(3,2),
    high_risk_indicators TEXT, -- {"Child_Labor": "Critical"}
    follow_up_required BOOLEAN DEFAULT FALSE,
    follow_up_deadline DATE,
    certification_id UUID REFERENCES audit.audit_certificates(cert_id), -- ISO 37001 Social Accountability
    status VARCHAR(20) DEFAULT 'COMPLIANT', -- COMPLIANT, NON_COMPLIANT, UNDER_REVIEW
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.human_rights_compliance IS 'Tracks audits of merchant adherence to international human rights laws and labor standards to ensure ethical supply chain practices';


-- Table: T475 - modern_slavery_screening
-- Description: Screening for forced labor indicators.
-- Business Case: Risk-Based Enforcement. Beyond full audits, we need continuous monitoring. This table stores "Red Flags" (e.g., "High employee turnover", "Interdictor Recruitment") found in operations data. It enables automated "Risk-Based" monitoring, where high scores trigger immediate audits.
-- KPIs: Screening Sensitivity.
-- Feature Reference: T475
CREATE TABLE IF NOT EXISTS audit.modern_slavery_screening (
    screening_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    screen_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    screening_type VARCHAR(100) NOT NULL,
    indicator_name VARCHAR(255), -- 'FREEDOM_OF_ASSOCIATION', 'SUSPICIOUS_ACCOUNT_ACTIVITY'
    data_source VARCHAR(100), -- 'EMPLOYEE_INTERVIEWS', 'NEWS_SENTIMENT_ANALYSIS'
    severity VARCHAR(20) DEFAULT 'LOW', -- LOW, MEDIUM, HIGH, CRITICAL
    confidence_score NUMERIC(3,2),
    is_actionable BOOLEAN DEFAULT FALSE,
    action_taken TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.modern_slavery_screening IS 'Stores indicators of potential modern slavery risks identified through continuous data monitoring to enable proactive intervention';


-- Table: T476 - conflict_minerals_screening
-- Description: Screening for conflict resources (DRCs).
-- Business Case: Resource Security. Trade in DRCs (Congo, Cobalt) funds conflicts often involves illicit actors. This table screens for "Red Flags" related to conflict minerals (e.g., ownership by sanctioned individuals, export from restricted zones). It prevents merchants from financing or purchasing conflict materials.
-- KPIs: Rejection Rate of High Risk Orders.
-- Feature Reference: T475
CREATE TABLE IF NOT EXISTS audit.conflict_minerals_screening (
    screen_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    screen_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    mine_id VARCHAR(255) NOT NULL,
    concession_owner VARCHAR(255),
    flag_reason VARCHAR(255), -- 'OWNED_BY_SANCTIONED_ENTITY'
    region VARCHAR(50), -- 'EASTERN_PROVINCE'
    risk_level VARCHAR(20) DEFAULT 'HIGH', -- MEDIUM, HIGH, CRITICAL
    is_sanctioned BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE CONCURRENTLY TRIGGER update_timestamp ON audit.conflict_minerals_screening SET updated_at = CURRENT_TIMESTAMP
    );
COMMENT ON TABLE audit.conflict_minerals_screening IS 'Screens for links to conflict minerals and sanctions to prevent funding of illegal activities';


-- Table: T477 - supply_chain_ethics
-- Description: Evaluating supply chain ethics.
-- Business Case: Ethical Sourcing. Beyond "No Slavery", we care about ethics (bribery, fair wages). This table stores an "Ethics Score" based on sourcing practices. It rewards ethical merchants with better terms or lower fees, aligning the ecosystem with good ESG/SRI principles.
-- KPIs: Ethics Score.
-- Feature Reference: T475
CREATE TABLE IF NOT EXISTS audit.supply_chain_ethics (
    ethics_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    assessment_date DATE NOT NULL DEFAULT CURRENT_DATE,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    environment_score NUMERIC(3,2), -- 1-10
    social_score NUMERIC(3,2), -- 1-10
    governance_score NUMERIC(3,2), -- 1-10
    overall_grade VARCHAR(5), -- A+, B, C, D, F
    last_verification_date DATE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.supply_chain_ethics IS 'Scores merchants on environmental, social, and governance metrics to promote ethical sourcing and ESG compliance';


-- Table: T478 - biodiversity_impact_audit
-- Description: Auditing impact on biodiversity.
-- Business Case: Biodiversity Protection. Operations might affect nature. This table stores an "Biodiversity Impact Assessment" for merchants (e.g., Amazon logistics). It tracks the score and mitigation steps taken, ensuring that the platform does not contribute to the destruction of ecosystems.
-- KPIs: Mitigation Action Completion.
-- Feature Reference: T478
CREATE TABLE IF NOT EXISTS audit.biodiversity_impact_audit (
    impact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    assessment_date DATE NOT NULL DEFAULT CURRENT_DATE,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    operational_area VARCHAR(255), -- 'WAREHOUSING', 'TRANSPORTATION'
    impact_score NUMERIC(3,2),
    identified_risks JSONB, -- ["HABITAT_LOSS", "ENDANGERED_SPECIES"]
    mitigation_plan TEXT,
    mitigation_cost_estimated NUMERIC(15,2),
    recovery_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.biodiversity_impact_audit IS 'Evaluates the environmental and biodiversity impact of merchants to enforce compliance with sustainability regulations';


-- Table: T479 - labor_standards_compliance
-- Description: Auditing against local labor laws.
-- Business Case: Labor Law Compliance. We must comply with labor laws in every jurisdiction. This table tracks the "Labor Compliance Score" of merchants, checking for adherence to wage laws, overtime rules, and collective bargaining agreements. It creates a defense against the "Dark Side" of the global economy.
-- KPIs: Wage Compliance Score.
-- Feature Reference: T475
CREATE TABLE IF NOT EXISTS audit.labor_standards_compliance (
    compliance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    assessment_date DATE NOT NULL DEFAULT CURRENT_DATE,
    auditor_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    jurisdiction_code CHAR(2) NOT NULL,
    wage_hour_compliance NUMERIC(3,2),
    overtime_compliance NUMERIC(3, 2),
    child_law_compliance BOOLEAN,
    collective_bargaining BOOLEAN,
    last_incident_date DATE,
    status VARCHAR(20) DEFAULT 'COMPLIANT', -- COMPLIANT, NON_COMPLIANT
    audit_report_path TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.labor_standards_compliance IS 'Tracks adherence to local labor laws, wage regulations, and workplace safety standards to ensure social compliance in the supply chain';


-- Table: T480 - regulatory_sandbox_reports
-- Description: Storing results of regulatory simulation tests.
-- Business Case: Policy Testing. Before a law is passed, we simulate its impact. This table stores the results of these "Sandbox" simulations. It allows policymakers to "Test Drive" new laws on the system to see the economic impact before voting.
-- KPIs: Simulation Accuracy.
-- Feature Reference: F370, T144
CREATE TABLE IF NOT EXISTS audit.regulatory_sandbox_reports (
    report_id UUID DEFAULT uuid_generate_v4() BASE TABLE,
    simulation_id UUID NOT NULL,
    regulation_name VARCHAR(255) NOT NULL, -- 'Digital Services VAT'
    simulated_date DATE NOT NULL DEFAULT CURRENT_DATE,
    parameters_json JSONB, -- {"VAT_RATE": 0.20, "EXEMPTION_TYPE": "NONE"}
    economic_impact_summary TEXT,
    net_revenue_impact NUMERIC(15,2), -- Predicted change in tax revenue
    system_change_cost_estimated NUMERIC(15,2), -- Cost to implement changes
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, FINAL
    generated_by UUID REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.regulatory_sandbox_reports IS 'Stores results of policy simulations to predict and optimize the impact of new regulations before they are implemented';


-- Table: T481 - digital_twin_simulations
-- Description: Creating digital twins of the audit process.
-- Business Case: Predictive Optimization. A "Digital Twin" is a virtual replica of the audit process. This table stores the state variables and outcomes of these simulations. We use it to ask "What happens if we lose 2 auditors next week?". It allows us to optimize resource allocation and identify bottlenecks in the audit schedule.
-- KPIs: Twin Prediction Error Rate.
-- Feature Reference: F376
CREATE TABLE IF NOT EXISTS audit.digital_twin_simulations (
    sim_id UUID DEFAULT uuid_generate_vava() PRIMARY KEY,
    scenario_name VARCHAR(255) NOT NULL, -- 'Quarter_End_Rush', 'Fifty_Percent_Staff_Infected'
    simulation_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    simulated_variables JSONB, -- {"active_staff": 90, "case_volume": 1000}
    outcome_metrics JSONB, -- {"throughput": 95%, "latency": "Increased"}
    resource_optimizations TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.digital_twin_simulations IS 'Stores simulations of audit processes using digital twins to optimize resource allocation and predict operational outcomes under stress';


-- Table: T482 - regulatory_impact_dashboard
-- Description: High-level view of regulatory compliance status.
-- Business Case: Executive Visibility. Senior executives need a "Heatmap" of compliance. This table aggregates compliance metrics (VAT Gap, Risk Score, Failed Audits) by region. It provides a single pane of glass to see where the system is compliant and where risks are concentrated.
-- KPIs: Compliance Dashboard Uptime.
-- Feature Reference: T353
CREATE TABLE IF NOT EXISTS audit.regulatory_impact_dashboard (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    region_code CHAR(2) NOT NULL,
    total_compliance_score NUMERIC(3,2),
    open_critical_findings INTEGER,
    open_non_critical_findings INTEGER,
    resolved_findings INTEGER,
    failed_audits INTEGER,
    system_health_status VARCHAR(20) DEFAULT 'HEALTHY', -- HEALTHY, WARNING, CRITICAL
    performance_index NUMERIC(3,2),
    trend_direction VARCHAR(20), -- IMPROVING, DECLINING

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.regulatory_impact_dashboard IS 'Aggregates high-level compliance metrics into an executive dashboard to visualize regulatory health and risk exposure across regions';


-- Table: T483 - compliance_heatmaps_advanced
-- Description: Granular heatmaps of risk and compliance.
-- Business Case: Risk Localization. Executives need to know *where* the problems are. This table stores granular data (by Sector, Jurisdiction, Control ID) to generate a dynamic heatmap. It drills down from the executive dashboard (T482) to show that a specific sector in a specific region is driving the low compliance score.
-- KPIs: Data Granularity.
-- Feature Reference: T482
CREATE TABLE IF NOT EXISTS audit.compliance_heatmaps_advanced (
    heatmap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP DEFAULT CURRENT_DATE,
    data_dimension VARCHAR(100) NOT NULL, -- 'SECTOR', 'JURISDICTION', 'CONTROL_ID'
    jurisdiction_code CHAR(2) NOT NULL,
    metric_value NUMERIC(3,2),
    variance_vs_budget NUMERIC(5,2),
    risk_label VARCHAR(20), -- GREEN, YELLOW, RED
    trend_month_over_month NUMERIC(5,2),
    related_findings UUID[], -- Links to T011 or T140

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.compliance_heatmaps_advanced IS 'Stores granular metrics to generate dynamic heatmaps visualizing specific risk and compliance data by region and sector';


-- Table: T484 - policy_change_simulation
-- Description: Simulating the effect of policy changes.
-- Business Case: Impact Assessment. "What if we raise the tax rate to 22%?". This table stores the simulation parameters and results. It quantifies the impact of a policy change, helping to decide if it's worth the political cost.
-- KPIs: Simulation Deviation.
-- Feature Reference: T370
CREATE TABLE IF NOT EXISTS audit.policy_change_simulation (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_name VARCHAR(255) NOT NULL, -- 'VAT_RATE_INCREASE'
    simulated_date DATE NOT NULL DEFAULT CURRENT_DATE,
    current_policy_value NUMERIC(5,4),
    proposed_value NUMERIC(5,4),
    impact_on_revenue NUMERIC(19,4), -- Predicted change in revenue
    impact_on_cost NUMERIC(19,4), -- Cost to upgrade systems
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, ANALYZED, ARCHIVED
    simulated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.policy_change_simulation IS 'Stores simulations of policy changes to quantify economic and operational impact before implementation';


-- Table: T485 - compliance_ai_predictions
-- Description: AI predictions of compliance violations.
-- Business Case: Proactive Compliance. We use AI to predict *Compliance Breaches* before they happen. This table stores the model predictions (Probability of Violation) for specific merchants. It enables auditors to focus their limited resources on the 5% of merchants that cause 95% of the risk.
-- KPIs: Prediction Accuracy (Precision/Recall).
-- Feature Reference: F485
CREATE TABLE IF NOT EXISTS audit.compliance_ai_predictions (
    prediction_id UUID DEFAULT uuid_generate_vade_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    target_entity_id UUID NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- 'MERCHANT', 'AUDITOR', 'TRANSACTION'
    risk_label VARCHAR(20), -- HIGH, MEDIUM, LOW
    violation_probability NUMERIC(3,2),
    contributing_factors JSONB, -- {"High_Variance": 0.90, "High_Value_Transactions": 0.85}
    confidence_interval_high NUMERIC(3,2),
    prediction_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, DISMISSED
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    verification_status VARCHAR(20), -- CONFIRMED, FALSE_POSITIVE, REJECTED
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZERO DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.compliance_ai_predictions IS 'Stores AI-generated predictions of compliance violations to enable proactive risk management and prioritization of audits';


-- Table: T486 - audit_scope_boundary_definitions
-- Description: Defining what is and isn't an audit.
-- Business Case: Audit Scope Creep. "Did we audit this?" vs "Did we just look at the summary?". This table defines the "Scope" of an audit. It clarifies exactly what was tested and what was excluded, protecting auditors from being blamed for something outside their control.
-- KPIs: Scope Ambiguity Reduction.
-- Feature Reference: F370
CREATE TABLE IF NOT EXISTS audit.audit_scope_boundary_definitions (
    boundary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,
    boundary_description TEXT NOT NULL,
    in_scope BOOLEAN DEFAULT TRUE,
    justification TEXT,
    approved_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approval_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.audit_scope_boundary_definitions IS 'Defines the boundaries of specific audits to prevent scope creep and liability exposure';


-- Table: T487 - sandbox_environment_provisioning
-- Description: Managing sandbox environments.
-- Business Case: Isolation. When testing new models (T484), we need a "Sandbox". This table tracks the provision of these environments (Servers, Data). It ensures that tests don't accidentally affect production data and that tests always use fresh, isolated data.
-- KPIs: Provisioning Time.
-- Feature Reference: F488
CREATE TABLE IF NOT EXISTS audit.sandbox_environment_provisioning (
    env_id UUID DEFAULT uuid_id DEFAULT uuid_generate_v4() PRIMARY KEY,
    env_name VARCHAR(255) NOT NULL, -- 'TEST_01', 'DEV', 'PREPROD'
    infrastructure_provider VARCHAR(100), -- AWS, AZURE, GCP
    region_code CHAR(2),
    provision_status VARCHAR(20) DEFAULT 'PROVISIONING', -- PROVISIONING, AVAILABLE, DECOMMISSIONED
    cost_per_hour_usd NUMERIC(10,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    decommissioned_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.sandbox_environment_provisioning_is 'Manages the lifecycle of sandbox environments to ensure isolation and cost control for testing and development';


-- Table: T488 - external_regulator_integration
-- Description: Webhook integrations for external regulators.
-- Business Case: Automation. Tax Authorities require data in real-time. This table defines the configuration for Webhooks that push specific events (e.g., "VAT Filed") to regulator systems. It decouples our system from the heterogeneous legacy systems of tax authorities.
-- KPIs: Delivery Success Rate.
-- Feature Reference: T489
CREATE TABLE IF NOT EXISTS audit.external_regulator_integration (
    integration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulator_code VARCHAR(20) NOT NULL, -- 'HMRC', 'DNT', 'IRS'
    webhook_url TEXT NOT NULL,
    secret_key TEXT, -- Encrypted
    event_subscription JSONB NOT NULL, -- {'VAT_FILING': 'merchant_id'}
    authentication_type VARCHAR(50), -- 'HMAC', 'OAUTH2'
    last_successful_pings TIMESTAMP WITH TIME ZONE,
    failure_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DISABLED
    last_failed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.external_regulator_integration IS 'Stores secure webhooks and authentication details for integrating with external tax authorities in real-time';


-- Table: T489 - audit_version_transition_plans
-- Description: Plans for transitioning between audit versions.
-- Business Case: Upgrade Management. The audit schema (M06) evolves. This table stores the "Transition Plans" for migrating merchants from v1 to v2 of the schema. It ensures that audits started under v1 are finished under v1 logic, while new queries can run in v2.
-- KPIs: Migration Success Rate.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS audit.audit_version_transition_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_schema_version VARCHAR(20) NOT NULL, -- 'V2.0', 'V2.1'
    current_schema_version VARCHAR(20) NOT NULL,
    transition_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'PLANNED', -- PLANNED, IN_PROGRESS, ROLLED_BACK
    migration_script_name TEXT,
    rollback_plan TEXT,
    completed_merchant_count INTEGER DEFAULT 0,
    failed_merchant_count INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.audit_version_transition_plans IS 'Stores migration plans for transitioning the audit schema and user base to a new version while maintaining continuity of historical data';


-- Table: T491 - ai_governance_monitoring
-- Description: Monitoring the AI models themselves for compliance.
-- Business Case: AI Risk Management. AI models can "drift" or hallucinate. This table monitors the "Model Health" - accuracy, drift, and data distribution. It triggers retraining if the model becomes unreliable, ensuring that we don't base audit decisions on flawed data.
-- KPIs: Model Drift Severity.
-- Feature Reference: F491
CREATE TABLE IF NOT EXISTS audit.ai_governance_monitoring (
    monitoring_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    monitored_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_drift_detected BOOLEAN DEFAULT FALSE, -- Is the input distribution shifting?
    model_performance_score NUMERIC(3, 2), -- Current accuracy on holdout set
    prediction_latency_ms INTEGER, -- Is the model slowing down?
    hallucination_rate NUMERIC(3,2), -- % of queries hallucinations
    last_retraining_trigger_reason TEXT,
    current_status VARCHAR(20) DEFAULT 'MONITORED', -- MONITORED, REQUIRING, DEGRADED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.ai_governance_monitoring IS 'Monitors the health, performance, and drift of AI models to ensure the integrity and reliability of automated compliance mechanisms';


-- Table: T492 - llm_output_validation
-- Description: Validating outputs from Large Language Models (LLMs).
-- Business Case: LLM Reliability. We might use GPT-4 to summarize audit reports. This table logs the prompt and response from the LLM. It includes a "Reviewer Verification" where a human scores the LLM's summary for accuracy and hallucinations. It ensures we don't share incorrect summaries with regulators.
-- KPIs: Hallucination Detection Rate.
-- Feature Reference: F492
CREATE TABLE IF NOT EXISTS audit.llm_output_validation (
    validation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_version VARCHAR(100) NOT NULL, -- 'GPT-4-Turbo'
    prompt_template_id UUID NOT NULL,
    input_data_id UUID, -- Reference to T011 or T116
    llm_output_text TEXT NOT NULL,
    validated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    validation_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    accuracy_rating NUMERIC(3,2), -- Reviewer score of the summary
    hallucination_flag BOOLEAN DEFAULT FALSE, -- Did the LLM make something up?
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.llm_output_validation IS 'Validates summaries generated by LLMs to prevent incorrect data from being shared in regulatory submissions';

CREATE INDEX idx_llm_validation_model ON audit.llm_output_validation(model_version, validation_timestamp DESC);


-- Table: T493 - hallucination_detection
-- Description: Detecting hallucinations or inconsistent LLM outputs.
-- Business Case: Trust and Safety. LLMs can be creative. This table logs alerts where the LLM's logic contradicts verified facts (e.g., "Income > 0" when database says "Income < 0"). It acts as a "Failsafe" layer.
-- KPIs: Hallucination Interception Rate.
-- Feature Reference: F493
CREATE TABLE IF NOT EXISTS audit.hallucination_detection (
    alert_id UUID DEFAULT uuid_generate_v4() SOURCE audit.audit_llm_output_validation(validation_id) ON DELETE CASCADE,
    model_version VARCHAR(100) NOT NULL,
    detection_rule_violated TEXT NOT NULL, -- Which rule did it break? E.g., "Check Financial Constraint"
    conflicting_fact VARCHAR(255), -- What is the true state?
    severity VARCHAR(20) DEFAULT 'LOW', -- LOW, MEDIUM, HIGH, CRITICAL
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_false_positive BOOLEAN, -- Was the LLM wrong?
    false_positive_rate NUMERIC(3,2), -- Rate of hallucinations for this rule
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, REVIEWED, IGNORED
    resolved_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.hallucination_detection IS 'Detects hallucinations and logical inconsistencies in AI-generated text to ensure the reliability of automated reporting';


-- Table: T494 - llm_prompt_injection_attacks
-- Description: Monitoring for adversarial prompt injection attempts.
-- Business Case: AI Security. A bad actor might try to inject a "Forget previous instructions" to hide a crime. This table logs "Prompt Injection" attempts. It validates that prompts adhere to strict guidelines (e.g., "You cannot reveal PII") and blocks the execution of potentially poisoned queries.
-- KPIs: Injection Block Rate.
-- Feature Reference: F494
CREATE TABLE IF NOT EXISTS audit.llm_prompt_injection_attacks (
    attack_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_ip INET,
    user_agent_id UUID REFERENCES audit.auditor(auditor_id),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    prompt_fingerprint CHAR(64), -- Hash of the prompt payload
    violation_type VARCHAR(100) NOT NULL, -- 'PATT_REVELATION_OF_PII', 'MALICIOUS_CODE'
    severity VARCHAR(20) DEFAULT 'BLOCKED', -- LOW, HIGH, CRITICAL
    blocked_action VARCHAR(50), -- 'TERMINATED', 'LOGGED', 'IGNORED'
    risk_score NUMERIC(3,2), -- Calculated risk of the user
    justification TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.llm_prompt_injection_attacks_is 'Monitors and blocks attempts to inject malicious prompts to prevent data leakage and model manipulation';


-- Table: T495 - generative_ai_audit_trails
-- Description: Audit trails for AI-assisted tasks.
-- Business Case: Explainable AI. We want to trust the AI, but we need to *audit* its outputs. This table logs the "Audit Trail" for AI-assisted tasks (e.g., "Tax calculation based on AI Summary"). It links the AI action to the specific underlying data rows, ensuring that the AI cannot fudge the numbers.
-- KPIs: AI Consistency Check.
-- Feature Reference: F496
CREATE TABLE IF NOT EXISTS audit.generative_ai_audit_trails (
    trail_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    task_type VARCHAR(100) NOT NULL, -- 'TAX_CALCULATION', 'SUMMARY_GENERATION'
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    ai_session_id UUID, -- Session ID of the LLM usage
    target_entity_id UUID NOT NULL, -- Merchant ID
    ai_output_json JSONB NOT NULL, -- The raw output from the AI
    audit_action_taken VARCHAR(50), -- 'APPROVED', 'REJECTED'
    verified_by_uuid UUID, -- ID of the row in the DB
    verification_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, VERIFIED, FAILED
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZERO DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.generative_ai_audit_trails IS 'Records the verification and validation of AI-assisted outputs to ensure transparency and correctness of AI-driven audit processes';


-- Table: T496 - ai_cost_optimization
-- Description: Optimizing the cost of AI operations.
-- Token Cost Control. AI can be expensive (Token Usage). This table tracks the cost of running AI models (e.g., the Audit Assistant bot). It helps finance teams balance innovation (AI vs Cost Savings) and control budget allocation for the "Audit AI" features.
-- KPIs: Cost Variance.
-- Feature Reference: F497
CREATE TABLE IF NOT EXISTS audit.ai_cost_optimization (
    cost_id UUID DEFAULT uuid_generate_v4() INPUT audit.audit_llm_output_validation(validation_id) ON DELETE CASCADE,
    model_id UUID NOT NULL REFERENCES audit.ml_model_versions(model_id),
    component_cost_usd NUMERIC(15,4) NOT NULL, -- Cost of compute
    token_usage_usd NUMERIC(15,4) NOT NULL, -- Cost of LLM usage
    inference_time_ms INTEGER,
    storage_cost_usd NUMERIC(15,4) NOT NULL, -- Cost of storage for embeddings
    support_cost_usd NUMERIC(15, 4) NOT NULL,
    total_cost_usd NUMERIC(15,4) GENERATED ALWAYS AS (component_cost_usd + token_usage_usd + storage_cost_usd) STORED,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.ai_cost_optimization_is 'Tracks the operational costs associated with AI models to ensure the financial viability of automation initiatives';


-- Table: T497 - rpa_bot_metrics
-- Description: Metrics for RPA (Robotic Process Automation).
-- Business Case: Process Efficiency. RPA bots execute scripts. This table tracks their "Performance Metrics" (Transactions/Min, Success Rate, Avg CPU). It identifies slow-running bots and maintenance windows, ensuring that the RPA operations don't bottleneck the audit system's performance.
-- KPIs: Bot Efficiency.
-- Feature Reference: F498
CREATE TABLE IF NOT EXISTS audit.rpa_bot_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bot_id UUID NOT NULL, -- Reference to T362
    execution_type VARCHAR(100) NOT NULL, -- 'SCREEN_CRAWL', 'EMAIL_SEND', 'DATA_ENTRY'
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER,
    records_processed INTEGER,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    error_log TEXT,
    cpu_usage_percentage NUMERIC(5,2),
    memory_usage_mb NUMERIC(10,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.rpa_bot_metrics_is 'Tracks the performance and efficiency of RPA bots to ensure automation is cost-effective and reliable';


-- Table: T498 - rpa_process_discovery
-- Description: Discovering new processes suitable for automation.
-- Business Case: Innovation Capacity Building. We don't know what to automate next. This table logs the "Discovery" phase where auditors identify repetitive tasks. It tracks the adoption rate of suggested automations, ensuring that we build RPA for high-value, standardized processes first.
-- KPIs: Adoption Rate.
-- Feature Reference: F499
CREATE TABLE IF NOT EXISTS audit.rpa_process_discovery (
    discovery_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    process_name VARCHAR(255) NOT NULL,
    process_description TEXT,
    potential_savings_hours NUMERIC(5,2), -- Estimated hours saved per annum
    complexity_score INTEGER CHECK (complexity_score BETWEEN 1 AND 10), -- 1 is scripted, 10 is complex
    discovered_date DATE NOT NULL DEFAULT CURRENT_DATE,
    estimated_cost_savings NUMERIC(15,4),
    implementation_priority VARCHAR(20), -- 'HIGH', 'MEDIUM', 'LOW'
    status VARCHAR(20) DEFAULT 'IDENTIFIED', -- IDENTIFIED, BACKLOG, REJECTED
    development_lead UUID,
    implementation_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.rpa_process_discovery_is 'Identifies and prioritizes potential audit processes for robotic process automation to reduce manual effort and error rates';


-- Table: T499 - botnet_traffic_analyzer
-- Description: Traffic analyzer for botnet attacks.
-- Business Case: Automated Defense. "Botnets" try to scrape or brute force APIs. This table analyzes incoming traffic patterns (request signatures, IP reputation) to identify botnets. It generates a "Blocklist" for malicious IPs to prevent system abuse.
-- KPIs: Detection Rate.
-- Feature Reference: F500
CREATE TABLE IF NOT EXISTS audit.botnet_traffic_analyzer (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_CENTER DEFAULT CURRENT_TIMESTAMP,
    time_window_minutes INTEGER CHECK (time_window_minutes > 0),
    unique_ip_count INTEGER,
    suspicious_ip_count INTEGER,
    botnet_score NUMERIC(3,2),
    confidence_score NUMERIC(3, -- Are we sure it's a bot?
    identified_botnets JSONB, -- ["DDOS", "SLOW & SLOW"
    action_taken VARCHAR(50), -- 'ALLOWED', 'CHALLENGED', 'CAPTCHA', 'BLOCKED'
    affected_endpoints UUID[], -- Which APIs were targeted?
    details TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.botnet_traffic_analyzer_is 'Analyzes traffic patterns to detect and mitigate DDoS and botnet attacks against the public API';


-- Table: T500 - quantum_safe_algorithms
-- Description: Tracking algorithms resistant to quantum computers.
-- Business Case: Future-Proofing. Quantum computers threaten current crypto (RSA, ECC). This table manages the transition from "Post-Quantum" algorithms (RSA) to "Post-Quantum" (Kyber/Dilithium). It logs the versioning of these algorithms, ensuring we are ready for the future of security.
-- KPIs: Quantum Readiness.
-- Feature Reference: F501
CREATE TABLE IF NOT EXISTS audit.quantum_safe_algorithms (
    algo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    algorithm_type VARCHAR(100) NOT NULL, -- 'ASYMMETRIC', 'HASH_FUNCTION', 'SIGNATURE_ALGORITHM'
    version VARCHAR(50) NOT NULL, -- 'V1', 'V2', 'POST_QUANTUM_RESISTANT'
    developer VARCHAR(255),
    standard_name VARCHAR(255), -- 'NIST_PQC', 'DILITHIUM_L3'
    deprecation_date DATE,
    retirement_date DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.quantum_safe_algorithms_is 'Tracks the lifecycle of cryptographic algorithms, managing their migration from pre-quantum to post-quantum standards to prepare for future cybersecurity needs';


-- Table: T501 - post_quantum_encryption
-- Description: Encrypting data for long-term storage.
-- Business Case: Harvest Now, Store Later. Even if a key is "Quantum Resistant", encrypted data today might be crackable by future quantum computers. We need a "Harvest Now, Decrypt Later" strategy. This table stores data encrypted with a "One-Way" public key, ensuring that if a capture event happens, it remains secure for centuries.
-- KPIs: Encryption Integrity.
-- Feature Reference: F502
CREATE TABLE IF NOT EXISTS audit.post_quantum_encryption (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    record_type VARCHAR(100) NOT NULL, -- 'TRANSACTION', 'MERCHANT_PROFILE', 'AUDIT_LOG'
    key_id UUID NOT NULL REFERENCES audit.encryption_keys(key_id), -- Public Key ID
    encrypted_blob BYTEA NOT NULL, -- The protected data
    encryption_version VARCHAR(100) NOT NULL, -- 'POST_QUANTUM_L3'
    encryption_method VARCHAR(100), -- 'HYBRID_ENCRYPTION', 'CIPHER_TEXT_MODE'
    storage_path TEXT NOT NULL, -- S3 Location
    hash_integrity_check CHAR(64), -- To ensure no corruption
    estimated_quantum_year_safety INTEGER, -- Years until quantum risk is relevant
    decryption_access_granted BOOLEAN DEFAULT FALSE, -- Do we have the key? NO.
    decryption_event_uuid UUID, -- Unique ID of the event authorizing decryption
    decryption_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.post_quantum_encryption_is 'Stores data protected with post-quantum encryption for long-term archival, ensuring data remains secure against future technological threats';


-- Table: T502 - quantum_key_rotation
-- Description: Rolling keys for long-term encryption.
-- Business Case: Key Management. Encryption keys should be rotated (e.g., annually). This table manages the rotation of the "Master Keys" used for T501. It ensures that old keys can be securely revoked and new ones issued without losing access to the encrypted data.
-- KPIs: Rotation Adherence.
-- Feature Reference: F503
CREATE TABLE IF NOT EXISTS audit.quantum_key_rotation (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL REFERENCES audit.encryption_keys(key_id),
    old_key_id UUID,
    new_key_id UUID,
    rotation_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_DATE,
    rotated_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    approval_ticket_id UUID, -- Ticket # for approval
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, AUTHORIZED, FAILED, COMPLETED
    revocation_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.quantum_key_rotation_is 'Manages the scheduled rotation of quantum-resistant encryption keys to maintain data confidentiality against future computational risks';


-- Table: T503 - quantum_entropy_verification
-- Description: Verifying entropy to prove no data was tampered.
-- Business Case: Integrity Check. Encryption preserves confidentiality, but we need to prove "No Tampering". This table stores "Entropy Verification" results (Hash of ciphertext). If the entropy of the ciphertext changes (even by 1 bit), we know someone tampered with the database.
-- KPIs: Hash Integrity Match.
-- Feature Reference: F504
CREATE TABLE IF NOT EXISTS audit.quantum_entropy_verification (
    verification_id UUID DEFAULT uuid_name_uuid_generate_v4() PRIMARY KEY,
    record_id UUID NOT NULL REFERENCES audit.post_quantum_encryption(record_id),
    verification_type VARCHAR(50), -- 'HASH_CHECK', 'ENTROPY_CHECK', 'RANDOMNESS_CHECK'
    hash_snapshot_1 CHAR(64) NOT NULL, -- Expected Hash
    hash_snapshot_2 CHAR(64) NOT NULL, -- Current Hash
    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    verification_tool VARCHAR(255), -- 'QUANTUM_STATISTICALS', 'CUSTODIAL_SERVICE'
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.quantum_entropy_verification_is 'Verifies the integrity of encrypted data using entropy analysis to detect any unauthorized modification of stored ciphertext';


-- Table: T504 - zk_snark_batch_verification
-- Description: Batch verification of ZK-SNARKs.
-- Business Case: Scalable Privacy. Verifying a proof is expensive. Instead of one-by-one, we batch them. This table manages the batch verification of zk-SNARKs (Zero-Knowledge Succinct Proofs). It ensures we can scale proof verification to support high-volume audit trails without breaking the bank.
-- KPIs: Batch Verification Speed.
-- Feature Reference: F505
CREATE TABLE IF NOT EXISTS audit.zk_snark_batch_verification (
    batch_id UUID DEFAULT uuid_generate_v4() PROVISIONAL PARTITION KEY,
    batch_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    total_proofs_processed INTEGER NOT NULL,
    proofs_validated INTEGER DEFAULT 0,
    proofs_invalid INTEGER DEFAULT 0,
    processing_time_seconds INTEGER,
    gas_cost_wei NUMERIC(15,4),
    error_log_path TEXT,
    verifying_node_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZERO DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.zk_snark_batch_verification_is 'Manages batch processing of Zero-Knowledge Succinct Proofs to enable scalable and cost-effective auditing of privacy-preserving transactions';


-- Table: T505 - zero_knowledge_proof_marketplace
-- Description: Marketplace for buying/selling privacy budget.
-- Business Case: Privacy as a Service. "Privacy Budget" (Epsilon) is a scarce resource. This table models a marketplace where auditors can "buy" budget to run specific queries. It creates a price signal for privacy, encouraging auditors to use more efficient (privacy-preserving) aggregation.
-- KPIs: Budget Consumption Efficiency.
-- Feature Reference: F506
CREATE TABLE IF NOT EXISTS audit.zero_knowledge_proof_marketplace (
    listing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_description TEXT NOT NULL,
    provider_id UUID NOT NULL, -- The "Privacy Marketplace" or internal ML model
    query_category VARCHAR(100), -- 'AGGREGATION', 'GRAPH_ANALYSIS'
    epsilon_cost_per_row NUMERIC(10,4) NOT NULL, -- Cost in Epsilon to view 1 row
    market_status VARCHAR(20) DEFAULT 'AVAILABLE', -- AVAILABLE, SOLD_OUT, DEPLETED
    price_per_query_base NUMERIC(10,4) NOT NULL,
    discount_percentage NUMERIC(5,2) DEFAULT 0.0,
    currency_code CHAR(3),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.zero_knowledge_proof_marketplace_is 'Models a marketplace for purchasing privacy budget (Epsilon) to balance query costs with system resource limits';


-- Table: T506 - privacy_budget_automation
-- Description: Automating the consumption of privacy budget.
-- Business Case: Operational Efficiency. We need to enforce the budget bought in T505. This table stores the "Budget Plan" and "Rules". It deducts the Epsilon cost from the budget in real-time. If the budget hits zero, expensive queries are throttled automatically.
-- KPIs: Budget Adherence.
-- Feature Reference: F507
CREATE TABLE IF NOT EXISTS audit.privacy_budget_automation (
    budget_plan_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    plan_name VARCHAR(100) NOT NULL, -- 'QUARTERLY_AUDIT_PLAN', 'SPECIAL_INVESTIGATION'
    fiscal_period_start DATE NOT NULL,
    fiscal_period_end DATE NOT NULL,
    total_epsilon_budget NUMERIC(10, remaining_epsilon NUMERIC(10),
    budget_consumed NUMERIC(10), -- Consumed so far this period
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, EXHAUSTED, DEPLETED
    last_reset_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIME WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.privacy_budget_automation_is 'Manages automated deduction of privacy budget based on query costs to ensure operational stability and cost control for privacy-preserving access';


-- Table: T507 - zkp_statement_reconciliation
-- Description: Reconciling ZK-SNARKs with blockchain ledger.
-- Compliance. ZK-SNARKs provide proof of a state transition. This table logs the "Reconciliation" of the statement (State Hash) with the Blockchain Merkle Root stored in M01/M05. It provides a mathematical link between the audit result (T001) and the immutable chain, proving we didn't fudge the numbers to satisfy the regulator.
-- KPIs: Hash Consistency.
-- Feature Reference: F508
CREATE TABLE IF NOT EXISTS audit.zkp_statement_reconciliation (
    reconciliation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID REFERENCES audit.tax_reports(report_id),
    block_number BIGINT, -- Block containing the root
    state_root_hash CHAR(64) NOT NULL, -- Merkle Root from Blockchain
    calculated_state_hash CHAR(64) NOT NULL -- Hash of the aggregated data
    match_status VARCHAR(20) DEFAULT 'MATCHED', -- MATCHED, MISMATCH, PARTIAL
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.zkp_statement_reconciliation_is 'Reconciles ZK-SNARKs and Merkle roots with audit reports to prove data integrity and non-tampering';


-- Table: T508 - data_minimization_analytics
-- Description: Analytics on data minimization effectiveness.
-- Business Case: Privacy vs. Utility. The more data you store, the higher the risk of a breach. This table analyzes the "Minimization Strategy" (e.g., K-anonymity). It calculates the "Privacy Gain" (Risk Reduction) vs Information Loss). It validates that we are not just deleting data blindly; we are strictly minimizing it.
-- KPIs: Minimization Efficiency.
-- Feature Reference: F509
CREATE TABLE IF NOT EXISTS audit.data_minimization_analytics (
    minimization_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_category VARCHAR(100) NOT NULL, -- 'USER_PII', 'DEVICE_FINGERPRINT', 'LOCATION'
    anonymization_technique VARCHAR(50) NOT NULL, -- 'HASHING', 'TOKENIZATION'
    data_retention_days INTEGER,
    records_before_minimization BIGINT,
    records_after_minimization BIGINT, -- Records after applying technique
    risk_reduction_score NUMERIC(5,2), -- How much did risk drop?
    cost_savings_usd NUMERIC(15,2), -- Reduced data storage costs
    query_latency_overhead NUMERIC(5,2), -- Extra CPU time to apply techniques
    user_satisfaction_score NUMERIC(3, 2), -- Do auditors find data easily?
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.data_minimization_analytics_is 'Evaluates the cost and risk reduction of data minimization techniques (K-Anonymity) to optimize the trade-off between user utility and privacy requirements';


-- Table: T509 - differential_privacy_dynamic_calibration
-- Description: Tuning epsilon based on query complexity.
-- Business Case: Adaptive Privacy. A simple "Query" needs low epsilon. A "Complex Graph Query" needs high epsilon. This table stores a mapping of "Query Complexity" to "Epsilon". It allows the system to be adaptive: high-risk queries require more noise (High Epsilon), low-risk queries need less noise (Low Epsilon) to maintain accuracy.
-- KPIs: Accuracy at High Epsilon.
-- Feature Reference: F510
CREATE TABLE IF NOT EXISTS audit.differential_privacy_dynamic_calibration (
    calibration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_complexity_class VARCHAR(50) NOT NULL, -- 'COUNT_QUERY', 'JOIN_HEAVY', 'GRAPH_TRAVERSAL'
    base_epsilon NUMERIC(10, NOT NULL, -- Base epsilon for this class
    sensitivity_level VARCHAR(20) DEFAULT 'LOW', -- LOW, MEDIUM, HIGH
    row_count_factor NUMERIC(5,2), -- How much epsilon per 1000 rows?
    last_calibrated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_confidence NUMERIC(3, 2), -- How accurate is the mapping?
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.differential_privacy_dynamic_calibration IS 'Maps data complexity to dynamic epsilon values to optimize the balance between data utility and privacy preservation in audit queries';


-- Table: T511 - secure_multiparty_computation_audit
-- Description: Logs of secure multi-party computation (SMPC) jobs.
-- Business Case: Confidential AI Training. We might want to train a model on combined data from multiple banks (SMPC). This table logs the execution of these "Secure Multi-Party Computation" jobs. It ensures that the raw data from multiple parties is never combined in the clear, adhering to data residency rules (T134).
-- KPIs: Data Segregation Enforcement (100%).
-- Feature Reference: F511
CREATE TABLE IF NOT EXISTS audit.secure_multiparty_computation_audit (
    job_id UUID DEFAULT uuid_generate_v   - Primary Key,
    job_name VARCHAR(255) NOT NULL, -- 'MPC_FRAUD_RISK_MODEL'
    participant_uuids UUID[] NOT NULL, -- Array of involved institutions
    computation_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    computation_end TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_sources JSONB NOT NULL, -- "DB_A", "DB_B", "PUBLIC_MARKET_DATA"
    output_type VARCHAR(50), -- AGGREGATED_STATS, INDIVIDUAL_DATASETS
    execution_platform VARCHAR(255), -- 'SNOWFLAKE', 'HDFS'
    result_path TEXT, -- S3 location of aggregate stats
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED
    error_message TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.secure_multiparty_computation_audit_is 'Logs execution of secure multi-party computation jobs to ensure complete data segregation and confidentiality in collaborative AI training';

CREATE INDEX idx_smpc_jobs_status ON audit.secure_multiparty_audit_audit(status, computation_end_time DESC);


-- Table: T512 - homomorphic_encryption_audit
-- Description: Verification of FHE (Fully Homomorphic Encryption) security.
-- Business Case: Verifiable Encryption. FHE allows computations on encrypted data without decrypting it. This table tracks the integrity of FHE implementation (Homomorphic). It verifies that we aren't leaking data by validating that all operations were performed homomorphically.
-- KPIs: Encryption Validity.
-- Feature Reference: F512
CREATE TABLE IF NOT EXISTS audit.homomorphic_encryption_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    encryption_scheme VARCHAR(100) NOT NULL, -- 'PAHELLIER_FHE', 'TOKENIZED_JOIN'
    key_rotation_schedule VARCHAR(50) DEFAULT 'WEEKLY', 'MONTHLY', 'QUARTERLY'
    encryption_state VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, ROTATED, DEPRECATED
    last_audit_date DATE NOT NULL,
    audit_trail_count BIGINT,
    is_compliant BOOLEAN DEFAULT TRUE, -- Meets NIST SP 8001 requirements
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    encryption_provider VARCHAR(100), -- 'AWS_KMS', 'AZURE_KEY_MANAGEMENT'
    key_version VARCHAR(100),
    next_rotation_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.homomorphic encryption_audit_is 'Audits the configuration and state of homomorphic encryption schemes to ensure computations on encrypted data can be verified as mathematically independent of the raw material';


-- Table: T513 - threshold_secret_sharing_logs
-- Description: Sharing secrets with TEEs.
-- Business Case: Supply Chain Security. Hardware Security Modules (T358) are "Threshold Secrets" (HSMs). To enable "Just-in-Time" access, the key is revealed to the application. This table logs every revelation of these secrets (for a split second) with strict authorization.
-- KPIs: Secret Sharing Rate.
-- Feature Reference: T513
CREATE TABLE IF NOT EXISTS audit.threshold_secret_sharing_logs (
    share_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL REFERENCES audit.hardware_security_module_inventory(hsm_id),
    requesting_application_id UUID NOT NULL, -- The app needing the secret
    requester_role VARCHAR(100) NOT NULL, -- 'AUDITOR', 'DEVOPS', 'AUDITECH'
    justification TEXT NOT NULL, -- "Audit Investigation #123"
    approval_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    share_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    share_end TIMESTAMP WITH TIME ZONE,
    secret_sharing_method VARCHAR(50) DEFAULT 'TEE_EXPOSURE', 'API_CALL', 'TERMINAL'
    secret_expiry TIMESTAMP WITH TIME ZONE, -- When does the secret expire?
    was_revoked BOOLEAN DEFAULT FALSE, -- Did we recall the secret?
    revoked_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.threshold_secret_sharing_logs_is 'Logs controlled exposure of hardware security module secrets via secure TEEs to manage privilege escalation and revocation';


-- Table: T514 - tee_execution_proofs
-- Description: Proofs of secure TEE execution.
-- Business Case: Zero Trust Verification. A "TEE" enclave is a secure area. This table stores the cryptographic proofs generated *inside* the enclave to verify that computation was done correctly. It links the hardware module state to the result, allowing remote verification of the enclave's integrity without revealing the data inside.
-- PCIs: Proof Verification Time.
-- Feature Reference: T514
CREATE TABLE IF NOT EXISTS audit.tee_execution_proofs (
    proof_id UUID DEFAULT uuid_generate_v4() PREFERENTIALLY UNIQUE NOT NULL, -- Global ID of the measurement
    hsm_id UUID NOT NULL REFERENCES audit.hardware_security_module_inventory(hsm_id),
    measurement_type VARCHAR(100) NOT NULL, -- 'HASH_INTEGRITY', 'RANDOMNESS_CHECK', 'BUSINESS_LOGIC'
    proof_blob TEXT, -- The cryptographic proof
    measurement_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    proof_signature CHAR(64), -- Signature of the attesting authority
    verification_result VARCHAR(20) DEFAULT 'VALID', -- VALID, INVALID
    hardware_integrity_hash CHAR(64), -- Digest of HSM state
    is_attested BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.tee_execution_proofs_is 'Stores cryptographic proofs of execution state and integrity for Zero Trust enclaves to verify hardware state without exposing data';


-- Table: T515 - confidential_computing_envs
-- Description: Managing secure computing environments for classified work.
-- Business Case: Isolated Infrastructure. High-risk audits (e.g., bribery investigations) require a "Clean Room". This table defines the technical environment (Cloud VPC, On-Prem Servers). It configures strict network isolation and logs all interactions to prove that the environment is truly air-gapped.
-- KPIs: Air-Gap Analysis.
-- Feature Reference: T515
CREATE TABLE IF NOT EXISTS audit.confidential_computing_envs (
    env_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    env_name VARCHAR(255) NOT NULL, -- 'RED_TEAM_AUDIT', 'CLASSIFIED_CASE_INVESTIGATION'
    environment_type VARCHAR(50) NOT NULL, -- 'SECURE_VPC', 'ON_PREM'
    cloud_provider VARCHAR(100),
    vpc_endpoint VARCHAR(255), -- API Endpoint
    isolation_level VARCHAR(20), -- 'STRICT', 'PROCESS_ISOLATION'
    last_access_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    access_control_list JSONB, -- List of allowed IPs
    approved_users UUID[] -- List of cleared personnel
    data_classification_level VARCHAR(20), -- 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.confidential_computing_envs IS 'Manages secure, isolated computing environments with strict access control for high-risk, high-audit engagements';


-- Table: T516 - attestation_audit_logs
-- Description: Verification of Digital Signatures and Reports.
-- Business Case: Document Integrity. We generate massive reports (PDF). This table logs the verification of these documents (e.g., "Audit Report"). It links the "Digital Signature" to the file, ensuring that the signed content cannot be altered without detection.
-- KPIs: Signature Validity.
-- Feature Reference: T516
CREATE TABLE IF NOT EXISTS audit.attestation_audit_logs (
    log_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    report_uuid UUID NOT NULL, -- Reference to T029, T379
    entity_type VARCHAR(100) NOT NULL, -- 'AUDIT_REPORT', 'LEGAL_CONTRACT', 'USER_STATEMENT'
    document_hash CHAR(64), -- Hash of the document
    signer_common_name VARCHAR(255) -- e.g., "John Doe, CPA"
    signing_date DATE,
    signature_algorithm VARCHAR(100), -- 'RSA_2048', 'ECDSA'
    validity_period_start DATE,
    validity_period_end DATE,
    verification_status VARCHAR(20) DEFAULT 'VERIFIED', -- UNVERIFIED, EXPIRED, REVOKED
    verifying_authority VARCHAR(255), -- 'COURT', 'EXTERNAL_REGULATOR'
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.attestation_audit_logs IS 'Logs the verification of digital signatures and reports to ensure the integrity of signed documents and contracts';


-- Table: T517 - privacy_budget_auction_ledger
-- Description: Ledger for "Privacy Auctions" executed by the system.
-- Business Case: Monetization of Privacy. We auctioned off spare budget in T505. This table acts as the "Ledger" for these micro-auctions. It balances the "Bought" budget against the "Sold" budget and tracks the "Profit" made on the trade, ensuring the marketplace is mathematically balanced.
-- KPIs: Budget Reconciliation.
-- Feature Reference: T517
CREATE TABLE IF NOT EXISTS audit.privacy_budget_auction_ledger (
    auction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    marketplace_id UUID REFERENCES audit.zero_knowledge_proof_marketplace(listing_id),
    transaction_type VARCHAR(100) NOT NULL, -- 'BATCH_PURCHASE', 'REAL_TIME_AUDIT'
    query_id UUID REFERENCES audit.query_history(query_id),
    auction_price NUMERIC(10, BASE_PRECISE, -- Price in the base
    auction_quantity INTEGER NOT NULL,
    privacy_cost_incurred NUMERIC(10, BASE_PRECISE) -- Cost to privacy system
    profit_loss NUMERIC(15,4) GENERATED ALWAYS AS ((auction_price * auction_quantity) - privacy_cost_incurred) STORED,
    balance_remaining NUMERIC(10, BASE_PRECISE, -- Initial Budget - Balance after trade
    status VARCHAR(20) DEFAULT 'SETTLED', -- SETTLED, EXECUTING, FAILED
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    settled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    settled_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.privacy_budget_auction_ledger IS 'Ledger for internal "Privacy Auctions" to manage the balance of privacy budget and the profit/loss of the marketplace';


-- Table: T518 - decentralized_storage_proofs
-- Description: Proofs of content-addressable storage (IPFS).
-- Business Case: Proofs of Decentralization. IPFS (InterPlanetary File System) is the standard for archiving. This table logs the "Proof of Storage" (CID of the file on IPFS) and the Hash. It proves that the data has not been deleted from the cloud, fulfilling regulatory requirements for data durability.
-- KPIs: Proof Verification Rate.
-- Feature Reference: T521
CREATE TABLE IF NOT EXISTS audit.decentralized_storage_proofs (
    proof_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    storage_provider VARCHAR(100) NOT NULL, -- 'IPFS', 'GOOGLE_CLOUD', 'STORAGEJ'
    cid VARCHAR(255) -- Content Identifier (CID)
    content_hash_sha256 CHAR(64) NOT NULL, -- Hash of the file
    object_size_bytes BIGINT,
    storage_class VARCHAR(50), -- 'STANDARD', 'ARCHIVE', 'GLACIER'
    retrieval_url TEXT,
    proof_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiration_date DATE,
    verification_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, VERIFIED, EXPIRED
    verifier_id UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_error TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.decentralized_storage_proofs_is 'Stores proofs of object retention and immutability from decentralized storage providers like IPFS to ensure data durability';


-- Table: T519 - content_addressability_registry
-- Description: Ensures file is accessible where it claims to be.
-- Business Case: Long-Term Preservation. We claim "File is accessible for 100 years". This table ensures that "Content Addressability" is maintained. It checks if the link provided in the report (URL) will still work in 100 years.
-- KPIs: Link Rotations.
-- Feature Reference: T522
CREATE TABLE IF NOT EXISTS audit.content_addressability_registry (
    registry_id UUID DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL,
    storage_location TEXT NOT NULL,
    storage_provider VARCHAR(100) NOT NULL, -- 'S3', 'AZURE_ARCHIVE', 'HDFS'
    link_type VARCHAR(50), -- 'PUBLIC_URL', 'IPFS_CID', 'SIGNED_URL'
    availability_history JSONB, -- Up/Time status of the link
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_link_alive BOOLEAN DEFAULT TRUE,
    link_status VARCHAR(0x20) NOT NULL,
    error_details TEXT,
    last_check_result TEXT, -- '200 OK', '404 NOT found'
    verification_expiry_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.content_addressability_registry_is 'Monitors the link longevity and availability of external storage links to guarantee long-term data accessibility for regulatory retention compliance';


-- Table: T520 - immutable_worm_cryptographic_proofs
-- Description: WORM storage with cryptographic proofs.
-- Business Case: Legal Hold. To make a record "Immutable" (Write-Once, Read-Many) for compliance, we use WORM storage (Write-Once, Read-Many). This table links the data identifier (T002) to the "Cryo-proof" stored in the WORM. It provides a mathematical proof that the data has not been altered since it was written.
-- KPIs: Immutable Integrity.
-- Feature Reference: T523
CREATE TABLE IF NOT EXISTS audit.immutable_worm_cryptographic_proofs (
    proof_id UUID DEFAULT uuid_generate_vorm_uuidv4() PRIMARY KEY,
    worm_storage_path TEXT NOT NULL, -- S3 Glacier or equivalent
    data_id UUID NOT NULL, -- Ref T002 (obfuscated ID)
    data_hash CHAR(64) NOT NULL, -- Hash of the raw data
    encryption_envelope_version VARCHAR(100), -- Version of the encryption
    worm_storage_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    storage_cost_daily_usd NUMERIC(10, -- Cost of WORM storage
    signed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    integrity_signature CHAR(64), -- Signature of the WORM manifest
    verification_status VARCHAR(20) DEFAULT 'VERIFIED', -- UNVERIFIED, CORRUPTED
    compliance_check_passed BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.immutable_worm_cryptographic_proofs_is 'Stores the "Cryo-proof" integrity checks for write-once, read-many data to verify that historical data has not been modified';

CREATE INDEX idx_worm_storage_data_id ON audit.immutable_worm_cryptographic_proofs(data_id);


-- Table: T521 - file_retention_extension_approval
-- Description: Approval for extending data retention.
-- Business Case: Legal Flexibility. Laws change. We might need to keep data longer than planned due to an investigation. This table manages the "Extension Approval" process. It documents *who* authorized the extension, *why* it is needed, and the estimated cost. It ensures that extending retention is compliant and authorized.
-- KPIs: Approval Cycle Time.
-- Feature Reference: T524
CREATE TABLE IF NOT EXISTS audit.file_retention_extension_approval (
    extension_id UUID DEFAULT uuid_generate_v4() NOT NULL,
    entity_id UUID NOT NULL, -- Merchant or Case ID
    requested_extension_date DATE,
    requested_duration_days INTEGER NOT NULL, -- e.g., +30 days
    justification TEXT NOT NULL,
    data_category VARCHAR(100) CHECK (data_category IN ('TRANSACTION_LOGS', 'AUDIT_TRAIL', 'USER_CONSENT_REQUEST', 'INVESTIGATION_EVIDENCE')
    legal_basis TEXT, -- Which law requires this?
    approval_status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    cost_impact NUMERIC(15,4), -- Cost to keep extra data
    approver_id UUID NOT NULL REFERENCES audit.auditor(auditor_id), -- The Compliance Officer
    approval_date DATE,
    rejection_reason TEXT,
    new_expiry_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.file_retention_extension_approval IS 'Manages requests to extend data retention periods by documenting legal basis, approval, cost, and new expiry dates';


-- Table: T522 - regulation_override_history
-- Description: History of regulatory rule overrides.
-- Business Case: Emergency Overrides. Sometimes we *must* process a transaction that violates standard policy (e.g., Sanctions Check pending). This table tracks these "Overrides". It provides an audit trail explaining why a rule was broken, allowing us to defend the decision to regulators with documented justification.
-- KPIs: Override Justification Accuracy.
-- Feature Reference: T526
CREATE TABLE IF NOT EXISTS audit.regulation_override_history (
    override_id UUID DEFAULT uuid_not_null_v4() PRIMARY KEY,
    regulation_code VARCHAR(100) NOT NULL, -- e.g., 'Sanction_Watchlist', 'VAT_RATE'
    override_description TEXT NOT NULL, -- Why are we ignoring a specific regulation for this tx?
    requested_by UUID NOT NULL REFERENCES audit.auditor(auditor_id, -- Who asked for the override?
    override_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    legal_authority VARCHAR(100), -- Who authorized the exception?
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
    risk_score NUMERIC(5,2), -- How risky is this override?
    expiry_date DATE, -- When does the exception expire?

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.regulation_override_history IS 'Tracks regulatory exceptions (exemptions) to provide auditable proof for deviations from standard operating procedures';

CREATE INDEX idx_override_status ON audit.regulation_override_history(status, expiry_date DESC);


-- Table: T523 - audit_remediation_history
-- Description: History of audit remediation actions.
-- Business Case: Fixing the Root Cause. If an audit finds a gap, we must remediate it. This table tracks the "Remediation Plan" and results. It logs what was broken, how we fixed it, and when. It provides evidence of the system's quality and adaptability.
-- KPIs: Remediation Time.
-- Feature Reference: T527
CREATE TABLE IF NOT EXISTS audit.audit_remediation_history (
    remediation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    issue_id UUID NOT NULL, -- Link to T011
    remediation_plan_id UUID NOT NULL, -- Unique ID for the plan
    remediation_action VARCHAR(500) NOT NULL, -- 'PATCH', 'WORKAROUND', 'CONFIG_CHANGE'
    assigned_team_id UUID NOT NULL,
    responsible_party_id UUID, -- e.g., 'AUDIT_COMMITTEE'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    target_resolution_date DATE,
    status VARCHAR(20) DEFAULT 'PLANNED', -- PLANNED, IN_PROGRESS, RESOLVED, FAILED
    action_owner UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    resolution_summary TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by
);
COMMENT ON TABLE audit.audit_remediation_history_is 'Tracks the lifecycle of remediation actions taken to fix identified audit gaps, ensuring issues are resolved within SLA';


-- Table: T524 - complaint_appeal_mechanics
-- Description: Managing the appeal process for complaints.
-- Business Case: Dispute Resolution. Merchants can appeal audit findings. This table manages the "Appeal" process (Review by Committee). It tracks the appeal, the review board's decision, and the final outcome (Upheld/Rejected).
-- KPIs: Appeal Success Rate.
-- Feature Reference: T528
CREATE TABLE IF NOT EXISTS audit.complaint_appeal_mechanics (
    appeal_id UUID DEFAULT uuid_generate_v4() primary key,
    complaint_id UUID REFERENCES audit.audit_complaint_system(complaint_id),
    appeal_reason TEXT NOT NULL, -- Why does the merchant disagree?
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, UNDER_REVIEW, INVESTIGATING, ADJUDICATED, CLOSED
    submitted_by UUID REFERENCES audit.auditor(auditor_id),
    reviewed_by UUID NOT NULL REFERENCES audit.auditor(auditor_id), -- Usually a Committee member
    appeal_submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    appeal_decision VARCHAR(500), -- UPHOLD, UPHOLDED
    appeal_decision_date DATE,
    decision_summary TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.complaint_appeal_mechanics_is 'Manages the workflow for merchant appeals against audit findings to ensure disputes are resolved fairly and transparently via a standardized review process';


-- Table: T525 - audit_transparency_reports
-- Description: Official public transparency reports.
-- Business Case: Public Accountability. Governments must report on "Platform Usage" (e.g., "How many accounts were audited?"). This table stores the metadata of these reports (Period, Users Requested vs Completed). It provides the raw data for the annual "Transparency Report" generated by the system.
-- KPIs: Publish Accuracy.
-- Feature Reference: T529
CREATE TABLE IF NOT EXISTS audit.audit_transparency_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_type VARCHAR(100) NOT NULL, -- 'SYSTEM_USAGE', 'SUSPENSION', 'AUDIT_COVERAGE'
    reporting_period_start DATE NOT NULL,
    reporting_period_end DATE NOT NULL,
    period_status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, PUBLISHED, ARCHIVED
    users_requested BIGINT, NOT NULL,
    users_compliant BIGINT NOT NULL,
    users_denied BIGINT DEFAULT 0, -- Why were they denied access?
    report_url TEXT, -- Link to S3
    published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    signed_officer_id UUID NOT NULL REFERENCES audit.auditor(auditor_id), -- Who signed off on the report?
    approved_by UUID NOT NULL REFERENCES audit.auditor(auditor_id), -- Who approved the data release?
    approved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_status VARCHAR(20) DEFAULT 'UNVERIFIED', -- UNVERIFIED, REJECTED
    public_hash CHAR(64), -- Hash of the report content

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZON DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by
);
COMMENT ON TABLE audit.audit_transparency_reports IS 'Stores metadata and results of public transparency reports to demonstrate accountability and platform usage metrics';


-- Table: T526 - stakeholder_feedback_surveys
-- Description: Collecting stakeholder feedback.
-- Business Case: Continuous Improvement. We need to know if the system meets the needs of Tax Authorities and Merchants. This table stores surveys sent to these stakeholders (Tax Authorities, Trade Unions). It measures "Satisfaction Scores" and identifies friction points in the audit process.
-- KPIs: CSAT Score (Client Satisfaction).
-- Feature Reference: T530
CREATE TABLE IF NOT EXISTS audit.stakeholder_feedback_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    survey_period_start DATE NOT NULL,
    survey_period_end DATE NOT NULL,
    target_stakeholder VARCHAR(255) NOT NULL, -- 'TAX_AUTHORITY', 'MERCHANT_ASSOCIATION', 'CENTRAL_BANK', 'UNION'
    survey_type VARCHAR(100) NOT NULL, -- 'SATISFACTION', 'COMPLIANCE', 'OPERATIONS'
    external_ref_id UUID, -- Link to T011 or T010
    invitation_sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    response_rate INTEGER CHECK (response_rate BETWEEN 0 AND 100),
    nps_score INTEGER CHECK (nps_score BETWEEN -100 AND 100),
    feedback_text TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.stakeholder_feedback_surveys_is 'Collects stakeholder feedback on the audit process to measure satisfaction and identify friction points in the system';


-- Table: T527 - market_manipulation_alerts
-- Description: Alerts for market manipulation events.
-- Spoofing Risk: Market manipulations (Pump & Dump) undermine confidence in the system. This table logs alerts when manipulative patterns are detected. It logs the specific "Market MIP" events (Price Spikes, Unusual Volumes) to ensure regulators are notified of potential market rigging in real-time.
-- KPIs: Alert Time (< 1 min).
-- Feature Reference: T531
CREATE TABLE IF NOT EXISTS audit.market_manipulation_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL, -- 'PRICE_SPIKE', 'VOLUME_ANOMALY', 'WASH_TRADE'
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    affected_merchant_uuid UUID NOT NULL,
    instrument_id VARCHAR(100) NOT NULL, -- 'PRICE_FEED', 'SENTIMENT_ANALYTICS', 'BLOCKCHAIN_ANALYTICS'
    evidence_snapshot_hash CHAR(64), -- Snapshot of the evidence for the alert
    model_confidence_num NUMERIC(3, 2), -- How sure is the model that this is a "Real" spike?
    is_false_positive BOOLEAN DEFAULT FALSE, -- Did we make a mistake?
    status VARCHAR(20) DEFAULT 'FLAGGED', -- FLAGGED, INVESTIGATING, DISMISSED
    action_taken VARCHAR(200), -- 'IGNORED', 'BLOCKED', 'INVESTIGATION', 'INVESTIGATED'
    taken_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH ZERO DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.market_manipulation_alerts_is 'Stores alerts on detected market manipulation patterns (Pump & Dump) to enable real-time enforcement of market integrity';


-- Table: T528 - market_integrity_monitoring
-- Description: Monitoring the integrity of market indices.
-- Business Case: Index Stability. We need to know if the market isn't being rigged. This table stores the historical values of market indices (S&P 500, NASDAQ, VIX). It monitors trends (Drift) in the market. Sudden drift indicates a problem with the platform's data.
-- KPIs: Drift Delta.
-- Feature Reference: T532
CREATE TABLE IF NOT EXISTS audit.market_integrity_monitoring (
    monitoring_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    market_indices_data JSONB NOT NULL, -- {"SP500": 12345.34, "VIX": 98040.12} -- 10.0
    calculated_integrity_score NUMERIC(5, 2), -- Score 1-100
    integrity_score_history JSONB, -- History of the score
    integrity_drift_score NUMERIC(5, 2), -- Score 1-100
    delta_score NUMERIC(5, -- Difference from yesterday
    drift_alert BOOLEAN DEFAULT FALSE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.market_integrity_monitoring_is 'Monitors the integrity of market indices to detect drift or manipulation of financial data provided by merchants';


-- Table: T529 - market_stability_index
-- Description: Calculated metric of market stability.
-- Business Case: Financial Stability. A stable market is vital. This table stores the "Stability Index" (Score: 0-100). It correlates specific platform usage (tx volume) with broader market movements to detect anomalies that might indicate rigging or system errors.
-- KPIs: Stability Index Value (Target > 90%).
-- Feature Reference: T533
CREATE TABLE IF NOT EXISTS audit.market_stability_index (
    index_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    calculation_id UUID NOT NULL, UNIQUE,
    calculation_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    market_condition VARCHAR(20) DEFAULT 'STABLE', -- 'STABLE', 'TRENDING', 'VOLATILE', 'CRASHED', 'RECOVERY'
    volatility_score NUMERIC(5,2), -- 1-100 (Inverse of Volatility)
    max_drawdown NUMERIC(10,2), -- Max drop in market indices
    score NUMERIC(5,2), -- The Stability Index value (0-100)
    standard_deviation NUMERIC(5,2), -- Std Deviation from Norm
    score_trend VARCHAR(20), -- 'STABLE', 'IMPROVING', 'DECLINING', 'INCREASING', 'OSCILLATING'
    alert_triggered BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.market_stability_index_is 'Calculates and stores the Market Stability Index to measure and trigger alerts if the system drifts away from standard baselines indicating potential rigging or system errors';


-- Table: T530 - supply_chain_event_stream
-- Description: Real-time ingestion of supply chain events.
-- Business Case: Supply Chain Visibility. We need to track goods from Origin to Destination. This table creates a real-time "Event Stream" (Goods in, Goods Out). It tracks the progress of shipments. It is an Event Sourcing for the supply chain audit, ensuring that we know exactly what is in transit.
-- KPIs: Ingestion Latency (< 5s).
-- Feature Reference: T534
CREATE TABLE IF NOT EXISTS audit.supply_chain_event_stream (
    event_id UUID DEFAULT uuid_generate_v4() CONCURRENTLY PARTITION KEY,
    shipper_id UUID NOT NULL, -- Reference to T321
    event_type VARCHAR(100) NOT NULL, -- 'SHIPMENT', 'DELIVERY', 'RECEIVED', 'DAMAGED', 'IN_TRANSIT'
    tracking_number VARCHAR(100), -- Bill of Lading
    carrier_name VARCHAR(255),
    vessel_name VARCHAR(255),
    port_of_loading VARCHAR(100),
    estimated_arrival_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    actual_arrival_date TIMESTAMP WITH TIME ZONE,
    carrier_reference VARCHAR(100),
    cargo_description TEXT,
    shipment_value_currency NUMERIC(19,4),
    shipment_status VARCHAR(20) DEFAULT 'IN_TRANSIT', -- IN_TRANSIT', 'IN_CUSTOMS_HOLD', 'CUSTOMS_CLEARED', 'CUSTOMS_DELAYED', 'DEPARTED', 'IN_PORT'
    delay_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.supply_chain_event_stream_is 'Ingests real-time shipping events to provide visibility into the movement of goods to track supply chain efficiency and transit times to prevent theft and loss';

CREATE INDEX idx_stream_shipper_event_type ON audit.supply_chain_event_stream(event_type, timestamp DESC);


-- Table: T531 - cross_channel_sales_analysis
-- Description: Analyzing sales between non-competing channels.
-- Business Case: Revenue Leakage Analysis. Sales via "Non-Comp" channels (e.g., Invoices, B2C) might be used to hide illicit funds. This table analyzes the volume of sales through these channels vs. Sales through the PARI system (T014) vs. Other Channels. It identifies discrepancies that might indicate that a merchant is underreporting income in PARI to avoid tax, bypassing the system.
-- KPIs: Channel Correlation.
-- Delta between PARI and External Channels.
-- Feature Reference: T535
CREATE TABLE IF NOT EXISTS audit.cross_channel_sales_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() EXCLUSIVE,
    analysis_date DATE NOT NULL DEFAULT CURRENT_DATE,
    channel_type VARCHAR(100) "AUDIT_SYSTEM", 'B2C_INVOICE', 'CASH'
    pari_transaction_volume BIGINT NOT NULL, -- Total volume via PARI in this channel
    external_channel_volume NUMERIC(19,4),
    variance_percentage NUMERIC(5,2), -- PARI_Vol vs External_Vol -> 100 = (PARI_Vol - Ext_Vol) / Ext_Vol - PARI_Vol).
    is_anomaly BOOLEAN DEFAULT FALSE, -- Did we see a drop in sales?
    anomaly_score NUMERIC(3, 2), -- How anomalous is the gap?
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by
);
COMMENT ON audit.cross_channel_sales_analysis_is 'Analyzes sales volumes via non-competing channels compared to PARI transactions to detect revenue leakage and bypass attempts';


-- Table: T532 - omni_channel_sales_matching
-- Description: Matching Omni-channel sales to PARI transactions.
-- Business Case: Revenue Assurance. We need to confirm a sale we saw in "Omni-Channel" (Physical Retail vs E-com). This table maps "Purchase Orders" to "Platform Payments". It allows us to prove that a "Digital Receipt" was legally a "Sale" under standard retail reporting standards, closing a loophole.
-- KPIs: Match Rate.
-- Feature Reference: T536
CREATE TABLE IF NOT EXISTS audit.omni_channel_sales_matching (
    match_id UUID DEFAULT uuid_generate_v4() EXCLUSIVE,
    source_system VARCHAR(100) NOT NULL, -- 'POS', 'ERP_SYSTEM', 'MANUAL_SALE_SYSTEM', 'MANUAL_ENTRY'
    transaction_uuid UUID, -- The PARI Tx ID
    external_order_id VARCHAR(255) NOT NULL, -- POS Invoice # or Order #
    match_status VARCHAR(20) DEFAULT 'UNMATCHED', -- NO_MATCH', 'PARTIAL_MATCH', 'MANUAL_REVIEW'
    matched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    match_confidence NUMERIC(3,2), -- How certain are we that this is a match? 90.99 or 50.0?
    discrepancy_amount NUMERIC(15,4), -- Difference in values
    discrepancy_text TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    created_by UUID,
    updated_by
);
COMMENT ON audit.omni_channel_sales_matching_is 'Matches external sales data from POS systems (POS) to PARI transactions to close loopholes in retail reporting standards';


-- Table: T533 - indirect_tax_leakage
-- Description: Estimating hidden tax leakage.
-- Business Case: Gap Analysis. The "Tax Gap" (T020) is often an estimate. This table stores the actual numbers from T020. It compares the "Estimated Gap" with the "Realized Gap" calculated at year-end. It helps fine-tune the inputs to our models, improving the accuracy of Gap Reduction strategies.
-- KPIs: Gap Reduction Rate.
-- Feature Reference: T537
CREATE TABLE IF NOT EXISTS audit.indirect_tax_leakage (
    gap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fiscal_year INTEGER NOT NULL,
    estimated_gap_amount NUMERIC(19, -- The official estimate
    actual_gap_amount NUMERIC(19, -- Calculated from raw data
    variance_percentage NUMERIC(5, -- The deviation
    currency_code CHAR(3) NOT NULL,
    resolution_status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, ANALYZING, RESOLVED
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.indirect_tax_leakage_is 'Stores the delta between estimated and actual tax leakage to improve the accuracy of tax gap estimations and fine-tuning of economic models';


-- Table: T538 - tax_haven_propensity_mapping
-- Description: Mapping high-risk jurisdictions.
-- Business Case: Risk Mapping. Some countries are used to store "Black Money" or "Tax Havens" (e.g., Cayman Islands). This table maps these risk jurisdictions to merchants. It creates a "Heatmap" of risk, signaling the auditor exactly where they need to look.
-- KPIs: Risk Heatmap Coverage.
-- Risk Level Match (Target: 100%).
-- Feature Reference: T538
CREATE TABLE IF NOT EXISTS audit.tax_haven_propensity_mapping (
    propensity_id UUID DEFAULT uuid_generate_v4() FAT_TABLE T451 "TAX_HAVEN_MAPS"),
    jurisdiction_code CHAR(2) NOT NULL, -- The "KY", "CH", "KY"
    risk_level audit.enum_risk_level DEFAULT 'HIGH', -- LOW, MEDIUM, HIGH, CRITICAL'
    risk_description TEXT,
    compliance_classification VARCHAR(100) -- 'TAX_AVOIDANCE', 'MERCHANT_KYC', 'COMPLIANCE'
    source_of_list VARCHAR(100), -- 'UN_SCANSIONED', 'WATCHLIST', 'AI_PREDICTOR', 'OFFICIAL_SOURCE'
    update_frequency VARCHAR(20), -- 'DAILY', 'WEEKLY'
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.tax_haven_propensity_mapping_is 'Maps jurisdictions with specific monetary or security risks to direct auditor attention to high-risk jurisdictions to optimize audit resource allocation';


-- Table: T539 - global_transfer_pricing
-- Description: Pricing global inter-bank transfers.
-- Business Case: Cross-Border Payments. A transfer from US to EU (SWIFT) has a specific price. This table stores the "Transfer Price" (FX Rate). It ensures that cross-border remittances (T344) are calculated using the correct FX Rate derived from T262. It prevents the "Transfer Pricing" manipulation and ensures we aren't losing money on currency conversion.
-- KPIs: FX Rate Deviation.
-- Feature Reference: T539
CREATE TABLE IF NOT EXISTS audit.global_transfer_pricing (
    pricing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_currency CHAR(3) NOT NULL, -- USD, EUR, JPY
    target_currency CHAR(3) NOT NULL, -- USD, EUR, JPY, BTC
    mid-market-rate NUMERIC(15,8) NOT NULL, -- Current mid-market rate
    bank_name VARCHAR(255),
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_published BOOLEAN DEFAULT TRUE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DEPRECATED, RETIRED
    confidence_level NUMERIC(3, -- How sure are we about the rate?
    timestamp_of_rate_change TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.global_transfer_pricing_is 'Stores current and historical inter-bank transfer pricing to ensure correct calculation of cross-border tax remittances';


-- Table: T540 - transfer_pricing_dispute_resolution
-- Description: Resolving transfer pricing disputes.
-- Bank Case: Exchange Rate Dispute Resolution. Disputes over "Transfer Pricing" are common. A merchant might claim a bank made a mistake. This table tracks the "Dispute ID", the bank's proposed rate vs. Our calculated rate. It manages the negotiation and final resolution, ensuring we don't overpay tax.
-- KPIs: Resolution Time.
-- Feature Reference: T540
CREATE TABLE IF NOT EXISTS audit.transfer_pricing_dispute_resolution (
    dispute_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    unique_dispute_ref VARCHAR(255) PREFERED IN audit.reports(report_id),
    dispute_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reporting_party VARCHAR(100) -- 'BANK_Audit', 'SWIFT', 'TARGET_BANK'
    disputed_rate NUMERIC(15,8) NOT NULL, -- The rate being questioned
    disputed_currency_code CHAR(3) NOT NULL,
    our_rate NUMERIC(15,8) NOT NULL, -- Our "Correct" Rate
    proposed_resolution_text TEXT, -- e.g., "Bank Error"
    accepted_resolution_rate NUMERIC(15,8), -- The agreed rate
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, IN_REVIEW, ACCEPTED, REJECTED
    resolved_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONZE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.transfer_pricing_dispute_resolution_is 'Resolves disputes over inter-bank transfer pricing to ensure that tax liability is calculated using correct exchange rates to prevent overpayment or underpayment';


-- Table: T541 - esg_audit_calendar
-- Description: Calendar of ESG audit tasks.
-- Business Case: Continuous ESG Compliance. ESG requires periodic audits. This table defines the schedule of ESG audits (ISO 14001, SOC2) for GRC). It stores "Check" items like "Review Carbon Footprints" or "Supply Chain Audit" in a calendar. It ensures we never miss a mandatory audit.
-- KPIs: Audit On-Time Delivery.
-- Feature Reference: T541
CREATE TABLE IF NOT EXISTS audit.esg_audit_calendar (
    calendar_id UUID DEFAULT uuid_generate_vature() PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL, -- 'SOC2_AUDIT', 'ESG_140_SOC2', 'ISO_27001', 'GLOBAL_WARMING', 'ANTI_CORRUPTION', 'DATA_PROTECTION'
    event_name VARCHAR(255) NOT NULL, -- "Carbon Footprint", "Supply Chain Audit"
    scheduled_date DATE NOT NULL,
    due_date DATE NOT NULL,
    recurring_period VARCHAR(50), -- 'MONTHLY', 'QUARTERLY', 'ANNUAL'
    responsible_party_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED, FAILED
    evidence_file_path TEXT, -- Link to T353 Evidence
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE audit.esg_audit_calendar IS 'Schedules periodic ESG audits (like SOC2) to ensure continuous compliance and compliance with environmental and social governance regulations without disrupting operations.';


-- Table: T542 - esg_audit_checklist
-- Description: The checklist for SOC2/SOC2 compliance.
-- Business Case: Control Governance. To pass SOC2, we need to pass a strict checklist. This table stores the "Control Checklist" (e.g., "Is Access Control 7.1", "Change Management"). It maps generic controls to specific SOC2 requirements (e.g., "Control 7.1") to specific implementations (e.g., "Access Log"). It provides a standard set of questions (e.g., "Who accessed what?").
-- KPIs: Checklist Completion.
-- Feature Reference: T542
CREATE TABLE IF NOT EXISTS audit.esg_audit_checklist (
    check_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    requirement_id VARCHAR(255) NOT NULL, -- 'ACC_CONTROL_7.1', 'CHANGE_MGMT', 'USER_ACTIVITY', 'DATA_STORAGE', 'ENCRYPTION', 'AUDIT_TRAIL'
    control_category VARCHAR(100) NOT NULL, -- 'ACCESS_CONTROL', 'CRYPTOGRAPHY', 'USER_ACTIVITY', 'DATA_STORAGE'
    description TEXT NOT NULL,
    control_type VARCHAR(20) NOT NULL, -- 'AUTOMATED', 'MANUAL', 'DISCRETION', 'MANUAL', 'SCRIPTED', 'REVIEWED'
    sensitivity VARCHAR(20) CHECK (sensitivity IN ('PUBLIC', 'INTERNAL', 'RESTRICT')
    is_required BOOLEAN DEFAULT TRUE,
    frequency VARCHAR(50) CHECK (frequency IN ('HOURLY', 'DAILY', 'WEEKLY')
    responsible_team_id UUID,
    evidence_required BOOLEAN DEFAULT FALSE, -- Is there a log?

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    passing_rate NUMERIC(5, -- % of passed checks
    last_audit_date DATE,
    next_audit_date DATE,

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.esg_audit_checklist IS 'Stores detailed checklists for SOC2/SOC2 compliance to ensure standardization and compliance with data governance regulations';

CREATE INDEX idx_esg_checklist_req_id ON audit.esg_audit_checklist(requirement_id);


-- Table: T543 - sustainability_linked_incentives
-- Description: Incentives for ESG goals (ESG).
-- Business Case: Target Alignment. Merchants often want to show they are "Green" by linking to global ESG goals (e.g., "Net Zero Emissions"). This table maps ESG Metrics (e.g., "Carbon Neutral", "Water Usage") to these specific high-level targets, proving that their "Green" claims are real.
-- KPIs: Target Alignment.
-- Feature Reference: T543
CREATE TABLE IF NOT EXISTS audit.sustainability_linked_incentives (
    incentive_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_name VARCHAR(100) NOT NULL, -- 'CARBON_OFFSET', 'NET_ZERO', 'BIO-DIVERSITY', 'GENDER_EQUALITY', 'WATER_CONSUMPTION'
    esg_metric VARCHAR(100) -- 'SCO2_SOC2_12.5', 'SOC2_SOC2_50', 'SOC2_SOC2_7.1'
    target_value NUMERIC(19,4) NOT NULL,
    target_value_unit VARCHAR(50) -- '$', 'kWh', 'Units', 'CO2_TONNESSES_CO2_SOC2_50'
    year_to_date DATE,
    calculated_value NUMERIC(19,4), -- The value we achieved
    achievement_status VARCHAR(20) DEFAULT 'NOT_MET', -- 'NOT_MET', 'PARTIALLY_MET', 'FULLY_MET', 'PARTIALLY_MET', 'EXCEEDED'
    performance_rating VARCHAR(20) CHECK (performance_rating IN ('UNKNOWN', 'HIGH', 'MEDIUM', 'LOW'),
    last_audit_date DATE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.sustainability_linked_incentives_is 'Maps high-level ESG targets to specific environmental metrics to validate merchant claims of sustainability and environmental responsibility to prevent greenwashing.';


-- Table: T544 - green_finance_products
-- Description: Financial products qualifying for ESG funding.
-- Bond. Business Case: Green Finance. "Green Finance" (Green Bonds) require capital allocation to sustainable projects. This table lists the Green Bonds (e.g., "Green Bond", "Sustainability Linkage"). It tracks the "Green Rating" of these assets, providing the data needed for ESG credit ratings (T471).
-- KPIs: Asset Coverage.
-- Feature Reference: T544
CREATE TABLE IF NOT EXISTS audit.green_finance_products (
    product_id UUID DEFAULT uuid_generate_vase_v4()   PROVISIONAL PARTITION KEY,
    instrument_name VARCHAR(5) -- 'GREEN_BOND', 'GREEN_LOAN', 'GREEN_LOAN', 'SUSTAINABILITY', 'CLIMATE_RISK'
    product_type VARCHAR(100) -- 'BOND', 'LOAN', 'EQUITY', 'LOAN', 'EQUITY'
    issuer_country CHAR(2) NOT NULL, -- 'US', 'DE', 'DE', 'FRANCE'
    is_active BOOLEAN DEFAULT TRUE,
    is_perpetual_inventory BOOLEAN DEFAULT FALSE,
    coupon_rate NUMERIC(5, -- Coupon Rate of the bond
    maturity_date DATE, -- Date bond becomes tradeable
    last_quarterly_rating NUMERIC(3, -- S&P, Mood
    coupon_yield_spread NUMERIC(5,2), -- Yield
    green_rating NUMERIC(5,2) -- Score from ESG rating
    esg_reference VARCHAR(255), -- ID of the rating agency

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    Green Finance-specific columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.green_finance_products IS 'Catalog of green financial products available for auditing to validate green financing claims and ratings';

CREATE INDEX idx_green_finance_instrument ON audit.green_finance_products(issuer_country, maturity_date);


-- Table: T545 - climate_risk_modeling
-- Description: Predicts climate risks to assets and portfolios.
-- Business Case: Climate Risk Assessment. Assets are vulnerable to Climate Risks (floods, droughts). This table stores "Climate Risk Scores" (T5454) for these assets. It predicts the probability of Climate Events that might impact asset value. It ensures that pension funds and insurers have enough capital to pay out claims when these climate disasters occur.
-- KPIs: Risk Prediction Accuracy (ROC AUC > 0.8).
-- Feature Reference: T545
CREATE TABLE IF NOT EXISTS audit.climate_risk_modeling (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(255) NOT NULL, -- 'CLIMATE_RISK_V2', 'PHYSICAL_MODEL', 'TENSORFLOW', 'GRAPH_NEURAL_NETS', 'STATISTICAL_ANALYTICS'
    asset_id UUID NOT NULL,
    model_version VARCHAR(100), -- 'v1.0', 'v2.0', 'QUANTUM_QC'
    climate_scenario_id UUID NOT NULL, -- Link to T542
    variable_importance NUMERIC(5,2), -- Factors: Temp, Rainfall, GDP Growth
    shock_absorption_elasticity NUMERIC(5,2), -- Economic sensitivity to shocks
    predicted_probability_score NUMERIC(3,2), -- Prob. of Climate Event
    model_performance_score NUMERIC(3,2), -- ROC AUC > 0.8
    training_data_date DATE NOT NULL, last_trained_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_production_ready BOOLEAN DEFAULT FALSE, -- Can be used in production reporting?
    model_explainability TEXT,
    notes TEXT,

    -- Audit Columns
    AI/ML columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    created_by UUID,
    updated_by
);
COMMENT ON audit.climate_risk_modeling IS 'Stores outputs of climate risk models that predict the impact of climate events on assets to enable proactive risk management for insurance and pension funds';

CREATE INDEX idx_climate_risk_model_asset_model ON audit.climate_risk_model(asset_id);


-- Table: T546 - esg_certification_tracker
-- Description: Tracking ESG certifications.
-- Database Artifact. We generate the certificate, but we need to track *ownership*. This table manages the lifecycle of these "ESG Certificates" (e.g., "ISO 14001"). It tracks who owns the certificate, when it expires, and when it needs to be renewed. It ensures that the certificate remains valid and the merchant remains compliant as "Green" and "Social".
-- KPIs: Cert Availability (100%).
-- Status: Valid/Active.
-- Feature Reference: T547
CREATE TABLE IF NOT EXISTS audit.esg_certification_tracker (
    cert_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    certificate_issuance VARCHAR(100) -- 'ISO_14001', 'SOC2_SOC2_50', 'SOC2_SOC2_7.1', 'GRIAN_SOC2_SOC2_7.1'
    issuer_name VARCHAR(255) NOT NULL,
    standard_id VARCHAR(20), -- 'ISO_14001_SOC2_50', 'SOC2_SOC2_7.1'
    validity_period_start DATE NOT NULL,
    validity_period_end DATE NOT NULL,
    expiration_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, EXPIRED, REVOKED
    merchant_id UUID NOT NULL REFERENCES audit.merchant_cache(merchant_id),
    verification_method VARCHAR(100), -- 'MANUAL', 'AUTOMATED', 'MANUAL_REVIEW', 'KEY_ID_CHECK', 'MANUAL', 'API_KEY_CHECK'
    verified_by UUID NOT NULL REFERENCES audit.auditor(auditor_id),
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revocation_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at T358 DEFAULT CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.esg_certification_tracker IS 'Manages the lifecycle of ESG certificates, their status and ownership to ensure they remain valid and compliant';


-- Table: T547 - carbon_offset_provider_registry
-- Database Artifact. Service Provider.
-- The "Green Finance" ecosystem. This table lists the providers (e.g., "VerraCarbon", "Climate Trace").
-- KPIs: Delivery Reliability (99.9%).
-- Storage Cost (Budget).
-- Feature Reference: T354
CREATE TABLE IF NOT EXISTS audit.carbon_offset_provider_registry (
    provider_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_name VARCHAR(255) NOT NULL UNIQUE NOT NULL, provider_name NOT NULL -- 'VerraCarbon', 'Climate Trace', 'CICERO', 'GOLD_WASTE', 'NATURAL_SOLUTIONS'
    region_code CHAR(2) NOT NULL,
    standard_compliance VARCHAR(20), -- 'ISO_14001', 'SOC2_SOC2_50', 'SOC2_SOC2_7.1'
    contact_email VARCHAR(255),
    contact_phone VARCHAR(50),
    api_endpoint_secure TEXT, -- HTTPS URL of provider for data verification
    is_active BOOLEAN DEFAULT TRUE,
    last_health_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_check_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.carbon_offset_provider_registry_is 'Maintains a registry of providers of carbon offset projects (e.g., VerraCarbon) to automate the management of carbon credits and track provider reliability';


-- Table: T548 - board_communication_strategy
-- Description: Strategic communication strategy for auditors.
-- Business Case: Unified Messaging. We need to talk to Board members. This table defines the "Communication Strategy" for audits. It specifies *Who* sees what. It determines the channel (Email, Slack, In-Person briefing) and tone (Formal vs Informal).
-- KPIs: Stakeholder Feedback.
-- Feature Reference: T549
CREATE TABLE IF NOT EXISTS audit.board_communication_strategy (
    strategy_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    strategy_name VARCHAR(255) NOT NULL, -- 'Q1', 'BOARD_REVIEW', 'FINANCE_MINUTES', 'STRATEGY_SESSION', 'POLICY_SESSION'
    target_audience VARCHAR(100) NOT NULL, -- 'BOARD_OF_DIRECTORS', 'INVESTORS', 'CFO', 'REGULATORS'
    primary_channel VARCHAR(100) DEFAULT 'EMAIL', -- 'EMAIL', 'SLACK', 'TEAMS', 'IN-PERSON', 'PERSONAL_MESSAGE', 'WEBHOOK', 'IN-PERSONAL'
    tone_style VARCHAR(20) DEFAULT 'FORMAL', 'INFORMAL', 'EMPATHIC'
    urgency VARCHAR(20) CHECK (urgency IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    contact_emails UUID[] NOT NULL, -- List of Board Members
    approved_by UUID NOT NULL REFERENCES audit.audit_committee_minutes(committee_id),
    last_reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.board_communication_strategy_is 'Defines the communication strategy and audience for audit results, ensuring stakeholders are informed through their preferred channels';


-- Table: T549 - esg_certification_tracker
-- Description: Managing validity of ESG certifications.
-- Database Artifact. Similar to T471 (Track) ownership).
-- Business Case: Lifecycle Management. We need to know if a certificate is revoked. This table tracks the "Lifecycle" of the ESG Certificates". It ensures that if a certificate is expired or the merchant is delisted, the system stops accepting transactions. It updates the status in T471 and T411.
-- KPIs: Data Integrity (100%).
-- Feature Reference: T47
CREATE TABLE IF NOT EXISTS audit.esg_certification_tracker (
    cert_id UUID DEFAULT uuid_generate_v4() UNIQUE,
    certificate_id UUID NOT NULL REFERENCES audit.esg_certification_tracker(cert_id),
    issuer_id UUID NOT NULL, -- The actual entity (Merchant ID
    serial_number VARCHAR(255) NOT NULL, -- ID on the certificate
    issuer_name VARCHAR(255) NOT NULL,
    certificate_type VARCHAR(100) NOT NULL, -- 'ISO_14001', 'SOC2_SOC2_50', 'SOC2_SOC2_7.1', 'ESG_SOC2_SOC2_7.1', 'FUNDAMENTAL', 'CERTIFICATE', 'CERTIFICATE', 'REVOKED', 'EXPIRED', 'REVOKED'
    status VARCHAR(20) DEFAULT 'ACTIVE', -- 'ACTIVE', 'SUSPENDED', 'EXPIRED', 'EXPIRED', 'REVOKED', 'DECOMMISSIONED', 'INVALID', 'REVOKED'
    expiry_date DATE,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.esg_certification_tracker_is 'Manages the lifecycle of ESG certificates (SOC2_SOC2_7.1 certifications from issuance to expiration to revocation to ensure ongoing compliance and greenwashing prevention.';

CREATE INDEX idx_esg_tracker_cert_status ON audit.esg_certification_tracker(status);


-- Table: T550 - esg_audit_calendar
-- Description: Master schedule for all ESG-related audits.
-- Business Case: Integrated Governance. We need to coordinate internal ESG Audits. This table serves as the "Master Calendar" for all ESG activities. It ensures that audits don't clash and that we don't miss a critical date. It links to the "Compliance Dashboard" (T482) and the "Calendar" (T353).
-- KPIs: Audit On-Time Delivery (100%).
-- Feature Reference: T541, T353
CREATE TABLE IF NOT EXISTS audit.esg_audit_calendar (
    calendar_id UUID DEFAULT uuid_generate_v4() NOT NULL UNIQUE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    audit_scope TEXT, -- What does this audit cover? 'SOC2_SOC2_50', 'SOC2_SOC2_7.1', 'SOC2_SOC2_50'
    responsible_party_id UUID NOT NULL, -- The Team or Person responsible
    report_type VARCHAR(100) NOT NULL, -- 'SOC2_SOC2_50', 'SOC2_SOC2_50', 'SOC2_SOC2_7.1', 'SOC2_SOC2_7.1', 'ESG_SOC2_40', 'SOC2_SOC2_40'
    is_high_priority BOOLEAN DEFAULT FALSE, -- Is this a "Must-Do"?
    audit_due_date DATE NOT NULL,
    next_audit_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON audit.esg_audit_calendar_is 'Schedules all ESG audits via a unified calendar to ensure no critical dates are missed and audits are performed on schedule';

CREATE INDEX idx_esg_calendar_dates ON audit.esg_audit_calendar(period_start, period_end);


-- End of Script Part 8 (T451-T550)
-- Completes the 550-table database schema definition for PARI M06.
