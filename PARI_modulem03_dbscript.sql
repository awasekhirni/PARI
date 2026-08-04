-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script
-- =============================================================================================
-- Author: Senior PostgreSQL DBA (AI Generation)
-- Description: Comprehensive schema for Fraud Detection, AI/ML Model Management, Dispute
--              Resolution, and Cryptographic Evidence Handling.
-- Version: 1.0.0
-- ============================================================================================================================================================

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 1. SCHEMA CREATION
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS fraud;
COMMENT ON SCHEMA fraud IS 'Core schema for fraud detection, scoring, and intelligence gathering.';

CREATE SCHEMA IF NOT EXISTS contract;
COMMENT ON SCHEMA contract IS 'Schema for managing cryptographic JSON-LD contracts and digital receipts.';

CREATE SCHEMA IF NOT EXISTS dispute;
COMMENT ON SCHEMA dispute IS 'Schema for managing dispute cases, evidence, and resolution workflows.';

CREATE SCHEMA IF NOT EXISTS refund;
COMMENT ON SCHEMA refund IS 'Schema for handling blinded refunds and cryptographic return logic.';

CREATE SCHEMA IF NOT EXISTS ml;
COMMENT ON SCHEMA ml IS 'Schema for Machine Learning models, training data, and feature stores.';

CREATE SCHEMA IF NOT EXISTS audit;
COMMENT ON SCHEMA audit IS 'Schema for immutable audit trails and compliance logging.';

CREATE SCHEMA IF NOT EXISTS common;
COMMENT ON SCHEMA common IS 'Common shared types and enums.';

CREATE SCHEMA IF NOT EXISTS system;
COMMENT ON SCHEMA system IS 'System configuration, feature flags, and health monitoring.';

CREATE SCHEMA IF NOT EXISTS ops;
COMMENT ON SCHEMA ops IS 'Operational data, maintenance windows, and performance metrics.';

CREATE SCHEMA IF NOT EXISTS sec;
COMMENT ON SCHEMA sec IS 'Security artifacts, keys, and access control logs.';

CREATE SCHEMA IF NOT EXISTS legal;
COMMENT ON SCHEMA legal IS 'Legal holds, reviews, and regulatory correspondence.';

CREATE SCHEMA IF NOT EXISTS compliance;
COMMENT ON SCHEMA compliance IS 'Regulatory compliance, AML, and sanctions screening.';

CREATE SCHEMA IF NOT EXISTS storage;
COMMENT ON SCHEMA storage IS 'Manifests and archives for cold storage.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 2. EXTENSIONS
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides functions to generate universally unique identifiers (UUIDs).';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Cryptographic functions for hashing, encryption, and signing (e.g., SHA-3, HMAC).';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to work on standard data types, improving composite index performance.';

CREATE EXTENSION IF NOT EXISTS "pg_trgm";
COMMENT ON EXTENSION "pg_trgm" IS 'Provides trigraph matching for fast fuzzy text search and similarity.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 3. LIST OF DATABASE OBJECTS TO BE IMPLEMENTED (First 50)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- Based on the provided matrix, the following object types are identified:
-- 1. TABLES (T001 - T050)
-- 2. ENUMS (E001 - E012)
-- 3. INDEXES (Implied for performance)
-- 4. TRIGGERS (For automated timestamp management)

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 4. ENUMS
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Enum: E001 - status_type
-- Description: Common statuses for cases, refunds, and workflows.
-- Business Case: Standardizes state management across the dispute and refund lifecycles.
-- Feature Reference: E001
------------------------------------------------------------------------------------------------
CREATE TYPE common.status_type AS ENUM (
    'open', 'pending', 'approved', 'rejected', 'closed', 'under_review', 'resolved', 'authorized', 'executed'
);
COMMENT ON TYPE common.status_type IS 'Standardized status enumeration for cross-module consistency.';

------------------------------------------------------------------------------------------------
-- Enum: E002 - entity_type
-- Description: Types of entities in the system.
-- Business Case: Enables role-based access control and risk profiling logic.
-- Feature Reference: E002
------------------------------------------------------------------------------------------------
CREATE TYPE common.entity_type AS ENUM (
    'customer', 'merchant', 'exchange', 'system', 'auditor', 'admin'
);
COMMENT ON TYPE common.entity_type IS 'Classification of actors within the PARI ecosystem.';

------------------------------------------------------------------------------------------------
-- Enum: E003 - fraud_reason
-- Description: Standardized reasons for disputes.
-- Business Case: Facilitates analytics and automation of dispute routing based on cause.
-- Feature Reference: E003
------------------------------------------------------------------------------------------------
CREATE TYPE common.fraud_reason AS ENUM (
    'fraud', 'item_not_received', 'unauthorized', 'duplicate', 'product_not_as_described', 'credit_not_processed', 'technical_error'
);
COMMENT ON TYPE common.fraud_reason IS 'Taxonomy of dispute triggers.';

------------------------------------------------------------------------------------------------
-- Enum: E004 - signature_algo
-- Description: Algorithms used for signing.
-- Business Case: Ensures cryptographic flexibility and future-proofing of contracts.
-- Feature Reference: E004
------------------------------------------------------------------------------------------------
CREATE TYPE contract.signature_algo AS ENUM (
    'ecdsa_secp256k1', 'rsa_4096', 'ed25519', 'sha3_256'
);
COMMENT ON TYPE contract.signature_algo IS 'Supported cryptographic signature algorithms.';

------------------------------------------------------------------------------------------------
-- Enum: E005 - incident_severity
-- Description: Severity levels for incidents.
-- Business Case: Prioritizes response efforts for security and fraud incidents.
-- Feature Reference: E005
------------------------------------------------------------------------------------------------
CREATE TYPE ops.incident_severity AS ENUM (
    'low', 'medium', 'high', 'critical'
);
COMMENT ON TYPE ops.incident_severity IS 'Severity classification for operational incidents.';

------------------------------------------------------------------------------------------------
-- Enum: E006 - job_status
-- Description: Status of background jobs.
-- Business Case: Tracks the lifecycle of async tasks like model training or batch processing.
-- Feature Reference: E006
------------------------------------------------------------------------------------------------
CREATE TYPE ops.job_status AS ENUM (
    'pending', 'running', 'completed', 'failed'
);
COMMENT ON TYPE ops.job_status IS 'State tracking for asynchronous background workers.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 5. HELPER FUNCTIONS (TRIGGERS)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION common.manage_timestamps()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.updated_by = current_setting('app.current_user_id', true)::UUID;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;

COMMENT ON FUNCTION common.manage_timestamps() IS 'Automatically updates updated_at and updated_by columns on modification.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 6. DDL STATEMENTS (TABLES T001 - T050)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: 001
-- Table: T001 - transaction_scores
-- Schema: fraud
-- Description: Stores real-time fraud scores for every transaction processed by the payment rail.
-- Business Case: The transaction score table is the central output of the fraud detection engine.
-- By capturing composite, LSTM, and rule-based scores, it provides a granular view of risk for every
-- payment event. This granularity is essential for post-transaction analysis, model drift detection,
-- and providing evidence in the event of a dispute. It enables the business to tune risk thresholds
-- dynamically and ensures that no decision is made without a retrievable, auditable record. The
-- composite score (0-100) acts as the primary decision gate for blocking or allowing transactions.
-- KPIs: Model Inference Latency (P99 < 50ms), Score Distribution Balance.
-- Feature Reference: F001, F014
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    composite_score INTEGER NOT NULL CHECK (composite_score BETWEEN 0 AND 100),
    lstm_score NUMERIC(5,2) CHECK (lstm_score BETWEEN 0 AND 1),
    rule_score INTEGER CHECK (rule_score BETWEEN 0 AND 100),

    -- Enhanced Decision Context
    final_decision VARCHAR(20) NOT NULL CHECK (final_decision IN ('APPROVE', 'REJECT', 'MANUAL_REVIEW', 'CHALLENGE')),
    reason_codes TEXT[],

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE INDEX idx_tx_scores_hash ON fraud.transaction_scores(transaction_hash);
CREATE INDEX idx_tx_scores_composite ON fraud.transaction_scores(composite_score);
COMMENT ON TABLE fraud.transaction_scores IS 'Real-time fraud scoring output; the single source of truth for payment risk decisions.';

------------------------------------------------------------------------------------------------
-- Serial No: 002
-- Table: T002 - lstm_model_versions
-- Schema: fraud
-- Description: Metadata for deployed LSTM models, tracking versioning and performance metrics.
-- Business Case: Managing the lifecycle of AI models is critical for maintaining detection accuracy.
-- This table serves as the registry for all model artifacts, ensuring that only validated, approved
-- models are active in production. By tracking accuracy metrics and active timeframes, it allows data
-- scientists to perform A/B testing and rollbacks efficiently if a new model exhibits higher drift or
-- bias. It ensures regulatory compliance by maintaining an immutable history of which model made which
-- decision, a key requirement for "explainable AI" in finance.
-- KPIs: Model Deployment Frequency, Model Accuracy Metric, Rollback Time.
-- Feature Reference: F017, F089
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.lstm_model_versions (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(50) NOT NULL UNIQUE,
    path TEXT NOT NULL, -- S3/Storage path for weights
    trained_at TIMESTAMP WITH TIME ZONE NOT NULL,
    active_from TIMESTAMP WITH TIME ZONE,
    active_to TIMESTAMP WITH TIME ZONE,
    accuracy_metric NUMERIC(5,4),

    -- Governance
    is_active BOOLEAN DEFAULT FALSE,
    approved_by UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT model_dates_check CHECK (active_from < active_to)
);

COMMENT ON TABLE fraud.lstm_model_versions IS 'Registry for LSTM model artifacts and their production lifecycle.';

------------------------------------------------------------------------------------------------
-- Serial No: 003
-- Table: T003 - anomaly_features
-- Schema: fraud
-- Description: Feature vectors used for ML inference, stored for short-term learning and analysis.
-- Business Case: Storing raw feature vectors immediately preceding a transaction allows for rapid
-- model retraining and forensic analysis. When a fraud case is confirmed, having the exact feature
-- state (time of day, location velocity, amount) enables the "Active Learning" loop (F061) to
-- retrain the model with positive examples. Although retention is short (7 days) to save costs,
-- this buffer is crucial for detecting complex, multi-transaction fraud patterns that only become
-- apparent after the sequence completes.
-- KPIs: Feature Storage Retrieval Latency, Retention Policy Adherence.
-- Feature Reference: F016, F039
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.anomaly_features (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    feature_vector JSONB NOT NULL,
    is_anomaly BOOLEAN DEFAULT FALSE,

    -- Lifecycle
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_anomaly_features_tx_hash ON fraud.anomaly_features(transaction_hash);
CREATE INDEX idx_anomaly_features_expires ON fraud.anomaly_features(expires_at);
COMMENT ON TABLE fraud.anomaly_features IS 'Ephemeral storage for high-dimensional feature vectors used in real-time inference.';

------------------------------------------------------------------------------------------------
-- Serial No: 004
-- Table: T004 - velocity_rules
-- Schema: fraud
-- Description: Configuration for velocity-based fraud checks (e.g., max amount per hour).
-- Business Case: Velocity checks are the first line of defense against obvious brute-force or
-- "smashing" attacks. This configuration table allows Fraud Ops to dynamically adjust limits
-- without redeploying code. For instance, during a holiday sale, limits can be raised to prevent
-- false positives, or lowered if a specific botnet is detected. The flexibility to target specific
-- entities (users or merchants) ensures that high-value merchants aren't throttled while new users
-- are strictly monitored.
-- KPIs: Rule Execution Time (< 5ms), Configuration Update Latency.
-- Feature Reference: F004
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.velocity_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type common.entity_type NOT NULL,
    limit_amount NUMERIC(15,2) NOT NULL,
    limit_count INTEGER NOT NULL,
    window_sec INTEGER NOT NULL,

    -- Targeting
    entity_id_filter UUID, -- Optional: specific merchant/user

    -- State
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

COMMENT ON TABLE fraud.velocity_rules IS 'Dynamic configuration for real-time velocity limiting rules.';

------------------------------------------------------------------------------------------------
-- Serial No: 005
-- Table: T005 - device_fingerprints
-- Schema: fraud
-- Description: Anonymous hashes of device attributes for persistent device identification.
-- Business Case: Device fingerprinting allows the system to detect account takeovers (ATO) and
-- device-based fraud rings without storing Personally Identifiable Information (PII). By hashing
-- device attributes (User-Agent, Screen Res, IP block), the system can link multiple transactions
-- to a single physical device. This helps identify "Man-in-the-Browser" attacks or fraudsters
-- switching accounts on the same machine to bypass simple velocity checks.
-- KPIs: Fingerprint Collision Rate, Device Match Accuracy.
-- Feature Reference: F005
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_fingerprints (
    fingerprint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_hash VARCHAR(64) NOT NULL UNIQUE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_fingerprint_hash ON fraud.device_fingerprints(device_hash);
COMMENT ON TABLE fraud.device_fingerprints IS 'PII-free storage of device identifiers for persistent risk tracking.';

------------------------------------------------------------------------------------------------
-- Serial No: 006
-- Table: T006 - geolocation_events
-- Schema: fraud
-- Description: Logs location data for velocity checks and impossible travel detection.
-- Business Case: Geolocation velocity is a powerful heuristic for detecting identity theft. If a
-- transaction occurs in London and 20 minutes later another occurs in Tokyo, it is physically
-- impossible. This table stores the precise coordinates and accuracy of every transaction location.
-- It also supports regulatory requirements for cross-border transaction reporting and helps build
-- "heatmaps" of fraud origins for strategic analysis.
-- KPIs: Location Accuracy, False Positive Rate on Travel Checks.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.geolocation_events (
    geo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    lat NUMERIC(9,6) NOT NULL CHECK (lat BETWEEN -90 AND 90),
    long NUMERIC(9,6) NOT NULL CHECK (long BETWEEN -180 AND 180),
    accuracy_m NUMERIC(10,2),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_geo_events_timestamp ON fraud.geolocation_events(timestamp);
COMMENT ON TABLE fraud.geolocation_events IS 'Geospatial data points for velocity and impossible travel heuristics.';

------------------------------------------------------------------------------------------------
-- Serial No: 007
-- Table: T007 - jsonld_contracts
-- Schema: contract
-- Description: Stores the canonical JSON-LD digital receipts/contracts for all transactions.
-- Business Case: The JSON-LD contract is the "source of truth" for dispute resolution. Unlike
-- traditional databases where logs can be altered, this table stores the cryptographic hash of the
-- agreement between Payer and Merchant. If a dispute arises, this immutable record mathematically
-- proves that the merchant delivered the hash and the payer accepted the coin. This eliminates
-- "friendly fraud" (false claims of non-receipt) and automates the resolution process, cutting
-- resolution time from weeks to seconds.
-- KPIs: Contract Generation Time (< 20ms), Immutable Storage Integrity.
-- Feature Reference: F007, F011
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.jsonld_contracts (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL UNIQUE,
    jsonld_document JSONB NOT NULL,
    sha3_hash CHAR(64) NOT NULL, -- Keccak-256
    contract_version VARCHAR(20) DEFAULT '1.0',

    -- State
    is_revoked BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

CREATE INDEX idx_contract_sha3 ON contract.jsonld_contracts(sha3_hash);
COMMENT ON TABLE contract.jsonld_contracts IS 'Immutable ledger of JSON-LD digital receipts; the core of the dispute resolution system.';

------------------------------------------------------------------------------------------------
-- Serial No: 008
-- Table: T008 - contract_signatures
-- Schema: contract
-- Description: Stores cryptographic signatures linked to contracts.
-- Business Case: A contract is only valid if signed. This table stores the cryptographic proof
-- of signing for all parties: the Merchant (receipt of funds) and the Exchange (settlement).
-- By separating signatures from the document, we support multi-party contracts and asynchronous
-- signing workflows. The signature value combined with the document hash creates a legally binding,
-- non-repudiable record that holds up in court and automated arbitration.
-- KPIs: Signature Verification Time, Non-repudiation Success Rate.
-- Feature Reference: F008
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.contract_signatures (
    sig_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    signer_role VARCHAR(50) NOT NULL CHECK (signer_role IN ('merchant', 'exchange', 'payer', 'oracle')),
    signature_value BYTEA NOT NULL,
    algo contract.signature_algo NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_contract_sigs_contract ON contract.contract_signatures(contract_id);
COMMENT ON TABLE contract.signatures IS 'Cryptographic evidence of contract ratification by relevant parties.';

------------------------------------------------------------------------------------------------
-- Serial No: 009
-- Table: T009 - cases
-- Schema: dispute
-- Description: Master table for all dispute/fraud cases.
-- Business Case: This is the central hub for the dispute lifecycle. It tracks the status of every
-- customer claim from "Open" to "Closed". By linking directly to the transaction and evidence tables,
-- it provides a 360-degree view of the conflict. This table drives SLA monitoring and ensures that
-- no dispute falls through the cracks. It aggregates financial impact data to support the business
--case showing the ROI of the fraud prevention system.
-- KPIs: Dispute Resolution Time (< 5s automated), SLA Adherence Rate.
-- Feature Reference: F010, F045
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.cases (
    case_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    status common.status_type NOT NULL DEFAULT 'open',
    reason_code common.fraud_reason NOT NULL,
    amount NUMERIC(15,2) NOT NULL,

    -- Resolution
    assigned_to UUID,
    resolution_method VARCHAR(50), -- 'automated', 'manual', 'arbitration'
    resolution_summary TEXT,

    -- Escalation
    escalated_at TIMESTAMP WITH TIME ZONE,
    escalation_level INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE INDEX idx_dispute_cases_status ON dispute.cases(status);
CREATE INDEX idx_dispute_cases_tx ON dispute.cases(transaction_hash);
COMMENT ON TABLE dispute.cases IS 'Operational record of dispute lifecycle and ownership.';

------------------------------------------------------------------------------------------------
-- Serial No: 010
-- Table: T010 - case_evidence
-- Schema: dispute
-- Description: Stores files and documents attached to cases.
-- Business Case: Evidence management is critical for manual review and arbitration. This table
-- acts as an index for the object store, tracking who uploaded what and when. By hashing every
-- file, it ensures the chain of custody is maintained—evidence cannot be tampered with once
-- attached. This supports the "Blinded Refund" workflow by providing the Merchant a secure way to
--upload proof of delivery without the user seeing the Merchant's internal PII.
-- KPIs: Evidence Upload Success Rate, Storage Integrity Check.
-- Feature Reference: F022, F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.case_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    file_uri TEXT NOT NULL,
    file_hash CHAR(64) NOT NULL,
    file_name VARCHAR(255),
    mime_type VARCHAR(100),
    file_size BIGINT,
    uploaded_by VARCHAR(100), -- Anonymized or External ID

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_case_evidence_case ON dispute.case_evidence(case_id);
COMMENT ON TABLE dispute.case_evidence IS 'Secure index of files and documents supporting dispute investigations.';

------------------------------------------------------------------------------------------------
-- Serial No: 011
-- Table: T011 - blinded_refunds
-- Schema: refund
-- Description: Tracks requests for refunds to blinded coins.
-- Business Case: The "Blinded Refund" is a privacy-preserving innovation. Traditionally, refunds
--require the merchant to know the customer's bank account. In PARI, the merchant pushes funds to
--a blinded hash. This table tracks the state of that transaction. It ensures that the Exchange
--validates the merchant's signature against the blinded coin before crediting the wallet. This
--prevents merchants from accidentally or maliciously identifying the payer while guaranteeing the
--payer gets their money back.
-- KPIs: Refund Success Rate, Refund Latency.
-- Feature Reference: F012, F072
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refund.blinded_refunds (
    refund_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_coin_hash VARCHAR(64) NOT NULL,
    blinded_refund_coin VARCHAR(64) NOT NULL,
    merchant_id UUID NOT NULL,
    status common.status_type NOT NULL DEFAULT 'pending',
    amount NUMERIC(15,2) NOT NULL,

    -- Validation
    signature_verified_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE INDEX idx_blinded_refunds_coin ON refund.blinded_refunds(original_coin_hash);
COMMENT ON TABLE refund.blinded_refunds IS 'Privacy-preserving refund ledger linking merchant payouts to anonymous coin hashes.';

------------------------------------------------------------------------------------------------
-- Serial No: 012
-- Table: T012 - refund_signatures
-- Schema: refund
-- Description: Stores merchant signatures authorizing refunds.
-- Business Case: Security is paramount when moving money. This table stores the cryptographic
--authorization from the merchant to refund a specific blinded coin. It acts as a non-repudiable
--receipt of the merchant's intent to refund. If the merchant later claims they didn't authorize
--the refund, this digital signature serves as the proof to the contrary.
-- KPIs: Signature Verification Speed.
-- Feature Reference: F013
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refund.refund_signatures (
    sig_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    signature_value BYTEA NOT NULL,
    merchant_key_id VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE refund.refund_signatures IS 'Cryptographic authorization proofs for refund transactions.';

------------------------------------------------------------------------------------------------
-- Serial No: 013
-- Table: T013 - risk_profiles
-- Schema: fraud
-- Description: Aggregated risk scores for entities (Users/Merchants).
-- Business Case: Individual transaction scores are noisy; aggregated profiles are signal. This
--table rolls up risk scores over 30 days to assign entities to tiers (Low, Medium, High). This
--allows for progressive friction—low-risk users get fast lanes, high-risk users get step-up
--authentication. It also helps in identifying "slow burn" fraud where an account builds trust
--before cashing out.
-- KPIs: Risk Tier Update Frequency, Accuracy of Risk Stratification.
-- Feature Reference: F009, F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.risk_profiles (
    entity_id UUID NOT NULL,
    entity_type common.entity_type NOT NULL,
    risk_tier VARCHAR(20) NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
    score_30day_avg NUMERIC(5,2),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_risk_profiles PRIMARY KEY (entity_id, entity_type)
);

CREATE INDEX idx_risk_profiles_tier ON fraud.risk_profiles(risk_tier);
COMMENT ON TABLE fraud.risk_profiles IS 'Time-aggregated risk assessments enabling dynamic friction and policy enforcement.';

------------------------------------------------------------------------------------------------
-- Serial No: 014
-- Table: T014 - blacklist_entries
-- Schema: fraud
-- Description: Dynamic blacklist for coins, devices, or IPs.
-- Business Case: When a fraudster is identified, they must be blocked instantly across the entire
--ecosystem. This table provides a centralized, low-latency blocklist accessible by the interception
--layer (F001). It supports various types of blocks (IP, Device Hash, Coin Hash) and includes
--expiry times to allow for temporary blocks during investigations.
-- KPIs: Blocklist Propagation Latency, False Positive Block Rate.
-- Feature Reference: F020
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.blacklist_entries (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(50) NOT NULL CHECK (type IN ('coin_hash', 'device_hash', 'ip_address', 'email_hash')),
    value VARCHAR(255) NOT NULL,
    reason TEXT,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT blacklist_unique_value UNIQUE (type, value)
);

CREATE INDEX idx_blacklist_type ON fraud.blacklist_entries(type, value);
COMMENT ON TABLE fraud.blacklist_entries IS 'Real-time deny-list for known malicious actors or compromised assets.';

------------------------------------------------------------------------------------------------
-- Serial No: 015
-- Table: T015 - fraud_audit_log
-- Schema: audit
-- Description: Immutable audit trail for all fraud module actions.
-- Business Case: In a financial environment, auditability is non-negotiable. This table records
--every action taken by the fraud system—whether automated (AI blocking) or manual (Analyst
--overriding a block). The "Immutable" nature (enforced via triggers or WORM storage) ensures that
--even database administrators cannot alter the history of decisions without detection, satisfying
--strict regulatory requirements (SOX, PCI-DSS).
-- KPIs: Audit Log Completeness, Log Query Performance.
-- Feature Reference: F034, F178
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.fraud_audit_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    actor_id UUID,
    action_type VARCHAR(100) NOT NULL,
    target_id UUID,
    target_type VARCHAR(50),
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_target ON audit.fraud_audit_log(target_id, timestamp);
COMMENT ON TABLE audit.fraud_audit_log IS 'Immutable, verifiable record of all system and human actions within the fraud module.';

------------------------------------------------------------------------------------------------
-- Serial No: 016
-- Table: T016 - training_data
-- Schema: ml
-- Description: Anonymized dataset for model training.
-- Business Case: To improve the AI, we need data. However, privacy (GDPR) prevents using raw user data.
--This table stores the "Feature Vectors" from T003 after they have been subjected to Differential
--Privacy (noise injection). It serves as the sanitized dataset for retraining the LSTM models,
--ensuring that models evolve without ever compromising the identity of the users who generated the
--data.
-- KPIs: Data Anonymization Verdict, Training Data Size.
-- Feature Reference: F061, F095
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.training_data (
    data_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    features JSONB NOT NULL,
    label BOOLEAN NOT NULL, -- true = fraud, false = legit
    model_id UUID,
    ingestion_date DATE NOT NULL,
    epsilon_value NUMERIC(5,2) -- Differential privacy budget
);

CREATE INDEX idx_training_data_label ON ml.training_data(label);
COMMENT ON TABLE ml.training_data IS 'Privacy-preserving dataset used for active learning and model retraining.';

------------------------------------------------------------------------------------------------
-- Serial No: 017
-- Table: T017 - sar_reports
-- Schema: fraud
-- Description: Suspicious Activity Reports for regulators.
-- Business Case: Financial institutions are legally required to file SARs for suspicious activity.
--This table tracks the generation and status of these reports. By automating the population of this
--table based on the Fraud Scores (T001), PARI ensures compliance with AML laws without requiring
--manual review of every transaction. It integrates with the Regulators' schema (M05).
-- KPIs: SAR Filing Accuracy, Reporting Latency.
-- Feature Reference: F019
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.sar_reports (
    sar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID REFERENCES dispute.cases(case_id),
    report_format VARCHAR(10) DEFAULT 'JSON',
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, SUBMITTED, ACCEPTED
    submission_date DATE,
    regulatory_body VARCHAR(100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

COMMENT ON TABLE fraud.sar_reports IS 'Registry of Suspicious Activity Reports filed with regulatory bodies.';

------------------------------------------------------------------------------------------------
-- Serial No: 018
-- Table: T018 - case_notes
-- Schema: dispute
-- Description: Internal notes on cases.
-- Business Case: Dispute resolution often requires collaboration between teams. This table stores
--the internal narrative of the investigation—why a case was escalated, what manual checks were
--performed, etc. Access is restricted to internal staff, ensuring that sensitive investigative
--techniques are not exposed to the external parties involved in the dispute.
-- KPIs: Note Entry Latency.
-- Feature Reference: F024
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.case_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    author_id UUID NOT NULL,
    note_text TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.case_notes IS 'Collaborative narrative log for dispute investigations.';

------------------------------------------------------------------------------------------------
-- Serial No: 019
-- Table: T019 - fraud_typelogy
-- Schema: fraud
-- Description: Reference table for fraud categories.
-- Business Case: To understand *what* kind of fraud is happening, we need a taxonomy. This reference
--table classifies fraud (e.g., Account Takeover, Friendly Fraud, Phishing). It powers the
--dashboard analytics (F067) and helps the ML team identify which models are performing poorly
--against specific attack vectors.
-- KPIs: Classification Accuracy.
-- Feature Reference: F067
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_typelogy (
    type_id SERIAL PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    subcategory VARCHAR(50),
    description TEXT
);

COMMENT ON TABLE fraud.fraud_typelogy IS 'Standardized taxonomy for categorizing fraud typologies.';

------------------------------------------------------------------------------------------------
-- Serial No: 020
-- Table: T020 - feature_flags
-- Schema: system
-- Description: Toggles for specific fraud features.
-- Business Case: "Kill switches" and "Gradual Rollouts" are essential for high-availability systems.
--This table allows the DevOps team to enable or disable specific fraud checks (e.g., disable "Geo
--Velocity" if the GPS provider is down) without deploying new code. It supports the "Graceful
--Degradation" requirement of the module.
-- KPIs: Feature Flag Update Propagation Speed.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system.feature_flags (
    flag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL UNIQUE,
    is_enabled BOOLEAN DEFAULT FALSE,
    config JSONB,
    description TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

COMMENT ON TABLE system.feature_flags IS 'Runtime configuration switches for system behavior and feature availability.';

------------------------------------------------------------------------------------------------
-- Serial No: 021
-- Table: T021 - ip_reputation
-- Schema: fraud
-- Description: Cached IP reputation scores.
-- Business Case: Checking external reputation APIs (Tor nodes, known proxies) is slow. This table
--caches the results of these lookups to ensure the real-time fraud engine (F001) does not exceed
--its P99 latency budget. It acts as a local cache of "bad neighborhoods" on the internet.
-- KPIs: Cache Hit Ratio, External API Reduction.
-- Feature Reference: F029
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.ip_reputation (
    ip_address INET PRIMARY KEY,
    score INTEGER CHECK (score BETWEEN 0 AND 100),
    provider VARCHAR(50),
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.ip_reputation IS 'High-speed cache of external IP intelligence data.';

------------------------------------------------------------------------------------------------
-- Serial No: 022
-- Table: T022 - user_behavior_baseline
-- Schema: fraud
-- Description: Stores baseline metrics for "normal" user behavior.
-- Business Case: Fraud detection relies on anomaly detection. To know what is "abnormal", we must
--know what is "normal". This table aggregates user behavior (avg transaction amount, favorite
--merchants, login times) to create a dynamic baseline. As user habits change, this baseline
--updates (see F152), ensuring that a user's legitimate lifestyle changes don't trigger false
--positives.
-- KPIs: Baseline Convergence Time, False Positive Reduction.
-- Feature Reference: F152
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_behavior_baseline (
    user_hash VARCHAR(64) PRIMARY KEY,
    avg_tx_amt NUMERIC(15,2),
    tx_frequency INTERVAL,
    favorite_merchants JSONB,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.user_behavior_baseline IS 'Dynamic reference profiles for anomaly detection and false positive reduction.';

------------------------------------------------------------------------------------------------
-- Serial No: 023
-- Table: T023 - social_graph_edges
-- Schema: fraud
-- Description: Graph edges for money flow analysis.
-- Business Case: Fraudsters rarely work alone; they operate in networks (rings). This table stores
--the relationships (edges) between entities (nodes) in the payment graph. By querying this table,
--the system can detect "money mule" networks where funds flow rapidly through multiple accounts
--to obfuscate the origin. This is the basis for Graph Neural Network analysis (F028).
-- KPIs: Graph Query Latency, Ring Detection Rate.
-- Feature Reference: F028, F125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.social_graph_edges (
    edge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_node VARCHAR(64) NOT NULL,
    target_node VARCHAR(64) NOT NULL,
    weight NUMERIC(10,2),
    edge_type VARCHAR(50), -- PAYMENT, REFUND, P2P
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_graph_edges_source ON fraud.social_graph_edges(source_node);
CREATE INDEX idx_graph_edges_target ON fraud.social_graph_edges(target_node);
COMMENT ON TABLE fraud.social_graph_edges IS 'Relationship data for graph-based fraud network detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 024
-- Table: T024 - case_history
-- Schema: dispute
-- Description: Status change history for cases.
-- Business Case: An audit trail of state changes is required for SLA reporting. This table tracks
--exactly when a case moved from "Open" to "Resolved" and who (or what) moved it. This data is
--critical for calculating the "Dispute Resolution Time" KPI and for identifying bottlenecks in
--the workflow (e.g., cases stuck in "Under Review").
-- KPIs: State Transition Accuracy, SLA Calculation.
-- Feature Reference: F097
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.case_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    old_status common.status_type,
    new_status common.status_type,
    changed_by UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_case_history_case ON dispute.case_history(case_id);
COMMENT ON TABLE dispute.case_history IS 'State machine audit trail for dispute lifecycle management.';

------------------------------------------------------------------------------------------------
-- Serial No: 025
-- Table: T025 - refund_history
-- Schema: refund
-- Description: Status change history for refunds.
-- Business Case: Similar to T024, but for financial movements. Tracking the lifecycle of a refund
--(Authorized -> Executed -> Settled) is crucial for Reconciliation. If a refund fails at the bank
--layer, this history helps identify exactly where the process broke down.
-- KPIs: Reconciliation Success Rate.
-- Feature Reference: T011
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refund.refund_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    old_status common.status_type,
    new_status common.status_type,
    changed_by UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE refund.refund_history IS 'Audit trail for the financial settlement state of refunds.';

------------------------------------------------------------------------------------------------
-- Serial No: 026
-- Table: T026 - feedback_loop
-- Schema: fraud
-- Description: Stores user feedback on false positives (anonymized).
-- Business Case: Users hate being blocked when they are legitimate. This table provides an
--anonymous channel for users to flag a block as a "False Positive". This data is fed back into
--the Active Learning pipeline (F061) to tune the model sensitivity. It balances security with
--user experience.
-- KPIs: User Feedback Volume, False Positive Recovery Rate.
-- Feature Reference: F121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.feedback_loop (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    was_false_positive BOOLEAN NOT NULL,
    comments TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.feedback_loop IS 'User-driven validation signals for model tuning and customer experience.';

------------------------------------------------------------------------------------------------
-- Serial No: 027
-- Table: T027 - contract_clauses
-- Schema: contract
-- Description: Library of legal clauses for JSON-LD.
-- Business Case: Different industries require different legal terms. This library stores reusable
--text blocks (clauses) that can be assembled into a JSON-LD contract on the fly (F007). This ensures
--that a ticket seller has different terms than a digital goods merchant, automating compliance
--without lawyers reviewing every transaction.
-- KPIs: Clause Assembly Time.
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.contract_clauses (
    clause_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    text TEXT NOT NULL,
    category VARCHAR(50),
    vertical VARCHAR(50), -- e.g., 'Travel', 'SaaS'
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE contract.contract_clauses IS 'Modular legal text library for dynamic contract generation.';

------------------------------------------------------------------------------------------------
-- Serial No: 028
-- Table: T028 - contract_clause_junction
-- Schema: contract
-- Description: Links contracts to specific clauses.
-- Business Case: Many-to-Many relationship. A single contract might use a "Refund Policy" clause,
--a "Jurisdiction" clause, and a "Data Processing" clause. This junction table enables the flexible
--composition of complex legal agreements from simple building blocks.
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.contract_clause_junction (
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    clause_id UUID NOT NULL REFERENCES contract.contract_clauses(clause_id),
    PRIMARY KEY (contract_id, clause_id)
);

COMMENT ON TABLE contract.contract_clause_junction IS 'Resolution table for contract-to-clause relationships.';

------------------------------------------------------------------------------------------------
-- Serial No: 029
-- Table: T029 - bot_signals
-- Schema: fraud
-- Description: Signals indicating bot activity.
-- Business Case: Bots (scripts) are used for card testing and credential stuffing. This table
--aggregates weak signals (header inconsistencies, superhuman click speeds) that individually might
--not block a transaction but collectively indicate a bot. The ML engine (F002) weights these
--signals to calculate a "Bot Score".
-- KPIs: Bot Detection Rate, False Positive on Scripts.
-- Feature Reference: F041, F062
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.bot_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    signal_type VARCHAR(50) NOT NULL,
    confidence NUMERIC(3,2),
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bot_signals_tx ON fraud.bot_signals(transaction_hash);
COMMENT ON TABLE fraud.bot_signals IS 'Aggregated telemetry for automated script and bot detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 030
-- Table: T030 - merchant_dispute_ratios
-- Schema: fraud
-- Description: Materialized cache of merchant performance.
-- Business Case: Calculating the dispute ratio for a merchant on the fly over millions of
--transactions is too slow for the checkout page. This table acts as a pre-calculated cache (updated
--daily) that allows the system to instantly know if a merchant is "high risk" (e.g., > 1% dispute
--rate). It supports the "Merchant ROI Calculator" (F059).
-- KPIs: Cache Freshness, Query Latency.
-- Feature Reference: F039
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_dispute_ratios (
    merchant_id UUID PRIMARY KEY,
    disputes_total INTEGER,
    disputes_won INTEGER,
    ratio NUMERIC(5,4),
    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.merchant_dispute_ratios IS 'Performance snapshot cache for merchant risk assessment.';

------------------------------------------------------------------------------------------------
-- Serial No: 031
-- Table: T031 - external_evidence
-- Schema: dispute
-- Description: Evidence from external shippers.
-- Business Case: For physical goods, "Proof of Delivery" is the ultimate defense against friendly
--fraud. This table links the internal dispute case to the tracking information from external
--carriers (FedEx, DHL). By ingesting this data automatically, the system can auto-close "Item Not
--Received" cases when the carrier confirms delivery.
-- KPIs: Carrier Sync Success Rate, Auto-Closure Rate.
-- Feature Reference: F128
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.external_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    tracking_number VARCHAR(100),
    carrier VARCHAR(50),
    status_json JSONB,
    synced_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.external_evidence IS 'Logistics data integration for physical goods dispute resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 032
-- Table: T032 - p2p_circular_flows
-- Schema: fraud
-- Description: Detected circular transaction chains.
-- Business Case: Money launderers often cycle money through accounts (A->B->C->A) to create
--artificial transaction volume or confuse audit trails. This table stores these detected loops.
--Once a loop is identified, the system can flag the involved accounts for AML review (M05).
-- KPIs: Loop Detection Accuracy.
-- Feature Reference: F028
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.p2p_circular_flows (
    flow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    start_node VARCHAR(64),
    end_node VARCHAR(64),
    hop_count INTEGER,
    total_amount NUMERIC(15,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.p2p_circular_flows IS 'Storage for identified circular transaction patterns indicative of layering.';

------------------------------------------------------------------------------------------------
-- Serial No: 033
-- Table: T033 - sim_swap_events
-- Schema: fraud
-- Description: Logs SIM swap check results.
-- Business Case: A SIM swap allows an attacker to intercept 2FA SMS codes. This table logs the
--result of checking with the telecom provider if a user's SIM was recently ported. If yes, the
--fraud system blocks the transaction or forces a different 2FA method (e.g., App-based).
-- KPIs: API Call Latency, Fraud Prevention via SIM Check.
-- Feature Reference: F086
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.sim_swap_events (
    user_hash VARCHAR(64) PRIMARY KEY,
    swap_detected BOOLEAN NOT NULL,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    provider VARCHAR(50)
);

COMMENT ON TABLE fraud.sim_swap_events IS 'Cache of telecom provider checks to prevent account takeover via SIM swapping.';

------------------------------------------------------------------------------------------------
-- Serial No: 034
-- Table: T034 - feature_importance
-- Schema: ml
-- Description: SHAP values for model explainability.
-- Business Case: Regulators require "Explainable AI". If the system blocks a transaction, why?
--This table stores the SHAP (Shapley Additive Explanations) values, which mathematically assign
--importance to each feature (e.g., "Location Velocity contributed 40% to the risk score"). This
--powers the "Model Explainability UI" (F076).
-- KPIs: Explanation Generation Time.
-- Feature Reference: F051
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_importance (
    importance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID,
    feature_name VARCHAR(100),
    importance_value NUMERIC(5,4),
    transaction_hash VARCHAR(64),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_feature_imp_model ON ml.feature_importance(model_id);
COMMENT ON TABLE ml.feature_importance IS 'Storage for explainability metrics (SHAP values) for AI decisions.';

------------------------------------------------------------------------------------------------
-- Serial No: 035
-- Table: T035 - refunds_issued
-- Schema: fraud
-- Description: Log of executed refunds.
-- Business Case: This is the financial ledger entry for refunds. Unlike the state table (T011),
--this table records the immutable fact that money moved. It is used for reconciliation with the
--bank and for calculating the exact "Cost of Fraud" (F120) by summing up the refunded amounts.
-- KPIs: Reconciliation Accuracy.
-- Feature Reference: F090
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refunds_issued (
    refund_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3),
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    settlement_ref VARCHAR(100)
);

COMMENT ON TABLE fraud.refunds_issued IS 'Immutable financial log of successfully executed refund payments.';

------------------------------------------------------------------------------------------------
-- Serial No: 036
-- Table: T036 - chargeback_savings
-- Schema: fraud
-- Description: Tracks savings calculation.
-- Business Case: PARI's value proposition is eliminating chargebacks. This table calculates the
--savings by comparing the "Estimated Loss" (if traditional card processing were used, assuming
--a 1% fraud rate) against the "Actual Loss" (via successful fraud). This data powers the
--"Merchant ROI Calculator" (F059) dashboard.
-- KPIs: Total Savings %, ROI.
-- Feature Reference: F059
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.chargeback_savings (
    merchant_id UUID,
    period DATE NOT NULL,
    estimated_loss NUMERIC(15,2),
    actual_loss NUMERIC(15,2),
    savings NUMERIC(15,2),

    PRIMARY KEY (merchant_id, period)
);

COMMENT ON TABLE fraud.chargeback_savings IS 'Aggregated financial metrics demonstrating the value of fraud prevention.';

------------------------------------------------------------------------------------------------
-- Serial No: 037
-- Table: T037 - high_risk_batches
-- Schema: fraud
-- Description: Flags batch uploads from merchants.
-- Business Case: Merchants sometimes upload bulk refund lists (e.g., recalls). If a batch is
--unusually large or comes from a high-risk merchant, it needs to be quarantined. This table flags
--these batches for manual review before the funds are released.
-- KPIs: Batch Review Time.
-- Feature Reference: F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.high_risk_batches (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    upload_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER,
    review_status VARCHAR(20) DEFAULT 'PENDING' -- PENDING, APPROVED, REJECTED
);

COMMENT ON TABLE fraud.high_risk_batches IS 'Quarantine list for bulk financial operations requiring manual oversight.';

------------------------------------------------------------------------------------------------
-- Serial No: 038
-- Table: T038 - bias_metrics
-- Schema: fraud
-- Description: Model fairness metrics per group.
-- Business Case: AI must be fair. If the model blocks 10% of one demographic but only 1% of another
--for the same behavior, it is biased. This table tracks these disparity scores to ensure the
--system adheres to ethical AI standards and avoids discrimination lawsuits.
-- KPIs: Disparity Score (< 0.2), Fairness Audit Pass Rate.
-- Feature Reference: F107
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.bias_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID,
    demographic_attribute VARCHAR(50), -- e.g., age_group, region
    disparity_score NUMERIC(5,4),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.bias_metrics IS 'Records of model fairness audits to prevent algorithmic bias.';

------------------------------------------------------------------------------------------------
-- Serial No: 039
-- Table: T039 - blockchain_anchors
-- Schema: contract
-- Description: Records of contract hashes on external blockchains.
-- Business Case: To prove a contract existed *at a specific point in time*, we anchor its hash to
--a public blockchain (e.g., Ethereum). This creates an immutable timestamp that no court or
--internal admin can dispute. It provides the highest level of evidence integrity for high-value
--disputes.
-- KPIs: Anchor Confirmation Time.
-- Feature Reference: F078
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.blockchain_anchors (
    anchor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_hash CHAR(64) NOT NULL,
    tx_hash VARCHAR(100),
    network VARCHAR(20),
    block_number BIGINT,
    anchored_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT anchor_unique UNIQUE (contract_hash, network)
);

COMMENT ON TABLE contract.blockchain_anchors IS 'Immutable timestamping proofs via public blockchain integration.';

------------------------------------------------------------------------------------------------
-- Serial No: 040
-- Table: T040 - dynamic_throttles
-- Schema: fraud
-- Description: Current throttle limits for IPs/Users.
-- Business Case: To mitigate Denial of Service (DoS) or Brute Force attacks, the system must slow
--down specific actors. This table stores the current "rate limit" counters. If an IP exceeds the
--limit, the throttle blocks further requests for a set window.
-- KPIs: Throttle Reaction Time.
-- Feature Reference: F062
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.dynamic_throttles (
    entity_key VARCHAR(100) PRIMARY KEY, -- Could be IP or User Hash
    max_requests INTEGER,
    window_sec INTEGER,
    current_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.dynamic_throttles IS 'Runtime state for rate limiting and DoS mitigation.';

------------------------------------------------------------------------------------------------
-- Serial No: 041
-- Table: T041 - geo_fences
-- Schema: fraud
-- Description: Merchant defined geo-fences.
-- Business Case: Some merchants only ship to specific countries or regions (e.g., due to licensing).
--This table stores these polygon definitions. The system checks user location against these fences
--to block invalid transactions before they happen, reducing disputes.
-- KPIs: Geo-Fence Filter Accuracy.
-- Feature Reference: F099
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.geo_fences (
    fence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    polygon_coords JSONB NOT NULL, -- GeoJSON format
    fence_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE fraud.geo_fences IS 'Merchant-defined geographic boundaries for transaction validation.';

------------------------------------------------------------------------------------------------
-- Serial No: 042
-- Table: T042 - sentiment_analysis
-- Schema: dispute
-- Description: Results of NLP sentiment on notes.
-- Business Case: Understanding the *emotion* behind a dispute helps prioritize it. A user screaming
--in caps lock (High Negative Sentiment) might need immediate attention to prevent churn, whereas a
--polite inquiry might wait. This table stores the sentiment score computed from user notes.
-- KPIs: Sentiment Accuracy.
-- Feature Reference: F064
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.sentiment_analysis (
    note_id UUID PRIMARY KEY REFERENCES dispute.case_notes(note_id),
    sentiment_score NUMERIC(3,2) CHECK (sentiment_score BETWEEN -1.0 AND 1.0),
    sentiment_label VARCHAR(20) -- POSITIVE, NEGATIVE, NEUTRAL
);

COMMENT ON TABLE dispute.sentiment_analysis IS 'NLP-derived emotional context for customer communications.';

------------------------------------------------------------------------------------------------
-- Serial No: 043
-- Table: T043 - watchlist
-- Schema: fraud
-- Description: Internal watchlist for entities.
-- Business Case: Unlike the hard "Blacklist" (T014), the Watchlist is for entities that are
--"suspicious" but not yet blocked. Transactions from these entities are flagged for extra
--scrutiny (e.g., Step-up Auth) rather than immediate rejection.
-- KPIs: Watchlist Conversion Rate (to Blacklist).
-- Feature Reference: F118
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.watchlist (
    entity_id UUID,
    entity_type VARCHAR(20),
    reason TEXT,
    added_by UUID,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_watchlist PRIMARY KEY (entity_id, entity_type)
);

COMMENT ON TABLE fraud.watchlist IS 'Monitoring list for entities requiring enhanced due diligence.';

------------------------------------------------------------------------------------------------
-- Serial No: 044
-- Table: T044 - smart_contract_clauses
-- Schema: fraud
-- Description: Clauses specific to smart contract execution.
-- Business Case: These are executable code snippets (e.g., "If shipment_status == 'delivered', release funds").
--The table links these logic definitions to the contract clauses so the system knows *how* to execute
--the terms, not just what they say.
-- KPIs: Execution Success Rate.
-- Feature Reference: F153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.smart_contract_clauses (
    clause_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    abi_signature VARCHAR(255),
    logic_hash VARCHAR(64),
    code_text TEXT
);

COMMENT ON TABLE fraud.smart_contract_clauses IS 'Executable logic definitions for automated contract terms.';

------------------------------------------------------------------------------------------------
-- Serial No: 045
-- Table: T045 - shadow_mode_results
-- Schema: ml
-- Description: Comparison of shadow model vs live model.
-- Business Case: Before deploying a new AI model to production (where it can block real users), we
--run it in "Shadow Mode" (parallel to live). It makes predictions but doesn't act on them. This
--table stores the comparison of the Shadow predictions vs Live predictions to verify the new model
--is actually better.
-- KPIs: Model Improvement Delta.
-- Feature Reference: F159
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.shadow_mode_results (
    comparison_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tx_hash VARCHAR(64),
    live_score NUMERIC(5,2),
    shadow_score NUMERIC(5,2),
    ground_truth BOOLEAN, -- If known later
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.shadow_mode_results IS 'A/B testing data for validating candidate ML models against production.';

------------------------------------------------------------------------------------------------
-- Serial No: 046
-- Table: T046 - forensic_snapshots
-- Schema: fraud
-- Description: Screenshots/HTML snapshots of webpages.
-- Business Case: In "Friendly Fraud" (Item Not Received), the merchant's webpage at the time of
--purchase is crucial evidence. Did it say "Digital Delivery"? This table stores snapshots of the
--merchant site captured at transaction time, preserving the state even if the merchant changes the
--site later.
-- KPIs: Snapshot Storage Cost vs. Fraud Recovery Value.
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.forensic_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID REFERENCES dispute.cases(case_id),
    storage_path TEXT,
    snapshot_type VARCHAR(20), -- SCREENSHOT, HTML, PDF
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.forensic_snapshots IS 'Visual and code state capture of merchant sites for dispute evidence.';

------------------------------------------------------------------------------------------------
-- Serial No: 047
-- Table: T047 - api_usage
-- Schema: system
-- Description: Tracks API usage for quotas.
-- Business Case: To prevent abuse of the Fraud API by external partners, we enforce quotas. This
--table tracks the request count per time window. If a partner exceeds their paid tier limit, the
--API Gateway blocks the request.
-- KPIs: Quota Enforcement Accuracy.
-- Feature Reference: F156
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system.api_usage (
    api_key_id UUID,
    endpoint VARCHAR(100),
    window_start TIMESTAMP WITH TIME ZONE,
    request_count BIGINT DEFAULT 0,

    CONSTRAINT pk_api_usage UNIQUE (api_key_id, endpoint, window_start)
);

CREATE INDEX idx_api_usage_window ON system.api_usage(window_start);
COMMENT ON TABLE system.api_usage IS 'Rate limiting counters for external API access.';

------------------------------------------------------------------------------------------------
-- Serial No: 048
-- Table: T048 - legacy_import_map
-- Schema: fraud
-- Description: Maps legacy IDs to PARI IDs.
-- Business Case: When onboarding a new merchant from an old payment processor, they bring their
--history. This table maps the "Old Merchant ID" to the "New PARI Merchant ID". This allows us to
--port their historical risk profiles and reputation, giving them a smooth start.
-- KPIs: Data Migration Accuracy.
-- Feature Reference: F157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.legacy_import_map (
    legacy_id VARCHAR(100),
    legacy_system VARCHAR(50),
    pari_id UUID,
    import_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.legacy_import_map IS 'Cross-reference table for historical data migration from legacy systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 049
-- Table: T049 - case_locks
-- Schema: dispute
-- Description: Row-level locks for collaborative case work.
-- Business Case: When two agents are working on the same complex fraud case, they might overwrite
--each other's notes. This table implements a pessimistic locking mechanism. If Agent A opens the
--case, Agent B gets a "Case Locked" message until Agent A closes it.
-- KPIs: Lock Contention Rate.
-- Feature Reference: F158
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.case_locks (
    case_id UUID PRIMARY KEY REFERENCES dispute.cases(case_id),
    locked_by UUID NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE dispute.case_locks IS 'Concurrency control mechanism for collaborative dispute resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 050
-- Table: T050 - quantum_prepared_keys
-- Schema: fraud
-- Description: Test keys for quantum-resistant crypto.
-- Business Case: Future-proofing. While current crypto (RSA/ECDSA) is secure, quantum computers
--threaten them. This table stores experimental keys using quantum-resistant algorithms (like Lattice-based
--crypto) to prepare the infrastructure for a post-quantum world.
-- KPIs: Crypto Migration Readiness.
-- Feature Reference: F151
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.quantum_prepared_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    algo_type VARCHAR(50),
    public_key_blob TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.quantum_prepared_keys IS 'Experimental storage for next-generation cryptographic keys.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR AUDIT COLUMNS
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

-- Apply the timestamp trigger to all relevant tables
CREATE TRIGGER trg_transaction_scores_timestamp
    BEFORE UPDATE ON fraud.transaction_scores
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_lstm_model_versions_timestamp
    BEFORE UPDATE ON fraud.lstm_model_versions
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_velocity_rules_timestamp
    BEFORE UPDATE ON fraud.velocity_rules
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_cases_timestamp
    BEFORE UPDATE ON dispute.cases
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_blinded_refunds_timestamp
    BEFORE UPDATE ON refund.blinded_refunds
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_feature_flags_timestamp
    BEFORE UPDATE ON system.feature_flags
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (First 50 Objects)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 2)
-- =============================================================================================
-- Tables T051 - T100
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 051
-- Table: T051 - user_risk_history
-- Schema: fraud
-- Description: Historical tracking of user risk tier changes over time.
-- Business Case: Understanding the trajectory of a user's risk score is as important as the
--current score. A sudden jump from 'Low' to 'Critical' indicates an account takeover, while a
--steady decline suggests improved behavior. This table maintains the immutable history of risk
--tier changes. It allows the Risk Management team to reconstruct the "why" behind a user's
--current status and provides data for analyzing the long-term effectiveness of friction
--interventions.
-- KPIs: Risk Tier Volatility, Reconstruction Accuracy.
-- Feature Reference: T013
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_risk_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    old_tier VARCHAR(20) CHECK (old_tier IN ('low', 'medium', 'high', 'critical')),
    new_tier VARCHAR(20) NOT NULL CHECK (new_tier IN ('low', 'medium', 'high', 'critical')),
    score_delta NUMERIC(5,2),
    trigger_reason VARCHAR(255), -- e.g., 'Velocity Check Failed', 'Manual Override'

    -- Metadata
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    changed_by UUID
);

CREATE INDEX idx_user_risk_history_user ON fraud.user_risk_history(user_hash);
COMMENT ON TABLE fraud.user_risk_history IS 'Chronological audit of user risk tier modifications for trajectory analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 052
-- Table: T052 - evidence_redactions
-- Schema: dispute
-- Description: Logs of redactions made to evidence documents.
-- Business Case: Privacy laws (GDPR/CCPA) often require that sensitive PII be redacted before
--sharing dispute evidence with external auditors or even internal support staff who don't
--have clearance. This table tracks exactly what was redacted (via coordinate mapping or text
--replacement), by whom, and for what legal reason. It ensures that the "Right to be Forgotten"
--is respected even within evidence archives.
-- KPIs: Redaction Processing Time, Compliance Audit Pass Rate.
-- Feature Reference: F069
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.evidence_redactions (
    redaction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES dispute.case_evidence(evidence_id),
    redacted_by UUID NOT NULL,
    redaction_coords JSONB, -- e.g., {"page": 1, "x": 10, "y": 20, "width": 100}
    reason_code VARCHAR(50),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.evidence_redactions IS 'Audit log of privacy redactions applied to dispute evidence files.';

------------------------------------------------------------------------------------------------
-- Serial No: 053
-- Table: T053 - canonical_documents
-- Schema: contract
-- Description: PDF/A versions of evidence for long-term archival.
-- Business Case: Raw JSON or HTML is great for machines, but legal systems and archives prefer
--PDF/A (a standardized ISO format for long-term preservation). This table stores the references
--to the canonical, flattened PDF version of the contract and evidence. It ensures that documents
--remain readable and legally valid decades after the transaction, regardless of software changes.
-- KPIs: Conversion Success Rate, Archival Integrity Check.
-- Feature Reference: F160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.canonical_documents (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_evidence_id UUID REFERENCES dispute.case_evidence(evidence_id),
    pdf_storage_path TEXT NOT NULL,
    pdf_hash CHAR(64) NOT NULL,
    page_count INTEGER,
    conversion_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED, FAILED

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_canonical_docs_original ON contract.canonical_documents(original_evidence_id);
COMMENT ON TABLE contract.canonical_documents IS 'Storage index for standardized PDF/A archival formats of legal documents.';

------------------------------------------------------------------------------------------------
-- Serial No: 054
-- Table: T054 - merchant_leagueboard
-- Schema: fraud
-- Description: Pre-calculated leaderboard stats for merchants.
-- Business Case: Gamification drives behavior. By publishing a leaderboard of merchants with the
--best fraud prevention practices (lowest dispute rates, fastest response times), PARI encourages
--merchants to improve their own hygiene. This table caches the calculated metrics to serve the
--"Merchant ROI Calculator" and "Leaderboard" UI (F155) without expensive real-time queries.
-- KPIs: Data Freshness, Leaderboard Rank Calculation Time.
-- Feature Reference: F155
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_leagueboard (
    merchant_id UUID PRIMARY KEY,
    rank INTEGER,
    score NUMERIC(5,2),
    period VARCHAR(20), -- 'WEEKLY', 'MONTHLY', 'ALL_TIME'
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.merchant_leagueboard IS 'Gamification snapshot data driving merchant competitive behavior and benchmarking.';

------------------------------------------------------------------------------------------------
-- Serial No: 055
-- Table: T055 - model_drift_alerts
-- Schema: ml
-- Description: Logs of drift detection events.
-- Business Case: ML models degrade over time as fraud patterns evolve ("Drift"). If left unchecked,
--the model will either miss fraud (Recall drops) or block legitimate users (Precision drops).
--This table logs when drift is detected, the magnitude of the drift (e.g., KL Divergence), and
--triggers the retraining pipeline (F137). It is the "check engine light" for the AI.
-- KPIs: Alert Latency, False Alarm Rate on Drift.
-- Feature Reference: F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_drift_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    drift_metric VARCHAR(50), -- e.g., 'kl_divergence', 'psi'
    threshold_value NUMERIC(10,4),
    actual_value NUMERIC(10,4),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_acknowledged BOOLEAN DEFAULT FALSE,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_drift_alerts_model ON ml.model_drift_alerts(model_id);
COMMENT ON TABLE ml.model_drift_alerts IS 'Operational alerts tracking statistical degradation of machine learning models.';

------------------------------------------------------------------------------------------------
-- Serial No: 056
-- Table: T056 - webhooks_delivered
-- Schema: dispute
-- Description: Log of webhook delivery attempts.
-- Business Case: Merchants use webhooks to update their internal systems when a dispute status
--changes. This table tracks the delivery of these events. If a webhook fails (e.g., merchant server
--is down), this log drives the retry logic. It also provides the merchant with proof that PARI
--sent the notification in case of "I never knew about the dispute" claims.
-- KPIs: Webhook Delivery Success Rate, Retry Success Rate.
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.webhooks_delivered (
    webhook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID REFERENCES dispute.cases(case_id),
    url TEXT NOT NULL,
    http_code INTEGER,
    response_body_hash CHAR(64),
    attempt_count INTEGER DEFAULT 1,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    delivery_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SENT, FAILED

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhooks_status ON dispute.webhooks_delivered(delivery_status, next_retry_at);
COMMENT ON TABLE dispute.webhooks_delivered IS 'Transaction log of external API event notifications with retry state management.';

------------------------------------------------------------------------------------------------
-- Serial No: 057
-- Table: T057 - refund_abuse_patterns
-- Schema: fraud
-- Description: Patterns of merchants abusing refunds.
-- Business Case: Some fraudsters act as merchants, processing payments and then refunding them
--(excluding the processing fee) to launder money or cash out stolen cards. This table flags
--merchants whose refund ratio is statistically impossible for a legitimate business. It supports
--the "Refund Fraud Detection" feature (F143).
-- KPIs: Abuse Pattern Accuracy, Detection Latency.
-- Feature Reference: F143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_abuse_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    pattern_type VARCHAR(50), -- e.g., 'HIGH_VELOCITY_REFUND', 'CIRCULAR_REFUND'
    frequency INTEGER,
    risk_score INTEGER,
    status VARCHAR(20) DEFAULT 'FLAGGED', -- FLAGGED, REVIEWED, CONFIRMED_BENIGN

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.refund_abuse_patterns IS 'Detection of merchant-side illicit financial behaviors involving refund mechanisms.';

------------------------------------------------------------------------------------------------
-- Serial No: 058
-- Table: T058 - insurance_claims
-- Schema: fraud
-- Description: Claims made against fraud insurance.
-- Business Case: PARI (or a partner) offers fraud insurance. When a transaction is confirmed
--as fraud, a claim is filed here. This table links the financial loss to the insurance payout
--process. It tracks the claim lifecycle from filing to payout, ensuring that the financial impact
--of fraud is accurately absorbed and reported.
-- KPIs: Claim Processing Time, Payout Accuracy.
-- Feature Reference: F154
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.insurance_claims (
    claim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    claim_amount NUMERIC(15,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'SUBMITTED', -- SUBMITTED, APPROVED, REJECTED, PAID
    payout_id UUID,
    policy_number VARCHAR(100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.insurance_claims IS 'Financial ledger for fraud insurance recovery and payout processing.';

------------------------------------------------------------------------------------------------
-- Serial No: 059
-- Table: T059 - currency_conversion_rates
-- Schema: fraud
-- Description: Cache of FX rates for refunds.
-- Business Case: Cross-border commerce requires currency conversion. When refunding a blinded coin,
--if the merchant holds balance in USD but the user paid in EUR, an FX conversion is needed. This
--table caches real-time rates to ensure the refunded amount is fair and up-to-date without
--querying an external API on every transaction.
-- KPIs: Rate Freshness, API Cost Reduction.
-- Feature Reference: F148
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.currency_conversion_rates (
    from_curr CHAR(3) NOT NULL,
    to_curr CHAR(3) NOT NULL,
    rate NUMERIC(15,6) NOT NULL,
    provider VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_fx_rates UNIQUE (from_curr, to_curr, timestamp)
);

CREATE INDEX idx_fx_rates_lookup ON fraud.currency_conversion_rates(from_curr, to_curr, timestamp DESC);
COMMENT ON TABLE fraud.currency_conversion_rates IS 'High-speed cache for foreign exchange rates supporting multi-currency refunds.';

------------------------------------------------------------------------------------------------
-- Serial No: 060
-- Table: T060 - dlp_violations
-- Schema: security
-- Description: Logs of DLP scans on disputes.
-- Business Case: Users sometimes accidentally upload credit card numbers or passwords as
--evidence. A Data Loss Prevention (DLP) system scans uploads. This table logs violations found.
--If a violation is critical (e.g., full PAN), the file can be automatically quarantined or
--redacted before storage, preventing a data leak within the support organization.
-- KPIs: Scan Latency, Violation Detection Rate.
-- Feature Reference: F149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.dlp_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID REFERENCES dispute.case_evidence(evidence_id),
    violation_type VARCHAR(50), -- e.g., 'CREDIT_CARD', 'SSN', 'PASSWORD'
    pii_found VARCHAR(100),
    action_taken VARCHAR(20), -- QUARANTINED, REDACTED, IGNORED

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE security.dlp_violations IS 'Security log of sensitive data discovery in user-uploaded content.';

------------------------------------------------------------------------------------------------
-- Serial No: 061
-- Table: T061 - voice_prints
-- Schema: fraud
-- Description: Stores voice biometrics hashes.
-- Business Case: Voice biometrics offer a powerful layer of authentication for phone-based disputes
--(F124). This table stores the "Voice Print" (a mathematical representation, not an audio file)
--for users. It allows the system to verify that the caller on the phone is actually the account
--holder, preventing social engineering attacks.
-- KPIs: Voice Match Accuracy, Enrollment Rate.
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.voice_prints (
    print_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    voice_hash VARCHAR(255) NOT NULL, -- Vectorized representation
    model_version VARCHAR(20),
    quality_score NUMERIC(3,2), -- Audio quality at enrollment

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_voice_prints_user ON fraud.voice_prints(user_hash);
COMMENT ON TABLE fraud.voice_prints IS 'Biometric templates for voice-based authentication and fraud verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 062
-- Table: T062 - merchant_health_scores
-- Schema: fraud
-- Description: Composite health score for merchants.
-- Business Case: A merchant might have high sales but also high fraud. The "Health Score"
--aggregates various signals (dispute rate, technical uptime, API errors) into a single metric.
--This helps Partner Managers identify merchants who need help (e.g., maybe they are suffering a
--bug causing false disputes) versus those who are malicious.
-- KPIs: Health Score Correlation with Churn.
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_health_scores (
    merchant_id UUID PRIMARY KEY,
    health_score NUMERIC(5,2),
    components JSONB, -- {"fraud": 80, "technical": 90, "financial": 95}
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.merchant_health_scores IS 'Multi-dimensional wellness index for partner merchants.';

------------------------------------------------------------------------------------------------
-- Serial No: 063
-- Table: T063 - satisfaction_surveys
-- Schema: dispute
-- Description: Feedback on dispute resolution.
-- Business Case: The dispute process is stressful. This table stores user feedback (CSAT) after a
--case is closed. High CSAT correlates with retention. Low CSAT flags specific agents or policy
--flaws that need correction. It feeds the "Customer Sentiment Analysis" feature (F064).
-- KPIs: CSAT Score, Response Rate.
-- Feature Reference: F145
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.satisfaction_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    comments TEXT,
    channel VARCHAR(50), -- EMAIL, IN_APP, SMS

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.satisfaction_surveys IS 'Customer experience metrics collected post-resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 064
-- Table: T064 - spam_keywords
-- Schema: fraud
-- Description: Keywords for narrative analysis.
-- Business Case: Fraudsters often use similar language in transaction notes (e.g., "test", "check",
--random characters). This table maintains a dictionary of suspicious keywords/phrases. The NLP engine
--scans transaction narratives (F142) against this list to flag potential bot activity or testing.
-- KPIs: Keyword Hit Rate, False Positive Rate.
-- Feature Reference: F142
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.spam_keywords (
    keyword_id SERIAL PRIMARY KEY,
    keyword VARCHAR(255) NOT NULL,
    risk_weight NUMERIC(3,2) DEFAULT 1.0,
    is_regex BOOLEAN DEFAULT FALSE,
    language CHAR(2) DEFAULT 'en',

    CONSTRAINT keyword_unique UNIQUE (keyword, language)
);

CREATE INDEX idx_spam_keywords_weight ON fraud.spam_keywords(risk_weight);
COMMENT ON TABLE fraud.spam_keywords IS 'Dictionary of linguistic patterns indicative of spam or bot activity.';

------------------------------------------------------------------------------------------------
-- Serial No: 065
-- Table: T065 - contract_permissions
-- Schema: contract
-- Description: Access control for contracts.
-- Business Case: Not everyone should see every contract. This ACL (Access Control List) defines
--who can view, sign, or audit a specific contract. It enforces the separation of duties; e.g.,
--a cashier might be able to sign, but not view the full legal terms, while an auditor can view but
--not sign.
-- KPIs: Permission Enforcement Speed.
-- Feature Reference: F002 (Conceptual)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.contract_permissions (
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    party_role VARCHAR(50) NOT NULL, -- Role based, not specific user for scalability
    can_view BOOLEAN DEFAULT FALSE,
    can_sign BOOLEAN DEFAULT FALSE,
    can_audit BOOLEAN DEFAULT FALSE,

    CONSTRAINT pk_contract_perms UNIQUE (contract_id, party_role)
);

COMMENT ON TABLE contract.contract_permissions IS 'Role-Based Access Control definitions for contract interactions.';

------------------------------------------------------------------------------------------------
-- Serial No: 066
-- Table: T066 - training_schedule
-- Schema: ml
-- Description: Schedule for automated model training.
-- Business Case: Models need regular retraining. This table configures *when* that happens. Using
--Cron expressions, it ensures models are trained during low-traffic hours (e.g., 3 AM) to avoid
--resource contention. It also links to the pipeline orchestration (F133).
-- KPIs: Schedule Adherence.
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.training_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_type VARCHAR(50) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    last_run TIMESTAMP WITH TIME ZONE,
    next_run TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE ml.training_schedule IS 'Temporal configuration for automated machine learning pipeline execution.';

------------------------------------------------------------------------------------------------
-- Serial No: 067
-- Table: T067 - anomaly_alerts
-- Schema: fraud
-- Description: Alerts generated by anomaly detection.
-- Business Case: This table captures the raw alerts from the unsupervised anomaly detection models
--(Isolation Forest, Autoencoders). Unlike "Fraud Scores" which are binary (Fraud/Legit), anomalies
--are just "weird". These alerts feed the Analyst queue for investigation. They are crucial for
--discovering *new* types of fraud that haven't been labeled yet.
-- KPIs: Alert Precision (Investigation Yield).
-- Feature Reference: F033
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.anomaly_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARN', 'CRITICAL')),
    details JSONB,
    status VARCHAR(20) DEFAULT 'NEW', -- NEW, INVESTIGATING, CLOSED, IGNORED
    assigned_to UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_anomaly_alerts_status ON fraud.anomaly_alerts(status, severity);
COMMENT ON TABLE fraud.anomaly_alerts IS 'Queue of statistical anomalies detected by unsupervised learning models.';

------------------------------------------------------------------------------------------------
-- Serial No: 068
-- Table: T068 - automated_actions
-- Schema: dispute
-- Description: Logs of actions taken by the automation engine.
-- Business Case: The "Automated Dispute Workflow" (F010) takes actions without human intervention.
--This table logs every automated action (e.g., "Auto-rejected due to valid proof of delivery").
--It provides transparency for users ("Why was my case closed?") and an audit trail for regulators
--ensuring the automation is behaving as programmed.
-- KPIs: Automation Accuracy, Action Traceability.
-- Feature Reference: F045, F090
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.automated_actions (
    action_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    action_type VARCHAR(50) NOT NULL, -- AUTO_CLOSE, AUTO_REFUND, AUTO_ESCALATE
    result VARCHAR(20), -- SUCCESS, FAILURE
    rule_id UUID, -- Which rule triggered the action
    details JSONB,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.automated_actions IS 'System-generated activity log for rule-based dispute resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 069
-- Table: T069 - dataset_partitions
-- Schema: ml
-- Description: Metadata for data partitions (train/val/test).
-- Business Case: In ML, you never test on the same data you train on (Overfitting). This table
--tracks how the historical data was split. It ensures reproducibility—if we retrain today, we
--get the same split as yesterday—so that performance comparisons are valid.
-- KPIs: Partition Balance (Class distribution).
-- Feature Reference: F016
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.dataset_partitions (
    partition_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    partition_type VARCHAR(20) NOT NULL CHECK (partition_type IN ('TRAIN', 'VALIDATION', 'TEST')),
    row_count BIGINT,
    start_date DATE,
    end_date DATE,
    hash_signature CHAR(64) -- Hash of the rows in the partition
);

COMMENT ON TABLE ml.dataset_partitions IS 'Version control for data segmentation in machine learning experiments.';

------------------------------------------------------------------------------------------------
-- Serial No: 070
-- Table: T070 - captcha_challenges
-- Schema: fraud
-- Description: Captcha sessions.
-- Business Case: Captchas are the last line of defense for "Medium Risk" traffic. This table stores
--the session state of a captcha challenge (generated vs solved). It prevents bots from simply
--ignoring the challenge or reusing a valid token from a previous request.
-- KPIs: Bot Block Rate via Captcha, Solve Rate (Human vs Bot).
-- Feature Reference: F131
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.captcha_challenges (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    challenge_hash VARCHAR(255) NOT NULL,
    ip_address INET,
    solved BOOLEAN DEFAULT FALSE,
    solve_time_ms INTEGER,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_captcha_session ON fraud.captcha_challenges(challenge_hash);
COMMENT ON TABLE fraud.captcha_challenges IS 'State management for Turing tests used to distinguish humans from bots.';

------------------------------------------------------------------------------------------------
-- Serial No: 071
-- Table: T071 - dark_web_monitoring
-- Schema: fraud
-- Description: Alerts from dark web scans.
-- Business Case: Credentials for PARI staff or merchants might leak on the dark web. This table
--ingests alerts from external intelligence services. If an admin password is found here, we force
--a password reset immediately. If merchant API keys are found, we rotate them.
-- KPIs: Threat Intelligence Latency.
-- Feature Reference: F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.dark_web_monitoring (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    keyword VARCHAR(255) NOT NULL, -- e.g., "parisystems.com"
    source_url TEXT,
    threat_level VARCHAR(20) CHECK (threat_level IN ('LOW', 'MEDIUM', 'HIGH')),
    found_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_processed BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE fraud.dark_web_monitoring IS 'External intelligence logs regarding leaked credentials or brand mentions on hidden networks.';

------------------------------------------------------------------------------------------------
-- Serial No: 072
-- Table: T072 - device_integrity
-- Schema: fraud
-- Description: Results of app integrity checks.
-- Business Case: Fraudsters often "root" or "jailbreak" devices to bypass app security (hooking
--into the SSL layer). This table stores the result of the integrity check performed by the mobile
--SDK (F070). Devices failing this check are flagged as high risk because the environment cannot
--be trusted.
-- KPIs: Integrity Check Failure Rate vs Fraud Rate.
-- Feature Reference: F070
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_integrity (
    device_hash VARCHAR(64) PRIMARY KEY,
    is_rooted BOOLEAN DEFAULT FALSE,
    app_signature_valid BOOLEAN DEFAULT TRUE,
    os_version VARCHAR(50),
    app_version VARCHAR(50),
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.device_integrity is 'Security assessment of the endpoint hardware/software environment.';

------------------------------------------------------------------------------------------------
-- Serial No: 073
-- Table: T073 - transaction_links
-- Schema: fraud
-- Description: Links related transactions.
-- Business Case: Complex transactions involve splits or merges (e.g., paying for 3 items at once).
--This table establishes a graph of relationships. If one item in a basket is fraudulent, the entire
--basket might be suspect. It also links refunds to original payments to validate "Double Dipping"
--attempts (claiming a refund twice).
-- KPIs: Linkage Accuracy.
-- Feature Reference: F091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_links (
    parent_tx VARCHAR(64) NOT NULL,
    child_tx VARCHAR(64) NOT NULL,
    link_type VARCHAR(50) NOT NULL CHECK (link_type IN ('SPLIT', 'MERGE', 'REFUND', 'RETRY')),

    CONSTRAINT pk_transaction_links PRIMARY KEY (parent_tx, child_tx)
);

CREATE INDEX idx_tx_links_child ON fraud.transaction_links(child_tx);
COMMENT ON TABLE fraud.transaction_links IS 'Graph database representation of complex payment relationships.';

------------------------------------------------------------------------------------------------
-- Serial No: 074
-- Table: T074 - communication_logs
-- Schema: dispute
-- Description: Logs of emails/SMS sent to users/merchants.
-- Business Case: Communication is a core part of dispute resolution (requesting info, notifying
--of decisions). This table records every outgoing message. It serves as proof of notification in
--legal proceedings and helps debug delivery issues (e.g., "The user says they never got the email").
-- KPIs: Delivery Success Rate, Bounce Rate.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.communication_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID REFERENCES dispute.cases(case_id),
    channel VARCHAR(20) NOT NULL, -- EMAIL, SMS, PUSH
    recipient VARCHAR(255) NOT NULL,
    message_id VARCHAR(255), -- Provider Message ID (e.g., SendGrid ID)
    status VARCHAR(20), -- SENT, DELIVERED, OPENED, BOUNCED
    template_id UUID,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_comm_logs_case ON dispute.communication_logs(case_id);
COMMENT ON TABLE dispute.communication_logs IS 'Exhaustive log of all notifications sent during dispute lifecycle.';

------------------------------------------------------------------------------------------------
-- Serial No: 075
-- Table: T075 - peer_benchmarks
-- Schema: fraud
-- Description: Industry benchmarks for fraud rates.
-- Business Case: Merchants need context. "Is my 0.5% fraud rate good?" This table stores
--aggregated industry stats (e.g., Retail Average: 0.8%). Displaying this to merchants shows them
--where they stand and motivates them to adopt PARI's tools to beat the average.
-- KPIs: Benchmark Data Freshness.
-- Feature Reference: F141
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.peer_benchmarks (
    industry_code VARCHAR(20) NOT NULL,
    avg_fraud_rate NUMERIC(5,4),
    percentile_25 NUMERIC(5,4),
    percentile_75 NUMERIC(5,4),
    sample_size BIGINT,

    CONSTRAINT pk_peer_benchmarks PRIMARY KEY (industry_code)
);

COMMENT ON TABLE fraud.peer_benchmarks IS 'External market data used for comparative performance analytics.';

------------------------------------------------------------------------------------------------
-- Serial No: 076
-- Table: T076 - location_spoofs
-- Schema: fraud
-- Description: Detected location spoofing events.
-- Business Case: GPS spoofing apps are common. If a user claims to be in New York (IP) but their GPS
--says London, one is fake. This table logs these discrepancies. High frequency of spoofing is a
--massive red flag for fraud.
-- KPIs: Spoof Detection Accuracy.
-- Feature Reference: F071
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.location_spoofs (
    spoof_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    reported_loc NUMERIC(9,6), -- What the GPS said
    verified_loc NUMERIC(9,6), --What the IP/Tower Triangulation said
    distance_km NUMERIC(10,2),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.location_spoofs IS 'Records of inconsistencies between self-reported and verified geolocation data.';

------------------------------------------------------------------------------------------------
-- Serial No: 077
-- Table: T077 - abi_definitions
-- Schema: contract
-- Description: ABI definitions for smart contracts.
-- Business Case: Smart contracts have a specific interface (ABI - Application Binary Interface).
--This table stores the valid JSON definition of these interfaces. It ensures that when the system
--executes a contract clause, it passes the correct data types (e.g., uint256 vs string).
-- KPIs: Execution Validity.
-- Feature Reference: F153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.abi_definitions (
    abi_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    version VARCHAR(20),
    definition_json JSONB NOT NULL,

    CONSTRAINT abi_name_version UNIQUE (name, version)
);

COMMENT ON TABLE contract.abi_definitions IS 'Interface specifications for deterministic smart contract execution.';

------------------------------------------------------------------------------------------------
-- Serial No: 078
-- Table: T078 - rule_audit
-- Schema: fraud
-- Description: Audit trail for rule changes.
-- Business Case: Rules (e.g., "Block > $1000") are powerful but dangerous. This table audits every
--change to a rule. Who changed it? What was the old value? What is the new one? This prevents
--"rogue admins" from opening the gates to fraud or accidentally blocking all traffic.
-- KPIs: Audit Trail Completeness.
-- Feature Reference: F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.rule_audit (
    rule_id UUID, -- Reference to the velocity_rules or similar
    changed_by UUID NOT NULL,
    old_value JSONB,
    new_value JSONB,
    change_type VARCHAR(20) CHECK (change_type IN ('CREATE', 'UPDATE', 'DELETE')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rule_audit_id ON fraud.rule_audit(rule_id);
COMMENT ON TABLE fraud.rule_audit IS 'Change-history log for fraud detection rule configurations.';

------------------------------------------------------------------------------------------------
-- Serial No: 079
-- Table: T079 - hyperparameters
-- Schema: ml
-- Description: Hyperparameters for model runs.
-- Business Case: Model performance depends heavily on hyperparameters (learning rate, batch size).
--This table stores the specific settings used for every training run. This is essential for
--reproducibility—if a specific run was great, we need to know exactly what settings were used to
--recreate it.
-- KPIs: Parameter Optimization Efficiency.
-- Feature Reference: F002
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.hyperparameters (
    run_id UUID REFERENCES ml.retraining_jobs(job_id),
    param_name VARCHAR(100) NOT NULL,
    param_value TEXT, -- Stored as text to handle various types (int, float, string array)

    CONSTRAINT pk_hyperparams UNIQUE (run_id, param_name)
);

COMMENT ON TABLE ml.hyperparameters IS 'Configuration snapshot for machine learning experiment runs.';

------------------------------------------------------------------------------------------------
-- Serial No: 080
-- Table: T080 - refund_transactions
-- Schema: dispute
-- Description: Financial ledger entries for refunds.
-- Business Case: The "General Ledger" for refunds. It tracks the double-entry accounting: Debit
--the Merchant Account, Credit the Exchange/Reserve Account. This table is critical for the
--Finance team (F075) to balance the books at the end of the day.
-- KPIs: Ledger Balance Accuracy.
-- Feature Reference: F090
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.refund_transactions (
    tx_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    debit_account VARCHAR(100) NOT NULL,
    credit_account VARCHAR(100) NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    settlement_batch_id VARCHAR(100),

    -- Metadata
    posted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.refund_transactions IS 'Double-entry accounting records for financial settlement of refunds.';

------------------------------------------------------------------------------------------------
-- Serial No: 081
-- Table: T081 - synthetic_id_signals
-- Schema: fraud
-- Description: Signals for synthetic identity detection.
-- Business Case: Synthetic identities (combining real SSN with fake name) are hard to catch. This
--table stores weak signals that, when combined, indicate a synthetic ID (e.g., IP doesn't match
--name region, name has weird entropy). These signals feed a specific ML model (F049).
-- KPIs: Synthetic ID Detection Rate.
-- Feature Reference: F049
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.synthetic_id_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    signal_type VARCHAR(50) NOT NULL, -- 'NAME_ENTROPY_HIGH', 'IP_NAME_MISMATCH'
    risk_contribution NUMERIC(3,2),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_synthetic_signals_user ON fraud.synthetic_id_signals(user_hash);
COMMENT ON TABLE fraud.synthetic_id_signals IS 'Feature storage for algorithms designed to detect fictitious identities.';

------------------------------------------------------------------------------------------------
-- Serial No: 082
-- Table: T082 - periodic_limits
-- Schema: fraud
-- Description: Limits per period (daily/weekly).
-- Business Case: Responsible gaming and fraud prevention require caps. A user shouldn't spend
--$100k in 10 minutes unless verified. This table tracks the rolling counters for these limits
--against user risk profiles (F140).
-- KPIs: Limit Enforcement Accuracy.
-- Feature Reference: F115
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.periodic_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    period_type VARCHAR(20) NOT NULL CHECK (period_type IN ('DAILY', 'WEEKLY', 'MONTHLY')),
    max_amount NUMERIC(15,2) NOT NULL,
    current_amount NUMERIC(15,2) DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_periodic_limits_entity ON fraud.periodic_limits(entity_id, period_type);
COMMENT ON TABLE fraud.periodic_limits IS 'Real-time counters for enforcing volume caps on entity spending.';

------------------------------------------------------------------------------------------------
-- Serial No: 083
-- Table: T083 - recurring_payments
-- Schema: fraud
-- Description: Metadata for recurring subscriptions.
-- Business Case: Subscriptions are a major source of "I didn't authorize this" disputes (often
--user forgetfulness). This table tracks active subscriptions. If a user disputes a recurring
--charge, we can check here if they previously authorized the subscription, helping to resolve
--the dispute quickly.
-- KPIs: Subscription Retrieval Speed.
-- Feature Reference: F085
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.recurring_payments (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    user_hash VARCHAR(64) NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3),
    interval VARCHAR(20), -- 'MONTHLY', 'YEARLY'
    next_billing_date DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_recurring_pay_user ON fraud.recurring_payments(user_hash);
COMMENT ON TABLE fraud.recurring_payments IS 'Registry for subscription-based payment arrangements facilitating dispute validation.';

------------------------------------------------------------------------------------------------
-- Serial No: 084
-- Table: T084 - dark_patterns
-- Schema: fraud
-- Description: Detected dark patterns on merchant sites.
-- Business Case: "Dark patterns" are UI tricks that trick users into buying things (e.g., hidden
--checkboxes). PARI scans merchant sites. If found, we log it here. This protects users and
--protects PARI from being associated with predatory merchants.
-- KPIs: Pattern Detection Rate.
-- Feature Reference: F101
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.dark_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_url TEXT NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- 'CONFUSION', 'SNEAK_INTO_BASKET'
    severity VARCHAR(20),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'FLAGGED' -- FLAGGED, REMOVED, IGNORED
);

COMMENT ON TABLE fraud.dark_patterns IS 'Log of deceptive user interface elements detected on partner platforms.';

------------------------------------------------------------------------------------------------
-- Serial No: 085
-- Table: T085 - fraud_costs
-- Schema: fraud
-- Description: Detailed breakdown of fraud costs.
-- Business Case: "Fraud" isn't just the lost transaction value; it's fees, chargeback penalties,
--and labor costs for disputes. This table attributes *every* cost associated with a fraudulent
--transaction. It provides the true "Total Cost of Ownership" for fraud events.
-- KPIs: Cost Attribution Accuracy.
-- Feature Reference: F120
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_costs (
    cost_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    cost_type VARCHAR(50) NOT NULL CHECK (cost_type IN ('TRANSACTION_VALUE', 'REFUND_FEE', 'CHARGEBACK_PENALTY', 'LABOR_COST')),
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_fraud_costs_tx ON fraud.fraud_costs(transaction_hash);
COMMENT ON TABLE fraud.fraud_costs IS 'Granular financial impact analysis of fraud incidents beyond simple lost revenue.';

------------------------------------------------------------------------------------------------
-- Serial No: 086
-- Table: T086 - active_learning_queue
-- Schema: ml
-- Description: Data points labeled for active learning.
-- Business Case: Humans are expensive, ML is cheap, but ML needs labels. This table prioritizes
--which "unknown" transactions the Humans should look at first to generate labels. It picks
--transactions where the ML model is most "uncertain" (e.g., 50/50 fraud probability), maximizing
--the value of the human's time.
-- KPIs: Label Efficiency (Model improvement per label).
-- Feature Reference: F061
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.active_learning_queue (
    queue_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    model_prediction NUMERIC(5,2),
    uncertainty_score NUMERIC(5,2) NOT NULL, -- High uncertainty = High priority
    labeled BOOLEAN DEFAULT FALSE,
    labeler_id UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_al_queue_uncertainty ON ml.active_learning_queue(uncertainty_score DESC) WHERE labeled IS FALSE;
COMMENT ON TABLE ml.active_learning_queue IS 'Prioritization list for human-in-the-loop model training.';

------------------------------------------------------------------------------------------------
-- Serial No: 087
-- Table: T087 - partial_refunds
-- Schema: dispute
-- Description: Logic for change in partial refunds.
-- Business Case: A user might want a partial refund (e.g., returned 1 of 2 items). In a blinded
--system, this is complex because you can't just subtract from the coin. This table tracks the
--"Change" logic—calculating how to issue the refund and perhaps generate a new blinded coin for
--the remaining balance if necessary (though PARI logic usually treats it as a new credit).
-- KPIs: Calculation Accuracy.
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.partial_refunds (
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    original_amount NUMERIC(15,2) NOT NULL,
    refund_amount NUMERIC(15,2) NOT NULL,
    change_amount NUMERIC(15,2),

    CONSTRAINT pk_partial_refunds PRIMARY KEY (refund_id)
);

COMMENT ON TABLE dispute.partial_refunds IS 'Financial logic tracking for non-total reimbursement scenarios.';

------------------------------------------------------------------------------------------------
-- Serial No: 088
-- Table: T088 - transaction_narratives
-- Schema: fraud
-- Description: Full text search index for narratives.
-- Business Case: Transaction notes (memo fields) often contain clues. Users might write "for mom"
--or "bitcoin". This table uses Postgres Full Text Search (FTS) capabilities to index these notes
--for rapid keyword searching (F142).
-- KPIs: Search Latency.
-- Feature Reference: F142
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_narratives (
    tx_hash VARCHAR(64) PRIMARY KEY,
    narrative_text TEXT NOT NULL,
    tsvector TSVECTOR,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create an index for full text search
CREATE INDEX idx_narratives_fts ON fraud.transaction_narratives USING GIN(tsvector);
COMMENT ON TABLE fraud.transaction_narratives IS 'Optimized full-text search repository for transaction memos and descriptions.';

------------------------------------------------------------------------------------------------
-- Serial No: 089
-- Table: T089 - api_keys
-- Schema: fraud
-- Description: API keys for external fraud partners.
-- Business Case: PARI shares fraud intelligence (Hashes of bad cards) with partner banks via an
--API. This table manages the authentication for that API (F127). It ensures only authorized
--partners can access the data and tracks usage quotas.
-- KPIs: API Security Incidents.
-- Feature Reference: F127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.api_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_key_hash VARCHAR(255) NOT NULL UNIQUE, -- Hashed secret
    partner_name VARCHAR(255) NOT NULL,
    permissions JSONB, -- {"read_sar": true, "write_blacklist": false}
    rate_limit_tier VARCHAR(50),
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

COMMENT ON TABLE fraud.api_keys IS 'Access control management for external fraud intelligence sharing endpoints.';

------------------------------------------------------------------------------------------------
-- Serial No: 090
-- Table: T090 - maintenance_windows
-- Schema: system
-- Description: Scheduled maintenance for fraud systems.
-- Business Case: Fraud systems cannot go down unexpectedly. All maintenance must be scheduled and
--announced. This table defines these windows. During these times, the system might switch to
--"Safe Mode" (rule-based only) or route traffic to a secondary data center (Geo-DNS F094).
-- KPIs: Maintenance Schedule Adherence.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system.maintenance_windows (
    window_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    affected_components TEXT[], -- ['LSTM_ENGINE', 'DB_REPLICA']
    description TEXT,
    status VARCHAR(20) DEFAULT 'SCHEDULED', -- SCHEDULED, IN_PROGRESS, COMPLETED
    owner_id UUID
);

COMMENT ON TABLE system.maintenance_windows IS 'Planned downtime registry ensuring high availability coordination.';

------------------------------------------------------------------------------------------------
-- Serial No: 091
-- Table: T091 - fraud_maps
-- Schema: fraud
-- Description: Data for fraud heatmaps.
-- Business Case: "Heatmaps" visually show where fraud is happening (e.g., "High fraud in specific
--zip code"). This table aggregates data by region to feed these visualizations (F080). It helps
--risk managers geographically target their prevention efforts.
-- KPIs: Data Aggregation Latency.
-- Feature Reference: F080
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_maps (
    region_code VARCHAR(20) NOT NULL, -- Could be Country, State, or Zip
    granularity VARCHAR(20) NOT NULL, -- 'COUNTRY', 'STATE', 'ZIP'
    fraud_count BIGINT DEFAULT 0,
    total_count BIGINT DEFAULT 0,
    risk_ratio NUMERIC(5,4),
    date DATE NOT NULL,

    CONSTRAINT pk_fraud_maps UNIQUE (region_code, granularity, date)
);

CREATE INDEX idx_fraud_maps_date ON fraud.fraud_maps(date);
COMMENT ON TABLE fraud.fraud_maps IS 'Aggregated geographic statistics for visual risk intelligence.';

------------------------------------------------------------------------------------------------
-- Serial No: 092
-- Table: T092 - wallet_security_events
-- Schema: fraud
-- Description: Security events from wallet app.
-- Business Case: The Wallet App is a vector for attacks (rooting, hooking). This table logs security
--events from the client side (e.g., "Debugging enabled", "App backgrounded during pin entry"). These
--client-side events enrich the server-side fraud score.
-- KPIs: Event Ingestion Rate.
-- Feature Reference: F030
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.wallet_security_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_wallet_sec_user ON fraud.wallet_security_events(user_hash);
COMMENT ON TABLE fraud.wallet_security_events IS 'Client-side telemetry regarding the security posture of the user device.';

------------------------------------------------------------------------------------------------
-- Serial No: 093
-- Table: T093 - model_artifacts
-- Schema: ml
-- Description: Storage locations for model files.
-- Business Case: Trained models are large files (weights). We don't store the BLOB in Postgres; we
--store the URI (S3 path). This table tracks these files. When the system loads a model (T002),
--it uses this table to find the file. It also tracks versioning (weights vs config).
-- KPIs: Artifact Retrieval Speed.
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_artifacts (
    artifact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID,
    storage_uri TEXT NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('WEIGHTS', 'CONFIG', 'CHECKPOINT')),
    file_size_bytes BIGINT,
    checksum CHAR(64),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_artifacts IS 'Metadata index for externalized machine learning model storage.';

------------------------------------------------------------------------------------------------
-- Serial No: 094
-- Table: T094 - escalation_rules
-- Schema: dispute
-- Description: Rules for auto-escalating cases.
-- Business Case: Not all disputes are equal. High value or VIP users need faster escalation. This
--table defines the logic matrix: "IF amount > $10,000 AND user = VIP, escalate to Level 3". It
--automates the triage process (F045).
-- KPIs: Triage Accuracy.
-- Feature Reference: F045
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.escalation_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    condition_json JSONB NOT NULL, -- {"amount": {">": 10000}, "user_tier": "VIP"}
    escalation_level INTEGER NOT NULL,
    assigned_role VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.escalation_rules IS 'Logic definitions for automated case prioritization and routing.';

------------------------------------------------------------------------------------------------
-- Serial No: 095
-- Table: T095 - session_risks
-- Schema: fraud
-- Description: Risk associated with a specific session.
-- Business Case: Sometimes a transaction looks okay, but the *session* is weird (e.g., 50 rapid
--clicks). This table aggregates risk at the session level. If a user is "speed running" a checkout,
--block them even if the individual transaction values are low.
-- KPIs: Session Risk Correlation.
-- Feature Reference: F119
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.session_risks (
    session_id VARCHAR(100) PRIMARY KEY,
    user_hash VARCHAR(64),
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    anomalies_detected INTEGER DEFAULT 0,
    ip_address INET,

    -- Metadata
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.session_risks IS 'Aggregated risk assessment tied to a specific user interaction session.';

------------------------------------------------------------------------------------------------
-- Serial No: 096
-- Table: T096 - external_contract_refs
-- Schema: contract
-- Description: References to external contract systems.
-- Business Case: PARI might sync contracts with external legal systems (e.g., DocuSign). This
--table maps the internal PARI contract ID to the external system's ID. It ensures we can link
--back and forth if the legal review happens outside PARI.
-- KPIs: Sync Accuracy.
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.external_contract_refs (
    ref_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_system VARCHAR(50) NOT NULL, -- 'DOCUSIGN', 'SALESFORCE'
    external_id VARCHAR(100) NOT NULL,
    pari_contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),

    CONSTRAINT pk_ext_contract_refs UNIQUE (external_system, external_id)
);

COMMENT ON TABLE contract.external_contract_refs IS 'Cross-reference mapping for integrated third-party contract management systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 097
-- Table: T097 - fraudster_profiles
-- Schema: fraud
-- Description: Aggregated profiles of known fraudsters.
-- Business Case: Intelligence on repeat offenders. This table aggregates known attributes of a
--fraudster (MOA - Modus Operandi). It links to the Watchlist but provides richer data (e.g., "This
--group usually targets electronics merchants").
-- KPIs: Profile Match Rate.
-- Feature Reference: F009
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraudster_profiles (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    moniker VARCHAR(100), -- Code name for the group/individual
    known_moa TEXT, -- Modus Operandi description
    risk_score INTEGER DEFAULT 100,
    associated_hashes TEXT[], -- Array of device/user hashes linked to this profile

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.fraudster_profiles IS 'Intelligence dossier on identified repeat offenders and fraud rings.';

------------------------------------------------------------------------------------------------
-- Serial No: 098
-- Table: T098 - email_headers
-- Schema: fraud
-- Description: Parsed headers from evidence emails.
-- Business Case: Phishing emails are common evidence. The *headers* of an email (SPF, DKIM,
--Received-From) prove whether an email is real or fake. This table stores the parsed headers so
--the automated analysis engine can validate the authenticity of the evidence.
-- KPIs: Header Parse Success Rate.
-- Feature Reference: F084
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.email_headers (
    header_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES dispute.case_evidence(evidence_id),
    header_name VARCHAR(100) NOT NULL,
    header_value TEXT NOT NULL
);

CREATE INDEX idx_email_headers_evidence ON fraud.email_headers(evidence_id);
COMMENT ON TABLE fraud.email_headers IS 'Structured storage for email metadata used in phishing evidence analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 099
-- Table: T099 - retraining_jobs
-- Schema: ml
-- Description: Async jobs for model training.
-- Business Case: Model training takes hours. This table tracks the job status (Pending -> Running ->
--Done/Failed). It allows the Ops team to monitor resource usage and identify if a training run has
--stalled. It links to the Hyperparameters (T079).
-- KPIs: Job Success Rate, Average Training Duration.
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.retraining_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    status ops.job_status NOT NULL DEFAULT 'pending',
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    model_id UUID, -- The result of the job
    cluster_node_id VARCHAR(100), -- Where it ran
    error_message TEXT
);

CREATE INDEX idx_retraining_jobs_status ON ml.retraining_jobs(status);
COMMENT ON TABLE ml.retraining_jobs IS 'Orchestration tracking for asynchronous machine learning model updates.';

------------------------------------------------------------------------------------------------
-- Serial No: 100
-- Table: T100 - configuration_history
-- Schema: system
-- Description: History of config changes for feature flags.
-- Business Case: If a feature flag (T020) is flipped and causes a system outage, we need to know
--*who* flipped it and *what* the previous value was to revert it immediately. This table provides
--that rollback capability and audit trail.
-- KPIs: Config Retrieval Speed.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system.configuration_history (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    changed_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_config_history_flag ON system.configuration_history(flag_name);
COMMENT ON TABLE system.configuration_history IS 'Immutable audit log of system-wide configuration parameter modifications.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 2 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER trg_user_risk_history_timestamp
    BEFORE UPDATE ON fraud.user_risk_history
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_insurance_claims_timestamp
    BEFORE UPDATE ON fraud.insurance_claims
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_voice_prints_timestamp
    BEFORE UPDATE ON fraud.voice_prints
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_escalation_rules_timestamp
    BEFORE UPDATE ON dispute.escalation_rules
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_fraudster_profiles_timestamp
    BEFORE UPDATE ON fraud.fraudster_profiles
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_session_risks_timestamp
    BEFORE UPDATE ON fraud.session_risks
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 2: Tables 051-100)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 3)
-- =============================================================================================
-- Tables T101 - T150
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 101
-- Table: T101 - dispute_templates
-- Schema: dispute
-- Description: Templates for dispute responses.
-- Business Case: Consistency and speed in communication are vital for customer satisfaction during
--stressful disputes. This table stores pre-written email and response templates (e.g., "Refund Approved",
--"Evidence Required"). It supports multi-language content and variable substitution (e.g., {{case_id}}).
--By using templates, agents reduce response time significantly and ensure legal compliance in language
--used. It also serves as the basis for the "Automated Response" system (F116) when low-risk cases are
--resolved instantly by the bot.
-- KPIs: Template Usage Rate, Agent Response Time.
-- Feature Reference: F024
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.dispute_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    language CHAR(2) NOT NULL DEFAULT 'en',
    category VARCHAR(50) NOT NULL, -- e.g., 'OPENING', 'EVIDENCE_REQUEST', 'CLOSURE'
    subject VARCHAR(255),
    content_text TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    required_variables TEXT[], -- e.g., '{merchant_name, refund_amount}'

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE INDEX idx_dispute_templates_cat ON dispute.dispute_templates(category, language);
COMMENT ON TABLE dispute.dispute_templates IS 'Library of standardized communication content for dispute agents and bots.';

------------------------------------------------------------------------------------------------
-- Serial No: 102
-- Table: T102 - voice_records
-- Schema: dispute
-- Description: Storage references for voice notes.
-- Business Case: Sometimes text isn't enough. A user might want to leave a voice note explaining
--their side of the story. This table stores the reference to the audio file in the object store.
--It links to the case and tracks the duration. This evidence can be crucial for "he said, she said"
--scenarios. It integrates with the Voice Biometrics system (F124) to verify that the voice
--belongs to the account holder.
-- KPIs: Storage Retrieval Speed, Voice Note Attachment Rate.
-- Feature Reference: F077
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.voice_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    storage_path TEXT NOT NULL,
    file_hash CHAR(64),
    duration_sec INTEGER,
    transcript_text TEXT, -- Optional ASR result
    file_format VARCHAR(10) DEFAULT 'MP3',

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE dispute.voice_records IS 'Index for audio evidence submitted by users during dispute cases.';

------------------------------------------------------------------------------------------------
-- Serial No: 103
-- Table: T103 - merchant_categories
-- Schema: fraud
-- Description: Mapping of merchants to MCC codes.
-- Business Case: Different industries have vastly different risk profiles (Jewelry vs Groceries).
--This table links a Merchant ID to their Merchant Category Code (MCC). The Risk Engine uses this
--mapping to apply industry-specific rules (e.g., "High Velocity check for Electronics is stricter").
--It also allows for automated "Group Risk" analysis—if one Electronics merchant is hit by a fraud
--ring, others in the same category are put on alert.
-- KPIs: Category Coverage Rate, Risk Stratification Efficiency.
-- Feature Reference: F092, F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_categories (
    merchant_id UUID NOT NULL,
    mcc_code CHAR(4) NOT NULL, -- Standard ISO 18245
    description VARCHAR(255),
    risk_level VARCHAR(20) DEFAULT 'MEDIUM', -- OVERWRITE based on MCC
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_merchant_categories PRIMARY KEY (merchant_id, mcc_code)
);

COMMENT ON TABLE fraud.merchant_categories IS 'Industry classification mapping for context-aware risk assessment.';

------------------------------------------------------------------------------------------------
-- Serial No: 104
-- Table: T104 - risk_thresholds
-- Schema: fraud
-- Description: Dynamic thresholds for blocking.
-- Business Case: A static score (e.g., "Block if > 80") doesn't work for everyone. A VIP might
--get blocked at 95, a new user at 60. This table stores the dynamic thresholds for different risk
--tiers. It supports the "Adaptive Threshold Tuning" feature (F027). It also allows temporal changes—
--thresholds can be lowered system-wide during known high-fraud periods (e.g., Black Friday).
-- KPIs: Threshold Update Latency, False Positive Reduction.
-- Feature Reference: F027, F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.risk_thresholds (
    threshold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_tier VARCHAR(20) NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
    min_score_for_block INTEGER NOT NULL CHECK (min_score_for_block BETWEEN 0 AND 100),
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

CREATE INDEX idx_risk_thresholds_tier ON fraud.risk_thresholds(risk_tier, effective_date);
COMMENT ON TABLE fraud.risk_thresholds IS 'Configurable score limits determining the friction applied to transactions.';

------------------------------------------------------------------------------------------------
-- Serial No: 105
-- Table: T105 - refund_reasons
-- Schema: dispute
-- Description: Detailed reason codes mapping.
-- Business Case: Analytics drive business decisions. This table defines the standardized taxonomy of
--why refunds happen. It maps internal codes (e.g., "R01") to human-readable descriptions and categories.
--This granularity allows the business to distinguish between "Product Defect" (Merchant problem) and
--"I changed my mind" (Customer problem), feeding the ROI calculator and dashboard.
-- KPIs: Reason Code Assignment Accuracy.
-- Feature Reference: F115
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.refund_reasons (
    code_id SERIAL PRIMARY KEY,
    code VARCHAR(10) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL, -- MERCHANT_FAULT, BUYER_REMORSE, FRAUD
    requires_evidence BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.refund_reasons IS 'Canonical dictionary of motivations behind refund requests.';

------------------------------------------------------------------------------------------------
-- Serial No: 106
-- Table: T106 - smpc_keys
-- Schema: fraud
-- Description: Keys for Secure Multi-Party Computation.
-- Business Case: PARI wants to share fraud intelligence (e.g., "Is this email bad?") with other banks
--without sharing the actual email list. SMPC allows this computation. This table stores the public
--shares or keys required for the joint computation rounds. It enables the "Collaborative Fraud
--Intelligence" feature (F043) while strictly maintaining privacy.
-- KPIs: Computation Success Rate, Key Sync Latency.
-- Feature Reference: F068
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.smpc_keys (
    party_id UUID NOT NULL,
    key_id UUID DEFAULT uuid_generate_v4(),
    computation_round BIGINT NOT NULL,
    public_share TEXT NOT NULL, -- Hex string
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_smpc_keys PRIMARY KEY (party_id, computation_round)
);

COMMENT ON TABLE fraud.smpc_keys IS 'Cryptographic artifacts enabling privacy-preserving collaborative fraud detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 107
-- Table: T107 - identity_providers
-- Schema: fraud
-- Description: Config for IdP verification (e.g., SIM swap).
-- Business Case: The system relies on external Identity Providers (Telecoms, Credit Bureaus) to
--verify user attributes. This table stores the connection details (API Endpoints, Auth Tokens) and
--SLA expectations. It ensures that if a provider is down, the system can failover gracefully or mark
--checks as "Skipped" rather than failing the transaction.
-- KPIs: Provider Availability, API Success Rate.
-- Feature Reference: F086
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.identity_providers (
    provider_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    provider_type VARCHAR(50) NOT NULL, -- 'TELECOM', 'CREDIT_BUREAU', 'KYC_VENDOR'
    api_endpoint TEXT,
    auth_token_encrypted BYTEA,
    sla_promise_ms INTEGER,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE fraud.identity_providers IS 'Registry of external third-party services used for identity verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 108
-- Table: T108 - contract_states
-- Schema: contract
-- Description: State transitions for contracts.
-- Business Case: Contracts are not static; they evolve. Created -> Signed -> Funded -> Settled.
--This table implements the state machine logic. It defines valid transitions to prevent illegal
--state changes (e.g., jumping from "Created" to "Settled" without "Signed"). This ensures the
--integrity of the contract lifecycle and provides a clear history for audit.
-- KPIs: State Transition Validation Rate.
-- Feature Reference: F153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.contract_states (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    from_state VARCHAR(50),
    to_state VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    triggered_by VARCHAR(100) -- USER, SYSTEM, ORACLE
);

CREATE INDEX idx_contract_states_contract ON contract.contract_states(contract_id);
COMMENT ON TABLE contract.contract_states IS 'State machine audit trail tracking the lifecycle progression of digital contracts.';

------------------------------------------------------------------------------------------------
-- Serial No: 109
-- Table: T109 - carrier_integration
-- Schema: dispute
-- Description: Config for shipping carriers.
-- Business Case: To track a package automatically (F128), we need to know how to talk to the carrier.
--This table stores the API mapping for carriers like FedEx, UPS, and DHL. It includes URL templates
--(e.g., `https://api.fedex.com/track/{number}`) and authentication. It ensures the system is
--extensible to new shipping partners globally.
-- KPIs: Carrier Sync Success Rate.
-- Feature Reference: F128
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.carrier_integration (
    carrier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    tracking_api_url TEXT NOT NULL,
    tracking_api_key_encrypted BYTEA,
    priority_level INTEGER DEFAULT 1, -- 1 = High Priority for API calls
    supported_countries CHAR(2)[],
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.carrier_integration IS 'Configuration registry for logistics provider API connections.';

------------------------------------------------------------------------------------------------
-- Serial No: 110
-- Table: T110 - ground_truth_labels
-- Schema: ml
-- Description: Human-verified labels for transactions.
-- Business Case: ML models need a "Ground Truth" to learn from. When a human investigator confirms a
--transaction was "Fraud" or "Legit", that fact is stored here. This is the gold standard dataset.
--It is used to calculate the actual accuracy of the live model (F159) and is the primary source
--for retraining the LSTM network.
-- KPIs: Label Quality (Consensus Rate), Labeling Velocity.
-- Feature Reference: F159
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.ground_truth_labels (
    tx_hash VARCHAR(64) PRIMARY KEY,
    label BOOLEAN NOT NULL, -- True = Fraud
    verified_by UUID NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    confidence_level VARCHAR(20) -- HIGH, MEDIUM, LOW
);

COMMENT ON TABLE ml.ground_truth_labels IS 'The verified dataset of transaction outcomes used for supervised learning.';

------------------------------------------------------------------------------------------------
-- Serial No: 111
-- Table: T111 - device_whitelist
-- Schema: fraud
-- Description: Whitelisted devices for users.
-- Business Case: High-value users want friction-free experiences. If a user explicitly whitelists
--their personal laptop, the system skips strict device integrity checks (F070) for that device. This
--table stores these trusted relationships. It balances security (checking unknown devices) with
--usability (trusting known devices).
-- KPIs: False Positive Reduction via Whitelist.
-- Feature Reference: F047
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_whitelist (
    user_hash VARCHAR(64) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    nickname VARCHAR(100), -- e.g., "My MacBook"
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional expiry for security

    CONSTRAINT pk_device_whitelist PRIMARY KEY (user_hash, device_hash)
);

COMMENT ON TABLE fraud.device_whitelist IS 'User-defined list of trusted hardware identifiers to reduce authentication friction.';

------------------------------------------------------------------------------------------------
-- Serial No: 112
-- Table: T112 - case_tags
-- Schema: dispute
-- Description: Tagging system for cases.
-- Business Case: Not all cases fit into rigid categories. Tags provide flexible metadata. Agents
--can tag a case as "VIP", "Legal Threat", or "Pressing". These tags help with filtering queues
--and generating ad-hoc reports (e.g., "Show me all 'Pressing' cases from Merchants in Tier 1"). It
--enhances the flexibility of the case management system.
-- KPIs: Tag Utilization Rate.
-- Feature Reference: F097
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.case_tags (
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    tag VARCHAR(50) NOT NULL,
    applied_by UUID,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_case_tags PRIMARY KEY (case_id, tag)
);

CREATE INDEX idx_case_tags_tag ON dispute.case_tags(tag);
COMMENT ON TABLE dispute.case_tags IS 'Flexible metadata labeling system for organizing and filtering dispute workloads.';

------------------------------------------------------------------------------------------------
-- Serial No: 113
-- Table: T113 - fraud_trends
-- Schema: fraud
-- Description: Aggregated fraud trends over time.
-- Business Case: Executives need high-level views. This table pre-aggregates fraud counts by date and
--type. It powers the "Fraud Trends" dashboard and executive reports. By pre-calculating these heavy
--aggregates, the dashboard loads instantly, even over billions of transactions.
-- KPIs: Dashboard Load Time, Aggregation Accuracy.
-- Feature Reference: F080
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_trends (
    trend_date DATE NOT NULL,
    fraud_type VARCHAR(50) NOT NULL,
    count BIGINT DEFAULT 0,
    total_volume BIGINT DEFAULT 0,
    percentage NUMERIC(5,2),

    CONSTRAINT pk_fraud_trends UNIQUE (trend_date, fraud_type)
);

CREATE INDEX idx_fraud_trends_date ON fraud.fraud_trends(trend_date);
COMMENT ON TABLE fraud.fraud_trends IS 'Materialized time-series data for executive fraud analytics and reporting.';

------------------------------------------------------------------------------------------------
-- Serial No: 114
-- Table: T114 - feature_drift
-- Schema: ml
-- Description: Drift metrics for specific features.
-- Business Case: We know the *model* drifts, but *which* feature caused it? This table tracks the
--statistical distribution of individual features (e.g., "Average transaction amount shifted by 20%").
--This allows data scientists to pinpoint the root cause of model degradation (e.g., "Inflation is
--driving up amounts, so the model needs retraining").
-- KPIs: Feature Monitoring Sensitivity.
-- Feature Reference: F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    distribution_metric VARCHAR(50) NOT NULL, -- e.g., 'psi', 'kl_divergence'
    train_value NUMERIC(10,4),
    prod_value NUMERIC(10,4),
    distance_value NUMERIC(10,4),
    threshold_value NUMERIC(10,4),
    is_alerted BOOLEAN DEFAULT FALSE,

    -- Metadata
    date DATE NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_feature_drift_date ON ml.feature_drift(date);
COMMENT ON TABLE ml.feature_drift IS 'Granular statistical tracking of input data distribution changes.';

------------------------------------------------------------------------------------------------
-- Serial No: 115
-- Table: T115 - suspicious_logins
-- Schema: fraud
-- Description: Correlation of login and payment anomalies.
-- Business Case: Fraudsters often test credentials (login) before using them (payment). This table
--correlates events from the Identity Provider (M05/M17) with Payment events. If a login happens in
--Russia and a payment happens in Brazil 5 minutes later, it's highly suspicious. It enriches the
--fraud score with session context.
-- KPIs: Correlation Detection Rate.
-- Feature Reference: F130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.suspicious_logins (
    login_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    payment_link BOOLEAN DEFAULT FALSE, -- Did a payment follow this login?
    ip_address INET,
    device_hash VARCHAR(64),
    login_time TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_suspicious_logins_user ON fraud.suspicious_logins(user_hash, login_time);
COMMENT ON TABLE fraud.suspicious_logins IS 'Security event log correlating authentication attempts with transactional behavior.';

------------------------------------------------------------------------------------------------
-- Serial No: 116
-- Table: T116 - automated_responses
-- Schema: dispute
-- Description: Auto-generated responses for disputes.
-- Business Case: Low-effort disputes (e.g., obvious user error) can be resolved automatically. This
--table stores the content sent to the user by the bot. It logs which template was used and if the
--user accepted the resolution or escalated. This helps refine the automation logic—if 90% of
--automated responses get escalated, the logic is wrong.
-- KPIs: Auto-Resolution Acceptance Rate.
-- Feature Reference: F096, F116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.automated_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    template_id UUID REFERENCES dispute.dispute_templates(template_id),
    generated_text TEXT,
    sentiment_adjusted BOOLEAN DEFAULT FALSE,
    user_action VARCHAR(50), -- ACCEPTED, ESCALATED, IGNORED

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.automated_responses IS 'Log of bot-generated communications and their reception by customers.';

------------------------------------------------------------------------------------------------
-- Serial No: 117
-- Table: T117 - fraud_network_nodes
-- Schema: fraud
-- Description: Nodes for graph analysis.
-- Business Case: In graph theory (Social Graph Analysis F125), we need "Nodes" (Entities) and "Edges"
--(Relationships). While T023 stores edges, this table stores the properties of the nodes themselves.
--It includes metrics like "Centrality Score" (how important this node is to the network). High
--centrality nodes might be "Money Mules" or "Ring Leaders".
-- KPIs: Node Classification Accuracy.
-- Feature Reference: F125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_network_nodes (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_hash VARCHAR(64) NOT NULL UNIQUE,
    node_type VARCHAR(20) NOT NULL, -- USER, MERCHANT, WALLET
    risk_score INTEGER,
    centrality_score NUMERIC(5,2), -- How connected is this node?
    community_id UUID, -- Which cluster does it belong to?

    -- Metadata
    last_analyzed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.fraud_network_nodes IS 'Vertex properties for the graph-based fraud network analysis system.';

------------------------------------------------------------------------------------------------
-- Serial No: 118
-- Table: T118 - health_checks
-- Schema: system
-- Description: Results of system health pings.
-- Business Case: Uptime is critical. This table stores the results of synthetic health checks (Can I
--reach the DB? Can I reach the LSTM API?). It provides the data for the uptime dashboards and
--triggers alerting if health fails (F150). It creates a historical record of system reliability
--(SLA) for internal review.
-- KPIs: Check Frequency, Uptime % calculation.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system.health_checks (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL, -- e.g., 'fraud_lstm_service'
    status VARCHAR(20) NOT NULL CHECK (status IN ('UP', 'DOWN', 'DEGRADED')),
    latency_ms INTEGER,
    region VARCHAR(50) DEFAULT 'PRIMARY',

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_health_checks_time ON system.health_checks(timestamp DESC);
COMMENT ON TABLE system.health_checks IS 'Historical telemetry of service availability and response times.';

------------------------------------------------------------------------------------------------
-- Serial No: 119
-- Table: T119 - transaction_limits
-- Schema: fraud
-- Description: Dynamic transaction limits.
-- Business Case: Sometimes we need to hard stop transactions. This table enforces limits. Limits
--can be global (System down) or specific (User suspected of ATO). It supports the "Transaction
--Value Limiting" feature (F054). By updating this table, Ops can instantly throttle specific
--users without changing code.
-- KPIs: Limit Enforcement Latency.
-- Feature Reference: F054
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_limits (
    entity_id UUID,
    entity_type VARCHAR(20) NOT NULL,
    limit_type VARCHAR(50) NOT NULL, -- DAILY_MAX, PER_TX_MAX
    max_value NUMERIC(15,2) NOT NULL,
    current_value NUMERIC(15,2) DEFAULT 0,

    -- Metadata
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_transaction_limits UNIQUE (entity_id, entity_type, limit_type)
);

COMMENT ON TABLE fraud.transaction_limits IS 'Real-time enforcement constraints on transaction values and volumes.';

------------------------------------------------------------------------------------------------
-- Serial No: 120
-- Table: T120 - external_case_refs
-- Schema: dispute
-- Description: References to external legal/case systems.
-- Business Case: Complex fraud involves law enforcement or external arbitration. This table links
--the internal PARI Case ID to the external Case Number (e.g., Police Report #12345). It allows
--bi-directional tracking and ensures that evidence generated in PARI can be easily submitted to
--external bodies.
-- KPIs: Reference Linkage Accuracy.
-- Feature Reference: F052
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.external_case_refs (
    pari_case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    external_system VARCHAR(50) NOT NULL, -- 'POLICE', 'COURT', 'ARBITRATION_BODY'
    external_case_id VARCHAR(100) NOT NULL,
    link_direction VARCHAR(20) DEFAULT 'BIDIRECTIONAL', -- OUTBOUND, INBOUND
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_external_case_refs UNIQUE (external_system, external_case_id)
);

COMMENT ON TABLE dispute.external_case_refs IS 'Cross-reference mapping for interoperability with external legal and judicial systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 121
-- Table: T121 - chaos_experiments
-- Schema: ops
-- Description: Records of chaos engineering attacks.
-- Business Case: To ensure the system is resilient, we proactively break it (Chaos Engineering).
--This table records these experiments (e.g., "Killed LSTM Node X"). It tracks the result: Did the
--system recover? How long did it take? This data proves the system's robustness and highlights
--weaknesses before they cause real outages.
-- KPIs: Recovery Time Objective (RTO) Achievement, Experiment Coverage.
-- Feature Reference: F038
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.chaos_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_service VARCHAR(100) NOT NULL,
    attack_type VARCHAR(50) NOT NULL, -- LATENCY, POD_KILL, NETWORK_DROP
    fault_injected JSONB,
    result VARCHAR(20) NOT NULL CHECK (result IN ('SUCCESS', 'FAILURE', 'TIMEOUT')),
    recovery_time_ms INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.chaos_experiments IS 'Controlled disruption logs validating system fault tolerance and self-healing capabilities.';

------------------------------------------------------------------------------------------------
-- Serial No: 122
-- Table: T122 - test_case_executions
-- Schema: ops
-- Description: Logs of automated test cases.
-- Business Case: Continuous Deployment requires Continuous Testing. This table logs the execution
--of regression tests against the Fraud Rules and Models. If a deployment breaks a test, this table
--captures the failure reason. It ensures that code changes never degrade the core fraud detection
--capabilities.
-- KPIs: Test Pass Rate, Regression Detection Speed.
-- Feature Reference: F038
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.test_case_executions (
    execution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_suite_id UUID,
    test_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('PASS', 'FAIL', 'SKIPPED')),
    duration_ms INTEGER,
    failure_reason TEXT,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_test_executions_status ON ops.test_case_executions(status);
COMMENT ON TABLE ops.test_case_executions IS 'Execution history of automated quality assurance suites for fraud logic.';

------------------------------------------------------------------------------------------------
-- Serial No: 123
-- Table: T123 - deployment_pipelines
-- Schema: ops
-- Description: Tracks deployment history.
-- Business Case: Knowing exactly what version is running where is crucial for debugging. This table
--tracks every deployment of M03 microservices. It links the Service Name, Version, and Environment.
--If a bug is reported in Production, we check this table to see which version is live and when it
--was deployed.
-- KPIs: Deployment Frequency, Deployment Failure Rate.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.deployment_pipelines (
    pipeline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    environment VARCHAR(20) NOT NULL CHECK (environment IN ('DEV', 'STAGING', 'PROD')),
    deployed_by UUID NOT NULL,
    deployment_status VARCHAR(20) NOT NULL, -- PENDING, SUCCESS, FAILED, ROLLBACK
    rollback_plan_id UUID,

    -- Metadata
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.deployment_pipelines IS 'Change management log recording the release history of application components.';

------------------------------------------------------------------------------------------------
-- Serial No: 124
-- Table: T124 - spiffe_identities
-- Schema: sec
-- Description: SPIFFE/SPIRE identities for Zero-Trust.
-- Business Case: In a Zero Trust architecture (F138), every service needs an identity to talk to
--other services. This table stores the SPIFFE IDs (e.g., `spiffe://pari.system/ns/fraud/sa/lstm`).
--It ensures that only authenticated services can access sensitive data (like Fraud Scores) and that
--communications are encrypted via mTLS.
-- KPIs: Identity Provisioning Speed, mTLS Handshake Success.
-- Feature Reference: F017, M17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.spiffe_identities (
    identity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    spiffe_id TEXT NOT NULL UNIQUE,
    service_account VARCHAR(100) NOT NULL,
    trust_domain VARCHAR(100) NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

COMMENT ON TABLE sec.spiffe_identities IS 'Registry of cryptographic identities enabling Zero Trust network service mesh.';

------------------------------------------------------------------------------------------------
-- Serial No: 125
-- Table: T125 - hsm_audit_trail
-- Schema: sec
-- Description: Logs every key operation in the HSM.
-- Business Case: The Hardware Security Module (HSM) holds the root keys for signing contracts.
--Access to the HSM is the most sensitive action in the system. This table logs *every* operation
--(Sign, Decrypt, Generate Key), who requested it, and if it succeeded. It provides the ultimate
--non-repudiation audit for cryptographic operations.
-- KPIs: Audit Completeness (100% required).
-- Feature Reference: F008, F013
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hsm_audit_trail (
    hsm_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    operation_type VARCHAR(50) NOT NULL, -- SIGN, VERIFY, WRAP_KEY
    key_id VARCHAR(100),
    user_id UUID,
    success BOOLEAN NOT NULL,
    error_code VARCHAR(20),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hsm_audit_time ON sec.hsm_audit_trail(timestamp DESC);
COMMENT ON TABLE sec.hsm_audit_trail IS 'Immutable log of interactions with the Hardware Security Module for cryptographic root of trust.';

------------------------------------------------------------------------------------------------
-- Serial No: 126
-- Table: T126 - gdpr_deletion_queue
-- Schema: legal
-- Description: Queue for processing "Right to be Forgotten".
-- Business Case: GDPR requires user data to be deleted upon request. However, fraud data must be
--kept for 5-7 years by law. This table manages the conflict. When a user requests deletion, they
--enter this queue. The system anonymizes (hashes) PII but retains the fraud data, satisfying both
--GDPR and Financial Regulations.
-- KPIs: Deletion Request Processing Time (SLA).
-- Feature Reference: F035
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.gdpr_deletion_queue (
    deletion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'PROCESSING', 'DONE', 'FAILED')),
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    requested_by VARCHAR(255) -- The ticket ID from the privacy portal
);

CREATE INDEX idx_gdpr_queue_status ON legal.gdpr_deletion_queue(status);
COMMENT ON TABLE legal.gdpr_deletion_queue IS 'Workflow tracker for privacy mandates ensuring compliance with data retention laws.';

------------------------------------------------------------------------------------------------
-- Serial No: 127
-- Table: T127 - sanction_screening_results
-- Schema: compliance
-- Description: Results of sanctions screening.
-- Business Case: Dealing with sanctioned entities (OFAC/UN) is illegal. This table stores the
--results of real-time screening checks against watchlists. If a "Hit" is found, the transaction
--is blocked and an audit trail is created here. It proves to regulators that PARI is actively
--preventing financial crime.
-- KPIs: Screening Latency, False Positive Hit Rate.
-- Feature Reference: F019, M05
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.sanction_screening_results (
    screen_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    list_name VARCHAR(50) NOT NULL, -- 'OFAC_SDN', 'UN_CONSOLIDATED'
    match_score NUMERIC(3,2),
    hit BOOLEAN DEFAULT FALSE,
    match_details JSONB,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sanction_screening_tx ON compliance.sanction_screening_results(transaction_hash);
COMMENT ON TABLE compliance.sanction_screening_results IS 'Record of automated checks against global sanctions and denied persons lists.';

------------------------------------------------------------------------------------------------
-- Serial No: 128
-- Table: T128 - dpia_assessments
-- Schema: compliance
-- Description: Data Protection Impact Assessments.
-- Business Case: New features that process user data require a DPIA to ensure privacy is baked in.
--This table stores the assessment (Risk Score, Mitigation Plan) for features like F051 (Model
--Explainability) or F003 (Behavioral Baselines). It forces the team to think about privacy before
--writing code.
-- KPIs: Assessment Completion Rate before Launch.
-- Feature Reference: F107
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.dpia_assessments (
    dpia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    mitigation_plan TEXT,
    approved_by UUID,
    approval_date DATE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.dpia_assessments IS 'Risk analysis documentation for new processing activities involving personal data.';

------------------------------------------------------------------------------------------------
-- Serial No: 129
-- Table: T129 - contract_legal_reviews
-- Schema: legal
-- Description: Tracks internal legal reviews.
-- Business Case: Some disputes go to court. The JSON-LD contracts (T007) might need review by the
--internal legal team before they are used as evidence. This table tracks that review process—was the
--contract valid? Were there any ambiguities? It ensures that PARI puts its best foot forward in
--legal battles.
-- KPIs: Legal Review Turnaround Time.
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.contract_legal_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    reviewer_id UUID NOT NULL,
    verdict VARCHAR(20) CHECK (verdict IN ('APPROVED', 'CONDITIONAL', 'REJECTED')),
    review_notes TEXT,

    -- Metadata
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE legal.contract_legal_reviews IS 'Approval workflow for legal validity of contract terms and evidence.';

------------------------------------------------------------------------------------------------
-- Serial No: 130
-- Table: T130 - synthetic_data_catalog
-- Schema: ml
-- Description: Metadata for synthetic datasets.
-- Business Case: We can't use real user data for testing. We generate synthetic data. This table
--catalogs these synthetic sets—how they were generated, what parameters were used, and where they are
--stored. It ensures that the test environment accurately mimics production without compromising
--privacy.
-- KPIs: Synthetic Data Fidelity.
-- Feature Reference: F130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.synthetic_data_catalog (
    dataset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_model_id UUID,
    generator_params JSONB,
    rows_count BIGINT,
    storage_path TEXT,
    fidelity_score NUMERIC(3,2), -- How close to real data is it?

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.synthetic_data_catalog IS 'Inventory of privacy-safe artificial data used for model testing and development.';

------------------------------------------------------------------------------------------------
-- Serial No: 131
-- Table: T131 - model_rollback_history
-- Schema: ml
-- Description: History of model rollbacks.
-- Business Case: Deployments fail. When a new model causes high false positives, we roll back
--immediately. This table records *why* the rollback happened and which version we reverted to. It
--is a critical tool for "Blameless Post-Mortems"—understanding what went wrong to prevent it in the
--future.
-- KPIs: Rollback Frequency, MTTR (Mean Time To Recover).
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_rollback_history (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    from_version VARCHAR(50), -- The bad version
    to_version VARCHAR(50), -- The good version
    reason TEXT NOT NULL,
    triggered_by_alert_id UUID,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_rollback_history IS 'Chronicle of model version reversions used for reliability analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 132
-- Table: T132 - data_lineage_graph
-- Schema: data
-- Description: Graph representation of data flow.
-- Business Case: "Where did this feature come from?" is a common question in data science. This
--table maps the lineage of data—from the Raw Event Log (Kafka) -> Cleaning -> Feature Store ->
--Training Data. If a bug is found in the cleaning logic, this table tells us exactly which
--models were affected.
-- KPIs: Lineage Coverage %.
-- Feature Reference: M10, F016
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS data.data_lineage_graph (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_type VARCHAR(50), -- TABLE, STREAM, API
    destination_type VARCHAR(50),
    transform_logic TEXT, -- SQL or Code snippet
    dependency_level INTEGER, -- 1 = Raw, 2 = Cleaned, 3 = Feature

    -- Metadata
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE data.data_lineage_graph IS 'Visual map dependencies tracking data flow from ingestion to model consumption.';

------------------------------------------------------------------------------------------------
-- Serial No: 133
-- Table: T133 - sms_delivery_logs
-- Schema: notify
-- Description: Logs of SMS delivery.
-- Business Case: SMS is used for 2FA (F025) and Alerts (F033). It costs money and can fail. This
--table logs every SMS attempt, the provider used, and the delivery status (Delivered, Bounced).
--It helps monitor provider reliability and prevents fraudsters from abusing the 2FA system
--(monitoring volume per number).
-- KPIs: SMS Delivery Success Rate, Cost per SMS.
-- Feature Reference: F033, F025
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify.sms_delivery_logs (
    sms_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    phone_hash VARCHAR(100) NOT NULL, -- Hashed for privacy
    provider VARCHAR(50) NOT NULL,
    message_id VARCHAR(100), -- Provider Message ID
    status VARCHAR(20) NOT NULL, -- SENT, DELIVERED, FAILED
    delivered_at TIMESTAMP WITH TIME ZONE,
    cost_credits NUMERIC(10,4),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sms_logs_status ON notify.sms_delivery_logs(status);
COMMENT ON TABLE notify.sms_delivery_logs IS 'Operational log of telephony notifications for security and alerting.';

------------------------------------------------------------------------------------------------
-- Serial No: 134
-- Table: T134 - push_notification_registrations
-- Schema: notify
-- Description: Device tokens for push notifications.
-- Business Case: In-app notifications (F136) are cheaper and faster than SMS. This table stores
--the Push Tokens (Apple APNS, Google FCM) for user devices. It allows the system to send real-time
--updates (e.g., "Your dispute was resolved") directly to the user's wallet app.
-- KPIs: Push Token Hit Rate, Bounce Rate.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify.push_notification_registrations (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    device_token TEXT NOT NULL,
    platform VARCHAR(20) NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_push_tokens_user ON notify.push_notification_registrations(user_hash);
COMMENT ON TABLE notify.push_notification_registrations IS 'Registry of endpoint identifiers for direct application messaging.';

------------------------------------------------------------------------------------------------
-- Serial No: 135
-- Table: T135 - email_bounce_handler
-- Schema: notify
-- Description: Tracks bounced emails.
-- Business Case: If a user's email is full or dead, we shouldn't keep sending to it (wastes money
--and looks spammy). This table processes bounces (Soft vs Hard). If an email hard bounces, we
--automatically update the user's preferences to stop sending emails there.
-- KPIs: Bounce Processing Accuracy.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify.email_bounce_handler (
    bounce_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    email_hash VARCHAR(100) NOT NULL,
    bounce_type VARCHAR(20) NOT NULL, -- SOFT, HARD
    diagnostic_code VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_email_bounce_hash ON notify.email_bounce_handler(email_hash);
COMMENT ON TABLE notify.email_bounce_handler IS 'Logs of failed email delivery attempts used for list hygiene.';

------------------------------------------------------------------------------------------------
-- Serial No: 136
-- Table: T136 - in_app_messages
-- Schema: notify
-- Description: Stores in-app notifications.
-- Business Case: Users need to know what's happening *inside* the app. This table acts as the
--inbox for the Wallet/Merchant Portal. It stores the title, body, and action link (e.g., "Click to
--view case"). Messages are marked read/unread.
-- KPIs: Message Read Rate.
-- Feature Reference: F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify.in_app_messages (
    msg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT,
    action_link TEXT,
    read_status BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_in_app_msgs_user ON notify.in_app_messages(user_hash, read_status);
COMMENT ON TABLE notify.in_app_messages IS 'User-centric inbox for time-sensitive operational and security alerts.';

------------------------------------------------------------------------------------------------
-- Serial No: 137
-- Table: T137 - merchant_credential_rotations
-- Schema: sec
-- Description: Audit log of API key rotations.
-- Business Case: API Keys must be rotated regularly for security. This table logs every rotation—
--which merchant, what the old key hash was, and what the new one is. It ensures that if a breach
--occurs, we know exactly which keys were compromised and when they were changed.
-- KPIs: Rotation Compliance %.
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.merchant_credential_rotations (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    old_key_hash CHAR(64) NOT NULL,
    new_key_hash CHAR(64) NOT NULL,
    rotated_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.merchant_credential_rotations IS 'Security log documenting the lifecycle of merchant API secrets.';

------------------------------------------------------------------------------------------------
-- Serial No: 138
-- Table: T138 - iso20022_message_store
-- Schema: integration
-- Description: Raw or parsed ISO 20022 messages.
-- Business Case: International banking speaks ISO 20022. When PARI integrates with global banks
--(M07), we receive these messages. This table stores the raw XML and the parsed JSON. It is the
--definitive source of truth for what the bank said about a transaction (e.g., "Payment Rejected").
-- KPIs: Message Parse Success Rate.
-- Feature Reference: F127, M07
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.iso20022_message_store (
    msg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    msg_type VARCHAR(50) NOT NULL, -- pacs.008, camt.053
    business_area VARCHAR(50),
    raw_xml TEXT,
    parsed_json JSONB,
    direction VARCHAR(20) CHECK (direction IN ('INBOUND', 'OUTBOUND')),

    -- Metadata
    ingestion_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_iso_msg_type ON integration.iso20022_message_store(msg_type);
COMMENT ON TABLE integration.iso20022_message_store IS 'Standardized storage for international financial messaging formats.';

------------------------------------------------------------------------------------------------
-- Serial No: 139
-- Table: T139 - e_invoice_linkages
-- Schema: integration
-- Description: Links disputes to e-invoices.
-- Business Case: In many countries (e.g., Italy with SDI), e-invoices are government
--certified. If a user disputes "Goods not received", we can check the e-invoice system. If the
--merchant sent the e-invoice, they legally sent the goods. This table links the PARI case to
--the government Invoice ID.
-- KPIs: Linkage Success Rate.
-- Feature Reference: F128, M22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.e_invoice_linkages (
    linkage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    e_invoice_id VARCHAR(100) NOT NULL UNIQUE,
    invoice_date DATE,
    tax_amount NUMERIC(15,2),
    supplier_vat VARCHAR(50)
);

COMMENT ON TABLE integration.e_invoice_linkages IS 'Connection to government tax systems for irrefutable proof of transaction legitimacy.';

------------------------------------------------------------------------------------------------
-- Serial No: 140
-- Table: T140 - ato_signals
-- Schema: fraud
-- Description: Account Takeover (ATO) specific signals.
-- Business Case: ATO is distinct from standard fraud. This table aggregates specific ATO indicators:
--failed logins, password resets, new device additions. If a user has a sudden spike in these, the
--risk score for ATO increases, prompting Step-Up Auth even for small transactions.
-- KPIs: ATO Detection Rate.
-- Feature Reference: F130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.ato_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    login_velocity INTEGER, -- Logins per minute
    new_device_count INTEGER, -- New devices seen today
    password_reset_attempts INTEGER,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ato_signals_user ON fraud.ato_signals(user_hash);
COMMENT ON TABLE fraud.ato_signals IS 'Aggregated security telemetry focused specifically on account intrusion attempts.';

------------------------------------------------------------------------------------------------
-- Serial No: 141
-- Table: T141 - promo_abuse_tracking
-- Schema: fraud
-- Description: Tracks usage of promotional codes.
-- Business Case: Fraudsters love free money. They create accounts just to harvest referral bonuses or
--promo codes. This table tracks promo usage. If one device/household claims 50 different "New
--User" promos, it is flagged as abuse (F140).
-- KPIs: Promo Abuse Detection Rate.
-- Feature Reference: F140, F155
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.promo_abuse_tracking (
    promo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    code_hash VARCHAR(100) NOT NULL,
    user_hash VARCHAR(64) NOT NULL,
    usage_count INTEGER DEFAULT 1,
    ip_address INET,
    device_fingerprint VARCHAR(64),
    suspicious_flag BOOLEAN DEFAULT FALSE,

    -- Metadata
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_promo_abuse_code ON fraud.promo_abuse_tracking(code_hash);
COMMENT ON TABLE fraud.promo_abuse_tracking IS 'Monitoring of incentive program utilization to prevent bonus harvesting fraud.';

------------------------------------------------------------------------------------------------
-- Serial No: 142
-- Table: T142 - loyalty_fraud_events
-- Schema: fraud
-- Description: Loyalty points manipulation.
-- Business Case: Loyalty points are currency. If points are stolen or generated fraudulently, it's a
--loss. This table tracks changes to loyalty point balances linked to payments. Unexplained jumps in
--points or circular transfer of points are logged here.
-- KPIs: Points Loss Prevention.
-- Feature Reference: F085
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.loyalty_fraud_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    points_delta INTEGER NOT NULL,
    fraud_score INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.loyalty_fraud_events IS 'Surveillance of alternative currency (loyalty points) for illicit manipulation.';

------------------------------------------------------------------------------------------------
-- Serial No: 143
-- Table: T143 - card_testing_patterns
-- Schema: fraud
-- Description: Card testing attacks.
-- Business Case: Bots test stolen cards by running small transactions ($1.00). This table identifies
--patterns: a merchant getting 100 declines for $1.00 in 1 minute. It feeds the "High-Frequency
--Filtering" feature (F062) to block these attacks early.
-- KPIs: Card Testing Detection Speed.
-- Feature Reference: F062
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.card_testing_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    declined_rate NUMERIC(5,2), -- % of declines
    small_amt_frequency INTEGER, -- Count of tx < $2.00
    unique_card_count INTEGER,
    bin_pattern VARCHAR(10), -- Common BIN if applicable
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.card_testing_patterns IS 'Identification of authorization attacks used to validate stolen payment credentials.';

------------------------------------------------------------------------------------------------
-- Serial No: 144
-- Table: T144 - refund_request_throttles
-- Schema: fraud
-- Description: Throttling of refund requests.
-- Business Case: Fraudsters might try to issue thousands of refund requests to crash the system or
--find a bug. This table implements "Leaky Bucket" or "Token Bucket" throttling per IP or Merchant.
--If they exceed the rate, subsequent requests are blocked.
-- KPIs: Throttle Enforcement Accuracy.
-- Feature Reference: F073, F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_request_throttles (
    throttle_key VARCHAR(100) PRIMARY KEY, -- IP:MerchantID composite key
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE fraud.refund_request_throttles IS 'Rate limiting controls for high-volume refund submission endpoints.';

------------------------------------------------------------------------------------------------
-- Serial No: 145
-- Table: T145 - archive_manifest
-- Schema: storage
-- Description: Manifest for cold storage.
-- Business Case: Cold storage (S3 Glacier) is cheap but slow. This table acts as the directory. It
--maps the Table Name and Date Range to the specific Archive ID. When an auditor asks for data from
--2020, we query this table to find which archive file to request from Glacier.
-- KPIs: Archive Retrieval Success Rate.
-- Feature Reference: F011, M11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.archive_manifest (
    manifest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    date_range DATERANGE NOT NULL,
    archive_id VARCHAR(100) NOT NULL, -- The S3/Glacier ID
    checksum CHAR(64) NOT NULL,
    size_bytes BIGINT,

    CONSTRAINT archive_manifest_unique UNIQUE (table_name, date_range)
);

CREATE INDEX idx_archive_manifest_table ON storage.archive_manifest(table_name);
COMMENT ON TABLE storage.archive_manifest IS 'Index of historical data batches moved to long-term cold storage solutions.';

------------------------------------------------------------------------------------------------
-- Serial No: 146
-- Table: T146 - cold_storage_retrieval
-- Schema: storage
-- Description: Retrieval requests from cold storage.
-- Business Case: Restoring from cold storage takes hours (and costs money). This table tracks these
--requests. It manages the status (Initiated -> Completed) and ensures the temporary restored files
--are deleted after the `restore_expiry` time to prevent runaway storage costs.
-- KPIs: Retrieval Time, Expiry Cleanup Efficiency.
-- Feature Reference: F011
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.cold_storage_retrieval (
    retrieval_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    archive_id VARCHAR(100) NOT NULL,
    requested_by UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'INITIATED', -- INITIATED, COMPLETED, EXPIRED
    temp_storage_uri TEXT,
    restore_expiry TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_cold_retrieval_status ON storage.cold_storage_retrieval(status);
COMMENT ON TABLE storage.cold_storage_retrieval IS 'Workflow tracker for restoring and expiring archived data segments.';

------------------------------------------------------------------------------------------------
-- Serial No: 147
-- Table: T147 - cache_invalidation_queue
-- Schema: perf
-- Description: Queue for invalidating Redis cache.
-- Business Case: The application uses Redis for speed. If DB data changes (e.g., a user is
--blocked), the cache must be invalidated. This table acts as a write-ahead queue for cache
--invalidation events. If Redis is down, the queue holds the keys to invalidate until it comes
--back up.
-- KPIs: Cache Inconsistency Window.
-- Feature Reference: F015
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS perf.cache_invalidation_queue (
    inv_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_key TEXT NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('INVALIDATE', 'UPDATE')),
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_cache_inv_queue ON perf.cache_invalidation_queue(processed_at) WHERE processed_at IS NULL;
COMMENT ON TABLE perf.cache_invalidation_queue IS 'Buffer for synchronizing high-speed cache layers with persistent storage.';

------------------------------------------------------------------------------------------------
-- Serial No: 148
-- Table: T148 - deadlock_monitor
-- Schema: db
-- Description: Logs of database deadlocks.
-- Business Case: Deadlocks stop transactions. This table captures the SQL involved, the victim
--process, and the timestamp. Analyzing this table helps DBAs optimize queries and locking strategies
--to prevent future deadlocks.
-- KPIs: Deadlock Frequency.
-- Feature Reference: F149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.deadlock_monitor (
    deadlock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    involved_queries TEXT,
    victim_pid INTEGER,
    blocked_pid INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE db.deadlock_monitor IS 'Diagnostic log recording resource contention events within the database engine.';

------------------------------------------------------------------------------------------------
-- Serial No: 149
-- Table: T149 - background_job_locks
-- Schema: db
-- Description: Advisory locks for distributed workers.
-- Business Case: We have multiple workers processing background jobs (e.g., retraining, archiving).
--We need to ensure two workers don't process the same job. This table uses Advisory Locks
--(Postgres feature) or simple row locking to coordinate these distributed processes.
-- KPIs: Lock Contention.
-- Feature Reference: F003
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.background_job_locks (
    job_name VARCHAR(100) PRIMARY KEY,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    locked_by_worker VARCHAR(100), -- Hostname/PID
    ttl INTERVAL DEFAULT '1 hour' -- Time to live
);

COMMENT ON TABLE db.background_job_locks IS 'Coordination mechanism ensuring singleton execution of periodic maintenance tasks.';

------------------------------------------------------------------------------------------------
-- Serial No: 150
-- Table: T150 - metric_alerts
-- Schema: ops
-- Description: Alerts for Prometheus/Grafana.
-- Business Case: Ops needs to know when things break. This table configures the alerting rules
--(e.g., "If P99 Latency > 100ms, Page the DBA"). It centralizes alert definitions so they can be
--version controlled and audited.
-- KPIs: Alert Coverage, Mean Time To Acknowledge (MTTA).
-- Feature Reference: F032, F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.metric_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL, -- fraud_latency_p99
    threshold NUMERIC(10,2) NOT NULL,
    condition VARCHAR(20) NOT NULL CHECK (condition IN ('>', '<', '==')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('INFO', 'WARN', 'CRITICAL')),
    notification_channel VARCHAR(100), -- Slack channel, Email list
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT alert_unique UNIQUE (metric_name, threshold, condition)
);

COMMENT ON TABLE ops.metric_alerts IS 'Configuration storage for system health monitoring and automated incident escalation.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 3 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER trg_dispute_templates_timestamp
    BEFORE UPDATE ON dispute.dispute_templates
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_risk_thresholds_timestamp
    BEFORE UPDATE ON fraud.risk_thresholds
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_transaction_limits_timestamp
    BEFORE UPDATE ON fraud.transaction_limits
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_push_notification_registrations_timestamp
    BEFORE UPDATE ON notify.push_notification_registrations
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.metric_alerts_timestamp
    BEFORE UPDATE ON ops.metric_alerts
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 3: Tables 101-150)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 4)
-- =============================================================================================
-- Tables T151 - T200
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 151
-- Table: T151 - feature_usage_stats
-- Schema: prod
-- Description: Aggregated statistics on feature usage within M03.
-- Business Case: Understanding which features drive value is critical for product roadmap. This table
--aggregates daily usage of specific features (e.g., "Blinded Refunds used 500 times", "Voice Auth used 50 times").
--It helps the Product Manager identify unused features (for potential deprecation) and high-traffic
--features (requiring scaling). It provides hard data to support ROI analysis of the engineering effort
--put into specific fraud modules.
-- KPIs: Feature Adoption Rate, Daily Active Users (DAU) per Feature.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prod.feature_usage_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    usage_count BIGINT DEFAULT 0,
    unique_users BIGINT DEFAULT 0, -- Approximate distinct count
    date DATE NOT NULL,

    CONSTRAINT fk_feature_usage UNIQUE (feature_name, date)
);

CREATE INDEX idx_feature_usage_date ON prod.feature_usage_stats(date);
COMMENT ON TABLE prod.feature_usage_stats IS 'Daily rollup of interaction metrics driving product development and capacity planning.';

------------------------------------------------------------------------------------------------
-- Serial No: 152
-- Table: T152 - merchant_onboarding_stages
-- Schema: onboarding
-- Description: Tracks specific stages of onboarding related to fraud setup.
-- Business Case: A merchant cannot start accepting payments until fraud thresholds are configured. This
--table tracks the granular progress of the onboarding checklist (e.g., "API Keys Generated", "Risk
--Profile Set", "Webhook Verified"). It allows the system to detect where merchants drop off during
--setup (e.g., 80% drop at "Webhook Config") and optimize that specific step or offer help chat.
-- KPIs: Onboarding Completion Rate, Drop-off Point Analysis.
-- Feature Reference: F021, M21
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS onboarding.merchant_onboarding_stages (
    stage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    stage_name VARCHAR(100) NOT NULL, -- 'FRAUD_CONFIG', 'KYB_SUBMISSION', 'API_TEST'
    completed_at TIMESTAMP WITH TIME ZONE,
    skipped_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT onboarding_merchant_stage UNIQUE (merchant_id, stage_name)
);

CREATE TRIGGER trg_merchant_onboarding_timestamp
    BEFORE UPDATE ON onboarding.merchant_onboarding_stages
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE onboarding.merchant_onboarding_stages IS 'Step-by-step progress tracker for merchant integration into the fraud ecosystem.';

------------------------------------------------------------------------------------------------
-- Serial No: 153
-- Table: T153 - settlement_exceptions
-- Schema: finance
-- Description: Financial adjustments made to settlements due to fraud disputes.
-- Business Case: When a merchant loses a dispute, the money must be clawed back or deducted from
--their daily payout. This table records these exceptions. It acts as a "Sub-ledger" that modifies
--the main settlement batch. It ensures that the Finance team has a clear audit trail of why a
--merchant was paid $10,000 but received a bank deposit of only $9,500 (due to $500 fraud loss).
-- KPIs: Exception Processing Accuracy, Settlement Delay Impact.
-- Feature Reference: F075
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.settlement_exceptions (
    exception_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    settlement_batch_id VARCHAR(100) NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    reason VARCHAR(255) NOT NULL, -- 'DISPUTE_LOSS', 'PENALTY_FEE', 'CORRECTION'
    original_case_id UUID REFERENCES dispute.cases(case_id),
    currency CHAR(3) NOT NULL,
    approved_by UUID NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_settlement_exception_batch ON finance.settlement_exceptions(settlement_batch_id);
COMMENT ON TABLE finance.settlement_exceptions IS 'Financial ledger adjustments applied to merchant payouts due to fraud liability.';

------------------------------------------------------------------------------------------------
-- Serial No: 154
-- Table: T154 - chargeback_representments
-- Schema: finance
-- Description: Logs of representments (fighting a chargeback) though rare in PARI.
-- Business Case: While PARI aims to prevent chargebacks, legacy bridges or card-present transactions
--might still trigger them. This table tracks "Representments"—the merchant's attempt to prove to
--the card network that the charge was valid. It keeps a record of the evidence submitted and the
--final network decision.
-- KPIs: Representment Win Rate.
-- Feature Reference: F007
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.chargeback_representments (
    rep_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID REFERENCES dispute.cases(case_id),
    reason_code VARCHAR(50),
    document_id UUID REFERENCES dispute.case_evidence(evidence_id),
    network_response VARCHAR(50), -- WON, LOST, ACCEPTED
    network_reference_id VARCHAR(100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE finance.chargeback_representments IS 'Historical record of legacy payment disputes handled via external card networks.';

------------------------------------------------------------------------------------------------
-- Serial No: 155
-- Table: T155 - fraud_rule_tests
-- Schema: qa
-- Description: Unit and integration tests for fraud rules.
-- Business Case: Deploying a broken rule can block revenue. This table stores the definitions of
--automated tests for fraud rules (e.g., "IF Input X, Expect Block"). It runs in the CI/CD
--pipeline. If a developer changes a rule logic and the test fails, deployment is blocked.
--It acts as a safety net for the complex logic defined in the rule engine.
-- KPIs: Test Coverage % for Rules.
-- Feature Reference: F038, F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qa.fraud_rule_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100), -- Reference to the rule being tested
    input_payload JSONB NOT NULL,
    expected_output VARCHAR(20) NOT NULL, -- 'BLOCK', 'ALLOW'
    actual_output VARCHAR(20),
    result VARCHAR(20) DEFAULT 'PENDING', -- PASS, FAIL, ERROR

    -- Metadata
    last_run TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE qa.fraud_rule_tests IS 'Test suite definitions validating the logic of deterministic fraud detection rules.';

------------------------------------------------------------------------------------------------
-- Serial No: 156
-- Table: T156 - kpi_snapshots
-- Schema: bi
-- Description: Daily snapshots of key performance indicators.
-- Business Case: Trend analysis requires consistent data points. This table takes the "pulse" of the
--system every day: Total Tx, Fraud Blocked, Avg Score, Open Disputes. By storing this daily snapshot,
--the BI team can build trend reports without running expensive queries over billions of historical
--transactions. It is the source of truth for the Executive Dashboard.
-- KPIs: Data Freshness, Dashboard Load Speed.
-- Feature Reference: F032, F001
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bi.kpi_snapshots (
    snapshot_date DATE PRIMARY KEY,
    total_tx BIGINT DEFAULT 0,
    fraud_blocked BIGINT DEFAULT 0,
    avg_score NUMERIC(5,2),
    disputes_open BIGINT DEFAULT 0,
    revenue_protected NUMERIC(15,2)
);

CREATE INDEX idx_kpi_snapshots_date ON bi.kpi_snapshots(snapshot_date);
COMMENT ON TABLE bi.kpi_snapshots IS 'Pre-aggregated daily metrics powering executive reporting and long-term trend analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 157
-- Table: T157 - audit_report_subscriptions
-- Schema: audit
-- Description: Manages subscriptions to automated audit reports for merchants.
-- Business Case: Merchants often require monthly "Proof of Fraud Prevention" for their own audits or
--insurance. This table manages subscriptions to these reports. It controls frequency (Weekly/Monthly)
--and delivery format (PDF/Email). It automates a value-add service for the merchants, increasing
--stickiness to the PARI platform.
-- KPIs: Report Delivery Success Rate.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.audit_report_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    report_type VARCHAR(50) NOT NULL, -- 'MONTHLY_FRAUD_SUMMARY', 'DISPUTE_BREAKDOWN'
    frequency VARCHAR(20) NOT NULL CHECK (frequency IN ('WEEKLY', 'MONTHLY', 'QUARTERLY')),
    last_sent_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.audit_report_subscriptions IS 'Configuration for recurring delivery of compliance and performance reports to partners.';

------------------------------------------------------------------------------------------------
-- Serial No: 158
-- Table: T158 - third_party_risk_scores
-- Schema: fraud
-- Description: Risk scores derived from external credit bureaus or intel providers.
-- Business Case: PARI doesn't know everything. External providers (like Experian or ThreatMetrix)
--provide a "Risk Score" for a user or device. This table caches these scores. If an external provider
--says "User is High Risk", PARI combines that with internal LSTM score for a final decision.
--It avoids calling expensive external APIs for every transaction.
-- KPIs: Cache Hit Ratio, External API Cost Savings.
-- Feature Reference: F009, F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.third_party_risk_scores (
    entity_id UUID,
    provider_name VARCHAR(50) NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    category VARCHAR(50), -- 'CREDIT_RISK', 'IDENTITY_RISK'
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_third_party_risk UNIQUE (entity_id, provider_name, category)
);

COMMENT ON TABLE fraud.third_party_risk_scores IS 'Cache of external risk intelligence augmenting internal fraud detection capabilities.';

------------------------------------------------------------------------------------------------
-- Serial No: 159
-- Table: T159 - compliance_policy_versions
-- Schema: policy
-- Description: Versioning of ABAC policies used for regulatory enforcement.
-- Business Case: Regulations change (e.g., new GDPR amendment). Policies (Who can do What) must be
--versioned to know what rule applied *at the time of the transaction*. This table stores the JSON
--logic of ABAC policies and their effective dates. It ensures that if a policy changes today,
--historical transactions remain governed by yesterday's policy.
-- KPIs: Policy Retrieval Accuracy.
-- Feature Reference: F063
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy.compliance_policy_versions (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL,
    content JSONB NOT NULL, -- The policy logic
    active_from TIMESTAMP WITH TIME ZONE NOT NULL,
    active_to TIMESTAMP WITH TIME ZONE,

    CONSTRAINT policy_name_version UNIQUE (policy_name, version)
);

CREATE INDEX idx_policy_name_time ON policy.compliance_policy_versions(policy_name, active_from);
COMMENT ON TABLE policy.compliance_policy_versions IS 'Temporal version control for regulatory and access control logic.';

------------------------------------------------------------------------------------------------
-- Serial No: 160
-- Table: T160 - user_consent_logs
-- Schema: privacy
-- Description: Granular logs of user consent for analytics vs. operational processing.
-- Business Case: Consent is the foundation of privacy compliance. A user might consent to "Fraud
--Detection" (Operational) but deny "Marketing Analytics". This table logs the granular consent
--state for every user. If a user withdraws consent for Analytics, this table triggers the GDPR
--Deletion Queue (T126) for analytics data, while retaining fraud data (which is legally required).
-- KPIs: Consent Management Accuracy.
-- Feature Reference: F095
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy.user_consent_logs (
    consent_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    consent_type VARCHAR(50) NOT NULL CHECK (consent_type IN ('analytics', 'fraud', 'marketing')),
    granted BOOLEAN NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_consent_hash ON privacy.user_consent_logs(user_hash);
COMMENT ON TABLE privacy.user_consent_logs IS 'Immutable ledger of user permissions governing data usage and retention.';

------------------------------------------------------------------------------------------------
-- Serial No: 161
-- Table: T161 - ontology_mappings
-- Schema: knowledge
-- Description: Maps internal fraud terms to public ontology standards (SKOS).
-- Business Case: Interoperability matters. PARI calls it "Friendly Fraud", but ISO 20022 calls
--it "Consumer Dispute". This table maps internal terms to public ontology URIs. It enables automated
--reporting to external bodies and semantic search across different datasets.
-- KPIs: Mapping Coverage %.
-- Feature Reference: M15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.ontology_mappings (
    id SERIAL PRIMARY KEY,
    internal_term VARCHAR(100) NOT NULL,
    uri TEXT NOT NULL,
    ontology_name VARCHAR(50) NOT NULL, -- 'ISO20022', 'FIBO'
    language CHAR(2) DEFAULT 'en',

    CONSTRAINT term_ontology_lang UNIQUE (internal_term, ontology_name, language)
);

COMMENT ON TABLE knowledge.ontology_mappings IS 'Translation bridge between proprietary taxonomy and standardized financial vocabularies.';

------------------------------------------------------------------------------------------------
-- Serial No: 162
-- Table: T162 - concept_relationships
-- Schema: knowledge
-- Description: Defines relationships between ontology concepts.
-- Business Case: Knowledge graphs define how things relate. This table stores triples: Subject, Predicate,
--Object. Example: "Account Takeover" -> "is a type of" -> "Identity Fraud". This structure
--powers the "Smart Search" in the analyst UI, allowing them to find related concepts they didn't
--explicitly search for.
-- KPIs: Graph Depth/Completeness.
-- Feature Reference: M15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.concept_relationships (
    id SERIAL PRIMARY KEY,
    subject_uri TEXT NOT NULL,
    predicate_uri TEXT NOT NULL,
    object_uri TEXT NOT NULL
);

CREATE INDEX idx_concept_rel_subject ON knowledge.concept_relationships(subject_uri);
CREATE INDEX idx_concept_rel_object ON knowledge.concept_relationships(object_uri);
COMMENT ON TABLE knowledge.concept_relationships IS 'Graph edges defining semantic associations between fraud concepts.';

------------------------------------------------------------------------------------------------
-- Serial No: 163
-- Table: T163 - incident_tickets
-- Schema: incident
-- Description: Links fraud cases to broader security incident tickets.
-- Business Case: A single fraudster might trigger 50 disputes. This is an "Incident". This table
--links all those individual cases (T009) to one master Incident Ticket (managed by M20). It
--provides a holistic view for the Security Ops team, allowing them to close the incident once the
--attacker is mitigated, automatically resolving all child cases.
-- KPIs: Incident Resolution Time.
-- Feature Reference: M20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.incident_tickets (
    ticket_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_ticket_id VARCHAR(100), -- JIRA/Servicenow ID
    case_id UUID REFERENCES dispute.cases(case_id),
    severity ops.incident_severity NOT NULL,
    status VARCHAR(20) DEFAULT 'OPEN',

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_incident_tickets_timestamp
    BEFORE UPDATE ON incident.incident_tickets
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE incident.incident_tickets IS 'Correlation layer connecting individual transactional fraud events to systemic security incidents.';

------------------------------------------------------------------------------------------------
-- Serial No: 164
-- Table: T164 - threat_model_findings
-- Schema: incident
-- Description: Findings from threat modeling exercises (STRIDE).
-- Business Case: Proactive security involves Threat Modeling (STRIDE). This table stores findings (e.g.,
--"Refund API is susceptible to Replay Attack"). It links these findings to the specific component
--and tracks the mitigation status. It ensures that design flaws are identified before code is written.
-- KPIs: Mitigation Completion Rate.
-- Feature Reference: M20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.threat_model_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50) NOT NULL, -- 'SPOOFING', 'TAMPERING', 'REPUDIATION'
    mitigation_status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, MITIGATED, ACCEPTED_RISK
    owner_id UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE incident.threat_model_findings IS 'Documentation of architectural vulnerabilities derived from structured threat analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 165
-- Table: T165 - pat_logs
-- Schema: ml
-- Description: Process Action Team (PAT) logs for continuous improvement (CMMI).
-- Business Case: CMMI Level 5 requires Process Management. PAT meetings discuss model performance and
--decide on actions. This table logs these decisions (e.g., "Decision: Retrain LSTM due to drift").
--It creates a permanent record of the "human-in-the-loop" decisions that guide the AI's evolution,
--satisfying audit requirements for AI governance.
-- KPIs: Action Item Completion Rate.
-- Feature Reference: M18, F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.pat_logs (
    pat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_date DATE NOT NULL,
    topic VARCHAR(255) NOT NULL,
    decision TEXT NOT NULL,
    action_items TEXT[],
    attendees UUID[],

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.pat_logs IS 'Minutes from governance meetings driving quantitative process management of AI models.';

------------------------------------------------------------------------------------------------
-- Serial No: 166
-- Table: T166 - monte_carlo_simulations
-- Schema: ml
-- Description: Results of Monte Carlo risk simulations for release planning.
-- Business Case: How much will a model change cost? Monte Carlo simulations run thousands of scenarios
--to predict outcomes. This table stores the results (Scenario, Outcome, Confidence Interval). It
--helps Management decide if deploying a model is financially sound (e.g., "90% chance of reducing fraud
--by 5%, but 10% chance of blocking 1M revenue").
-- KPIs: Simulation Fidelity.
-- Feature Reference: M18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.monte_carlo_simulations (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_id VARCHAR(100) NOT NULL,
    run_id UUID NOT NULL,
    outcome_metric NUMERIC(10,2), -- e.g., Expected ROI
    confidence_interval_low NUMERIC(10,2),
    confidence_interval_high NUMERIC(10,2),

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.monte_carlo_simulations IS 'Probabilistic modeling results supporting risk-aware decision making for AI deployments.';

------------------------------------------------------------------------------------------------
-- Serial No: 167
-- Table: T167 - refund_reason_aggregates
-- Schema: fraud
-- Description: Pre-aggregated table for reporting on refund reasons by merchant.
-- Business Case: Merchants want to know *why* they are losing money. This table pre-calculates the
--breakdown of refund reasons per merchant per month. Querying raw transactions for this is too slow.
--This powers the "Merchant Portal" dashboards, providing instant insights into operational
--efficiency (e.g., "You have a high rate of 'Item Not Received', check your shipping.").
-- KPIs: Report Generation Speed.
-- Feature Reference: F115
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_reason_aggregates (
    merchant_id UUID NOT NULL,
    reason_code VARCHAR(10) NOT NULL,
    period DATE NOT NULL,
    count BIGINT DEFAULT 0,
    amount NUMERIC(15,2) DEFAULT 0,

    CONSTRAINT pk_refund_reason_agg UNIQUE (merchant_id, reason_code, period)
);

CREATE INDEX idx_refund_agg_period ON fraud.refund_reason_aggregates(period);
COMMENT ON TABLE fraud.refund_reason_aggregates IS 'Optimized data mart for merchant performance analytics regarding return reasons.';

------------------------------------------------------------------------------------------------
-- Serial No: 168
-- Table: T168 - device_risk_history
-- Schema: fraud
-- Description: Historical changes in device risk scores.
-- Business Case: A device might be safe today, but compromised tomorrow. This table tracks the risk
--score of a device over time. It creates a timeline that helps investigators see *when* a device
--became risky, which often correlates with a malware infection or purchase of a rooted device.
-- KPIs: Historical Reconstruction Accuracy.
-- Feature Reference: T005
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_risk_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_hash VARCHAR(64) NOT NULL,
    old_score INTEGER,
    new_score INTEGER NOT NULL,
    change_reason VARCHAR(255), -- 'MALWARE_DETECTED', 'LOCATION_VELOCITY'

    -- Metadata
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_risk_history_hash ON fraud.device_risk_history(device_hash);
COMMENT ON TABLE fraud.device_risk_history IS 'Time-series tracking of device trustworthiness facilitating forensic analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 169
-- Table: T169 - dispute_escrow_ledger
-- Schema: dispute
-- Description: Tracks funds held in escrow during high-value dispute resolution.
-- Business Case: For high-value disputes, funds might be frozen until arbitration. This table acts as
--the ledger for those funds. It ensures that the money is accounted for—it is neither with the
--merchant nor the payer—but held securely by PARI. It tracks the release conditions
--(e.g., "Release to Payer if Arbitrator decides in their favor").
-- KPIs: Escrow Balance Accuracy.
-- Feature Reference: F045
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.dispute_escrow_ledger (
    escrow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    release_condition JSONB NOT NULL, -- Logic for release
    status VARCHAR(20) DEFAULT 'HELD', -- HELD, RELEASED_MERCHANT, RELEASED_PAYER
    released_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.dispute_escrow_ledger IS 'Financial custody record for funds pending final adjudication in complex disputes.';

------------------------------------------------------------------------------------------------
-- Serial No: 170
-- Table: T170 - service_dependencies
-- Schema: ops
-- Description: Maps dependencies between M03 and other services (M01, M05).
-- Business Case: M03 relies on M01 (Payment) and M05 (Identity). This table explicitly maps these
--dependencies. It supports the Dependency Health Map (F224). If M01 goes down, this table helps Ops
--understand that M03 might be affected. It is crucial for Impact Analysis during outages.
-- KPIs: Dependency Discovery Completeness.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.service_dependencies (
    service_id UUID DEFAULT uuid_generate_v4(),
    dependency_id UUID DEFAULT uuid_generate_v4(),
    type VARCHAR(20) CHECK (type IN ('SYNC', 'ASYNC')),
    required BOOLEAN DEFAULT TRUE,

    CONSTRAINT pk_service_dependencies PRIMARY KEY (service_id, dependency_id)
);

COMMENT ON TABLE ops.service_dependencies IS 'Graph representation of architectural coupling facilitating impact analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 171
-- Table: T171 - api_rate_limit_quotas
-- Schema: api
-- Description: Configuration for API rate limits per tier.
-- Business Case: Not all users are equal. "Free" tier users get 10 req/min. "Enterprise" gets
--10,000. This table defines these quotas. The API Gateway (F255) references this table to enforce
--limits. It allows dynamic changing of quotas without redeploying the gateway service.
-- KPIs: Quota Enforcement Accuracy.
-- Feature Reference: F073
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api.rate_limit_quotas (
    tier_name VARCHAR(50) PRIMARY KEY, -- GOLD, SILVER, BRONZE
    requests_per_minute INTEGER NOT NULL,
    requests_per_hour INTEGER NOT NULL,
    description VARCHAR(255)
);

COMMENT ON TABLE api.rate_limit_quotas IS 'Capacity management definitions for API access tiers.';

------------------------------------------------------------------------------------------------
-- Serial No: 172
-- Table: T172 - certificate_inventory
-- Schema: sec
-- Description: Inventory of TLS certificates used for internal/external communication.
-- Business Case: Expired certificates cause outages. This table tracks all TLS certs for M03 services
--(API, Internal gRPC). It monitors expiry dates. It triggers automated renewal logic (T237) and
--alerts Ops well before a cert expires. It ensures Zero Trust encryption is always valid.
-- KPIs: Certificate Uptime %.
-- Feature Reference: F017, M17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.certificate_inventory (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    common_name VARCHAR(255) NOT NULL,
    issuer VARCHAR(255),
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    auto_renew BOOLEAN DEFAULT TRUE,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cert_expiry ON sec.certificate_inventory(expiry_date);
COMMENT ON TABLE sec.certificate_inventory IS 'Registry of cryptographic assets ensuring encrypted channel availability.';

------------------------------------------------------------------------------------------------
-- Serial No: 173
-- Table: T173 - data_access_requests
-- Schema: audit
-- Description: Logs requests by auditors to access sensitive dispute data.
-- Business Case: Auditors (Internal or External) sometimes need raw data. This table logs every
--request: Who asked? For what table? Was it granted? It enforces the "Principle of Least Privilege".
--Even admins cannot just dump the database without a logged request in this table.
-- KPIs: Access Request Compliance.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.data_access_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    requested_table VARCHAR(100) NOT NULL,
    justification TEXT NOT NULL,
    access_granted BOOLEAN DEFAULT FALSE,
    granted_by UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.data_access_requests IS 'Authorization workflow for auditors seeking elevated data privileges.';

------------------------------------------------------------------------------------------------
-- Serial No: 174
-- Table: T174 - behavioral_biometric_raw
-- Schema: fraud
-- Description: Raw telemetry for behavioral biometrics.
-- Business Case: Passive biometrics (typing speed, gyroscope) are powerful. This table stores the
--raw time-series data for a user session. It is high-volume and short-lived (TTL). The ML
--pipeline consumes this to generate vectors (T175). Keeping raw data allows re-tuning if the
--algorithm changes.
-- KPIs: Telemetry Ingestion Throughput.
-- Feature Reference: F040
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.behavioral_biometric_raw (
    telemetry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    sensor_type VARCHAR(50) NOT NULL, -- 'KEYSTROKE', 'ACCELEROMETER', 'TOUCH'
    data_blob JSONB NOT NULL, -- The actual time-series points
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Partitioning is recommended for this table in production
CREATE INDEX idx_biometric_session ON fraud.behavioral_biometric_raw(session_id);
COMMENT ON TABLE fraud.behavioral_biometric_raw IS 'High-frequency sensor input stream for passive user authentication algorithms.';

------------------------------------------------------------------------------------------------
-- Serial No: 175
-- Table: T175 - biometric_templates
-- Schema: ml
-- Description: Stored templates for passive behavioral authentication.
-- Business Case: Comparing raw data (T174) every time is slow. We compare against a "Template". This
--table stores the enrolled mathematical model of the user's behavior. During a transaction, new
--data is compared against this template. If the match score is high, it's the user.
-- KPIs: False Rejection Rate (FRR).
-- Feature Reference: F040
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.biometric_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    template_vector NUMERIC[], -- Array of floats representing the behavior
    model_version VARCHAR(20),
    last_used TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_biometric_templates_timestamp
    BEFORE UPDATE ON ml.biometric_templates
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ml.biometric_templates IS 'Reference models for comparing live biometric telemetry against known user baselines.';

------------------------------------------------------------------------------------------------
-- Serial No: 176
-- Table: T176 - canary_releases
-- Schema: ops
-- Description: Tracks the status of canary deployments for new fraud models.
-- Business Case: Rolling out a new model to 100% of traffic is dangerous. We do Canary releases
--(e.g., 1% traffic gets new model). This table tracks the canary: Version ID, Traffic Percentage,
--Start Time. Ops monitors this table—if the 1% shows high error rates, they stop the rollout.
-- KPIs: Canary Failure Detection Time.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.canary_releases (
    canary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(50) NOT NULL,
    traffic_percentage INTEGER DEFAULT 1, -- 1 to 100
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE, -- NULL if active
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, STOPPED, PROMOTED
    rollback_reason TEXT
);

COMMENT ON TABLE ops.canary_releases IS 'Control plane for gradual traffic shifting during software deployments.';

------------------------------------------------------------------------------------------------
-- Serial No: 177
-- Table: T177 - feature_flag_audits
-- Schema: ops
-- Description: Audit trail for changes to feature flags.
-- Business Case: Who turned off the "Fraud Check"? This table logs every change to the Feature
--Flags (T020). It tracks Before/After values and the operator. It prevents "Silent" changes to
--system behavior, ensuring that every configuration shift is accountable.
-- KPIs: Audit Completeness.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.feature_flag_audits (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    changed_by UUID NOT NULL,
    old_value JSONB,
    new_value JSONB,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_flag_audit_name ON ops.feature_flag_audits(flag_name);
COMMENT ON TABLE ops.feature_flag_audits IS 'Immutable record of all runtime configuration modifications.';

------------------------------------------------------------------------------------------------
-- Serial No: 178
-- Table: T178 - money_laundering_alerts
-- Schema: fraud
-- Description: Alerts specifically triggered for AML patterns (structuring).
-- Business Case: AML is distinct from standard fraud. It involves moving money to hide origin. This table
--stores alerts for AML patterns (e.g., Smurfing, Layering). These alerts link to SAR reports (T017).
--It ensures that PARI is not used as a laundry service, which would result in massive fines.
-- KPIs: AML Pattern Detection Rate.
-- Feature Reference: F091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.money_laundering_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    related_tx_hashes TEXT[] NOT NULL,
    suspicious_pattern TEXT NOT NULL,
    reporter_id UUID, -- System or Analyst
    status VARCHAR(20) DEFAULT 'OPEN',

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.money_laundering_alerts IS 'Specialized queue for Anti-Money Laundering suspicious activity detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 179
-- Table: T179 - webhooks_subscriptions
-- Schema: integration
-- Description: Manages webhook endpoints for merchant dispute notifications.
-- Business Case: Merchants want real-time updates in their own systems. This table stores their
--webhook URLs and the Secret used for signing (HMAC). When a dispute changes, M03 POSTs to this URL.
--It manages the subscription lifecycle (activate, pause, retry).
-- KPIs: Webhook Delivery Success Rate.
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.webhooks_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret_hash VARCHAR(255), -- For HMAC signature
    active BOOLEAN DEFAULT TRUE,
    last_success_at TIMESTAMP WITH TIME ZONE,
    failure_count INTEGER DEFAULT 0
);

CREATE INDEX idx_webhooks_merchant ON integration.webhooks_subscriptions(merchant_id);
COMMENT ON TABLE integration.webhooks_subscriptions IS 'Configuration for real-time push notifications to external merchant systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 180
-- Table: T180 - brute_force_attempts
-- Schema: sec
-- Description: Tracks failed login attempts to detect brute force attacks.
-- Business Case: Brute force (trying 1000 passwords) is a common attack vector. This table logs failed
--attempts (IP, Username). If a single IP exceeds a threshold, it is added to the Blacklist (T014).
--It protects the Merchant Portal and Wallet Login from credential stuffing.
-- KPIs: Attack Detection Speed.
-- Feature Reference: F073
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.brute_force_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username_or_ip VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_brute_force_time ON sec.brute_force_attempts(timestamp DESC);
COMMENT ON TABLE sec.brute_force_attempts IS 'Access control log identifying repetitive authentication failures indicative of attacks.';

------------------------------------------------------------------------------------------------
-- Serial No: 181
-- Table: T181 - api_mapping_rules
-- Schema: integration
-- Description: Maps external fraud provider fields to internal schema.
-- Business Case: Integrating with 3rd party APIs (e.g., ThreatMetrix) requires mapping their JSON fields
--to our DB columns. This table stores that map. If the provider changes their API, we just update
--this table, not the code. It decouples PARI from external vendor schema changes.
-- KPIs: Mapping Transformation Success Rate.
-- Feature Reference: F029, F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.api_mapping_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_provider VARCHAR(50) NOT NULL,
    external_field VARCHAR(100) NOT NULL,
    internal_field VARCHAR(100) NOT NULL,
    data_type VARCHAR(20), -- STRING, INT, FLOAT
    transformation_rule TEXT -- Optional SQL snippet
);

COMMENT ON TABLE integration.api_mapping_rules IS 'Configuration layer translating external data formats to internal canonical schema.';

------------------------------------------------------------------------------------------------
-- Serial No: 182
-- Table: T182 - file_storage_quota
-- Schema: storage
-- Description: Monitors storage usage for evidence files per tenant.
-- Business Case: Storage costs money. Evidence files can pile up. This table enforces quotas per tenant
--(Merchant). If a Merchant uploads 10TB of PDFs, they hit their limit. It prevents noisy neighbors
--(one merchant eating all disk space) and drives cost recovery.
-- KPIs: Quota Enforcement %.
-- Feature Reference: T010
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.file_storage_quota (
    tenant_id UUID NOT NULL, -- Merchant ID or System ID
    used_bytes BIGINT DEFAULT 0,
    limit_bytes BIGINT NOT NULL,
    warning_threshold_pct INTEGER DEFAULT 80, -- Alert at 80%

    CONSTRAINT pk_storage_quota PRIMARY KEY (tenant_id)
);

COMMENT ON TABLE storage.file_storage_quota IS 'Capacity planning enforcement for digital evidence repositories.';

------------------------------------------------------------------------------------------------
-- Serial No: 183
-- Table: T183 - maintenance_logs
-- Schema: ops
-- Description: Logs of scheduled maintenance activities and their impacts.
-- Business Case: Maintenance happens. This table documents it. It records description, impact level
--(Service Degraded vs Down), and actual execution times. It feeds the Availability Report and
--helps Ops improve future maintenance windows (e.g., "We said 30 mins, took 2 hours").
-- KPIs: Maintenance Window Adherence.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.maintenance_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    description TEXT NOT NULL,
    impact_level VARCHAR(20) CHECK (impact_level IN ('NONE', 'DEGRADED', 'DOWN'))
);

CREATE INDEX idx_maint_logs_time ON ops.maintenance_logs(start_time);
COMMENT ON TABLE ops.maintenance_logs IS 'Operational history of scheduled downtime events for availability reporting.';

------------------------------------------------------------------------------------------------
-- Serial No: 184
-- Table: T184 - refund_velocity_limits
-- Schema: fraud
-- Description: Limits on refund volume to prevent rapid fire refund fraud.
-- Business Case: Fraudsters might issue 100 refunds in 1 minute to cash out before being caught. This
--table enforces velocity limits on refunds *per merchant*. If a merchant exceeds the limit (e.g.,
--> 10 refunds/min), the API blocks further requests until the window passes.
-- KPIs: Limit Enforcement Latency.
-- Feature Reference: F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_velocity_limits (
    merchant_id UUID PRIMARY KEY,
    max_refund_per_hour INTEGER NOT NULL,
    current_refund_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.refund_velocity_limits IS 'Real-time counter preventing abusive bulk refund operations.';

------------------------------------------------------------------------------------------------
-- Serial No: 185
-- Table: T185 - regulator_correspondence
-- Schema: compliance
-- Description: Logs correspondence with tax authorities or regulators regarding cases.
-- Business Case: Regulators often request info. This table stores the history of correspondence—Request
--received, Reply sent. It ensures PARI meets SLAs for regulatory response (e.g., "Reply to FinCEN
--within 48 hours"). It stores references to the documents provided.
-- KPIs: Regulatory Response SLA Adherence.
-- Feature Reference: F019
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.regulator_correspondence (
    correspondence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulator_id VARCHAR(50) NOT NULL, -- e.g., 'FINCEN', 'FCA'
    case_id UUID REFERENCES dispute.cases(case_id),
    direction VARCHAR(20) CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    content_ref VARCHAR(255), -- Link to stored PDF
    subject TEXT,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reg_corr_case ON compliance.regulator_correspondence(case_id);
COMMENT ON TABLE compliance.regulator_correspondence IS 'Legal document trail of interactions with government oversight bodies.';

------------------------------------------------------------------------------------------------
-- Serial No: 186
-- Table: T186 - model_metadata_registry
-- Schema: ml
-- Description: Central registry of all model metadata for governance (MLOps).
-- Business Case: MLOps requires a single source of truth. This table aggregates info from other tables
--(Training Data, Hyperparameters, Owner) into a model "Card". It answers: Who owns this model?
--What is its ethical approval status? What is its current performance? It is the foundation for
--AI Governance.
-- KPIs: Registry Completeness.
-- Feature Reference: F089
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_metadata_registry (
    model_id UUID PRIMARY KEY,
    owner UUID NOT NULL,
    description TEXT,
    input_features JSONB, -- List of features used
    output_variables JSONB,
    ethical_constraints TEXT[], -- e.g., 'NO_GENDER', 'NO_RACE'
    status VARCHAR(20) DEFAULT 'DEVELOPMENT' -- DEVELOPMENT, STAGING, PRODUCTION, RETIRED
);

COMMENT ON TABLE ml.model_metadata_registry IS 'Canonical catalog of machine learning assets supporting governance and lifecycle management.';

------------------------------------------------------------------------------------------------
-- Serial No: 187
-- Table: T187 - arbitration_awards
-- Schema: dispute
-- Description: Details of arbitration awards for escalated disputes.
-- Business Case: When automated resolution fails, we go to Arbitration. This table stores the outcome:
--Amount awarded, Payer Liability, Merchant Liability. It is the legally binding record of the
--decision. The Financial Engine (T080) uses this to move funds accordingly.
-- KPIs: Award Execution Accuracy.
-- Feature Reference: F052
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.arbitration_awards (
    award_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    amount NUMERIC(15,2) NOT NULL,
    payer_liability NUMERIC(15,2) NOT NULL,
    payee_liability NUMERIC(15,2) NOT NULL,
    arbitrator_id UUID,

    -- Metadata
    awarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.arbitration_awards IS 'Final financial disposition records for disputes escalated to third-party judgment.';

------------------------------------------------------------------------------------------------
-- Serial No: 188
-- Table: T188 - glossary_terms
-- Schema: knowledge
-- Description: Business glossary defining terms used in fraud/dispute context.
-- Business Case: A shared language is key. This table defines business terms (e.g., "Chargeback",
--"Blind Refund"). It includes definitions and owners. It helps new analysts understand the domain
--and is used for data dictionary generation.
-- KPIs: Term Consistency.
-- Feature Reference: M10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.glossary_terms (
    term_id SERIAL PRIMARY KEY,
    term VARCHAR(100) NOT NULL UNIQUE,
    definition TEXT NOT NULL,
    source VARCHAR(50), -- BUSINESS, TECHNICAL, LEGAL
    steward UUID -- Who owns this definition
);

COMMENT ON TABLE knowledge.glossary_terms IS 'Lexicon of domain-specific vocabulary ensuring consistent communication across teams.';

------------------------------------------------------------------------------------------------
-- Serial No: 189
-- Table: T189 - penetration_test_reports
-- Schema: security
-- Description: Stores summaries of external penetration tests.
-- Business Case: Security must be validated by outsiders. This table stores results from Pen-Test vendors.
--It lists High Risk findings and their status (Open/Fixed). It ensures that security vulnerabilities
--are tracked to closure and not lost in email threads.
-- KPIs: Vulnerability MTTR (Mean Time To Remediate).
-- Feature Reference: M20, F113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.penetration_test_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor VARCHAR(100) NOT NULL,
    test_date DATE NOT NULL,
    high_risk_findings INTEGER DEFAULT 0,
    status VARCHAR(20) CHECK (status IN ('DRAFT', 'REMEDIATION_IN_PROGRESS', 'CLOSED')),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE security.penetration_test_reports IS 'Tracking of offensive security assessments and remediation lifecycle.';

------------------------------------------------------------------------------------------------
-- Serial No: 190
-- Table: T190 - sla_breach_details
-- Schema: ops
-- Description: Detailed breakdown of SLA breaches for root cause analysis.
-- Business Case: SLA breaches (e.g., Dispute took 6 days instead of 5) are bad. This table stores the
--granular details: Which SLA type? Target vs Actual? Duration of breach? It helps Ops identify
--bottlenecks (e.g., "Most breaches happen due to Carrier delays").
-- KPIs: SLA Breach Root Cause Frequency.
-- Feature Reference: F126
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.sla_breach_details (
    breach_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sla_type VARCHAR(50) NOT NULL, -- 'DISPUTE_RESOLUTION', 'API_RESPONSE'
    target_value NUMERIC(10,2) NOT NULL,
    actual_value NUMERIC(10,2) NOT NULL,
    duration_sec BIGINT NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sla_breach_time ON ops.sla_breach_details(timestamp);
COMMENT ON TABLE ops.sla_breach_details IS 'Granular failure analysis for service level agreement violations.';

------------------------------------------------------------------------------------------------
-- Serial No: 191
-- Table: T191 - merchant_clusters
-- Schema: fraud
-- Description: Clusters merchants based on fraud behavior similarity.
-- Business Case: Merchants cluster by risk. "Jewelry in NY" might have a certain fraud profile. This table
--stores the results of Unsupervised Learning (K-Means) that groups merchants. It helps in identifying
--new risks—if a new merchant joins a "High Risk" cluster, we scrutinize them immediately.
-- KPIs: Cluster Separation Quality.
-- Feature Reference: F009
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_clusters (
    cluster_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    cluster_label VARCHAR(50) NOT NULL, -- e.g., 'HIGH_RISK_ELECTRONICS'
    confidence NUMERIC(3,2),

    -- Metadata
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_merchant_cluster_label ON fraud.merchant_clusters(cluster_label);
COMMENT ON TABLE fraud.merchant_clusters IS 'Result of segmentation algorithms grouping merchants by shared behavioral characteristics.';

------------------------------------------------------------------------------------------------
-- Serial No: 192
-- Table: T192 - openbanking_tokens
-- Schema: integration
-- Description: Stores OAuth tokens for Open Banking integrations (PSD2).
-- Business Case: Under PSD2, users can share bank data. This table stores the OAuth Access/Refresh tokens
--for the bank connections. It allows PARI to query bank account history to validate "I have no funds"
--claims in disputes, adding a powerful layer of proof.
-- KPIs: Token Refresh Success Rate.
-- Feature Reference: M07
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.openbanking_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    access_token_encrypted BYTEA,
    refresh_token_encrypted BYTEA,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT openbanking_merchant UNIQUE (merchant_id)
);

COMMENT ON TABLE integration.openbanking_tokens IS 'Secure storage for third-party financial data access credentials.';

------------------------------------------------------------------------------------------------
-- Serial No: 193
-- Table: T193 - configuration_backups
-- Schema: ops
-- Description: Backups of system configurations.
-- Business Case: "It works on my machine" syndrome. If a production config breaks things, we need to
--restore the last known good state fast. This table stores snapshots of the configuration (JSON blobs)
--for all services. It allows rapid rollback of configuration without waiting for a DB restore.
-- KPIs: Config Restore Speed.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.configuration_backups (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_snapshot JSONB NOT NULL,
    created_by UUID NOT NULL,
    restored_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.configuration_backups IS 'Point-in-time snapshots of system settings enabling rapid disaster recovery.';

------------------------------------------------------------------------------------------------
-- Serial No: 194
-- Table: T194 - identity_verification_logs
-- Schema: fraud
-- Description: Logs of identity verification checks (eIDAS) for high value refunds.
-- Business Case: High value refunds need extra proof. This table logs eIDAS (European Digital Identity)
--checks. It links the PARI user to the Government ID verification result. It ensures that the
--person receiving the refund is the legitimate account holder.
-- KPIs: Verification Check Latency.
-- Feature Reference: F104, M09
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.identity_verification_logs (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    verification_method VARCHAR(50) NOT NULL, -- 'EIDAS', 'DOCUSIGN'
    provider VARCHAR(50),
    result VARCHAR(20) NOT NULL CHECK (result IN ('pass', 'fail', 'indeterminate')),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_id_verif_user ON fraud.identity_verification_logs(user_hash);
COMMENT ON TABLE fraud.identity_verification_logs IS 'Records of third-party identity corroboration used for high-risk transactions.';

------------------------------------------------------------------------------------------------
-- Serial No: 195
-- Table: T195 - hyperparameter_tuning_runs
-- Schema: ml
-- Description: Logs of hyperparameter optimization runs.
-- Business Case: Finding the best Model Settings (Learning Rate, Layers) is trial and error. This table
--logs the runs of the optimization algorithm (e.g., Bayesian Optimization). It stores the parameters
--tried and the resulting Score. It prevents re-testing bad configurations and guides the final model
--selection.
-- KPIs: Optimization Efficiency.
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.hyperparameter_tuning_runs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID,
    params JSONB NOT NULL, -- The settings tried
    final_score NUMERIC(5,2),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hp_tuning_model ON ml.hyperparameter_tuning_runs(model_id);
COMMENT ON TABLE ml.hyperparameter_tuning_runs IS 'History of automated experiments searching for optimal model configurations.';

------------------------------------------------------------------------------------------------
-- Serial No: 196
-- Table: T196 - query_performance_stats
-- Schema: db
-- Description: Tracks slow queries in the fraud module.
-- Business Case: DB performance is critical. This table logs queries that take longer than a threshold
--(e.g., > 500ms). It helps DBAs identify indexes to add or SQL to rewrite. It directly impacts
--the P99 latency KPI of the fraud module.
-- KPIs: Slow Query Count Reduction.
-- Feature Reference: F149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.query_performance_stats (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash CHAR(32) NOT NULL, -- MD5 of normalized query
    exec_time_ms NUMERIC(10,2) NOT NULL,
    calls_count BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_slow_query_hash ON db.query_performance_stats(query_hash);
COMMENT ON TABLE db.query_performance_stats IS 'Diagnostic data identifying database performance bottlenecks.';

------------------------------------------------------------------------------------------------
-- Serial No: 197
-- Table: T197 - incident_commander_log
-- Schema: ops
-- Description: Logs actions taken by the Incident Commander during major outages.
-- Business Case: In a major incident, a Commander is appointed. This table logs their commands
--("Stop Traffic", "Revert Commit"). It provides a chronological timeline of the response effort,
--which is essential for the Post-Mortem meeting.
-- KPIs: Command Log Latency.
-- Feature Reference: M19
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.incident_commander_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    commander_id UUID NOT NULL,
    action TEXT NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_inc_cmdr_incident ON ops.incident_commander_log(incident_id);
COMMENT ON TABLE ops.incident_commander_log IS 'Sequential record of executive decisions made during critical operational incidents.';

------------------------------------------------------------------------------------------------
-- Serial No: 198
-- Table: T198 - referral_program_abuse
-- Schema: fraud
-- Description: Tracks potential abuse of referral or loyalty programs.
-- Business Case: Referral programs are easy targets for fraud (self-referral). This table links a
--referrer to a referee. If it detects patterns (same IP, same device), it flags abuse here.
--It protects the marketing budget from being drained by fraudsters.
-- KPIs: Abuse Detection Rate.
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.referral_program_abuse (
    abuse_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    referrer_hash VARCHAR(64) NOT NULL,
    referee_hash VARCHAR(64) NOT NULL,
    relationship_type VARCHAR(50), -- 'FAMILY', 'COLLEAGUE', 'UNKNOWN'
    risk_score INTEGER,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_referral_abuse_referrer ON fraud.referral_program_abuse(referrer_hash);
COMMENT ON TABLE fraud.referral_program_abuse IS 'Graph analysis of promotional program participation to detect circular exploitation.';

------------------------------------------------------------------------------------------------
-- Serial No: 199
-- Table: T199 - smart_contract_executions
-- Schema: contract
-- Description: Logs of execution steps for complex smart contracts.
-- Business Case: Some contracts are complex (Multi-step). This table logs the execution of each step
--(e.g., "Step 1: Validate Funds", "Step 2: Lock Funds"). It acts as a trace log. If a
--contract fails, we know exactly which step caused the failure.
-- KPIs: Execution Step Success Rate.
-- Feature Reference: F153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.smart_contract_executions (
    exec_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    step_name VARCHAR(100) NOT NULL,
    input_data JSONB,
    output_data JSONB,
    gas_used INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sc_exec_contract ON contract.smart_contract_executions(contract_id);
COMMENT ON TABLE contract.smart_contract_executions IS 'Detailed trace of programmatic contract clause execution.';

------------------------------------------------------------------------------------------------
-- Serial No: 200
-- Table: T200 - backup_verification_logs
-- Schema: storage
-- Description: Logs verification of backup integrity (checksums).
-- Business Case: A backup is useless if it's corrupt. This table logs the results of periodic
--verification jobs that read backups and verify their checksums. If a backup is corrupt, it alerts
--Ops immediately. It ensures the Disaster Recovery plan will actually work when needed.
-- KPIs: Backup Integrity Score.
-- Feature Reference: F145
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.backup_verification_logs (
    verify_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id VARCHAR(100) NOT NULL,
    verification_method VARCHAR(50) NOT NULL, -- 'CHECKSUM', 'PARTIAL_RESTORE'
    checksum_match BOOLEAN NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_backup_verify_status ON storage.backup_verification_logs(checksum_match);
COMMENT ON TABLE storage.backup_verification_logs IS 'Quality assurance records for disaster recovery artifacts.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 4 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER ops.maintenance_logs_timestamp
    BEFORE UPDATE ON ops.maintenance_logs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER sec.certificate_inventory_timestamp
    BEFORE UPDATE ON sec.certificate_inventory
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.incident_tickets_timestamp
    BEFORE UPDATE ON incident.incident_tickets
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.maintenance_logs_timestamp
    BEFORE UPDATE ON ops.maintenance_logs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 4: Tables 151-200)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 5)
-- =============================================================================================
-- Tables T201 - T250
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 201
-- Table: T201 - access_session_logs
-- Schema: security
-- Description: Detailed logs of user/admin sessions in the Fraud Console.
-- Business Case: The Fraud Console contains sensitive PII and financial data. Tracking sessions is
--critical for security forensics. This table logs every login, logout, and session activity. It
--identifies suspicious access patterns (e.g., Admin login at 3 AM from a new country) which could
--indicate an insider threat or compromised credentials. It supports the "Zero Trust" model by
--ensuring every session is attributable to a specific identity and timeframe.
-- KPIs: Session Duration, Failed Login Ratio, Insider Threat Detection Rate.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.access_session_logs (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    login_time TIMESTAMP WITH TIME ZONE NOT NULL,
    logout_time TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'LOGGED_OUT', 'TERMINATED', 'TIMEOUT')),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_session_user ON security.access_session_logs(user_id, login_time DESC);
COMMENT ON TABLE security.access_session_logs IS 'Comprehensive audit of administrative and user interactions with the fraud management interface.';

------------------------------------------------------------------------------------------------
-- Serial No: 202
-- Table: T202 - synthetic_identity_components
-- Schema: fraud
-- Description: Breakdown of signals indicating a synthetic identity.
-- Business Case: Synthetic identities (fake personas built from real data fragments) are hard to catch
--with simple rules. This table stores the specific weak signals that, when combined, suggest a
--synthetic ID. For example, an IP geolocation mismatch combined with an address that doesn't
--exist in postal records. By aggregating these component signals (F049), the ML model can detect
--complex fraud rings that create accounts to scale rewards abuse or cash out stolen funds.
-- KPIs: Synthetic ID Detection Precision, False Positive Rate.
-- Feature Reference: F049
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.synthetic_identity_components (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    signal_type VARCHAR(50) NOT NULL CHECK (signal_type IN ('IP_MISMATCH', 'NAME_ENTROPY_HIGH', 'DEVICE_AGE_ANOMALY', 'EMAIL_DOMAIN_SUSPICIOUS')),
    risk_contribution NUMERIC(3,2), -- Weight of this specific signal to the total score
    detail_value TEXT, -- The actual value (e.g., the specific mismatched IP)

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_synthetic_components_user ON fraud.synthetic_identity_components(user_hash);
COMMENT ON TABLE fraud.synthetic_identity_components IS 'Granular evidence repository for algorithmic detection of fabricated user identities.';

------------------------------------------------------------------------------------------------
-- Serial No: 203
-- Table: T203 - cron_job_history
-- Schema: ops
-- Description: History of scheduled cron job executions.
-- Business Case: Automated maintenance and data pipelines rely on cron jobs (e.g., nightly model retraining,
--log rotation). This table logs the execution status of these jobs. It acts as a heartbeat monitor;
--if a job fails to run or runs with errors, alerts are triggered. This ensures that background
--processes essential for system health (like generating the daily fraud report) are functioning reliably.
-- KPIs: Job Success Rate, Average Execution Duration, SLA Adherence.
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.cron_job_history (
    job_id SERIAL PRIMARY KEY,
    job_name VARCHAR(100) NOT NULL,
    run_status VARCHAR(20) NOT NULL CHECK (run_status IN ('SUCCESS', 'FAILURE', 'TIMEOUT')),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    output_log TEXT,
    error_message TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cron_history_name_time ON ops.cron_job_history(job_name, start_time DESC);
COMMENT ON TABLE ops.cron_job_history IS 'Execution ledger for scheduled system tasks ensuring operational continuity.';

------------------------------------------------------------------------------------------------
-- Serial No: 204
-- Table: T204 - training_data_distribution
-- Schema: ml
-- Description: Statistical distribution of training data to detect drift at source.
-- Business Case: Model drift often starts with the data changing. This table tracks the statistical
--properties (mean, variance, min, max) of training datasets over time. If the input data
--distribution shifts significantly from the training baseline, the model may need retraining even if
--performance hasn't degraded yet. It provides a proactive measure for model maintenance.
-- KPIs: Distribution Shift Detection Speed (KL-Divergence).
-- Feature Reference: F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.training_data_distribution (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    mean NUMERIC(15,6),
    variance NUMERIC(15,6),
    min_val NUMERIC(15,6),
    max_val NUMERIC(15,6),
    dataset_version VARCHAR(50) NOT NULL,

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_training_dist_feature ON ml.training_data_distribution(feature_name);
COMMENT ON TABLE ml.training_data_distribution IS 'Statistical baseline tracking for machine learning feature sets to proactively identify drift.';

------------------------------------------------------------------------------------------------
-- Serial No: 205
-- Table: T205 - partner_sla_metrics
-- Schema: integration
-- Description: Tracks SLA performance of external fraud data providers.
-- Business Case: PARI relies on external partners for data (e.g., Device fingerprinting, Email
--intelligence). This table tracks their uptime and response time. If a partner consistently misses
--their SLA, PARI can switch providers or negotiate credits. It ensures that external dependencies
--do not degrade the overall performance of the fraud engine.
-- KPIs: Partner Uptime %, Response Time P99.
-- Feature Reference: F029, F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.partner_sla_metrics (
    partner_id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    uptime_pct NUMERIC(5,2),
    response_time_p99_ms INTEGER,
    period DATE NOT NULL, -- e.g., '2023-10-01' for daily snapshot
    incidents_count INTEGER DEFAULT 0
);

CREATE INDEX idx_partner_sla_period ON integration.partner_sla_metrics(period);
COMMENT ON TABLE integration.partner_sla_metrics IS 'Performance monitoring data for third-party API integrations enforcing service level agreements.';

------------------------------------------------------------------------------------------------
-- Serial No: 206
-- Table: T206 - scam_reports
-- Schema: fraud
-- Description: User-reported scam instances that didn't result in a transaction yet.
-- Business Case: Users are often the first to spot scams (e.g., a phishing link sent in a chat).
--This table captures reports of potential scams that haven't yet resulted in a financial loss.
--Analyzing this data allows the system to blacklist URLs or domains pre-emptively, preventing
--other users from falling victim. It transforms users into active sensors in the fraud defense network.
-- KPIs: Report Triage Speed, Prevention Rate via Reported Scams.
-- Feature Reference: F087
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.scam_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporter_hash VARCHAR(64) NOT NULL,
    scammer_details TEXT, -- Description provided by user
    context TEXT, -- Where it happened (Email, Chat, Social Media)
    status VARCHAR(20) DEFAULT 'NEW' CHECK (status IN ('NEW', 'UNDER_REVIEW', 'CONFIRMED', 'DISMISSED')),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_scam_reports_timestamp
    BEFORE UPDATE ON fraud.scam_reports
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE fraud.scam_reports IS 'User-generated intelligence feed for preemptive identification of emerging fraud vectors.';

------------------------------------------------------------------------------------------------
-- Serial No: 207
-- Table: T207 - disaster_recovery_tests
-- Schema: ops
-- Description: Results of DR drills and failover tests.
-- Business Case: A Disaster Recovery (DR) plan is only good if it works. This table logs the results
--of scheduled drills where we intentionally fail services or data centers. It records RTO (Recovery
--Time Objective) and RPO (Recovery Point Objective) actuals vs targets. It validates that the
--system can actually survive a catastrophic failure without data loss.
-- KPIs: RTO/RPO Achievement %, Drill Success Rate.
-- Feature Reference: F019
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.disaster_recovery_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_date DATE NOT NULL,
    rto_target_sec INTEGER NOT NULL,
    rpo_target_sec INTEGER NOT NULL,
    rto_actual_sec INTEGER,
    rpo_actual_sec INTEGER,
    failover_node VARCHAR(100),
    result VARCHAR(20) CHECK (result IN ('SUCCESS', 'PARTIAL', 'FAILED')),
    notes TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.disaster_recovery_tests IS 'Validation records for business continuity planning and system resilience.';

------------------------------------------------------------------------------------------------
-- Serial No: 208
-- Table: T208 - mediation_notes
-- Schema: dispute
-- Description: Notes recorded during mediation sessions for disputes.
-- Business Case: Mediation is an informal step before arbitration. It involves negotiation between
--Payer and Merchant. This table stores the notes taken by the mediator or the system during this
--phase. It captures offers, counter-offers, and points of agreement. This history is crucial
--if the case escalates further, as it establishes what has already been attempted.
-- KPIs: Mediation Success Rate (Resolution without Arbitration).
-- Feature Reference: F052
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.mediation_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    mediator_id UUID,
    summary TEXT,
    recording_ref VARCHAR(255), -- Link to audio/video recording if applicable

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_mediation_notes_timestamp
    BEFORE UPDATE ON dispute.mediation_notes
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE dispute.mediation_notes IS 'Chronological log of negotiation events and dialogue during informal dispute resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 209
-- Table: T209 - model_explanations_cache
-- Schema: ml
-- Description: Cached SHAP explanations for specific transactions.
-- Business Case: Generating explanations (SHAP values) is computationally expensive. Since a user might
--view the explanation for a specific transaction multiple times (or an auditor might request it), this
--table caches the result. It stores the pre-calculated explanation JSON, reducing latency for the
--UI and saving CPU cycles.
-- KPIs: Cache Hit Ratio, Explanation Retrieval Latency.
-- Feature Reference: F051
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_explanations_cache (
    cache_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    explanation_json JSONB NOT NULL, -- The SHAP feature contributions
    model_version VARCHAR(50) NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL -- TTL: 30 Days from prompt
);

CREATE INDEX idx_explanation_cache_tx ON ml.model_explanations_cache(transaction_hash);
CREATE INDEX idx_explanation_cache_expire ON ml.model_explanations_cache(expires_at);
COMMENT ON TABLE ml.model_explanations_cache IS 'High-speed lookup layer for pre-computed AI decision interpretability data.';

------------------------------------------------------------------------------------------------
-- Serial No: 210
-- Table: T210 - key_derivation_events
-- Schema: security
-- Description: Logs of cryptographic key derivation events for wallets.
-- Business Case: Wallets use Hierarchical Deterministic (HD) key derivation. This table logs the
--derivation events (Parent Key -> Child Key) for auditing purposes. It ensures that the cryptographic
--lineage of funds can be traced. If a specific child key is compromised, this log helps identify
--which parent keys or sibling keys might also be at risk.
-- KPIs: Audit Trace Completeness.
-- Feature Reference: F012
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.key_derivation_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_key_id VARCHAR(100) NOT NULL,
    child_key_id VARCHAR(100) NOT NULL,
    derivation_path TEXT, -- e.g., "m/44'/60'/0'/0"
    purpose VARCHAR(50), -- e.g., "PAYMENT", "AUTHENTICATION"

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_key_derivation_child ON security.key_derivation_events(child_key_id);
COMMENT ON TABLE security.key_derivation_events IS 'Cryptographic genealogy log tracking wallet hierarchy for forensic analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 211
-- Table: T211 - feature_binning_configs
-- Schema: ml
-- Description: Configuration for binning continuous variables into discrete buckets for WOE encoding.
-- Business Case: Some models (like Logistic Regression or Gradient Boosting) handle categorical data better
--than continuous. This table stores the configuration for "binning" (e.g., Age: 0-18, 19-25, 26+).
--Weight of Evidence (WOE) encoding is then applied. It allows data scientists to experiment with
--different binning strategies without changing code.
-- KPIs: Binning Strategy Performance (AUC).
-- Feature Reference: F016
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_binning_configs (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    bin_edges NUMERIC[] NOT NULL, -- Array of cut points
    created_by UUID NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_feature_binning_timestamp
    BEFORE UPDATE ON ml.feature_binning_configs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ml.feature_binning_configs IS 'Parameter storage for discretization of continuous variables into risk-relevant categories.';

------------------------------------------------------------------------------------------------
-- Serial No: 212
-- Table: T212 - model_training_epochs
-- Schema: ml
-- Description: Detailed metrics (loss, accuracy) per training epoch for model debugging.
-- Business Case: Training a model takes many epochs (iterations). This table stores the granular metrics
--(Training Loss, Validation Loss, Accuracy) for every single epoch. It allows data scientists to
--plot learning curves and diagnose issues like overfitting (where training loss goes down but
--validation loss goes up) or underfitting.
-- KPIs: Model Convergence Speed, Final Loss Value.
-- Feature Reference: F002
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_training_epochs (
    epoch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    training_run_id UUID NOT NULL REFERENCES ml.retraining_jobs(job_id),
    epoch_num INTEGER NOT NULL,
    train_loss NUMERIC(10,6),
    val_loss NUMERIC(10,6),
    accuracy NUMERIC(5,4),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_training_epochs_run ON ml.model_training_epochs(training_run_id);
COMMENT ON TABLE ml.model_training_epochs IS 'Fine-grained performance telemetry for iterative machine learning model refinement.';

------------------------------------------------------------------------------------------------
-- Serial No: 213
-- Table: T213 - account_takeover_attempts
-- Schema: fraud
-- Description: Specific tracking of ATO attempts distinct from general transaction fraud.
-- Business Case: Account Takeover (ATO) is a specific threat vector involving credential theft or session
--hijacking. This table aggregates signals specific to ATO: rapid successive logins, password
--resets, and login from impossible geographies. It helps separate "transactional fraud" (stolen
--card) from "identity fraud" (stolen account), which require different remediation strategies.
-- KPIs: ATO Detection Rate, False Positive Rate on Logins.
-- Feature Reference: F130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.account_takeover_attempts (
    ato_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    source_ip INET,
    success BOOLEAN NOT NULL, -- Did the attacker get in?
    method VARCHAR(50) CHECK (method IN ('CREDENTIAL_STUFFING', 'PHISHING', 'SESSION_HIJACK')),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ato_user ON fraud.account_takeover_attempts(user_hash);
COMMENT ON TABLE fraud.account_takeover_attempts IS 'Focused surveillance log targeting identity intrusion events separate from payment anomalies.';

------------------------------------------------------------------------------------------------
-- Serial No: 214
-- Table: T214 - triangulation_fraud_events
-- Schema: fraud
-- Description: Tracks triangulation patterns (Buyer -> Mule -> Fraudster merchant).
-- Business Case: In triangulation, a fraudster acts as a seller, uses a stolen card to buy their own
--item, and ships to a "mule" address. This table detects this specific loop. It identifies
--relationships where a merchant is receiving payments that lead to known mule accounts, allowing PARI
--to shut down the fraudulent merchant account.
-- KPIs: Triangulation Loop Detection Rate.
-- Feature Reference: F091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.triangulation_fraud_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mule_account VARCHAR(64) NOT NULL, -- The address/account receiving goods
    fraudster_merchant_id UUID NOT NULL, -- The "Seller"
    buyer_tx_id VARCHAR(64), -- The stolen card transaction

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.triangulation_fraud_events IS 'Detection records for complex multi-party fraud schemes involving fictitious sales.';

------------------------------------------------------------------------------------------------
-- Serial No: 215
-- Table: T215 - carding_attack_vectors
-- Schema: fraud
-- Description: Logs patterns indicative of card testing (authorization attacks).
-- Business Case: "Carding" involves testing thousands of stolen card numbers via small authorization
--requests. This table identifies the attack vectors: are they testing one merchant? Are they using
--specific BINs (Bank Identification Numbers)? Analyzing this helps block the attack vector and
--identify the source of the stolen card list.
-- KPIs: Carding Attack Mitigation Speed.
-- Feature Reference: F062
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.carding_attack_vectors (
    vector_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID,
    payment_method_prefix VARCHAR(10), -- First 6-10 digits of card (BIN/IIN)
    attack_velocity INTEGER, -- Attempts per minute
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, BLOCKED

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.carding_attack_vectors IS 'Analysis of high-volume authorization attempts characteristic of stolen card validation.';

------------------------------------------------------------------------------------------------
-- Serial No: 216
-- Table: T216 - dispute_workflow_states
-- Schema: dispute
-- Description: State machine definition for the dispute lifecycle.
-- Business Case: Disputes follow a strict workflow (Open -> Review -> Mediation -> Closed). This table
--defines the valid states and transitions for that workflow. It enforces business rules, such as
--"A dispute cannot move from Open to Closed without passing through Review." It prevents manual
--errors or database manipulations that bypass required steps.
-- KPIs: Workflow Adherence Rate.
-- Feature Reference: F045, F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.dispute_workflow_states (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    state_name VARCHAR(50) NOT NULL UNIQUE,
    allowed_transitions JSONB NOT NULL, -- Array of state names this state can transition to
    timeout_minutes INTEGER, -- Auto-transition if stuck this long?

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.dispute_workflow_states IS 'Governance layer defining the valid progression and escalation paths of a dispute case.';

------------------------------------------------------------------------------------------------
-- Serial No: 217
-- Table: T217 - escalation_matrix
-- Schema: dispute
-- Description: Defines the matrix for escalating disputes based on value and type.
-- Business Case: Not all disputes are equal. High value ($10k+) disputes need Senior Management review,
--while low value disputes might be handled by Tier 1 agents. This table defines the "Escalation Matrix"
--mapping dispute attributes (Amount, Type, VIP Status) to the required Escalation Level. It ensures
--that critical issues get appropriate attention.
-- KPIs: Escalation Accuracy, Resolution Time by Tier.
-- Feature Reference: F045
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.escalation_matrix (
    matrix_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dispute_type VARCHAR(50) NOT NULL,
    value_range NUMRANGE NOT NULL, -- e.g., '[0,1000)'
    escalation_level INTEGER NOT NULL,
    assigned_role VARCHAR(50) NOT NULL, -- e.g., 'TIER_1_AGENT', 'SENIOR_MANAGER'
);

CREATE INDEX idx_escalation_matrix_type ON dispute.escalation_matrix(dispute_type);
COMMENT ON TABLE dispute.escalation_matrix IS 'Configuration logic routing incoming disputes to appropriate queues based on complexity and risk.';

------------------------------------------------------------------------------------------------
-- Serial No: 218
-- Table: T218 - circuit_breaker_states
-- Schema: ops
-- Description: Tracks the state of circuit breakers protecting the fraud detection API.
-- Business Case: If a downstream dependency (like the ML inference service) starts failing, the API
--should "trip the breaker" to fail fast rather than hanging. This table tracks the state of these
--circuit breakers (Open, Closed, Half-Open) and the failure counts. It prevents cascading failures
--across the payment platform.
-- KPIs: Mean Time to Recovery (MTTR) for Circuit Breakers.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.circuit_breaker_states (
    service_name VARCHAR(100) PRIMARY KEY,
    state VARCHAR(20) NOT NULL CHECK (state IN ('CLOSED', 'OPEN', 'HALF_OPEN')),
    failure_count BIGINT DEFAULT 0,
    last_failure_time TIMESTAMP WITH TIME ZONE,
    last_state_change TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.circuit_breaker_states IS 'Resilience pattern state machine preventing system overload during dependency failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 219
-- Table: T219 - service_mesh_policies
-- Schema: security
-- Description: Stores IAM/Service Mesh policies for M03 microservices.
-- Business Case: In a Service Mesh architecture, communication between services is governed by policies
--(mTLS, Traffic Splitting). This table stores the configuration for these policies. It defines which
--services can talk to which (e.g., "Public API" -> "Fraud Engine" is allowed, but "DB" -> "Public" is denied).
--It enforces Zero Trust security at the network layer.
-- KPIs: Policy Enforcement Success Rate.
-- Feature Reference: F017, M17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.service_mesh_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    ingress_rules JSONB, -- Rules for incoming traffic
    egress_rules JSONB, -- Rules for outgoing traffic
    version VARCHAR(20),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_service_mesh_policies_timestamp
    BEFORE UPDATE ON security.service_mesh_policies
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE security.service_mesh_policies IS 'Network traffic governance rules implementing micro-segmentation and security policies.';

------------------------------------------------------------------------------------------------
-- Serial No: 220
-- Table: T220 - prediction_explanations
-- Schema: ml
-- Description: Detailed SHAP/LIME explanations stored for specific high-value transactions.
-- Business Case: For high-value transactions or high-risk decisions, a simple score isn't enough.
--Regulators and customers demand an explanation. This table stores the detailed breakdown of feature
--contributions (e.g., "Location Velocity added 0.3 to the risk score"). It is the "Why" behind
--the "What".
-- KPIs: Explanation Storage Retrieval Speed.
-- Feature Reference: F051
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.prediction_explanations (
    explanation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    feature_contributions JSONB NOT NULL, -- Map of Feature -> Importance
    model_version VARCHAR(50) NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pred_expl_tx ON ml.prediction_explanations(transaction_hash);
COMMENT ON TABLE ml.prediction_explanations IS 'Detailed interpretability records for high-stakes fraud decisions.';

------------------------------------------------------------------------------------------------
-- Serial No: 221
-- Table: T221 - promo_abuse_events
-- Schema: fraud
-- Description: Logs specific abuse of promotional codes or coupons.
-- Business Case: Fraudsters exploit promotional economics (e.g., "Referral Bonus"). This table logs
--events where a promo code is used suspiciously (e.g., same IP using 50 different referral codes).
--It helps distinguish between genuine viral marketing and bot-driven incentive harvesting.
-- KPIs: Promo Abuse Detection Accuracy.
-- Feature Reference: F141
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.promo_abuse_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    promo_code_hash VARCHAR(100) NOT NULL,
    user_hash VARCHAR(64) NOT NULL,
    usage_count INTEGER,
    fraud_indicator BOOLEAN DEFAULT FALSE,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_promo_abuse_code ON fraud.promo_abuse_events(promo_code_hash);
COMMENT ON TABLE fraud.promo_abuse_events IS 'Incident log tracking the misuse of marketing incentives for financial gain.';

------------------------------------------------------------------------------------------------
-- Serial No: 222
-- Table: T222 - merchant_velocity_limits
-- Schema: fraud
-- Description: Custom velocity limits applied to specific merchants based on negotiation.
-- Business Case: Some merchants have legitimate high-volume needs (e.g., ticket sales for a stadium).
--This table stores custom velocity overrides for these trusted partners. It allows the system to
--apply risk-based friction without hindering legitimate high-velocity business, maintaining a balance
--between security and revenue enablement.
-- KPIs: Merchant Throughput Satisfaction Rate.
-- Feature Reference: F004, F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_velocity_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    max_tx_per_sec INTEGER,
    max_vol_per_hour NUMERIC(15,2),
    reason TEXT, -- Why was this limit granted?

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE fraud.merchant_velocity_limits IS 'Exception handling configuration for trusted high-volume partners.';

------------------------------------------------------------------------------------------------
-- Serial No: 223
-- Table: T223 - mediation_sessions
-- Schema: dispute
-- Description: Records of mediation sessions held for complex disputes.
-- Business Case: Mediation is a structured process. This table records the sessions themselves: Who
--was the mediator? When did it start/end? What was the outcome? It serves as the master record
--for the mediation phase, distinct from the notes (T208) or the case itself (T009).
-- KPIs: Mediation Session Duration, Resolution per Session.
-- Feature Reference: F052
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.mediation_sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    mediator_id UUID NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    outcome VARCHAR(50), -- AGREED, DEADLOCK, FAILED
    outcome_summary TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_mediation_sessions_timestamp
    BEFORE UPDATE ON dispute.mediation_sessions
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE dispute.mediation_sessions IS 'Administrative tracking of structured negotiation events between disputing parties.';

------------------------------------------------------------------------------------------------
-- Serial No: 224
-- Table: T224 - dependency_health_map
-- Schema: ops
-- Description: Real-time health status of M03 dependencies (Kafka, Redis, Postgres).
-- Business Case: The Fraud Engine is a stack. If the database is slow, or Kafka is lagging, the system
--degrades. This table stores the real-time health metrics (status, latency) for every dependency.
--It powers the status dashboard and allows for automated graceful degradation (e.g., switching to
--rules-only if ML is down).
-- KPIs: Dependency Availability %, Latency P99.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.dependency_health_map (
    dependency_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('HEALTHY', 'DEGRADED', 'DOWN', 'MAINTENANCE')),
    latency_ms INTEGER,
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dep_health_name ON ops.dependency_health_map(name);
COMMENT ON TABLE ops.dependency_health_map IS 'Live monitoring data for infrastructure components supporting the fraud ecosystem.';

------------------------------------------------------------------------------------------------
-- Serial No: 225
-- Table: T225 - hyperparameter_search_space
-- Schema: ml
-- Description: Defines the search space for automated hyperparameter tuning.
-- Business Case: Automated tuning (Grid Search, Bayesian Optimization) needs to know the bounds. This table
--defines the space: e.g., "Learning Rate: search between 0.001 and 0.1 on a log scale." It
--allows the tuning jobs to run autonomously without hard-coding limits in the software, supporting
--flexible experimentation.
-- KPIs: Search Space Coverage.
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.hyperparameter_search_space (
    param_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    param_name VARCHAR(100) NOT NULL,
    min_val NUMERIC(10,6),
    max_val NUMERIC(10,6),
    scale VARCHAR(20) CHECK (scale IN ('log', 'linear'))
);

COMMENT ON TABLE ml.hyperparameter_search_space IS 'Boundary definitions for automated machine learning optimization algorithms.';

------------------------------------------------------------------------------------------------
-- Serial No: 226
-- Table: T226 - blue_green_deployment_status
-- Schema: ops
-- Description: Tracks the status of blue/green deployments for zero-downtime updates.
-- Business Case: Blue/Green deployment minimizes risk by keeping the old version (Blue) live while the new
--version (Green) is deployed. This table tracks which environment is active and how much traffic
--it is receiving. It is the control plane for the traffic switcher.
-- KPIs: Deployment Cutover Time, Traffic Switch Latency.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.blue_green_deployment_status (
    deployment_id UUID NOT NULL,
    env_color VARCHAR(20) NOT NULL CHECK (env_color IN ('blue', 'green')),
    active_traffic_pct INTEGER CHECK (active_traffic_pct BETWEEN 0 AND 100),
    status VARCHAR(20) DEFAULT 'IDLE', -- IDLE, DEPLOYING, ACTIVE, DRAINING
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_blue_green PRIMARY KEY (deployment_id, env_color)
);

COMMENT ON TABLE ops.blue_green_deployment_status IS 'State tracker for zero-downtime release strategies ensuring continuous service availability.';

------------------------------------------------------------------------------------------------
-- Serial No: 227
-- Table: T227 - behavioral_biomarkers
-- Schema: fraud
-- Description: Anonymized biomarkers used for passive biometric authentication.
-- Business Case: Passive biometrics (how you type, move mouse) relies on identifying "biomarkers" (e.g.,
--"Typing Rhythm: Fast"). This table stores the statistical properties of these biomarkers for
--user groups. It allows the system to authenticate users based on behavior without storing raw
--sensitive telemetry data forever.
-- KPIs: Biomarker Distinctiveness (False Match Rate).
-- Feature Reference: F040
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.behavioral_biomarkers (
    biomarker_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_group VARCHAR(50), -- e.g., "DESKTOP_USER", "MOBILE_USER"
    marker_type VARCHAR(50) NOT NULL,
    mean_value NUMERIC(10,4),
    std_dev NUMERIC(10,4),

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.behavioral_biomarkers IS 'Statistical profiles of human-computer interaction patterns used for identity verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 228
-- Table: T228 - auto_response_templates
-- Schema: dispute
-- Description: Templates for automated responses to common dispute reasons.
-- Business Case: Automation reduces costs. This table links specific dispute reason codes (e.g., "Item Not
--Delivered") to specific automated response templates. It supports the logic in F116, where
--low-complexity disputes are resolved by bots using these pre-written responses.
-- KPIs: Auto-Resolution Success Rate.
-- Feature Reference: F024, F116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.auto_response_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reason_code VARCHAR(10) NOT NULL REFERENCES dispute.refund_reasons(code_id), -- Link to T105
    language_code CHAR(2) NOT NULL DEFAULT 'en',
    response_text TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.auto_response_templates IS 'Rule-based text repository enabling instant resolution of routine support inquiries.';

------------------------------------------------------------------------------------------------
-- Serial No: 229
-- Table: T229 - certificate_transparency_logs
-- Schema: security
-- Description: Logs of Certificate Transparency checks for internal TLS certs.
-- Business Case: Certificate Transparency (CT) logs provide a public record of issued certificates. This
--table logs the verification of internal certificates against these logs. It ensures that internal
--TLS certificates have not been compromised or issued by a rogue CA. It is a critical check for
--Man-in-the-Middle attacks.
-- KPIs: CT Log Verification Success Rate.
-- Feature Reference: F172
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.certificate_transparency_logs (
    ct_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cert_id UUID REFERENCES sec.certificate_inventory(cert_id),
    sct_list TEXT, -- Signed Certificate Timestamps
    validation_status VARCHAR(20) CHECK (validation_status IN ('VALID', 'NOT_FOUND', 'INVALID')),

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE security.certificate_transparency_logs IS 'Audit trail of public transparency log checks validating cryptographic trust anchors.';

------------------------------------------------------------------------------------------------
-- Serial No: 230
-- Table: T230 - money_mule_networks
-- Schema: fraud
-- Description: Identified networks of accounts used as money mules.
-- Business Case: Money mules are the "trucks" of money laundering—receiving funds and moving them along.
--This table groups identified mule accounts into networks. If a new transaction involves an account in
--a known mule network, it is immediately flagged. It helps map the flow of illicit funds across
--the platform.
-- KPIs: Network Link Accuracy, Cluster Size.
-- Feature Reference: F091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.money_mule_networks (
    network_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mule_account_ids TEXT[] NOT NULL, -- Array of user hashes
    confidence_score NUMERIC(3,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.money_mule_networks IS 'Collaborative intelligence grouping complicit accounts facilitating illicit fund transfers.';

------------------------------------------------------------------------------------------------
-- Serial No: 231
-- Table: T231 - geo_risk_zones
-- Schema: fraud
-- Description: Definitions of high-risk geographic zones for insurance/rating.
-- Business Case: Risk varies by location. This table stores definitions of high-risk zones (e.g., specific
--zip codes, countries known for cybercrime). Transactions originating or terminating in these zones
--are assigned a higher base risk score or require step-up authentication. It enables location-based
--risk pricing and routing.
-- KPIs: Geo-Risk Prediction Accuracy.
-- Feature Reference: F029, F091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.geo_risk_zones (
    zone_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2),
    region_risk_level VARCHAR(20) NOT NULL CHECK (region_risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reason TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_geo_risk_zones_timestamp
    BEFORE UPDATE ON fraud.geo_risk_zones
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE fraud.geo_risk_zones IS 'Geospatial risk configuration allowing automated adjustment of security protocols by location.';

------------------------------------------------------------------------------------------------
-- Serial No: 232
-- Table: T232 - capacity_planning_metrics
-- Schema: ops
-- Description: Historical metrics used for capacity planning (CPU, IO, TPS).
-- Business Case: Scaling requires data. This table stores historical performance metrics (CPU %, Disk
--IOPS, Transactions Per Second) for M03 services. It is used to trend growth and predict when
--new hardware is needed. It ensures that the fraud engine never degrades due to lack of resources.
-- KPIs: Capacity Forecast Accuracy.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.capacity_planning_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    cpu_pct NUMERIC(5,2),
    memory_pct NUMERIC(5,2),
    tps INTEGER, -- Transactions Per Second
    disk_io_wait NUMERIC(5,2)
);

CREATE INDEX idx_capacity_metrics_time ON ops.capacity_planning_metrics(timestamp DESC);
COMMENT ON TABLE ops.capacity_planning_metrics IS 'Infrastructure telemetry resource usage logs supporting hardware scaling decisions.';

------------------------------------------------------------------------------------------------
-- Serial No: 233
-- Table: T233 - feature_correlation_matrix
-- Schema: ml
-- Description: Stores correlation coefficients between features to reduce multicollinearity.
-- Business Case: Highly correlated features (e.g., "Invoice Amount" and "Tax Amount") can confuse some
--models and add noise. This table stores the calculated correlation coefficients between all feature
--pairs. Data scientists use it to select a subset of uncorrelated features for more efficient and
--robust training.
-- KPIs: Feature Selection Efficiency.
-- Feature Reference: F016
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_correlation_matrix (
    feat_a VARCHAR(100) NOT NULL,
    feat_b VARCHAR(100) NOT NULL,
    correlation_coefficient NUMERIC(5,4),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_correlation_matrix UNIQUE (feat_a, feat_b)
);

CREATE INDEX idx_corr_matrix_feat_a ON ml.feature_correlation_matrix(feat_a);
COMMENT ON TABLE ml.feature_correlation_matrix IS 'Statistical analysis data used to optimize feature sets by removing redundant variables.';

------------------------------------------------------------------------------------------------
-- Serial No: 234
-- Table: T234 - settlement_freezes
-- Schema: dispute
-- Description: Records of funds frozen due to ongoing disputes.
-- Business Case: When a dispute is opened, funds might be "frozen" to prevent the merchant from withdrawing
--them if they lose. This table records these freezes. It tracks the amount, the case ID, and the
--release condition. It acts as a temporary hold on the merchant's ledger balance.
-- KPIs: Freeze Release Latency, Accounting Accuracy.
-- Feature Reference: F045
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.settlement_freezes (
    freeze_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    currency CHAR(3) NOT NULL,
    released_at TIMESTAMP WITH TIME ZONE, -- NULL if still frozen
    release_condition JSONB
);

CREATE INDEX idx_settlement_freezes_merchant ON dispute.settlement_freezes(merchant_id);
COMMENT ON TABLE dispute.settlement_freezes IS 'Financial ledger locks reserving funds during the adjudication of conflicting claims.';

------------------------------------------------------------------------------------------------
-- Serial No: 235
-- Table: T235 - device_reputation_cache
-- Schema: fraud
-- Description: Temporary cache of external device reputation lookups.
-- Business Case: Calling external reputation APIs for every request is too slow. This table acts as a short-term
--cache (TTL) for device reputation. If we check "Device ABC" today, we cache the result for 1 hour.
--It significantly reduces latency and API costs while maintaining reasonably fresh risk data.
-- KPIs: Cache Hit Ratio, Freshness vs. Latency Trade-off.
-- Feature Reference: F005
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_reputation_cache (
    device_hash VARCHAR(64) PRIMARY KEY,
    reputation_score INTEGER CHECK (reputation_score BETWEEN 0 AND 100),
    provider VARCHAR(50),
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Note: A separate process or TTL mechanism is needed to purge old entries
COMMENT ON TABLE fraud.device_reputation_cache IS 'High-speed temporary storage for external device intelligence reducing API call overhead.';

------------------------------------------------------------------------------------------------
-- Serial No: 236
-- Table: T236 - superuser_access_logs
-- Schema: security
-- Description: High-security audit log for superuser (root) access to the fraud DB.
-- Business Case: Direct database access (root/superuser) bypasses application controls. This table logs
--EVERY command executed by a superuser. It is the "Black Box" recorder for the database. If data
--is modified illicitly or accidentally, this log is the only way to trace the "Who, When, What". It
--is strictly read-only after insert.
-- KPIs: Audit Completeness (100%).
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.superuser_access_logs (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    admin_id UUID NOT NULL,
    command TEXT NOT NULL, -- The SQL executed
    rows_affected INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_superuser_access_time ON security.superuser_access_logs(timestamp DESC);
COMMENT ON TABLE security.superuser_access_logs IS 'Tamper-evident log recording all privileged database activity for forensic integrity.';

------------------------------------------------------------------------------------------------
-- Serial No: 237
-- Table: T237 - key_rotation_schedule
-- Schema: security
-- Description: Schedule for automated rotation of cryptographic keys.
-- Business Case: Keys must be rotated regularly for security. This table stores the schedule for keys (API keys,
--Encryption Keys). It defines when a key was last rotated and when it should be next. It drives
--automation scripts that generate new keys and update configurations without downtime.
-- KPIs: Rotation Compliance %.
-- Feature Reference: F137
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.key_rotation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL, -- 'API_KEY', 'TLS_CERT', 'DB_ENCRYPTION'
    last_rotated TIMESTAMP WITH TIME ZONE NOT NULL,
    next_rotation TIMESTAMP WITH TIME ZONE NOT NULL,
    owner UUID NOT NULL
);

COMMENT ON TABLE security.key_rotation_schedule IS 'Planned maintenance calendar ensuring cryptographic assets are cycled to mitigate compromise impact.';

------------------------------------------------------------------------------------------------
-- Serial No: 238
-- Table: T238 - anomaly_detection_jobs
-- Schema: ops
-- Description: Logs of unsupervised anomaly detection jobs on system metrics.
-- Business Case: Fraud isn't just in transactions; it's in the system behavior too (e.g., DDOS).
--Unsupervised ML runs on system metrics (CPU, network traffic) to detect anomalies (DDOS attacks).
--This table logs the results of these background jobs. It helps security teams respond to infrastructure
--attacks.
-- KPIs: Anomaly Detection Sensitivity.
-- Feature Reference: F038, F126
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.anomaly_detection_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_metric VARCHAR(100) NOT NULL, -- e.g., 'inbound_traffic_gb'
    anomaly_score NUMERIC(5,2),
    threshold NUMERIC(5,2),
    is_alerted BOOLEAN DEFAULT FALSE,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.anomaly_detection_jobs IS 'Background task records identifying statistical outliers in infrastructure behavior.';

------------------------------------------------------------------------------------------------
-- Serial No: 239
-- Table: T239 - training_data_sampling
-- Schema: ml
-- Description: Logs of how datasets were sampled (stratified, random) to ensure fairness.
-- Business Case: Sampling bias leads to model bias. This table records exactly how the training data was
--sampled from the raw dataset. Did we use Stratified Sampling (to keep class ratios)? Did we
--balance by geography? It ensures reproducibility and fairness compliance in model training.
-- KPIs: Fairness Metric Score.
-- Feature Reference: F107
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.training_data_sampling (
    sample_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    sampling_method VARCHAR(50) NOT NULL, -- 'STRATIFIED', 'RANDOM', 'CLUSTER'
    strata_columns TEXT[], -- Columns used for stratification (e.g., ['region', 'gender'])
    sample_size BIGINT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.training_data_sampling IS 'Methodology documentation for dataset creation ensuring representative and unbiased model training.';

------------------------------------------------------------------------------------------------
-- Serial No: 240
-- Table: T240 - transaction_morphology
-- Schema: fraud
-- Description: Stores the "shape" of a transaction (time, freq, amount) for clustering.
-- Business Case: Transactions have a "shape" (Time of day, Amount bucket, Frequency). This table stores
--a vector representation of that shape. It is used for clustering algorithms (K-Means) to group
--similar transactions. If a new transaction falls into a "High Fraud Cluster", it is flagged, even
--if the user is new.
-- KPIs: Cluster Separation Quality.
-- Feature Reference: F009
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_morphology (
    tx_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    morphology_vector NUMERIC[] NOT NULL, -- The vectorized shape
    cluster_id UUID, -- Which cluster does it belong to?

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.transaction_morphology IS 'Feature vector storage enabling pattern recognition clustering for fraud detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 241
-- Table: T241 - legal_hold_notices
-- Schema: dispute
-- Description: Places a legal hold on evidence/deletion of specific cases.
-- Business Case: When a lawsuit is filed, evidence must be preserved indefinitely (Legal Hold). This table
--places a hold on specific cases or evidence. It overrides standard retention policies (like GDPR
--deletion) to ensure that critical evidence is not destroyed during ongoing litigation.
-- KPIs: Hold Enforcement Accuracy.
-- Feature Reference: F011, F035
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.legal_hold_notices (
    hold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    issued_by UUID NOT NULL,
    description TEXT NOT NULL,
    release_date DATE, -- NULL = Indefinite
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_legal_hold_notices_timestamp
    BEFORE UPDATE ON dispute.legal_hold_notices
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE dispute.legal_hold_notices IS 'Preservation order blocking data destruction protocols for ongoing legal proceedings.';

------------------------------------------------------------------------------------------------
-- Serial No: 242
-- Table: T242 - feature_rollout_phases
-- Schema: ops
-- Description: Manages phased rollout of new fraud features.
-- Business Case: Rolling out a feature to 100% of users is risky. This table manages phased rollouts. It
--defines which percentage of users (e.g., 10%, 50%) see the new feature. It allows for gradual
--monitoring and instant rollback if issues are detected in the early phases.
-- KPIs: Rollout Progress %, Incident Rate per Phase.
-- Feature Reference: F050
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.feature_rollout_phases (
    phase_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    percentage INTEGER NOT NULL CHECK (percentage BETWEEN 0 AND 100),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'PLANNED' -- PLANNED, ACTIVE, COMPLETED, STOPPED
);

COMMENT ON TABLE ops.feature_rollout_phases IS 'Staged deployment controller minimizing blast radius of new functionality.';

------------------------------------------------------------------------------------------------
-- Serial No: 243
-- Table: T243 - voice_auth_attempts
-- Schema: fraud
-- Description: Logs of voice biometric authentication attempts.
-- Business Case: Voice authentication (F124) can fail or be spoofed. This table logs every attempt: Who
--tried? What was the match score? Did it pass? It allows security teams to detect patterns of
--attacks (e.g., repeated failures from a specific caller ID) or tuning issues with the voice model.
-- KPIs: False Acceptance Rate (FAR), False Rejection Rate (FRR).
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.voice_auth_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    voice_hash VARCHAR(64) NOT NULL, -- The print being matched against
    match_score NUMERIC(3,2),
    result VARCHAR(20) NOT NULL CHECK (result IN ('MATCH', 'NO_MATCH', 'INCONCLUSIVE')),
    duration_ms INTEGER,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_voice_auth_user ON fraud.voice_auth_attempts(user_hash);
COMMENT ON TABLE fraud.voice_auth_attempts IS 'Verification event log for biometric identity checks using voiceprint analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 244
-- Table: T244 - ip_whitelists
-- Schema: security
-- Description: Whitelisted IP ranges for merchant API callbacks.
-- Business Case: Merchants configure webhooks. To prevent other actors from spoofing these webhooks or
--flooding them, PARI (or the Merchant) may whitelist IP ranges that PARI is allowed to connect
--from. This table stores these IP ranges (CIDR blocks) and enforces them at the gateway.
-- KPIs: Spoofing Block Success Rate.
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.ip_whitelists (
    range_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    ip_range INET NOT NULL, -- e.g., '192.168.1.0/24'
    description TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ip_whitelist_merchant ON security.ip_whitelists(merchant_id);
COMMENT ON TABLE security.ip_whitelists IS 'Access control list defining permitted network sources for partner integrations.';

------------------------------------------------------------------------------------------------
-- Serial No: 245
-- Table: T245 - model_deployment_drift
-- Schema: ml
-- Description: Tracks the drift between training environment and production data.
-- Business Case: Data drift can be subtle. This table tracks the statistical distance (e.g., Population
--Stability Index) between the data used to train the model and the data currently being seen in
--production. If the distance grows too large, it triggers a retraining alert. It ensures the model
--remains relevant to the real world.
-- KPIs: Drift Magnitude, Retraining Trigger Frequency.
-- Feature Reference: F026
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_deployment_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    train_distribution NUMERIC(10,4),
    prod_distribution NUMERIC(10,4),
    distance_metric VARCHAR(50), -- 'PSI', 'KL_DIVERGENCE'
    distance_value NUMERIC(10,4),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_model_deploy_drift_model ON ml.model_deployment_drift(model_id, timestamp);
COMMENT ON TABLE ml.model_deployment_drift IS 'Statistical monitoring comparing live data characteristics against model training baselines.';

------------------------------------------------------------------------------------------------
-- Serial No: 246
-- Table: T246 - refund_split_details
-- Schema: dispute
-- Description: Details of refunds split across multiple original transactions (basket refund).
-- Business Case: A user might buy 3 items in one transaction, but return only 1. The system must calculate
--how to split the refund. This table stores the breakdown: Original Transaction ID, Amount
--Refunded, and perhaps "Change" logic. It ensures financial accuracy when partial refunds occur
--against a single payment authorization.
-- KPIs: Calculation Accuracy.
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.refund_split_details (
    refund_parent_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    original_tx_id VARCHAR(64) NOT NULL,
    amount_refunded NUMERIC(15,2) NOT NULL,

    CONSTRAINT pk_refund_split_details PRIMARY KEY (refund_parent_id, original_tx_id)
);

COMMENT ON TABLE dispute.refund_split_details IS 'Financial breakdown for complex refunds involving proration across bundled items.';

------------------------------------------------------------------------------------------------
-- Serial No: 247
-- Table: T247 - communication_templates
-- Schema: dispute
-- Description: Master templates for SMS/Email communications with users.
-- Business Case: Consistent communication builds trust. This table stores the master templates for all
--outgoing messages (SMS, Email, Push). It supports variables (e.g., {{amount}}) and multi-language.
--It is the single source of truth for all customer-facing text in the dispute module.
-- KPIs: Template Usage Rate, Localization Coverage.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.communication_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    channel VARCHAR(20) NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'PUSH', 'WEBHOOK')),
    locale VARCHAR(10) NOT NULL DEFAULT 'en_US',
    subject VARCHAR(255),
    body_template TEXT NOT NULL,
    variables TEXT[], -- List of expected variables
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.communication_templates IS 'Canonical library of messaging content ensuring brand consistency across channels.';

------------------------------------------------------------------------------------------------
-- Serial No: 248
-- Table: T248 - container_image_registries
-- Schema: ops
-- Description: Audit of container images deployed for M03 services.
-- Business Case: In a containerized environment (Docker/K8s), we must know exactly what image hash is
--running. This table stores the image hash for every deployed service version. If a vulnerability is
--found in a specific image hash (e.g., CVE-2023-XXXX), we can instantly identify which services
--are affected.
-- KPIs: Image Traceability.
-- Feature Reference: F017
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.container_image_registries (
    image_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    image_hash VARCHAR(255) NOT NULL, -- SHA256 of the image
    registry_url TEXT,
    security_scan_date DATE,

    -- Metadata
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_container_image_service ON ops.container_image_registries(service_name);
COMMENT ON TABLE ops.container_image_registries IS 'Inventory of software artifacts facilitating rapid vulnerability assessment.';

------------------------------------------------------------------------------------------------
-- Serial No: 249
-- Table: T249 - social_media_handles
-- Schema: fraud
-- Description: Anonymized social media handles linked to accounts for OSINT fraud checks.
-- Business Case: Open Source Intelligence (OSINT) helps verify identity. This table stores anonymized
--hashes of social media handles linked to user accounts (with consent). It allows the system to
--check if a user's social profile looks "real" and established, reducing risk of synthetic identity.
-- KPIs: Profile Enrichment Success Rate.
-- Feature Reference: F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.social_media_handles (
    handle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    platform VARCHAR(50) NOT NULL, -- 'TWITTER', 'LINKEDIN', 'FACEBOOK'
    handle_hash VARCHAR(255) NOT NULL,
    account_age_days INTEGER,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_social_media_user ON fraud.social_media_handles(user_hash);
COMMENT ON TABLE fraud.social_media_handles IS 'Cross-reference data linking user identities to external social footprints for validation.';

------------------------------------------------------------------------------------------------
-- Serial No: 250
-- Table: T250 - jwt_revocation_list
-- Schema: security
-- Description: List of revoked JWT tokens for immediate session invalidation.
-- Business Case: JWTs are stateless, but we need a way to revoke them immediately (e.g., user clicks
--"Logout from all devices"). This table stores the JTI (JWT ID) of revoked tokens. The
--authentication middleware checks this list on every request. It balances JWT statelessness with
--security requirements.
-- KPIs: Revocation Propagation Latency.
-- Feature Reference: F119
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.jwt_revocation_list (
    jti VARCHAR(255) PRIMARY KEY, -- The unique ID of the token
    user_hash VARCHAR(64) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL -- To keep table size small
);

CREATE INDEX idx_jwt_revocation_expiry ON security.jwt_revocation_list(expires_at);
COMMENT ON TABLE security.jwt_revocation_list IS 'Deny-list of invalidated authentication tokens supporting immediate session termination.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 5 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

-- Create triggers for tables with updated_by/updated_at columns managed by common.manage_timestamps()
-- (Note: Triggers for specific tables were added inline above for brevity where appropriate,
-- but here we ensure standard ones are applied if columns exist)

CREATE TRIGGER trg_access_session_logs_timestamp
    BEFORE UPDATE ON security.access_session_logs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_training_data_distribution_timestamp
    BEFORE UPDATE ON ml.training_data_distribution
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_device_reputation_cache_timestamp
    BEFORE UPDATE ON fraud.device_reputation_cache
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_feature_rollout_phases_timestamp
    BEFORE UPDATE ON ops.feature_rollout_phases
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 5: Tables 201-250)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 6)
-- =============================================================================================
-- Tables T251 - T350
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 251
-- Table: T251 - telemetry_sampling_rates
-- Schema: ops
-- Description: Dynamic configuration for telemetry sampling (traces/metrics).
-- Business Case: Observability (Tracing/Metrics) at 100% volume is too expensive. This table stores
--configuration for adaptive sampling rates. For example, sample 1% of `GET` requests but 100% of
--`POST` transactions. Or sample 100% of error traces. It allows Ops to maintain visibility
--into critical paths without bankrupting the cloud bill for observability backends like Jaeger.
--KPIs: Sampling Cost Efficiency, Critical Path Visibility Retention.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.telemetry_sampling_rates (
    telemetry_type VARCHAR(50) NOT NULL, -- 'TRACE', 'METRIC', 'LOG'
    service_name VARCHAR(100) NOT NULL,
    sampling_rate NUMERIC(3,2) CHECK (sampling_rate BETWEEN 0 AND 1),
    criteria JSONB, -- e.g., {"status_code": 500} to sample 100% errors
    version INTEGER DEFAULT 1,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT pk_telemetry_sampling UNIQUE (telemetry_type, service_name, version)
);

CREATE TRIGGER trg_telemetry_sampling_timestamp
    BEFORE UPDATE ON ops.telemetry_sampling_rates
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ops.telemetry_sampling_rates IS 'Adaptive configuration for reducing observability costs while retaining critical system visibility.';

------------------------------------------------------------------------------------------------
-- Serial No: 252
-- Table: T252 - user_risk_questions
-- Schema: fraud
-- Description: Dynamic challenge-response questions for step-up authentication.
-- Business Case: Dynamic Friction (F081) requires questions. This table stores the bank of questions
--(e.g., "What city did you file taxes in last year?"). It maps questions to Risk Score
--thresholds (e.g., "Ask this if score > 80"). It ensures that Step-Up Auth is context-aware
--and difficult for bots to script against.
-- KPIs: Bot Bypass Rate, Legitimate User Pass Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_risk_questions (
    question_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    question_text TEXT NOT NULL,
    answer_type VARCHAR(20) CHECK (answer_type IN ('TEXT', 'MULTIPLE_CHOICE', 'BOOLEAN')),
    risk_score_min INTEGER CHECK (risk_score_min BETWEEN 0 AND 100),
    risk_score_max INTEGER CHECK (risk_score_max BETWEEN 0 AND 100),
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

COMMENT ON TABLE fraud.user_risk_questions IS 'Repository of knowledge-based authentication challenges used for dynamic step-up security.';

------------------------------------------------------------------------------------------------
-- Serial No: 253
-- Table: T253 - data_masking_rules
-- Schema: audit
-- Description: Rules for masking PII in logs and non-prod environments.
-- Business Case: Developers shouldn't see real PII in dev logs. This table defines Regex rules
--(e.g., `\b\d{3}-\d{2}-\d{4}\b` for SSN) and the masking function (Redact, Hash,
--Tokenize). It applies to ETL pipelines that copy production data to development environments, ensuring
--GDPR compliance in lower environments.
-- KPIs: PII Leak Count in Dev Environments.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.data_masking_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    regex_pattern TEXT NOT NULL,
    mask_function VARCHAR(50) NOT NULL, -- 'REDACT_STARS', 'HASH_SHA256', 'TOKENIZE'
    target_column VARCHAR(100), -- e.g., 'user_email'

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

COMMENT ON TABLE audit.data_masking_rules IS 'Configuration for automated sanitization of sensitive data in non-production pipelines.';

------------------------------------------------------------------------------------------------
-- Serial No: 254
-- Table: T254 - cost_allocation_tags
-- Schema: ops
-- Description: Tags for allocating cloud infrastructure costs to specific teams/features.
-- Business Case: Cloud bills are huge. This table maps AWS/Azure resources (e.g., S3 Buckets, EC2
--Instances) to Cost Centers (e.g., "M03-LSTM-Training"). It enables FinOps to chargeback
--costs accurately to specific projects and optimize spend.
-- KPIs: Cost Attribution Accuracy, Budget Adherence.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.cost_allocation_tags (
    resource_id VARCHAR(100) NOT NULL, -- Cloud Resource ID
    tag_key VARCHAR(50) NOT NULL,
    tag_value VARCHAR(100) NOT NULL,

    CONSTRAINT pk_cost_allocation UNIQUE (resource_id, tag_key)
);

COMMENT ON TABLE ops.cost_allocation_tags IS 'Metadata linking cloud resources to financial cost centers for budget management.';

------------------------------------------------------------------------------------------------
-- Serial No: 255
-- Table: T255 - api_gateway_routes
-- Schema: api
-- Description: Definitions of API routes mapped to internal M03 services.
-- Business Case: The API Gateway is the door. This table maps external paths (e.g., `/v1/fraud/score`)
--to internal services (e.g., `fraud-engine-prod`). It also applies rate limiting references
--and authentication requirements. It centralizes routing logic.
-- KPIs: Route Configuration Latency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api.api_gateway_routes (
    route_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    path_pattern VARCHAR(255) NOT NULL UNIQUE, -- e.g., /check/*
    target_service VARCHAR(100) NOT NULL,
    rate_limit_ref UUID REFERENCES api.rate_limit_quotas(tier_name),
    auth_required BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_api_gateway_routes_timestamp
    BEFORE UPDATE ON api.api_gateway_routes
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE api.api_gateway_routes IS 'Routing configuration mapping external endpoints to internal microservices.';

------------------------------------------------------------------------------------------------
-- Serial No: 256
-- Table: T256 - active_learning_uncertainty
-- Schema: ml
-- Description: Stores uncertainty scores for data points selected for human labeling.
-- Business Case: Active Learning works by labeling the most "confusing" points. This table stores those
--points. It calculates uncertainty (e.g., 0.5 probability means model is clueless). Humans
--label these first to maximize model improvement per label. It optimizes the expensive human
--labeling effort.
-- KPIs: Label Efficiency (Model Gain per Label).
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.active_learning_uncertainty (
    sample_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    model_prediction NUMERIC(5,2), -- e.g., 0.5 (Fraud probability)
    uncertainty_score NUMERIC(5,2) NOT NULL, -- e.g., 0.9 (Very uncertain)
    labeled BOOLEAN DEFAULT FALSE,
    labeler_id UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.active_learning_uncertainty IS 'Prioritization queue for human-in-the-loop annotation of ambiguous data points.';

------------------------------------------------------------------------------------------------
-- Serial No: 257
-- Table: T257 - phishing_intelligence
-- Schema: fraud
-- Description: Hashes of known phishing URLs targeting the platform.
-- Business Case: Phishing is a top vector. This table stores hashes of URLs known to be phishing kits.
--When a user clicks a link in a dispute email or chat, the hash is checked here. It warns
--the user "This is a known scam site", preventing credential theft.
-- KPIs: Phishing Detection Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.phishing_intelligence (
    url_hash VARCHAR(64) NOT NULL PRIMARY KEY, -- SHA256 of URL
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    threat_level VARCHAR(20) CHECK (threat_level IN ('LOW', 'MEDIUM', 'HIGH')),
    active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE fraud.phishing_intelligence IS 'Blocklist of known malicious URLs to prevent social engineering attacks.';

------------------------------------------------------------------------------------------------
-- Serial No: 258
-- Table: T258 - failed_login_locations
-- Schema: sec
-- Description: Tracks failed login attempts with location data for geo-fencing.
-- Business Case: Logins from impossible locations are suspicious. This table logs failed attempts with
--GeoIP data. If a user fails login in Russia, then succeeds in Brazil 5 mins later, it's
--clearly an ATO or travel fraud. It enriches the context of authentication events.
-- KPIs: Geo-Anomaly Detection Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.failed_login_locations (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    ip_address INET,
    country_code CHAR(2),
    city VARCHAR(100),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_failed_login_geo ON sec.failed_login_locations(user_hash, timestamp);
COMMENT ON TABLE sec.failed_login_locations IS 'Geospatial log of unsuccessful authentication attempts used for travel fraud detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 259
-- Table: T259 - alert_escalation_paths
-- Schema: ops
-- Description: Defines how alerts escalate from Ops -> Engineering -> Executives.
-- Business Case: Not all alerts are equal. This table defines the path. "High CPU" -> Ops. "Database
--Down" -> VP of Engineering. It ensures that critical issues get the right attention immediately
--and don't get lost in a junior engineer's inbox.
-- KPIs: Mean Time To Acknowledge (MTTA) by Severity.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.alert_escalation_paths (
    alert_type VARCHAR(50) PRIMARY KEY,
    level_1_recipient VARCHAR(255) NOT NULL, -- Email/Slack channel
    level_2_recipient VARCHAR(255),
    level_3_recipient VARCHAR(255),
    max_wait_minutes INTEGER NOT NULL
);

COMMENT ON TABLE ops.alert_escalation_paths IS 'Workflow definitions ensuring critical system events reach appropriate management levels.';

------------------------------------------------------------------------------------------------
-- Serial No: 260
-- Table: T260 - user_anonymity_metrics
-- Schema: fraud
-- Description: Tracks the size of the anonymity set for users (privacy metric).
-- Business Case: Differential Privacy relies on "k-anonymity" (being indistinguishable from k-1 others).
--This table tracks the size of the anonymity set for users over time. If sets shrink below a
--threshold, we must inject more noise or stop processing that user to guarantee privacy.
-- KPIs: Average Anonymity Set Size.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_anonymity_metrics (
    user_hash VARCHAR(64) PRIMARY KEY,
    set_size BIGINT, -- How many other users look like this one?
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.user_anonymity_metrics IS 'Quantitative measure of privacy assurance tracking crowd-mixing effectiveness.';

------------------------------------------------------------------------------------------------
-- Serial No: 261
-- Table: T261 - distributed_traces
-- Schema: ops
-- Description: Stores trace IDs for cross-service request tracking (Jaeger/Zipkin).
-- Business Case: Microservices are distributed. A single request hits Fraud, DB, and User Service. This table
--links these "Spans" by a Trace ID. It allows debugging of performance bottlenecks across
--service boundaries.
-- KPIs: Trace Completeness %.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.distributed_traces (
    trace_id UUID NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_traces_id ON ops.distributed_traces(trace_id);
CREATE INDEX idx_traces_time ON ops.distributed_traces(start_time);
COMMENT ON TABLE ops.distributed_traces IS 'Index of distributed tracing spans enabling root cause analysis across microservices.';

------------------------------------------------------------------------------------------------
-- Serial No: 262
-- Table: T262 - third_party_arbitrators
-- Schema: dispute
-- Description: Approved third-party arbitrators for high-value disputes.
-- Business Case: Sometimes we need a judge. This table lists approved arbitration firms (e.g., JAMS).
--It tracks their credentials, jurisdiction, and contact info. When a case is escalated (F052),
--the system assigns a qualified arbitrator from this list.
-- KPIs: Arbitrator Assignment Speed.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.third_party_arbitrators (
    arbitrator_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    jurisdiction VARCHAR(100),
    contact_info TEXT,
    active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.third_party_arbitrators IS 'Registry of certified external dispute resolution service providers.';

------------------------------------------------------------------------------------------------
-- Serial No: 263
-- Table: T263 - transaction_chain_analysis
-- Schema: fraud
-- Description: Pre-computed chain analysis results for deep forensic investigations.
-- Business Case: Following the money is hard. This table stores pre-computed chains (A -> B -> C).
--Instead of querying the graph DB (T023) during an investigation, we query this fast table
--of known suspicious paths. It speeds up forensic analysis for law enforcement.
-- KPIs: Forensic Query Latency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_chain_analysis (
    chain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    start_tx VARCHAR(64) NOT NULL,
    end_tx VARCHAR(64) NOT NULL,
    hop_count INTEGER NOT NULL,
    total_amount NUMERIC(15,2),
    risk_score INTEGER,

    -- Metadata
    last_analyzed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.transaction_chain_analysis IS 'Optimized cache of complex money trail correlations for rapid forensic review.';

------------------------------------------------------------------------------------------------
-- Serial No: 264
-- Table: T264 - salt_values
-- Schema: sec
-- Description: Manages salt values for hashing sensitive identifiers.
-- Business Case: Salting prevents Rainbow Table attacks on hashes. This table stores the active salt
--values used for hashing specific data types (e.g., Device Hashes). Rotating salts regularly
--increases security. It ensures that deterministic hashing remains secure against pre-computed attacks.
-- KPIs: Salt Rotation Compliance.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.salt_values (
    salt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    purpose VARCHAR(50) NOT NULL, -- e.g., 'DEVICE_FINGERPRINT'
    salt_value BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE sec.salt_values IS 'Lifecycle management for cryptographic salts ensuring hash integrity.';

------------------------------------------------------------------------------------------------
-- Serial No: 265
-- Table: T265 - feature_statistics_cache
-- Schema: ml
-- Description: Cached statistics (mean, std) for real-time feature normalization.
-- Business Case: Normalizing features (e.g., Z-Score) requires knowing the global mean/std dev. Querying
--the full training set is slow. This table caches the current stats. The inference engine reads
--from here to normalize inputs instantly.
-- KPIs: Inference Latency, Cache Freshness.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_statistics_cache (
    feature_name VARCHAR(100) PRIMARY KEY,
    mean NUMERIC(15,6),
    variance NUMERIC(15,6),
    sample_count BIGINT,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.feature_statistics_cache IS 'High-speed lookup layer for statistical parameters used in data normalization.';

------------------------------------------------------------------------------------------------
-- Serial No: 266
-- Table: T266 - environment_variables
-- Schema: ops
-- Description: Secure storage of environment variable configurations (encrypted).
-- Business Case: Env vars contain secrets. This table acts as a secure, auditable store for them. It
--encrypts values at rest. It allows Ops to update configs (e.g., switch to new DB node) via
--SQL triggers rather than SSHing into servers.
-- KPIs: Secret Rotation Speed.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.environment_variables (
    env_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    var_name VARCHAR(100) NOT NULL,
    encrypted_value BYTEA NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_environment_variables_timestamp
    BEFORE UPDATE ON ops.environment_variables
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ops.environment_variables IS 'Secure repository for configuration secrets enabling automated management.';

------------------------------------------------------------------------------------------------
-- Serial No: 267
-- Table: T267 - data_export_requests
-- Schema: audit
-- Description: Logs of requests to export data (e.g., for auditors).
-- Business Case: Exporting data is a risk. This table logs every request. Who asked? What tables?
--Was it granted? It ensures that no data leaves the production environment without a logged,
--approved request. It satisfies strict data governance policies.
-- KPIs: Audit Trail Completeness.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.data_export_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requester_id UUID NOT NULL,
    tables_requested TEXT[] NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, COMPLETED
    export_path TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.data_export_requests IS 'Authorization workflow tracking for extraction of sensitive datasets.';

------------------------------------------------------------------------------------------------
-- Serial No: 268
-- Table: T268 - bin_range_risk
-- Schema: fraud
-- Description: Risk associated with specific card BIN/IIN ranges.
-- Business Case: Some BINs (Bank Identification Numbers) are riskier than others (e.g., pre-paid cards).
--This table assigns risk scores to BIN ranges. It allows the rule engine to block or step-up auth
--for cards from high-risk issuing banks without expensive external API calls.
-- KPIs: BIN Coverage %.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.bin_range_risk (
    bin_range VARCHAR(10) PRIMARY KEY, -- First 6-10 digits
    risk_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH
    issuer_country VARCHAR(3),
    card_type VARCHAR(20) CHECK (card_type IN ('CREDIT', 'DEBIT', 'PREPAID'))
);

COMMENT ON TABLE fraud.bin_range_risk IS 'Risk assignment tables for payment card identifiers enabling fast heuristic filtering.';

------------------------------------------------------------------------------------------------
-- Serial No: 269
-- Table: T269 - cron_job_statistics
-- Schema: ops
-- Description: Statistics of cron job execution times (min, max, avg).
-- Business Case: Monitoring cron health. This table aggregates runtime stats (min, max, avg) for every
--scheduled job. It helps identify performance degradation (e.g., "The backup job is taking
--2x longer than last week").
-- KPIs: Job Runtime Stability.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.cron_job_statistics (
    job_name VARCHAR(100) PRIMARY KEY,
    run_count BIGINT,
    min_duration_ms INTEGER,
    max_duration_ms INTEGER,
    avg_duration_ms NUMERIC(10,2),

    -- Metadata
    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.cron_job_statistics IS 'Aggregated performance metrics for scheduled background tasks.';

------------------------------------------------------------------------------------------------
-- Serial No: 270
-- Table: T270 - settlement_exceptions_log
-- Schema: dispute
-- Description: Log of exceptions during financial settlement processing.
-- Business Case: Settlements fail (Bank timeout, wrong IBAN). This table logs these exceptions. It links
--the refund ID to the error message. The Finance team uses this to retry failed settlements or
--contact the merchant for correct details.
-- KPIs: Exception Resolution Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.settlement_exceptions_log (
    exception_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    batch_id VARCHAR(100) NOT NULL,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    error_message TEXT NOT NULL,
    retry_count INTEGER DEFAULT 0,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_settlement_exc_batch ON dispute.settlement_exceptions_log(batch_id);
COMMENT ON TABLE dispute.settlement_exceptions_log IS 'Error log for financial payouts facilitating retry logic and support troubleshooting.';

------------------------------------------------------------------------------------------------
-- Serial No: 271
-- Table: T271 - smart_contracts_code
-- Schema: contract
-- Description: Actual code/logic references for smart contracts used in disputes.
-- Business Case: Smart contracts execute code. This table stores the logic (e.g., Solidity or JSON-Logic
--snippets) referenced by the contract (T007). It ensures that the "Terms" are not just text, but
--executable code that the system runs to validate conditions.
-- KPIs: Code Execution Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.smart_contracts_code (
    code_ref UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.jsonld_contracts(contract_id),
    code_snippet TEXT NOT NULL,
    language VARCHAR(20), -- 'SOLIDITY', 'JS_LOGIC'
    version_hash VARCHAR(64),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE contract.smart_contracts_code IS 'Repository of executable logic defining automated contract terms.';

------------------------------------------------------------------------------------------------
-- Serial No: 272
-- Table: T272 - health_check_history
-- Schema: ops
-- Description: Historical log of health check endpoints for uptime calculation.
-- Business Case: SLA reporting requires historical uptime. This table logs the result of every health
--check ping (200 OK vs 503 Service Unavailable). It is used to calculate the "99.99% Uptime"
--metrics presented to merchants.
-- KPIs: Uptime Calculation Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.health_check_history (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint VARCHAR(100) NOT NULL, -- URL or Service Name
    status_code INTEGER,
    response_time_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_health_history_time ON ops.health_check_history(timestamp);
COMMENT ON TABLE ops.health_check_history IS 'Time-series data of service availability supporting SLA compliance reporting.';

------------------------------------------------------------------------------------------------
-- Serial No: 273
-- Table: T273 - model_decommission_log
-- Schema: ml
-- Description: Log of models that have been retired and why.
-- Business Case: Models have a lifecycle. This table records why a model was retired (e.g., "Bias
--Detected", "Newer Model Better", "Drift Too High"). It provides a history of the AI evolution
--and supports "Explainability" of why a certain decision was made by an old model.
-- KPIs: Model Governance Compliance.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_decommission_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    decommissioned_by UUID NOT NULL,
    reason TEXT NOT NULL,
    replaced_by_model_id UUID,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_decommission_log IS 'Retirement record for machine learning models ensuring auditability of AI history.';

------------------------------------------------------------------------------------------------
-- Serial No: 274
-- Table: T274 - ip_threat_intelligence
-- Schema: sec
-- Description: Aggregated threat intel for IP addresses.
-- Business Case: We aggregate threat data. This table stores combined threat intel for IPs (e.g., "Is
--Tor Exit Node" AND "Is on Spamhaus"). A single source might be weak, but combined signals are
--strong. It powers the "Blacklist" feature (T014).
-- KPIs: Threat Confidence Score.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ip_threat_intelligence (
    ip_address INET PRIMARY KEY,
    threat_types TEXT[], -- ['TOR', 'BOTNET', 'PROXY']
    confidence NUMERIC(3,2),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.ip_threat_intelligence IS 'Consolidated security profile for IP addresses derived from multiple external sources.';

------------------------------------------------------------------------------------------------
-- Serial No: 275
-- Table: T275 - friendly_fraud_signals
-- Schema: fraud
-- Description: Specific signals indicating potential friendly fraud (e.g., repeat claims).
-- Business Case: Friendly fraud (customer lies) is distinct. This table stores specific signals like
--"High frequency of Item Not Received claims" or "Claims refund immediately after delivery". It
--helps the model distinguish between real dissatisfaction and systematic abuse.
-- KPIs: Friendly Fraud Detection Precision.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.friendly_fraud_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    merchant_id UUID,
    claim_frequency INTEGER,
    time_delta_hours INTEGER,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.friendly_fraud_signals IS 'Behavioral markers identifying patterns of consumer dispute abuse.';

------------------------------------------------------------------------------------------------
-- Serial No: 276
-- Table: T276 - service_dependencies_audit
-- Schema: ops
-- Description: Auditable log of changes to service dependencies.
-- Business Case: Dependencies change. This table logs every change to the dependency graph (T170). Who
--added a dependency? Who removed one? It ensures that no unauthorized "shadow" dependencies
--are introduced into the production environment.
-- KPIs: Dependency Change Traceability.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.service_dependencies_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_id UUID NOT NULL,
    dependency_id UUID,
    change_type VARCHAR(20) CHECK (change_type IN ('ADD', 'REMOVE', 'UPDATE')),
    old_value JSONB,
    new_value JSONB,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.service_dependencies_audit IS 'Governance log tracking modifications to system topology and coupling.';

------------------------------------------------------------------------------------------------
-- Serial No: 277
-- Table: T277 - communication_preferences
-- Schema: dispute
-- Description: User/Merchant preferences for dispute notifications.
-- Business Case: Users want choice. This table stores preferences: Email vs SMS vs Push. It also tracks
--language and frequency. It ensures that notifications are effective and don't annoy users
--(reducing opt-outs).
-- KPIs: Notification Opt-in Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.communication_preferences (
    entity_id UUID NOT NULL,
    channel_preference VARCHAR(20) DEFAULT 'EMAIL' CHECK (channel_preference IN ('EMAIL', 'SMS', 'PUSH')),
    frequency VARCHAR(20) DEFAULT 'IMMEDIATE', -- IMMEDIATE, DIGEST
    language VARCHAR(10) DEFAULT 'en',

    CONSTRAINT pk_comm_prefs UNIQUE (entity_id)
);

COMMENT ON TABLE dispute.communication_preferences IS 'User-defined settings governing delivery method and frequency of alerts.';

------------------------------------------------------------------------------------------------
-- Serial No: 278
-- Table: T278 - feature_interactions
-- Schema: ml
-- Description: Stores discovered significant feature interactions for polynomial features.
-- Business Case: Feature A + Feature B might be predictive, even if alone they are not. This table stores
--discovered interactions (e.g., "High Amount" + "New Device" = High Risk). It is used by Feature
--Engineering to create new, more powerful inputs for the model.
-- KPIs: Feature Interaction Lift.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_interactions (
    interaction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_a VARCHAR(100) NOT NULL,
    feature_b VARCHAR(100) NOT NULL,
    interaction_strength NUMERIC(5,2),

    -- Metadata
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.feature_interactions IS 'Repository of non-linear feature relationships enhancing predictive power.';

------------------------------------------------------------------------------------------------
-- Serial No: 279
-- Table: T279 - backup_validation_jobs
-- Schema: ops
-- Description: Jobs that validate backup integrity via restoration testing.
-- Business Case: A backup is useless if it can't be restored. This table logs scheduled jobs that
--attempt to restore a backup to a test DB, verify checksums, and delete the test DB. It proves
--Disaster Recovery plans work.
-- KPIs: Backup Validation Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.backup_validation_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id VARCHAR(100) NOT NULL,
    test_db_instance VARCHAR(100),
    result VARCHAR(20) CHECK (result IN ('SUCCESS', 'FAILURE')),
    checksum_match BOOLEAN,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.backup_validation_jobs IS 'Operational records of disaster recovery verification testing.';

------------------------------------------------------------------------------------------------
-- Serial No: 280
-- Table: T280 - transaction_notes
-- Schema: fraud
-- Description: Free text notes added by fraud analysts to transactions.
-- Business Case: Sometimes a number isn't enough. An analyst might add a note "User called, confirmed
--it was a gift." This context is invaluable for future reference and for training the model
--(Ground Truth). It adds qualitative data to quantitative fraud scores.
-- KPIs: Note Entry Volume.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    analyst_id UUID NOT NULL,
    note_text TEXT NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tx_notes_hash ON fraud.transaction_notes(transaction_hash);
COMMENT ON TABLE fraud.transaction_notes IS 'Qualitative annotations adding human context to quantitative transaction records.';

------------------------------------------------------------------------------------------------
-- Serial No: 281
-- Table: T281 - api_authentication_logs
-- Schema: sec
-- Description: Logs of every API key authentication attempt.
-- Business Case: API Keys are the keys to the kingdom. This table logs every use of an API Key:
--Success, Fail, IP, Endpoint. It detects API Key leakage (if a key is used from IPs in
--different continents simultaneously) and abuse.
-- KPIs: API Abuse Detection Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_authentication_logs (
    auth_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_key_hash VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255),
    success BOOLEAN NOT NULL,
    ip_address INET,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_auth_key ON sec.api_authentication_logs(api_key_hash);
COMMENT ON TABLE sec.api_authentication_logs IS 'Access control log for programmatic interfaces tracking key usage and anomalies.';

------------------------------------------------------------------------------------------------
-- Serial No: 282
-- Table: T282 - deployment_rollback_history
-- Schema: ops
-- Description: History of rollbacks triggered by feature flags or alerts.
-- Business Case: Rollbacks happen. This table logs them. It records the trigger reason (Alert ID),
--the source version, and the target version. It is essential for "Blameless Post-Mortems"
--to understand why a change had to be reverted.
-- KPIs: Rollback Frequency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.deployment_rollback_history (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    trigger_reason TEXT NOT NULL, -- Alert ID or Manual
    triggered_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.deployment_rollback_history IS 'Change history documenting reversion of software releases due to instability.';

------------------------------------------------------------------------------------------------
-- Serial No: 283
-- Table: T283 - fraud_network_community
-- Schema: fraud
-- Description: Communities detected within the transaction graph (Louvain algo).
-- Business Case: Fraud operates in clusters (rings). This table stores the result of community detection
--algorithms. Which nodes belong to "Ring A"? It allows analysts to take down whole rings
--at once rather than one account at a time.
-- KPIs: Community Detection Precision.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_network_community (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    community_id UUID,
    member_entities TEXT[] NOT NULL, -- List of user hashes
    detection_date DATE NOT NULL
);

COMMENT ON TABLE fraud.fraud_network_community IS 'Results of unsupervised graph clustering identifying organized crime rings.';

------------------------------------------------------------------------------------------------
-- Serial No: 284
-- Table: T284 - auto_resolution_rules
-- Schema: dispute
-- Description: Rule logic for automatically resolving specific dispute types.
-- Business Case: Automation reduces costs. This table stores the logic for auto-closing cases (e.g.,
--"IF tracking shows Delivered AND no prior history, THEN Auto-Refund"). It encodes business
--rules into data, allowing updates without code deploys.
-- KPIs: Auto-Resolution Coverage %.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.auto_resolution_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    condition_json JSONB NOT NULL,
    action VARCHAR(50) NOT NULL, -- 'CLOSE_WITH_REFUND', 'REJECT', 'ESCALATE'
    priority INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE dispute.auto_resolution_rules IS 'Logic definitions enabling straight-through processing of routine disputes.';

------------------------------------------------------------------------------------------------
-- Serial No: 285
-- Table: T285 - sla_credit_history
-- Schema: ops
-- Description: Tracks SLA credits issued to merchants due to system failures.
-- Business Case: If PARI is down, we owe merchants credits. This table tracks issued credits. It
--calculates the financial impact of outages and ensures that the Finance team pays out what was
--promised in the SLA.
-- KPIs: SLA Credit Payout Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.sla_credit_history (
    credit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    reason VARCHAR(255) NOT NULL, -- Which SLA was breached?
    incident_id UUID,

    -- Metadata
    issued_date DATE NOT NULL
);

COMMENT ON TABLE ops.sla_credit_history IS 'Financial ledger tracking penalties paid to partners for service level failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 286
-- Table: T286 - privileged_session_requests
-- Schema: sec
-- Description: Requests for elevated privileges within the Fraud Ops console.
-- Business Case: Support staff sometimes need "God Mode" to fix a user account. This table logs requests
--for that privilege. It requires approval (Manager's ID) and logs exactly what they did. It prevents
--internal abuse of power.
-- KPIs: Privilege Request Approval Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privileged_session_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    requested_role VARCHAR(50),
    justification TEXT,
    approved_by UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.privileged_session_requests IS 'Approval workflow for temporary elevation of access rights for troubleshooting.';

------------------------------------------------------------------------------------------------
-- Serial No: 287
-- Table: T287 - model_serving_configs
-- Schema: ml
-- Description: Configuration for model serving (batch size, threads, timeout).
-- Business Case: Serving models (via TensorRT/Triton) needs config. This table stores the config: Max Batch
--Size, Timeout, Thread Count. It allows tuning of inference performance without changing code.
-- KPIs: Inference Throughput.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_serving_configs (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    max_batch_size INTEGER,
    timeout_ms INTEGER,
    accelerator VARCHAR(20), -- 'CPU', 'GPU', 'TPU'

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_model_serving_configs_timestamp
    BEFORE UPDATE ON ml.model_serving_configs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ml.model_serving_configs IS 'Performance tuning parameters for real-time inference engine execution.';

------------------------------------------------------------------------------------------------
-- Serial No: 288
-- Table: T288 - query_change_log
-- Schema: audit
-- Description: Logs changes to stored procedures or queries.
-- Business Case: DB changes are risky. This table logs changes to Stored Procs (SP) or Views. It tracks
--the old and new definitions (hash). It allows rollback of logic changes and provides an audit
--trail for "Who changed the scoring logic?".
-- KPIs: Schema Drift Detection.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.query_change_log (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    object_type VARCHAR(20) NOT NULL, -- 'PROCEDURE', 'VIEW', 'FUNCTION'
    object_name VARCHAR(100) NOT NULL,
    change_type VARCHAR(20) CHECK (change_type IN ('CREATE', 'ALTER', 'DROP')),
    changed_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.query_change_log IS 'Version control for database logic objects ensuring reproducibility of behavior.';

------------------------------------------------------------------------------------------------
-- Serial No: 289
-- Table: T289 - merchant_chargeback_rights
-- Schema: fraud
-- Description: Defines merchant rights regarding chargebacks/fightbacks.
-- Business Case: Merchants have rights. This table defines them (e.g., "Can Represent? Yes. Time limit:
--30 days"). It ensures that PARI enforces the correct rules for representments (fighting
--the chargeback) on behalf of the merchant.
-- KPIs: Representment Policy Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_chargeback_rights (
    merchant_id UUID PRIMARY KEY,
    can_represent BOOLEAN DEFAULT FALSE,
    max_represent_time_hours INTEGER DEFAULT 720, -- 30 days

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.merchant_chargeback_rights IS 'Configuration of merchant privileges regarding disputed transaction reversals.';

------------------------------------------------------------------------------------------------
-- Serial No: 290
-- Table: T290 - incident_impact_analysis
-- Schema: ops
-- Description: Post-incident analysis of impact on users/merchants.
-- Business Case: After an outage, we need to know "Who suffered?". This table stores the analysis:
--Affected User Count, Financial Impact (Lost Transactions). It is used to calculate SLA
--credits (T285) and for executive reporting.
-- KPIs: Impact Assessment Completeness.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.incident_impact_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    affected_users_count BIGINT,
    financial_impact NUMERIC(15,2),
    affected_merchants_count INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.incident_impact_analysis IS 'Quantified damage assessment of operational failures used for remediation planning.';

------------------------------------------------------------------------------------------------
-- Serial No: 291
-- Table: T291 - training_pipeline_dags
-- Schema: ml
-- Description: Definitions of DAGs for ML training pipelines (Airflow/Kubeflow).
-- Business Case: ML pipelines are DAGs (Directed Acyclic Graphs). This table stores the JSON definition
--of the DAG. It allows versioning of the pipeline logic (e.g., Add a new cleaning step) and
--triggering of runs.
-- KPIs: Pipeline Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.training_pipeline_dags (
    dag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dag_name VARCHAR(100) NOT NULL,
    schedule_interval VARCHAR(50), -- Cron expression
    json_definition JSONB NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.training_pipeline_dags IS 'Workflow definition storage orchestrating complex machine learning data processes.';

------------------------------------------------------------------------------------------------
-- Serial No: 292
-- Table: T292 - device_software_version
-- Schema: fraud
-- Description: Logs software version of the device app for correlation with bugs.
-- Business Case: Bugs in specific app versions can cause false positives (e.g., a GPS bug triggering
--velocity checks). This table logs the App Version and OS Version per transaction. It helps Ops
--quickly identify "Oh, everyone failing this check is on iOS 15.4".
-- KPIs: Version Correlation Latency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_software_version (
    device_hash VARCHAR(64) NOT NULL,
    app_version VARCHAR(20),
    os_version VARCHAR(20),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_device_software UNIQUE (device_hash, app_version, os_version)
);

COMMENT ON TABLE fraud.device_software_version IS 'App release tracking to correlate technical faults with fraud detection anomalies.';

------------------------------------------------------------------------------------------------
-- Serial No: 293
-- Table: T293 - refund_reconciliation
-- Schema: dispute
-- Description: Matches internal refund logs with bank settlement files.
-- Business Case: We must match our "Refund Sent" log with the Bank's "Money Left" file. This table
--stores the reconciliation. It flags mismatches (We said we sent it, Bank says they didn't get it).
--It is crucial for Finance to balance the books.
-- KPIs: Reconciliation Match Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.refund_reconciliation (
    recon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    refund_id UUID NOT NULL REFERENCES refund.blinded_refunds(refund_id),
    settlement_ref VARCHAR(100), -- Bank Reference
    amount_match BOOLEAN,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refund_recon_ref ON dispute.refund_reconciliation(settlement_ref);
COMMENT ON TABLE dispute.refund_reconciliation IS 'Cross-validation of internal disbursement records against external bank settlements.';

------------------------------------------------------------------------------------------------
-- Serial No: 294
-- Table: T294 - feature_flag_targeting
-- Schema: ops
-- Description: Specific targeting rules for feature flags (user ID, geography).
-- Business Case: Canary deployments need targeting. This table defines rules like "Enable for 10% of users
--in Germany". It allows for granular rollouts to specific cohorts to monitor impact before
--full release.
-- KPIs: Targeting Rule Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.feature_flag_targeting (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    target_attribute VARCHAR(50), -- 'USER_ID', 'COUNTRY', 'MERCHANT_ID'
    operator VARCHAR(10), -- 'IN', 'NOT_IN'
    values TEXT[],

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.feature_flag_targeting IS 'Segmentation logic for phased feature rollouts to specific user populations.';

------------------------------------------------------------------------------------------------
-- Serial No: 295
-- Table: T295 - vpn_detection_logs
-- Schema: fraud
-- Description: Logs of IP addresses identified as VPN/Proxy exits.
-- Business Case: VPNs are suspicious for account creation. This table logs IPs identified as VPN exits
--by external intel. It maintains a cache of these IPs to add extra friction for new users
--coming from them.
-- KPIs: VPN Detection Speed.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.vpn_detection_logs (
    ip_address INET PRIMARY KEY,
    vpn_provider VARCHAR(100),
    type VARCHAR(20), -- 'OPENVPN', 'SSH', 'TOR'
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.vpn_detection_logs IS 'Cache of network infrastructure identifiers associated with anonymization services.';

------------------------------------------------------------------------------------------------
-- Serial No: 296
-- Table: T296 - data_quality_metrics
-- Schema: ml
-- Description: Metrics tracking the quality of training data (missing values, outliers).
-- Business Case: "Garbage In, Garbage Out." This table tracks data quality metrics for the datasets
--used to train models. It alerts if "Missing Values in Feature X > 50%". It ensures models
--are trained on clean, reliable data.
-- KPIs: Data Quality Score.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.data_quality_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id UUID NOT NULL,
    completeness_score NUMERIC(3,2),
    outlier_ratio NUMERIC(3,2),
    duplicate_row_count BIGINT,

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.data_quality_metrics IS 'Health check statistics for data assets used in model development.';

------------------------------------------------------------------------------------------------
-- Serial No: 297
-- Table: T297 - chaos_scenarios
-- Schema: ops
-- Description: Library of chaos engineering scenarios to execute.
-- Business Case: We need to break things to test resilience. This table defines the library of attacks
--(Latency Injection, Pod Kill). The Chaos Engine (T038) picks scenarios from this table to run.
--It ensures we have a standard set of "Disaster Rehearsals".
-- KPIs: Scenario Coverage.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.chaos_scenarios (
    scenario_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    fault_definition JSONB NOT NULL, -- e.g., {"service": "api", "latency_ms": 5000}
    severity VARCHAR(20),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.chaos_scenarios IS 'Catalog of disruption experiments used to validate system fault tolerance.';

------------------------------------------------------------------------------------------------
-- Serial No: 298
-- Table: T298 - legal_document_requests
-- Schema: dispute
-- Description: Tracks requests for legal documents (affidavits) from users.
-- Business Case: High value disputes need affidavits. This table logs the request: Who asked? For
--which case? Was it uploaded? It tracks the status of gathering legal evidence to support
--arbitration (T262).
-- KPIs: Document Collection Time.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.legal_document_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    doc_type VARCHAR(50), -- 'AFFIDAVIT', 'POLICE_REPORT'
    status VARCHAR(20) DEFAULT 'REQUESTED', -- REQUESTED, RECEIVED, EXPIRED
    received_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE dispute.legal_document_requests IS 'Workflow tracker for procurement of formal evidence required for adjudication.';

------------------------------------------------------------------------------------------------
-- Serial No: 299
-- Table: T299 - session_hijack_attempts
-- Schema: sec
-- Description: Logs of attempts to hijack active user sessions.
-- Business Case: Session hijacking is a threat. This table logs suspicious activity indicating a hijack
--(e.g., User changes IP mid-session, or User-Agent string changes). It enables the system to
--force-reauth the user.
-- KPIs: Hijack Detection Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.session_hijack_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_hijack_sid ON sec.session_hijack_attempts(session_id);
COMMENT ON TABLE sec.session_hijack_attempts IS 'Security logs identifying potential interference with established user sessions.';

-- =============================================================================================
-- PART 6 (CONTINUED): T300 - T350
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 300
-- Table: T300 - telemetry_sampling_config_v2
-- Schema: ops
-- Description: Advanced sampling configuration for metrics aggregation.
-- Business Case: Standard sampling (T251) is simple. T300 adds "Head-Based Sampling" logic, keeping all
--traces for specific User IDs (e.g., VIPs) or specific error codes regardless of global rate.
--It ensures that critical user flows are always fully observable.
-- KPIs: VIP Observability Coverage.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.telemetry_sampling_config_v2 (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trace_type VARCHAR(50) NOT NULL,
    target_entity VARCHAR(100), -- 'USER_ID', 'MERCHANT_ID'
    entity_value VARCHAR(255), -- Specific ID or 'ALL_VIPS'
    sampling_rate NUMERIC(3,2) DEFAULT 1.0, -- 100%

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.telemetry_sampling_config_v2 IS 'Granular override controls ensuring full observability for critical entities.';

------------------------------------------------------------------------------------------------
-- Serial No: 301
-- Table: T301 - risk_challenge_library
-- Schema: fraud
-- Description: Expanded library for dynamic MFA challenges.
-- Business Case: Security questions need variety. This table acts as an expanded library of questions,
--categorized by difficulty (Easy, Medium, Hard). It allows the Step-Up Auth system (F081)
--to pick questions appropriate to the user's history (e.g., don't ask a Hard question to a new user).
-- KPIs: Challenge Diversity Index.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.risk_challenge_library (
    library_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    category VARCHAR(50) NOT NULL, -- 'HISTORY', 'DEVICE', 'TRANSACTION'
    difficulty VARCHAR(20) CHECK (difficulty IN ('EASY', 'MEDIUM', 'HARD')),
    question TEXT NOT NULL,
    expected_answer_type VARCHAR(20)
);

COMMENT ON TABLE fraud.risk_challenge_library IS 'Categorized repository of authentication challenges supporting adaptive risk-based security.';

------------------------------------------------------------------------------------------------
-- Serial No: 302
-- Table: T302 - pii_redaction_patterns
-- Schema: audit
-- Description: Advanced regex patterns for PII redaction.
-- Business Case: Basic masking (T253) uses simple regex. T302 allows for complex, multi-field patterns
--(e.g., "Redact phone number IF email domain is @gmail.com"). It provides sophisticated logic
--for protecting specific data relationships in logs.
-- KPIs: Redaction Logic Complexity.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.pii_redaction_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    logic_definition JSONB NOT NULL, -- {"conditions": [...], "action": "REDACT"}
    priority INTEGER DEFAULT 1
);

COMMENT ON TABLE audit.pii_redaction_patterns IS 'Sophisticated rule engine for context-aware sanitization of sensitive data.';

------------------------------------------------------------------------------------------------
-- Serial No: 303
-- Table: T303 - cloud_resource_tags
-- Schema: ops
-- Description: Tags for cloud resource costing.
-- Business Case: Similar to T254 but focused on raw Cloud Provider tags. It maps internal cost codes
--to external cloud tags to ensure accurate billing aggregation in the Cloud Provider console.
-- KPIs: Billing Tag Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.cloud_resource_tags (
    resource_id VARCHAR(100) NOT NULL,
    provider_tag_key VARCHAR(50) NOT NULL,
    provider_tag_value VARCHAR(100) NOT NULL,

    CONSTRAINT pk_cloud_tags UNIQUE (resource_id, provider_tag_key)
);

COMMENT ON TABLE ops.cloud_resource_tags IS 'Synchronization layer between internal cost centers and external cloud billing metadata.';

------------------------------------------------------------------------------------------------
-- Serial No: 304
-- Table: T304 - correlation_graph_nodes
-- Schema: fraud
-- Description: Node table for the transaction correlation graph.
-- Business Case: For graph analytics (T263), we need node metadata. This table stores properties of
--nodes (Users/Merchants) in the correlation graph, such as "Centrality Score" or "Risk Tier".
--It helps visualize the network topology.
-- KPIs: Graph Render Performance.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.correlation_graph_nodes (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_hash VARCHAR(64) NOT NULL UNIQUE,
    entity_type VARCHAR(20) NOT NULL,
    centrality_score NUMERIC(5,2),
    risk_tier VARCHAR(20),

    -- Metadata
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.correlation_graph_nodes IS 'Vertex attributes for visualization of transactional relationship networks.';

------------------------------------------------------------------------------------------------
-- Serial No: 305
-- Table: T305 - industry_analytics
-- Schema: fraud
-- Description: Aggregated industry fraud metrics.
-- Business Case: Merchants want to know how they compare. This table aggregates fraud metrics by
--Industry (e.g., Retail, Travel). It powers the "Peer Comparison" feature (F141) giving
--merchants context on their performance relative to their sector.
-- KPIs: Industry Benchmark Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.industry_analytics (
    industry_code VARCHAR(20) NOT NULL,
    date DATE NOT NULL,
    avg_fraud_rate NUMERIC(5,4),
    total_volume BIGINT,

    CONSTRAINT pk_industry_analytics UNIQUE (industry_code, date)
);

CREATE INDEX idx_ind_analytics_date ON fraud.industry_analytics(date);
COMMENT ON TABLE fraud.industry_analytics IS 'Benchmark data enabling merchants to evaluate their performance against sector norms.';

------------------------------------------------------------------------------------------------
-- Serial No: 306
-- Table: T306 - anonymity_pool_stats
-- Schema: fraud
-- Description: Detailed statistics on the anonymity pool.
-- Business Case: Differential Privacy needs a "pool" of users. This table tracks the size and composition
--of the pool (e.g., "Currently 5000 users in the 50-60 Age bracket"). It ensures that we have
--enough data to inject noise effectively without destroying utility.
-- KPIs: Pool Health Score.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.anonymity_pool_stats (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bucket_definition JSONB NOT NULL, -- e.g., {"age": "50-60", "country": "US"}
    current_count BIGINT,
    min_required_count BIGINT,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.anonymity_pool_stats IS 'Monitoring of data cohort sizes ensuring differential privacy guarantees can be met.';

------------------------------------------------------------------------------------------------
-- Serial No: 307
-- Table: T307 - graph_community_detection
-- Schema: fraud
-- Description: Results of community detection algorithms.
-- Business Case: Detecting rings. This table stores the result of algorithms like Louvain or Label
--Propagation. It assigns a "Community ID" to nodes. Nodes with the same Community ID are likely
--part of the same fraud ring.
-- KPIs: Community Modularity Score.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.graph_community_detection (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    node_hash VARCHAR(64) NOT NULL,
    community_id UUID NOT NULL,
    algorithm VARCHAR(50),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_graph_comm_run ON fraud.graph_community_detection(run_id);
COMMENT ON TABLE fraud.graph_community_detection IS 'Output of unsupervised graph clustering identifying groups of colluding entities.';

------------------------------------------------------------------------------------------------
-- Serial No: 308
-- Table: T308 - workflow_state_definitions
-- Schema: dispute
-- Description: State machine definitions for workflows.
-- Business Case: Dispute logic is a workflow. This table defines the state machine. States, Transitions,
--Actions. It is the source of truth for the UI workflow (e.g., "Can I click 'Close' from
--'Open'? Only if 'Resolved' is true").
-- KPIs: Workflow Consistency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.workflow_state_definitions (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_name VARCHAR(50) NOT NULL, -- 'DISPUTE_LIFECYCLE', 'REFUND_FLOW'
    state_name VARCHAR(50) NOT NULL,
    allowed_transitions TEXT[], -- List of next state names
    timeout_action JSONB, -- Action if timeout
    ui_config JSONB
);

COMMENT ON TABLE dispute.workflow_state_definitions IS 'Orchestration logic defining valid paths and automated behaviors of business processes.';

------------------------------------------------------------------------------------------------
-- Serial No: 309
-- Table: T309 - ip_blacklist_cache
-- Schema: sec
-- Description: High-speed cache for banned IPs.
-- Business Case: Checking T014 (Blacklist) is slow. This table is a RAM-cached (Redis-backed) version
--for the API layer. It stores IPs that are immediately blocked. It ensures the first line of
--defense is instant.
-- KPIs: Blacklist Lookup Latency (< 1ms).
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ip_blacklist_cache (
    ip_address INET PRIMARY KEY,
    reason VARCHAR(255),
    banned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    expires_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE sec.ip_blacklist_cache IS 'High-performance denial list for immediate network-level rejection of hostile actors.';

------------------------------------------------------------------------------------------------
-- Serial No: 310
-- Table: T310 - histogram_bucket_config
-- Schema: ops
-- Description: Config for histogramming metrics.
-- Business Case: Histograms show distribution (e.g., latency percentiles). This table configures the buckets
--(e.g., 0-10ms, 10-50ms, 50-100ms). It ensures that Prometheus/Grafana metrics
--are aggregated correctly for visualization.
-- KPIs: Metric Resolution Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.histogram_bucket_config (
    metric_name VARCHAR(100) NOT NULL,
    bucket_le NUMERIC(15,2) NOT NULL,
    bucket_id SERIAL NOT NULL,

    CONSTRAINT pk_histogram_config UNIQUE (metric_name, bucket_id)
);

COMMENT ON TABLE ops.histogram_bucket_config IS 'Configuration for statistical distribution tracking of system performance metrics.';

------------------------------------------------------------------------------------------------
-- Serial No: 311
-- Table: T311 - merchant_risk_audit_trail
-- Schema: fraud
-- Description: Audit trail of changes to merchant risk scores.
-- Business Case: Why is Merchant X "High Risk" today when they were "Low Risk" yesterday? This table
--logs the history of risk score changes. It tracks the trigger (e.g., "Surge in disputes")
--and the analyst who made the change (if manual).
-- KPIs: Risk History Traceability.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_risk_audit_trail (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    old_score INTEGER,
    new_score INTEGER NOT NULL,
    trigger_reason TEXT,
    changed_by UUID,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_merchant_risk_audit ON fraud.merchant_risk_audit_trail(merchant_id);
COMMENT ON TABLE fraud.merchant_risk_audit_trail IS 'Immutable log of reputation score modifications for forensic analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 312
-- Table: T312 - model_ensemble_weights
-- Schema: ml
-- Description: Current weights assigned to models in an ensemble.
-- Business Case: We use an Ensemble (LSTM + Random Forest + XGBoost). This table stores the weight of
--each model in the final score. e.g., LSTM 60%, RF 20%. It allows tuning the contribution
--of each model without redeploying code.
-- KPIs: Ensemble Weight Sum Check.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_ensemble_weights (
    ensemble_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    weight NUMERIC(5,2) CHECK (weight > 0),
    effective_date DATE NOT NULL,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_ensemble_weights IS 'Runtime parameters controlling the contribution of individual models to a composite prediction.';

------------------------------------------------------------------------------------------------
-- Serial No: 313
-- Table: T313 - finance_batch_manifest
-- Schema: dispute
-- Description: Manifests for batch settlements.
-- Business Case: Payouts happen in batches. This table is the manifest for a batch. It lists the batch
--ID, total amount, and file hash. It provides a checksum for the bank to verify they received
--the correct file.
-- KPIs: Batch Manifest Integrity.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.finance_batch_manifest (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    settlement_date DATE NOT NULL,
    total_amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,
    file_hash CHAR(64),
    file_record_count INTEGER
);

COMMENT ON TABLE dispute.finance_batch_manifest IS 'Header record for financial disbursement batches ensuring data integrity.';

------------------------------------------------------------------------------------------------
-- Serial No: 314
-- Table: T314 - api_tier_limits
-- Schema: api
-- Description: Rate limits per API tier.
-- Business Case: Not all users are equal. This table defines the hard limits per tier (Free, Gold). It
--is referenced by the Gateway (T255) to throttle requests.
-- KPIs: Limit Enforcement Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api.api_tier_limits (
    tier_name VARCHAR(50) PRIMARY KEY,
    requests_per_minute INTEGER NOT NULL,
    requests_per_hour INTEGER NOT NULL,
    concurrent_connections INTEGER
);

COMMENT ON TABLE api.api_tier_limits IS 'Capacity management definitions controlling traffic volume per subscriber tier.';

------------------------------------------------------------------------------------------------
-- Serial No: 315
-- Table: T315 - human_review_queue
-- Schema: ml
-- Description: Queue of data points for human review (Ground Truth).
-- Business Case: Machines can't do everything. This table queues transactions that need human eyes.
--It prioritizes by uncertainty (T256) or value. It is the worklist for the "Annotation Team".
-- KPIs: Queue Depth, Review Throughput.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.human_review_queue (
    queue_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    priority INTEGER CHECK (priority BETWEEN 1 AND 10),
    assigned_to UUID,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, IN_REVIEW, COMPLETED
    reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_human_review_priority ON ml.human_review_queue(priority, created_at);
COMMENT ON TABLE ml.human_review_queue IS 'Workstream management for manual data labeling and quality assurance.';

------------------------------------------------------------------------------------------------
-- Serial No: 316
-- Table: T316 - vendor_sla_tracking
-- Schema: ops
-- Description: Tracking of SLA for external vendors.
-- Business Case: PARI uses external vendors (Email, SMS, Threat Intel). This table tracks their SLA.
--Did they meet 99.9% uptime? If not, we bill them credit. It holds vendors accountable.
-- KPIs: Vendor SLA Compliance.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.vendor_sla_tracking (
    vendor_id UUID PRIMARY KEY,
    uptime_target NUMERIC(5,2) NOT NULL,
    uptime_actual NUMERIC(5,2),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    penalty_applied NUMERIC(15,2)
);

COMMENT ON TABLE ops.vendor_sla_tracking IS 'Performance monitoring for third-party service providers enforcing contractual obligations.';

------------------------------------------------------------------------------------------------
-- Serial No: 317
-- Table: T317 - policy_governance_log
-- Schema: policy
-- Description: Log of changes to compliance policies.
-- Business Case: Policies change. This table logs every change to the ABAC or Data Retention policies.
--It tracks who changed it and why. It is essential for regulatory audits to prove that policy
--X was in effect on Date Y.
-- KPIs: Governance Audit Score.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy.policy_governance_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    change_type VARCHAR(20) NOT NULL,
    old_version_hash VARCHAR(64),
    new_version_hash VARCHAR(64),
    changed_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE policy.policy_governance_log IS 'History of regulatory and access control policy modifications for audit trails.';

------------------------------------------------------------------------------------------------
-- Serial No: 318
-- Table: T318 - consent_event_stream
-- Schema: privacy
-- Description: Stream of consent events (granted/revoked).
-- Business Case: Consent is an event. This table logs every event: User grants consent for Analytics.
--User revokes consent for Marketing. It is the source of truth for the Consent Manager
--service.
-- KPIs: Event Processing Latency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy.consent_event_stream (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    consent_type VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL, -- GRANTED, REVOKED
    source VARCHAR(50), -- UI, API, LEGAL_REQUEST
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_consent_event_user ON privacy.consent_event_stream(user_hash, timestamp);
COMMENT ON TABLE privacy.consent_event_stream IS 'Chronological ledger of user permission changes supporting dynamic privacy compliance.';

------------------------------------------------------------------------------------------------
-- Serial No: 319
-- Table: T319 - taxonomy_map_v2
-- Schema: knowledge
-- Description: Version 2 of Taxonomy mapping.
-- Business Case: Taxonomies evolve. This table holds the new version of the mapping between internal terms
--and external standards (SKOS/ISO). It supports backward compatibility during upgrades.
-- KPIs: Mapping Consistency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.taxonomy_map_v2 (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    internal_term VARCHAR(100) NOT NULL,
    external_uri TEXT NOT NULL,
    external_system VARCHAR(50) NOT NULL,
    version INTEGER DEFAULT 2,

    CONSTRAINT pk_taxonomy_map_v2 UNIQUE (internal_term, external_system, version)
);

COMMENT ON TABLE knowledge.taxonomy_map_v2 IS 'Versioned cross-reference linking proprietary vocabulary to public standards.';

------------------------------------------------------------------------------------------------
-- Serial No: 320
-- Table: T320 - knowledge_graph_edges
-- Schema: knowledge
-- Description: Edges in the knowledge graph.
-- Business Case: Knowledge is connected. This table stores the edges (Subject, Predicate, Object).
--It supports "Knowledge Graph Search" where you can find related concepts.
-- KPIs: Graph Connectivity.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.knowledge_graph_edges (
    edge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subject_uri TEXT NOT NULL,
    predicate_uri TEXT NOT NULL,
    object_uri TEXT NOT NULL,
    weight NUMERIC(3,2) DEFAULT 1.0
);

CREATE INDEX idx_kg_subject ON knowledge.knowledge_graph_edges(subject_uri);
COMMENT ON TABLE knowledge.knowledge_graph_edges IS 'Relationship storage enabling semantic search and inference within the knowledge base.';

------------------------------------------------------------------------------------------------
-- Serial No: 321
-- Table: T321 - security_alert_queue
-- Schema: incident
-- Description: Queue of security alerts.
-- Business Case: Security tools generate alerts (IDS, WAF). This table normalizes them into a queue.
--It triages them and assigns owners. It is the central inbox for the Security Operations Center (SOC).
-- KPIs: Alert Mean Time to Resolve (MTTR).
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.security_alert_queue (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source VARCHAR(50) NOT NULL, -- 'WAF', 'IDS', 'FRAUD_ENGINE'
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title VARCHAR(255),
    description TEXT,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CLOSED
    assigned_to UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_alert_severity ON incident.security_alert_queue(severity, status);
COMMENT ON TABLE incident.security_alert_queue IS 'Centralized triage inbox for security telemetry requiring analyst attention.';

------------------------------------------------------------------------------------------------
-- Serial No: 322
-- Table: T322 - threat_assessment_risks
-- Schema: incident
-- Description: Detailed risks identified in threat models.
-- Business Case: Threat Modeling (STRIDE) identifies risks. This table stores them. e.g., "Spoofing
--risk in API Gateway". It tracks the mitigation plan. It ensures that design flaws are addressed
--before implementation.
-- KPIs: Risk Mitigation Coverage.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.threat_assessment_risks (
    risk_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    likelihood VARCHAR(20), -- LOW, MEDIUM, HIGH
    impact VARCHAR(20), -- LOW, MEDIUM, HIGH
    mitigation_status VARCHAR(20) DEFAULT 'OPEN',

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE incident.threat_assessment_risks IS 'Registry of architectural security risks derived from structured threat modeling exercises.';

------------------------------------------------------------------------------------------------
-- Serial No: 323
-- Table: T323 - pat_meeting_minutes
-- Schema: ml
-- Description: Minutes from Process Action Team meetings.
-- Business Case: CMMI Level 5 requires PAT meetings. This table stores the minutes. It tracks
--decisions made and action items. It proves that the organization is managing its processes
--quantitatively.
-- KPIs: Action Item Closure Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.pat_meeting_minutes (
    minutes_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    meeting_date DATE NOT NULL,
    topic VARCHAR(255) NOT NULL,
    decisions TEXT[],
    action_items JSONB,
    attendees UUID[],

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.pat_meeting_minutes IS 'Record of governance proceedings driving continuous improvement of AI systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 324
-- Table: T324 - simulation_results
-- Schema: ml
-- Description: Results of Monte Carlo simulations.
-- Business Case: What happens if we change a model? This table stores the results of Monte Carlo
--simulations (Scenario, Outcome, Confidence). It supports risk-based decision making for
--model deployment.
-- KPIs: Simulation Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.simulation_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_id VARCHAR(100) NOT NULL,
    run_id UUID NOT NULL,
    outcome_metric NUMERIC(10,2),
    confidence_interval_low NUMERIC(10,2),
    confidence_interval_high NUMERIC(10,2),

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.simulation_results IS 'Probabilistic forecasting data supporting risk-aware decision making.';

------------------------------------------------------------------------------------------------
-- Serial No: 325
-- Table: T325 - refund_reason_dim
-- Schema: fraud
-- Description: Dimension table for refund reasons.
-- Business Case: Analytics needs dimensions. This table breaks down refund reasons by Merchant, Region, and
--Time. It is optimized for slicing and dicing in the BI tool (e.g., "Show me 'Item Not Received'
--in Germany for Q3").
-- KPIs: Query Performance (< 1s).
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_reason_dim (
    merchant_id UUID,
    region CHAR(2),
    reason_code VARCHAR(10),
    month DATE NOT NULL,
    count BIGINT,

    CONSTRAINT pk_refund_dim UNIQUE (merchant_id, region, reason_code, month)
);

CREATE INDEX idx_refund_dim_region ON fraud.refund_reason_dim(region, month);
COMMENT ON TABLE fraud.refund_reason_dim IS 'Optimized data mart for high-performance analytical slicing of dispute metrics.';

------------------------------------------------------------------------------------------------
-- Serial No: 326
-- Table: T326 - device_profile_history
-- Schema: fraud
-- Description: History of device profile changes.
-- Business Case: Device profiles (T005) change. This table logs changes to the device hash or risk
--score. e.g., "User rooted device". It helps track the evolution of a specific device's trustworthiness.
-- KPIs: Profile Change Frequency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_profile_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_hash VARCHAR(64) NOT NULL,
    old_score INTEGER,
    new_score INTEGER,
    change_reason TEXT,

    -- Metadata
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_prof_hist_device ON fraud.device_profile_history(device_hash);
COMMENT ON TABLE fraud.device_profile_history IS 'Timeline of device trust evolution supporting long-term risk assessment.';

------------------------------------------------------------------------------------------------
-- Serial No: 327
-- Table: T327 - fund_hold_ledger
-- Schema: dispute
-- Description: Ledger for funds held in escrow.
-- Business Case: Money in limbo. This table tracks funds held in escrow (T169) at a granular level.
--It shows exactly which wallet has how much money locked in which case. It ensures that the
--total escrow balance matches the sum of individual holds.
-- KPIs: Ledger Balance Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.fund_hold_ledger (
    hold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_hash VARCHAR(64) NOT NULL,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.fund_hold_ledger IS 'Double-entry bookkeeping track of funds reserved pending dispute resolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 328
-- Table: T328 - infrastructure_topology
-- Schema: ops
-- Description: Topology map of infrastructure.
-- Business Case: We need to know what depends on what. This table describes the topology (Database
---> Cluster -> Region). It is used by the Impact Analysis tool (T290) to predict blast radius
--of failures.
-- KPIs: Topology Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.infrastructure_topology (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    node_type VARCHAR(20) NOT NULL, -- 'SERVICE', 'DATABASE', 'LOAD_BALANCER'
    parent_id UUID REFERENCES ops.infrastructure_topology(node_id),
    node_name VARCHAR(100),
    health_status VARCHAR(20) DEFAULT 'UNKNOWN'
);

COMMENT ON TABLE ops.infrastructure_topology IS 'Hierarchical structure of system components facilitating dependency impact analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 329
-- Table: T329 - throttling_policies
-- Schema: ops
-- Description: Policies for throttling.
-- Business Case: Preventing overload. This table defines throttling policies (e.g., "If DB CPU > 80%, drop
--10% of traffic"). It is the logic for self-preservation of the system.
-- KPIs: Throttle Response Time.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.throttling_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_metric VARCHAR(100) NOT NULL,
    threshold_value NUMERIC(10,2),
    action VARCHAR(50) NOT NULL, -- 'DROP_TRAFFIC', 'SCALE_UP'
    enabled BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE ops.throttling_policies IS 'Automated rules protecting system stability during periods of extreme load.';

------------------------------------------------------------------------------------------------
-- Serial No: 330
-- Table: T330 - certificate_rotation_schedule
-- Schema: sec
-- Description: Schedule for rotating certs.
-- Business Case: Certs expire. This table schedules rotation (auto-generate new, deploy new, retire old).
--It ensures we never have an expired cert in production.
-- KPIs: Rotation Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.certificate_rotation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cert_id UUID REFERENCES sec.certificate_inventory(cert_id),
    last_rotated TIMESTAMP WITH TIME ZONE NOT NULL,
    next_rotation TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'SCHEDULED'
);

COMMENT ON TABLE sec.certificate_rotation_schedule IS 'Planned maintenance calendar for cryptographic asset lifecycle management.';

------------------------------------------------------------------------------------------------
-- Serial No: 331
-- Table: T331 - privileged_access_review
-- Schema: audit
-- Description: Review of privileged access.
-- Business Case: Who has admin access? This table stores the results of periodic reviews. "User X
--still needs admin access? Yes/No". It ensures adherence to the Principle of Least Privilege.
-- KPIs: Access Review Compliance.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.privileged_access_review (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL,
    reviewer_id UUID NOT NULL,
    decision VARCHAR(20) NOT NULL, -- 'KEEP', 'REVOKE'

    -- Metadata
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.privileged_access_review IS 'Governance records certifying continued necessity of elevated system permissions.';

------------------------------------------------------------------------------------------------
-- Serial No: 332
-- Table: T332 - behavioral_sensor_data
-- Schema: fraud
-- Description: Raw behavioral sensor data.
-- Business Case: Biometrics (T174) needs raw data. This table is the staging area for raw sensor streams
--(Gyroscope, Accelerometer) before aggregation. It holds the high-frequency data for short-term
--processing.
-- KPIs: Data Ingestion Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.behavioral_sensor_data (
    data_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    sensor_type VARCHAR(50) NOT NULL,
    data_blob JSONB NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_behavior_sensor_session ON fraud.behavioral_sensor_data(session_id);
COMMENT ON TABLE fraud.behavioral_sensor_data IS 'Raw telemetry ingestion point for high-frequency biometric input signals.';

------------------------------------------------------------------------------------------------
-- Serial No: 333
-- Table: T333 - biometric_models_v2
-- Schema: ml
-- Description: V2 of Biometric Models.
-- Business Case: Biometric models improve. This table stores the V2 models (e.g., updated algorithm for
--typing rhythm). It allows A/B testing of new biometric models against the old ones.
-- KPIs: Model Accuracy Improvement.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.biometric_models_v2 (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sensor_type VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    model_path TEXT,
    is_active BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.biometric_models_v2 IS 'Next generation identity verification models supporting enhanced security features.';

------------------------------------------------------------------------------------------------
-- Serial No: 334
-- Table: T334 - deployment_canary_analysis
-- Schema: ops
-- Description: Analysis of canary deployments.
-- Business Case: How is the canary doing? This table compares metrics between Canary and Stable.
--e.g., "Canary error rate 0.1% vs Stable 0.05%". It drives the decision to promote or rollback.
-- KPIs: Canary Metric Delta.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.deployment_canary_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    stable_value NUMERIC(10,2),
    canary_value NUMERIC(10,2),
    delta NUMERIC(10,2),
    recommendation VARCHAR(20), -- 'PROMOTE', 'ROLLBACK'

    -- Metadata
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.deployment_canary_analysis IS 'Comparative metrics evaluating the safety of progressive software rollouts.';

------------------------------------------------------------------------------------------------
-- Serial No: 335
-- Table: T335 - configuration_change_log
-- Schema: ops
-- Description: Log of config changes.
-- Business Case: Config changes cause bugs. This table logs every change to Config Maps or Feature
--Flags. It captures Before/After values. It allows rapid rollback if a bad config was pushed.
-- KPIs: Config Revert Time.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.configuration_change_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    changed_by UUID NOT NULL,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.configuration_change_log IS 'Audit trail for runtime parameter modifications enabling precise system reversion.';

------------------------------------------------------------------------------------------------
-- Serial No: 336
-- Table: T336 - aml_pattern_detection
-- Schema: fraud
-- Description: Specific AML patterns detected.
-- Business Case: AML has specific patterns (e.g., Smurfing). This table logs detections of these
--specific patterns. It feeds the SAR generation (T017) and the Money Laundering Alerts (T178).
-- KPIs: AML Pattern Recall.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.aml_pattern_detection (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hashes TEXT[] NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- 'SMURFING', 'LAYERING', 'STRUCTURING'
    confidence NUMERIC(3,2),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.aml_pattern_detection IS 'Detection results for specialized anti-money laundering algorithmic heuristics.';

------------------------------------------------------------------------------------------------
-- Serial No: 337
-- Table: T337 - event_publisher_subscriptions
-- Schema: integration
-- Description: Subscriptions to event streams (Pub/Sub).
-- Business Case: Decoupling. Services subscribe to events (e.g., "Fraud Score Updated"). This table
--manages the subscriptions. Who subscribes to what topic? It allows for dynamic event routing
--without code changes.
-- KPIs: Event Delivery Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.event_publisher_subscriptions (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(100) NOT NULL,
    subscriber_service VARCHAR(100) NOT NULL,
    endpoint_url TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE integration.event_publisher_subscriptions IS 'Routing configuration for asynchronous event-driven architecture communication.';

------------------------------------------------------------------------------------------------
-- Serial No: 338
-- Table: T338 - authentication_failures
-- Schema: sec
-- Description: Logs of auth failures.
-- Business Case: Failed auth is a signal. This table logs failed attempts (Wrong Password, Invalid
--Token). It is used to detect brute force (T180) or account takeover (T213) attempts.
-- KPIs: Auth Failure Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.authentication_failures (
    failure_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    method VARCHAR(50) NOT NULL, -- 'PASSWORD', 'MFA', 'TOKEN'
    failure_reason VARCHAR(50),
    ip_address INET,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_failures_user ON sec.authentication_failures(user_hash);
COMMENT ON TABLE sec.authentication_failures IS 'Detailed telemetry tracking unsuccessful access attempts for security analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 339
-- Table: T339 - data_transform_maps
-- Schema: integration
-- Description: Maps for transforming data formats.
-- Business Case: External data is messy. This table defines the transformation logic (JSONata/Jolt)
--to convert external JSON to our internal schema. It decouples integration code from schema
--changes.
-- KPIs: Transformation Error Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.data_transform_maps (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_system VARCHAR(50) NOT NULL,
    target_schema VARCHAR(50) NOT NULL,
    transform_logic JSONB NOT NULL,

    -- Metadata
    version INTEGER DEFAULT 1
);

COMMENT ON TABLE integration.data_transform_maps IS 'Logic definitions for translating heterogeneous external data into canonical models.';

------------------------------------------------------------------------------------------------
-- Serial No: 340
-- Table: T340 - storage_quota_enforcement
-- Schema: storage
-- Description: Enforces storage quotas.
-- Business Case: Storage costs money. This table checks quotas before writing to S3 (T010). It acts
--as a gatekeeper to prevent overages. It enforces limits defined in T182.
-- KPIs: Quota Violation Count.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.storage_quota_enforcement (
    tenant_id UUID NOT NULL,
    used_bytes BIGINT DEFAULT 0,
    limit_bytes BIGINT NOT NULL,

    CONSTRAINT pk_storage_enforcement UNIQUE (tenant_id)
);

COMMENT ON TABLE storage.storage_quota_enforcement IS 'Runtime state tracker ensuring adherence to data volume restrictions.';

------------------------------------------------------------------------------------------------
-- Serial No: 341
-- Table: T341 - outage_calendar
-- Schema: ops
-- Description: Calendar of planned outages.
-- Business Case: Maintenance needs to be communicated. This table is the calendar of planned outages.
--It populates the public status page and internal dashboards. It manages user expectations.
-- KPIs: Outage Communication Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.outage_calendar (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    affected_services TEXT[],
    is_public BOOLEAN DEFAULT FALSE, -- Show on status page?

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.outage_calendar IS 'Schedule of planned maintenance windows communicating service availability to stakeholders.';

------------------------------------------------------------------------------------------------
-- Serial No: 342
-- Table: T342 - velocity_check_state
-- Schema: fraud
-- Description: State for velocity checks.
-- Business Case: Velocity checks need memory (sliding window). This table (or cache) stores the current
--count for the sliding window. e.g., "User X has made 5 requests in last 60 seconds". It powers
--the logic in T004.
-- KPIs: State Accuracy.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.velocity_check_state (
    key VARCHAR(100) PRIMARY KEY, -- Composite key: entity_type:id
    count INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE fraud.velocity_check_state IS 'Transient state cache supporting real-time rate limiting and velocity rule execution.';

------------------------------------------------------------------------------------------------
-- Serial No: 343
-- Table: T343 - regulatory_correspondence
-- Schema: compliance
-- Description: Correspondence with regulators.
-- Business Case: Regulators ask questions. This table logs the back-and-forth. "Request for Info",
--"Response". It ensures we meet SLAs for regulatory requests (e.g., 48 hours).
-- KPIs: Regulator Response SLA.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.regulatory_correspondence (
    correspondence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulator_name VARCHAR(100) NOT NULL,
    direction VARCHAR(20) NOT NULL, -- INBOUND, OUTBOUND
    subject TEXT,
    document_ref VARCHAR(255),

    -- Metadata
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.regulatory_correspondence IS 'Communication log tracking interactions with government oversight bodies.';

------------------------------------------------------------------------------------------------
-- Serial No: 344
-- Table: T344 - model_asset_lifecycle
-- Schema: ml
-- Description: Lifecycle of model assets.
-- Business Case: Models are assets. This table tracks the full lifecycle: Development -> Validation ->
--Production -> Retired. It is the master registry for all model artifacts.
-- KPIs: Asset Utilization.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_asset_lifecycle (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_name VARCHAR(100) NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- MODEL, PIPELINE, FEATURE_SET
    status VARCHAR(20) NOT NULL, -- DEV, STAGING, PROD, RETIRED
    owner_id UUID NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_asset_lifecycle IS 'Master inventory tracking the evolution and deployment status of machine learning components.';

------------------------------------------------------------------------------------------------
-- Serial No: 345
-- Table: T345 - final_rulings
-- Schema: dispute
-- Description: Final rulings on disputes.
-- Business Case: When arbitration ends, a ruling is issued. This table stores the final verdict.
--It is the source of truth for the final state of a dispute. It triggers the release of escrow
--funds (T169).
-- KPIs: Ruling Execution Time.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.final_rulings (
    ruling_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    ruling_type VARCHAR(50) NOT NULL, -- 'FULL_REFUND', 'PARTIAL_REFUND', 'DENIED'
    arbitrator_notes TEXT,
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE dispute.final_rulings IS 'Authoritative conclusion records for escalated dispute cases.';

------------------------------------------------------------------------------------------------
-- Serial No: 346
-- Table: T346 - business_dictionary
-- Schema: knowledge
-- Description: Dictionary of business terms.
-- Business Case: Common language. This table defines business terms (e.g., "Chargeback Rate") to ensure
--everyone in the org uses them consistently. It is the foundation for the Glossary (T188).
-- KPIs: Term Usage Consistency.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.business_dictionary (
    term_id SERIAL PRIMARY KEY,
    term VARCHAR(100) NOT NULL UNIQUE,
    definition TEXT NOT NULL,
    context VARCHAR(50), -- FINANCE, RISK, TECH
    acronym VARCHAR(20)
);

COMMENT ON TABLE knowledge.business_dictionary IS 'Lexicon standardizing terminology used across the organization.';

------------------------------------------------------------------------------------------------
-- Serial No: 347
-- Table: T347 - vulnerability_scans
-- Schema: sec
-- Description: Results of vulnerability scans.
-- Business Case: Code has bugs. This table stores results from automated scanners (Snyk, Sonarqube).
--It lists CVEs found in the codebase. It drives the remediation backlog.
-- KPIs: Vulnerability Remediation Time.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_scans (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scanner_name VARCHAR(50) NOT NULL,
    cve_id VARCHAR(50),
    severity VARCHAR(20),
    status VARCHAR(20), -- OPEN, FIXED, IGNORED
    file_path TEXT,

    -- Metadata
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.vulnerability_scans IS 'Security defect tracker derived from static application security testing tools.';

------------------------------------------------------------------------------------------------
-- Serial No: 348
-- Table: T348 - performance_violations
-- Schema: ops
-- Description: Logs of performance SLA violations.
-- Business Case: We promise performance. This table logs when we miss it (e.g., "P99 Latency > 500ms").
--It is used to calculate SLA Credits (T285) and identify bottlenecks.
-- KPIs: Performance Breach Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.performance_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    threshold_value NUMERIC(10,2) NOT NULL,
    actual_value NUMERIC(10,2) NOT NULL,
    duration_sec BIGINT,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_perf_violations_time ON ops.performance_violations(timestamp);
COMMENT ON TABLE ops.performance_violations IS 'Incident log recording failures to meet guaranteed service levels.';

------------------------------------------------------------------------------------------------
-- Serial No: 349
-- Table: T349 - risk_segmentation_groups
-- Schema: fraud
-- Description: Groups of risk segments.
-- Business Case: Segmentation is powerful. This table stores groups of users with similar risk profiles.
--e.g., "High Value / Low Risk" (Whales) vs "Low Value / High Risk". It enables targeted
--marketing and fraud prevention strategies.
-- KPIs: Segment Homogeneity.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.risk_segmentation_groups (
    segment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    segment_name VARCHAR(100) NOT NULL,
    criteria JSONB NOT NULL, -- Rules defining the segment
    user_count BIGINT,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.risk_segmentation_groups IS 'Population aggregates enabling customized risk management strategies.';

------------------------------------------------------------------------------------------------
-- Serial No: 350
-- Table: T350 - bank_integration_keys
-- Schema: integration
-- Description: Keys for bank API integrations.
-- Business Case: We need keys to talk to banks. This table stores the API keys/Secrets for specific
--banks (Wise, Plaid). It ensures that financial data retrieval is secure and authenticated.
-- KPIs: Integration Success Rate.
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.bank_integration_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bank_name VARCHAR(100) NOT NULL,
    encrypted_key BYTEA NOT NULL,
    key_type VARCHAR(20) NOT NULL, -- 'API_KEY', 'CLIENT_SECRET'
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_bank_integration_keys_timestamp
    BEFORE UPDATE ON integration.bank_integration_keys
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE integration.bank_integration_keys IS 'Secure storage for credentials enabling automated financial data exchange.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 6 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER trg_risk_questions_timestamp
    BEFORE UPDATE ON fraud.user_risk_questions
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_feature_statistics_cache_timestamp
    BEFORE UPDATE ON ml.feature_statistics_cache
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_graph_community_detection_timestamp
    BEFORE UPDATE ON fraud.graph_community_detection
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_fraud_risk_audit_trail_timestamp
    BEFORE UPDATE ON fraud.merchant_risk_audit_trail
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_threat_assessment_risks_timestamp
    BEFORE UPDATE ON incident.threat_assessment_risks
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_model_ensemble_weights_timestamp
    BEFORE UPDATE ON ml.model_ensemble_weights
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.throttling_policies_timestamp
    BEFORE UPDATE ON ops.throttling_policies
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER integration.bank_integration_keys_timestamp
    BEFORE UPDATE ON integration.bank_integration_keys
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 6: Tables 251-350)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 7)
-- =============================================================================================
-- Tables T351 - T450
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 351
-- Table: T351 - graph_link_prediction
-- Schema: ml
-- Description: Stores predictions of future transaction links between entities in the graph.
-- Business Case: Fraud rings often operate in predictable patterns. This table stores the output of
--Link Prediction algorithms (e.g., "User A is 80% likely to transact with Fraudster B in the
--next 7 days"). By preemptively identifying these likely connections, the system can apply
--heightened scrutiny to the specific link or block it entirely before money moves.
-- KPIs: Link Prediction Precision, False Positive Rate on Blocking.
-- Feature Reference: F028, F125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.graph_link_prediction (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    node_a VARCHAR(64) NOT NULL,
    node_b VARCHAR(64) NOT NULL,
    link_probability NUMERIC(3,2) CHECK (link_probability BETWEEN 0 AND 1),
    prediction_window_days INTEGER DEFAULT 7,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_graph_link_nodes ON ml.graph_link_prediction(node_a, node_b);
COMMENT ON TABLE ml.graph_link_prediction IS 'Probabilistic forecast of future financial connections enabling preventative disruption.';

------------------------------------------------------------------------------------------------
-- Serial No: 352
-- Table: T352 - user_session_heatmap
-- Schema: fraud
-- Description: Aggregated heatmap data showing user activity intensity by time.
-- Business Case: Understanding *when* a user acts is as important as *how* they act. This table
--aggregates user activity into a heatmap (Day of Week vs Hour). It allows the system to detect
--anomalies like "This user usually logs in at 9 AM, but is now active at 3 AM". Deviations
--from the heatmap pattern are a strong signal of Account Takeover (ATO).
-- KPIs: Heatmap Anomaly Detection Rate.
-- Feature Reference: F040, F152
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_session_heatmap (
    user_hash VARCHAR(64) NOT NULL,
    day_of_week SMALLINT CHECK (day_of_week BETWEEN 0 AND 6),
    hour_of_day SMALLINT CHECK (hour_of_day BETWEEN 0 AND 23),
    activity_score INTEGER DEFAULT 0, -- Weighted score of activity (logins, txs)

    CONSTRAINT pk_user_heatmap UNIQUE (user_hash, day_of_week, hour_of_day)
);

COMMENT ON TABLE fraud.user_session_heatmap IS 'Temporal density map of user behavior identifying deviations in activity schedules.';

------------------------------------------------------------------------------------------------
-- Serial No: 353
-- Table: T353 - device_fingerprint_rotation
-- Schema: fraud
-- Description: Tracks the rotation or changing of device fingerprints associated with a user.
-- Business Case: Fraudsters using device spoofing tools often have to rotate their "fingerprint" to
--avoid blacklists. This table tracks when a user's fingerprint hash changes. If a user changes
--their fingerprint too frequently (e.g., 3 times a week), it indicates the use of emulation tools
--rather than genuine hardware, triggering a "High Risk" flag.
-- KPIs: Rotation Frequency Threshold Accuracy.
-- Feature Reference: F005
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_fingerprint_rotation (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    old_fingerprint_hash VARCHAR(64) NOT NULL,
    new_fingerprint_hash VARCHAR(64) NOT NULL,
    rotation_reason VARCHAR(255), -- 'USER_UPGRADE', 'SPOOFING_DETECTED'

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.device_fingerprint_rotation IS 'Surveillance of hardware identity changes indicative of anti-fingerprinting evasion techniques.';

------------------------------------------------------------------------------------------------
-- Serial No: 354
-- Table: T354 - fraud_cost_allocation
-- Schema: finance
-- Description: FinOps attribution of cloud infrastructure costs to specific fraud features.
-- Business Case: Fraud detection is expensive (GPU time for ML, storage for evidence). This table
--allocates these cloud costs back to specific features (e.g., "LSTM Training", "Image Storage").
--It allows the business to calculate the precise ROI of each fraud prevention feature by comparing
--the money saved vs. the cost of the feature itself.
-- KPIs: Cost Attribution Accuracy, Feature ROI Calculation.
-- Feature Reference: F017, T151
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.fraud_cost_allocation (
    allocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    infrastructure_cost NUMERIC(15,2) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    CONSTRAINT pk_fraud_cost_alloc UNIQUE (feature_name, period_start)
);

COMMENT ON TABLE finance.fraud_cost_allocation IS 'Financial ledger mapping compute and storage expenses to functional cost centers.';

------------------------------------------------------------------------------------------------
-- Serial No: 355
-- Table: T355 - kubernetes_pod_states
-- Schema: ops
-- Description: Real-time state tracking for Kubernetes pods in the fraud detection cluster.
-- Business Case: M03 runs on Kubernetes. This table acts as a state-store for pod health, scraped
--from the K8s API. It tracks which node a pod is on, its phase (Pending/Running), and resource
--usage. It provides the data for the Dependency Health Map (T224) and triggers scaling events.
-- KPIs: Pod Availability %, Scaling Event Latency.
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.kubernetes_pod_states (
    pod_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    node_name VARCHAR(255),
    phase VARCHAR(20) CHECK (phase IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
    restart_count INTEGER DEFAULT 0,

    -- Metadata
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_k8s_pod UNIQUE (pod_name, namespace)
);

COMMENT ON TABLE ops.kubernetes_pod_states IS 'Operational telemetry tracking container orchestration health and placement.';

------------------------------------------------------------------------------------------------
-- Serial No: 356
-- Table: T356 - helm_release_history
-- Schema: ops
-- Description: Versioning history for Helm charts deployed to the cluster.
-- Business Case: Infrastructure as Code (IaC) uses Helm. This table tracks the history of chart
--deployments (e.g., "fraud-engine v1.2.3"). It provides a link between the Deployment Pipeline
--(T123) and the actual state of the cluster. It allows for instant rollback to a specific
--chart version if an issue arises.
-- KPIs: Deployment Success Rate.
-- Feature Reference: F123
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.helm_release_history (
    release_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    chart_name VARCHAR(100) NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    values_hash CHAR(64), -- Hash of the values.yaml
    deployed_by UUID NOT NULL,

    -- Metadata
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_helm_release_chart ON ops.helm_release_history(chart_name);
COMMENT ON TABLE ops.helm_release_history IS 'Deployment registry for Kubernetes package management ensuring environment consistency.';

------------------------------------------------------------------------------------------------
-- Serial No: 357
-- Table: T357 - anomaly_feedback_loop
-- Schema: fraud
-- Description: User feedback flagging valid transactions as anomalous (True Negatives).
-- Business Case: Sometimes the system flags a transaction as anomalous, but it's actually the user
--behaving normally (e.g., going on a sudden spending spree). This table captures user corrections
--("This was me"). Feeding these True Negatives back into the model is crucial for reducing
--False Positives and training the model to understand "normal" outlier behavior.
-- KPIs: False Positive Reduction Rate.
-- Feature Reference: F121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.anomaly_feedback_loop (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    anomaly_score NUMERIC(5,2) NOT NULL,
    user_explanation TEXT,
    is_valid_anomaly BOOLEAN, -- User confirms it was anomalous or valid
    confidence_in_feedback INTEGER CHECK (confidence_in_feedback BETWEEN 1 AND 5),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE fraud.anomaly_feedback_loop IS 'Ground truth channel for correcting over-sensitive unsupervised learning models.';

------------------------------------------------------------------------------------------------
-- Serial No: 358
-- Table: T358 - email_link_tracking
-- Schema: dispute
-- Description: Tracks clicks on links within dispute notification emails.
-- Business Case: Email links (e.g., "Click here to resolve") can be phishing targets. This table logs
--every click: who clicked, when, and from what IP. If a link is clicked from a geo-location
--inconsistent with the user's normal behavior, it could indicate an account takeover via a phishing
--email sent from our own thread.
-- KPIs: Phishing Link Detection Rate.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.email_link_tracking (
    click_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    email_log_id UUID REFERENCES notify.sms_delivery_logs(sms_id), -- Using generic log ID for link
    link_url TEXT NOT NULL,
    clicked_by_user_hash VARCHAR(64),
    click_ip INET,
    user_agent TEXT,

    -- Metadata
    clicked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.email_link_tracking IS 'Security surveillance tracking interaction with hyperlinks in official communications.';

------------------------------------------------------------------------------------------------
-- Serial No: 359
-- Table: T359 - sms_provider_failures
-- Schema: notify
-- Description: Tracks downtime and failures of SMS gateway providers (e.g., Twilio).
-- Business Case: 2FA (F025) relies on SMS. If a provider goes down, users are locked out. This
--table logs failures (Timeout, 503 Error). If failure rates exceed a threshold, the system can
--automatically failover to a secondary provider (T107) or switch to App-based 2FA.
-- KPIs: Provider Downtime %, Failover Success Rate.
-- Feature Reference: F025
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notify.sms_provider_failures (
    failure_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_name VARCHAR(50) NOT NULL,
    error_code VARCHAR(20),
    error_message TEXT,
    duration_sec INTEGER,

    -- Metadata
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sms_failures_provider ON notify.sms_provider_failures(provider_name);
COMMENT ON TABLE notify.sms_provider_failures IS 'Reliability monitoring for multi-factor authentication channels enabling redundancy.';

------------------------------------------------------------------------------------------------
-- Serial No: 360
-- Table: T360 - payment_gateway_bridge
-- Schema: integration
-- Description: Mapping of legacy Payment Gateway IDs to PARI transaction hashes.
-- Business Case: During migration, legacy transactions must be accessible. This table bridges the old
--gateway's Transaction ID (e.g., Stripe "ch_12345") to PARI's hash. It allows support agents
--to look up old transactions using the ID printed on a customer's old bank statement.
-- KPIs: Lookup Success Rate for Migrated Data.
-- Feature Reference: F157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.payment_gateway_bridge (
    bridge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    legacy_psp VARCHAR(50) NOT NULL, -- e.g., 'STRIPE', 'PAYPAL'
    legacy_tx_id VARCHAR(100) NOT NULL,
    pari_tx_hash VARCHAR(64) NOT NULL,
    migrated_date DATE NOT NULL
);

CREATE INDEX idx_psp_bridge_legacy ON integration.payment_gateway_bridge(legacy_psp, legacy_tx_id);
COMMENT ON TABLE integration.payment_gateway_bridge IS 'Cross-reference key enabling access to historical transaction data during platform migration.';

------------------------------------------------------------------------------------------------
-- Serial No: 361
-- Table: T361 - clickstream_events
-- Schema: fraud
-- Description: Raw UI clickstream data for detecting bot behavior patterns.
-- Business Case: Bots navigate webpages differently than humans (too fast, straight lines). This table
--stores raw clickstream data (Mouse X/Y, Click Timestamp, Scroll Depth). Analyzing this stream
--with ML helps distinguish between a "Power User" and a "Scripting Bot" trying to farm
--accounts or test cards.
-- KPIs: Bot Detection Accuracy via Heuristics.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.clickstream_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('CLICK', 'SCROLL', 'SUBMIT')),
    target_element VARCHAR(255), -- CSS Selector ID
    x_coordinate INTEGER,
    y_coordinate INTEGER,
    timestamp_ms BIGINT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_clickstream_session ON fraud.clickstream_events(session_id);
COMMENT ON TABLE fraud.clickstream_events IS 'High-frequency behavioral telemetry differentiating human interaction from automated scripts.';

------------------------------------------------------------------------------------------------
-- Serial No: 362
-- Table: T362 - voice_biometric_enrollment
-- Schema: fraud
-- Description: Tracks the enrollment process and status for voice biometrics.
-- Business Case: Voice Authentication (F124) requires enrollment. This table tracks the process: Did the
--user provide enough samples? Is the quality sufficient? What is the status of the enrollment
--(Pending, Active, Rejected)? It manages the lifecycle of the voice print before it hits the
--active template table (T175).
-- KPIs: Enrollment Success Rate.
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.voice_biometric_enrollment (
    enrollment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'INITIATED', -- INITIATED, COLLECTING, PROCESSING, ACTIVE, FAILED
    sample_count INTEGER DEFAULT 0,
    quality_score NUMERIC(3,2), -- Average signal-to-noise ratio of samples
    failure_reason TEXT,

    -- Metadata
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_voice_enrollment_timestamp
    BEFORE UPDATE ON fraud.voice_biometric_enrollment
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE fraud.voice_biometric_enrollment IS 'Workflow management for the setup and validation of voice-based authentication factors.';

------------------------------------------------------------------------------------------------
-- Serial No: 363
-- Table: T363 - smart_contract_gas_tracking
-- Schema: contract
-- Description: Tracks gas prices and costs for blockchain contract anchors.
-- Business Case: Anchoring contracts to the blockchain (T078) costs money (Gas). Gas prices fluctuate.
--This table tracks the gas price at the time of anchoring and the total cost. It allows FinOps to
--monitor these "Gas Costs" and optimize when we anchor (e.g., wait for low gas periods).
-- KPIs: Gas Cost Optimization Savings.
-- Feature Reference: F078
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.smart_contract_gas_tracking (
    anchor_id UUID NOT NULL REFERENCES contract.blockchain_anchors(anchor_id),
    network VARCHAR(20) NOT NULL, -- 'ETHEREUM', 'POLYGON'
    gas_price_gwei NUMERIC(10,2),
    gas_used BIGINT,
    transaction_fee_eth NUMERIC(15,18),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_gas_tracking UNIQUE (anchor_id, network)
);

COMMENT ON TABLE contract.smart_contract_gas_tracking IS 'Financial ledger tracking variable execution costs for blockchain evidence anchoring.';

------------------------------------------------------------------------------------------------
-- Serial No: 364
-- Table: T364 - ai_explanation_drift
-- Schema: ml
-- Description: Monitors the consistency of feature explanations over time.
-- Business Case: Model interpretability is vital (F051). However, if the explanation for "Fraud"
--changes suddenly (e.g., last month it was "Location", this month it's "Time of Day"), it confuses
--auditors. This table tracks the drift in feature importance (SHAP values) to ensure the story
--remains consistent and explainable to regulators.
-- KPIs: Explanation Stability Score.
-- Feature Reference: F051
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.ai_explanation_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    importance_current NUMERIC(5,2),
    importance_baseline NUMERIC(5,2),
    delta NUMERIC(5,2),

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.ai_explanation_drift IS 'Stability monitoring for machine learning interpretability ensuring consistent narrative for auditors.';

------------------------------------------------------------------------------------------------
-- Serial No: 365
-- Table: T365 - cross_border_risk_matrix
-- Schema: fraud
-- Description: Risk matrix for cross-border transactions (Source -> Dest Currency).
-- Business Case: Cross-border payments carry different risks (sanctions, forex volatility). This table
--defines a matrix of risk scores based on the currency pair involved (e.g., USD -> EUR is low risk,
--USD -> High Risk Jurisdiction is high risk). It applies a multiplier to the base fraud score.
-- KPIs: Cross-Border Fraud Reduction.
-- Feature Reference: F029
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.cross_border_risk_matrix (
    source_currency CHAR(3) NOT NULL,
    dest_currency CHAR(3) NOT NULL,
    risk_multiplier NUMERIC(3,2) DEFAULT 1.0,
    sanctions_check_required BOOLEAN DEFAULT FALSE,

    CONSTRAINT pk_cross_border UNIQUE (source_currency, dest_currency)
);

COMMENT ON TABLE fraud.cross_border_risk_matrix IS 'Configuration matrix applying geographic and regulatory risk adjustments to international payments.';

------------------------------------------------------------------------------------------------
-- Serial No: 366
-- Table: T366 - biometric_revocation_list
-- Schema: fraud
-- Description: List of revoked biometric identifiers (Face, Voice).
-- Business Case: Biometrics are immutable identifiers. If a user's face print is compromised (Deepfake),
--we cannot just change the password. We must revoke the biometric identifier. This table stores
--hashes of revoked prints, ensuring the system enrolls the user again or blocks them if they try to
--use the old compromised print.
-- KPIs: Revocation Enforcement Time.
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.biometric_revocation_list (
    revocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    biometric_hash VARCHAR(255) NOT NULL, -- Hash of the face/voice vector
    biometric_type VARCHAR(20) NOT NULL CHECK (biometric_type IN ('FACE', 'VOICE', 'BEHAVIORAL')),
    reason VARCHAR(255) NOT NULL, -- 'COMPROMISED', 'USER_REQUEST', 'QUALITY_DEGRADED'

    -- Metadata
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bio_revocation_hash ON fraud.biometric_revocation_list(biometric_hash);
COMMENT ON TABLE fraud.biometric_revocation_list IS 'Blocklist of compromised biological identifiers ensuring user security and account recovery.';

------------------------------------------------------------------------------------------------
-- Serial No: 367
-- Table: T367 - dynamic_rule_evaluation
-- Schema: fraud
-- Description: Performance metrics for dynamic rules versus static rules.
-- Business Case: Dynamic rules (context-aware) are harder to maintain than static ones. This table
--compares their performance (Precision/Recall) side-by-side. It validates the hypothesis that
--dynamic rules actually catch more fraud with fewer false positives, justifying their complexity.
-- KPIs: Rule Lift (Dynamic vs Static).
-- Feature Reference: F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.dynamic_rule_evaluation (
    eval_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) NOT NULL,
    rule_type VARCHAR(20) CHECK (rule_type IN ('STATIC', 'DYNAMIC')),
    precision_score NUMERIC(5,2),
    recall_score NUMERIC(5,2),
    execution_period DATE NOT NULL
);

COMMENT ON TABLE fraud.dynamic_rule_evaluation IS 'Performance benchmarking validating the efficacy of adaptive versus static fraud prevention logic.';

------------------------------------------------------------------------------------------------
-- Serial No: 368
-- Table: T368 - forensic_image_hashes
-- Schema: dispute
-- Description: Perceptual hashes (pHash) of evidence images to detect duplicates.
-- Business Case: Fraudsters upload fake evidence repeatedly. This table stores the "perceptual hash"
--(pHash) of evidence images. A pHash is the same for images that look similar (even if pixels differ
--slightly). It allows the system to instantly flag that an "Uploaded Receipt" is actually just a
--screenshot of a different transaction found in previous cases.
-- KPIs: Duplicate Evidence Detection Rate.
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.forensic_image_hashes (
    evidence_id UUID NOT NULL REFERENCES dispute.case_evidence(evidence_id),
    phash_value BIGINT NOT NULL, -- 64-bit perceptual hash
    hamming_distance_threshold INTEGER DEFAULT 10, -- Similarity threshold
    matched_with_evidence UUID REFERENCES dispute.case_evidence(evidence_id)
);

CREATE INDEX idx_fimg_phash ON dispute.forensic_image_hashes(phash_value);
COMMENT ON TABLE dispute.forensic_image_hashes IS 'Content-based image indexing enabling rapid detection of reused or manipulated evidence media.';

------------------------------------------------------------------------------------------------
-- Serial No: 369
-- Table: T369 - user_knowledge_graph
-- Schema: fraud
-- Description: Graph of user interests and attributes derived from transaction history.
-- Business Case: "Know Your User" (KYU) beyond just ID. This table constructs a graph of user attributes
--derived from transactions (User -> Likes -> "Electronics", User -> Lives -> "NY"). If a user
--suddenly buys something completely disconnected from their graph, it's high risk. It enables
--contextual anomaly detection.
-- KPIs: Graph Node Coverage per User.
-- Feature Reference: F125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_knowledge_graph (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    attribute_type VARCHAR(50) NOT NULL, -- 'INTEREST', 'LOCATION', 'PRICE_POINT'
    attribute_value VARCHAR(255),
    confidence_score NUMERIC(3,2),

    -- Metadata
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_kg_user ON fraud.user_knowledge_graph(user_hash);
COMMENT ON TABLE fraud.user_knowledge_graph IS 'Entity-attribute graph representing behavioral profile for contextual anomaly detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 370
-- Table: T370 - model_quantization
-- Schema: ml
-- Description: Details of quantized ML models (Float32 -> Float16/Int8) for edge deployment.
-- Business Case: Running models on edge devices (mobile app) requires quantization (reducing precision).
--This table tracks the quantization parameters (bits, scaling factor) and the resulting accuracy loss.
--It ensures that the "Fraud Check on Phone" remains fast without losing too much predictive power.
-- KPIs: Model Compression Ratio, Accuracy Loss %.
-- Feature Reference: F002
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.model_quantization (
    quant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    original_precision VARCHAR(10) DEFAULT 'FLOAT32',
    target_precision VARCHAR(10) NOT NULL, -- 'FLOAT16', 'INT8'
    accuracy_loss_pct NUMERIC(5,2),
    model_size_reduction_pct NUMERIC(5,2),

    -- Metadata
    quantized_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.model_quantization IS 'Optimization metadata for deploying lightweight models to edge devices.';

------------------------------------------------------------------------------------------------
-- Serial No: 371
-- Table: T371 - fraud_dispute_crosstab
-- Schema: bi
-- Description: Crosstabulation matrix linking Fraud Type to Dispute Reason.
-- Business Case: Do "Friendly Fraud" claims usually stem from "Product Not Received"? This crosstab table
--pre-calculates the intersection of Detected Fraud Type and the Dispute Reason users gave. It helps
--product teams fix the root cause (e.g., if shipping is always the issue, fix the warehouse).
-- KPIs: Correlation Coefficient.
-- Feature Reference: F067
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bi.fraud_dispute_crosstab (
    fraud_type VARCHAR(50) NOT NULL,
    dispute_reason VARCHAR(50) NOT NULL,
    count BIGINT DEFAULT 0,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    CONSTRAINT pk_crosstab UNIQUE (fraud_type, dispute_reason, period_start)
);

CREATE INDEX idx_crosstab_period ON bi.fraud_dispute_crosstab(period_start);
COMMENT ON TABLE bi.fraud_dispute_crosstab IS 'Statistical intersection of categorization variables highlighting causal relationships in failure modes.';

------------------------------------------------------------------------------------------------
-- Serial No: 372
-- Table: T372 - api_rate_limit_history
-- Schema: api
-- Description: Historical tracking of API rate limit changes and justifications.
-- Business Case: Rate limits (T171) change based on business needs or attacks. This table logs the history
--of changes: Why did we limit "Gold" tier users? Was there a bot attack? It provides an audit trail
--for customer disputes ("Why am I being throttled?") and for operational review.
-- KPIs: Policy Change Justification Traceability.
-- Feature Reference: F073, F171
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api.rate_limit_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tier_name VARCHAR(50) NOT NULL REFERENCES api.rate_limit_quotas(tier_name),
    old_limit INTEGER,
    new_limit INTEGER NOT NULL,
    changed_by UUID NOT NULL,
    reason_code VARCHAR(50) NOT NULL, -- 'DDOS_MITIGATION', 'CAPACITY_UPGRADE'

    -- Metadata
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE api.rate_limit_history IS 'Version control log for access policy changes ensuring operational transparency.';

------------------------------------------------------------------------------------------------
-- Serial No: 373
-- Table: T373 - geo_velocity_polygons
-- Schema: fraud
-- Description: Dynamic polygon definitions for geolocation velocity checks.
-- Business Case: Simple "Distance / Time" checks aren't enough. Some users (e.g., delivery drivers) move fast
--within a valid zone. This table stores GeoJSON polygons representing "Valid High Velocity Zones".
--If a user moves fast *inside* the polygon, it's allowed; fast movement *outside* is blocked.
-- KPIs: False Positive Reduction for Mobile Users.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.geo_velocity_polygons (
    polygon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    polygon_name VARCHAR(100) NOT NULL,
    geo_json JSONB NOT NULL, -- Polygon coordinates
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_geo_velocity_polygons_timestamp
    BEFORE UPDATE ON fraud.geo_velocity_polygons
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE fraud.geo_velocity_polygons IS 'Spatial configuration defining legitimate high-mobility zones for anomaly detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 374
-- Table: T374 - merchant_anomaly_score
-- Schema: fraud
-- Description: Real-time anomaly score for merchant behavior compared to their baseline.
-- Business Case: Merchants usually behave predictably. A sudden spike in sales or refund rate can
--indicate the merchant account has been compromised or they are attempting a cash-out. This table
--stores the real-time "Anomaly Score" derived from comparing current stats (T030) against the
--30-day baseline.
-- KPIs: Merchant Compromise Detection Time.
-- Feature Reference: F030
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.merchant_anomaly_score (
    merchant_id UUID PRIMARY KEY,
    anomaly_score NUMERIC(5,2) CHECK (anomaly_score BETWEEN 0 AND 100),
    contributing_factors JSONB, -- {"sales_spike": true, "refund_rate_high": false}

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.merchant_anomaly_score IS 'Behavioral baseline deviation flag for identifying compromised partner accounts.';

------------------------------------------------------------------------------------------------
-- Serial No: 375
-- Table: T375 - feature_store_snapshots
-- Schema: ml
-- Description: Point-in-time snapshots of features for time-travel debugging.
-- Business Case: "Why was User X blocked yesterday?" requires knowing the features *yesterday*. This table
--creates daily snapshots of the Feature Store. It allows analysts to query "What was User X's location
--velocity on Nov 1st?" even if the raw logs have been archived or rotated.
-- KPIs: Data Reconstruction Accuracy.
-- Feature Reference: F016
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.feature_store_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id VARCHAR(64) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    feature_value NUMERIC(15,6),
    snapshot_date DATE NOT NULL
);

CREATE INDEX idx_feat_snap_entity ON ml.feature_store_snapshots(entity_id, snapshot_date);
COMMENT ON TABLE ml.feature_store_snapshots IS 'Time-travel capability for historical feature reconstruction facilitating retrospective model debugging.';

------------------------------------------------------------------------------------------------
-- Serial No: 376
-- Table: T376 - kafka_lag_metrics
-- Schema: ops
-- Description: Metrics tracking consumer lag for Kafka topics.
-- Business Case: Real-time fraud detection depends on consuming Kafka topics instantly. If consumer lag grows
--(falling behind production), fraud occurs undetected. This table logs the "lag" (offset difference)
--for every consumer group. It triggers alarms if the system falls too far behind.
-- KPIs: Consumer Lag (Max Offset).
-- Feature Reference: F094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.kafka_lag_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL,
    consumer_group VARCHAR(100) NOT NULL,
    partition_id INTEGER,
    current_offset BIGINT,
    log_end_offset BIGINT,
    lag_count BIGINT GENERATED ALWAYS AS (log_end_offset - current_offset) STORED,

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kafka_lag_topic ON ops.kafka_lag_metrics(topic_name);
COMMENT ON TABLE ops.kafka_lag_metrics IS 'Throughput latency monitoring ensuring real-time data pipelines keep pace with event generation.';

------------------------------------------------------------------------------------------------
-- Serial No: 377
-- Table: T377 - ml_model_sharding
-- Schema: ml
-- Description: Sharding keys and distribution for distributed model inference.
-- Business Case: Large models are sharded across multiple servers. This table defines the sharding logic
--(e.g., "Modulo 10 of User Hash"). It maps a shard ID to the server hosting that shard. It ensures
--that the load balancer knows exactly which server to send the request to for the specific user segment.
-- KPIs: Sharding Key Distribution Balance.
-- Feature Reference: F002
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.ml_model_sharding (
    model_id UUID NOT NULL,
    shard_index INTEGER NOT NULL,
    shard_key_expression VARCHAR(255), -- e.g., "hash(user_id) % 10"
    target_server_dns TEXT NOT NULL,

    CONSTRAINT pk_model_sharding UNIQUE (model_id, shard_index)
);

COMMENT ON TABLE ml.ml_model_sharding IS 'Routing configuration for distributed inference nodes supporting high-volume model serving.';

------------------------------------------------------------------------------------------------
-- Serial No: 378
-- Table: T378 - audit_log_signature_chain
-- Schema: audit
-- Description: Cryptographic chain linking audit log entries to prevent tampering.
-- Business Case: Auditors (and regulators) require absolute proof that logs haven't been altered. This table
--creates a "Chain of Custody". Each record contains a hash of the *previous* record. If any record is
--deleted or modified, the chain breaks, rendering the log invalid. It provides mathematical
--integrity for the audit trail (T015).
-- KPIs: Chain Integrity Check (100% success).
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.audit_log_signature_chain (
    chain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    linked_log_id UUID NOT NULL,
    prev_chain_id UUID REFERENCES audit.audit_log_signature_chain(chain_id),
    current_log_hash CHAR(64) NOT NULL,
    digital_signature BYTEA, -- Signed by the system's private key
    signature_algo contract.signature_algo NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_chain_linked ON audit.audit_log_signature_chain(linked_log_id);
COMMENT ON TABLE audit.audit_log_signature_chain IS 'Cryptographically linked sequence providing tamper-evident proof for audit records.';

------------------------------------------------------------------------------------------------
-- Serial No: 379
-- Table: T379 - transaction_time_warp
-- Schema: ops
-- Description: Detection of system clock jumps (Time Warp) affecting risk rules.
-- Business Case: Time-based rules (e.g., "If < 5 mins between transactions") break if the system clock jumps.
--This table logs NTP (Network Time Protocol) anomalies detected across the cluster. If Server A is
--5 seconds ahead of Server B, fraud rules might behave inconsistently. It detects and alerts on
--time skew.
-- KPIs: Clock Skew Threshold Breach.
-- Feature Reference: F004
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.transaction_time_warp (
    warp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_id VARCHAR(100) NOT NULL,
    ntp_offset_ms NUMERIC(10,2), -- Difference from reference time
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_reason VARCHAR(255),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.transaction_time_warp IS 'Time synchronization monitoring ensuring temporal consistency of fraud prevention logic.';

------------------------------------------------------------------------------------------------
-- Serial No: 380
-- Table: T380 - behavioral_consistency_score
-- Schema: fraud
-- Description: Score measuring how consistent a user's behavior is over time.
-- Business Case: Humans are variable; bots are repetitive. This table calculates a "Consistency Score".
--If a user types with *exactly* the same keystroke latency for 100 logins, it's statistically impossible
--(it's a script). A low consistency score indicates a human; a perfect score (100%) indicates a bot.
-- KPIs: Bot Classification Accuracy.
-- Feature Reference: F040
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.behavioral_consistency_score (
    user_hash VARCHAR(64) PRIMARY KEY,
    consistency_score NUMERIC(3,2), -- 1.0 = perfectly consistent (bot), 0.0 = chaotic (human)
    sample_size INTEGER,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.behavioral_consistency_score IS 'Inverted variability metric identifying automated actors via lack of natural entropy.';

------------------------------------------------------------------------------------------------
-- Serial No: 381
-- Table: T381 - voice_stress_detection
-- Schema: fraud
-- Description: NLP analysis results of voice recordings for stress levels.
-- Business Case: Voice biometrics verify identity, but stress detection verifies intent. A user pleading "That
--wasn't me!" sounds different than a fraudster reading a script. This table stores the audio
--analysis results (Pitch variance, jitter) to infer stress levels during dispute calls.
-- KPIs: Stress Classification Accuracy.
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.voice_stress_detection (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    recording_id UUID NOT NULL REFERENCES dispute.voice_records(record_id),
    stress_level VARCHAR(20) CHECK (stress_level IN ('LOW', 'MEDIUM', 'HIGH', 'PANIC')),
    pitch_variance NUMERIC(5,2),
    jitter_score NUMERIC(5,2),
    confidence NUMERIC(3,2),

    -- Metadata
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.voice_stress_detection IS 'Paralinguistic analysis of acoustic features to determine the veracity of voice claims.';

------------------------------------------------------------------------------------------------
-- Serial No: 382
-- Table: T382 - refund_recurrence
-- Schema: fraud
-- Description: Tracks users who habitually refund the same item or merchant.
-- Business Case: Abusing the refund policy is a specific type of friendly fraud. This table tracks the
--recurrence of refunds. If User X refunds the same "Item A" 3 times a month, they might be buying
--it, using it, and returning it (renting the product). It flags "Habitual Returners" for
--policy enforcement.
-- KPIs: Abuse Pattern Detection Rate.
-- Feature Reference: F115
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.refund_recurrence (
    recurrence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    merchant_id UUID,
    item_id VARCHAR(100), -- SKU or Description
    refund_count INTEGER DEFAULT 0,
    period_start DATE NOT NULL,

    CONSTRAINT pk_refund_recurrence UNIQUE (user_hash, merchant_id, item_id, period_start)
);

COMMENT ON TABLE fraud.refund_recurrence IS 'Frequency analysis identifying policy abuse through repeated return cycles.';

------------------------------------------------------------------------------------------------
-- Serial No: 383
-- Table: T383 - synthetic_media_generation
-- Schema: fraud
-- Description: Metadata on AI-generated media and detection scores.
-- Business Case: Generative AI can now create fake videos (Deepfakes). This table tracks both the *generation*
--of synthetic media (for training our detectors) and the *detection* of suspected deepfakes
--submitted as evidence. It ensures that the system can distinguish between real evidence and
--AI-generated fraud.
-- KPIs: Deepfake Detection Confidence.
-- Feature Reference: F093
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.synthetic_media_generation (
    media_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(20) NOT NULL CHECK (type IN ('TRAINING_DATA', 'SUSPECTED_EVIDENCE')),
    generator_model VARCHAR(100), -- Model that created it
    detector_confidence NUMERIC(3,2), -- 0.0 = Definitely Synthetic, 1.0 = Definitely Real
    file_hash CHAR(64) NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.synthetic_media_generation IS 'Registry tracking the generation and verification of AI-synthetic multimedia content.';

------------------------------------------------------------------------------------------------
-- Serial No: 384
-- Table: T384 - multi_factor_authentication_logs
-- Schema: sec
-- Description: Detailed logs for Step-up Authentication (MFA) events.
-- Business Case: MFA is critical for high-value transactions. This table logs every MFA challenge: Which method
--was used (SMS, App, Biometric)? Did it pass? How long did it take? It allows security teams to
--identify if specific MFA methods (e.g., Email) are too weak or being bypassed.
-- KPIs: MFA Success Rate per Method.
-- Feature Reference: F081
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.multi_factor_authentication_logs (
    mfa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    mfa_type VARCHAR(20) NOT NULL, -- 'TOTP', 'SMS', 'PUSH', 'BIO'
    trigger_reason VARCHAR(50),
    status VARCHAR(20) NOT NULL, -- 'PASSED', 'FAILED', 'SKIPPED'
    challenge_flow_id UUID, -- Reference to the workflow definition

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.multi_factor_authentication_logs IS 'Detailed telemetry of strong authentication workflows for security assurance.';

------------------------------------------------------------------------------------------------
-- Serial No: 385
-- Table: T385 - zero_knowledge_proof_cache
-- Schema: sec
-- Description: Cache for Zero-Knowledge Proof (ZKP) verifications.
-- Business Case: ZKPs (T079) are computationally expensive to verify. This table caches the result of a
--proof verification. If a user submits a ZKP to prove "I have funds", we verify it once and
--cache the result "Valid" for a short period (e.g., 1 minute) to prevent replay attacks
--while saving CPU.
-- KPIs: Cache Hit Ratio.
-- Feature Reference: F079
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.zero_knowledge_proof_cache (
    proof_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proof_hash CHAR(64) NOT NULL,
    is_valid BOOLEAN NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_zkp_cache_hash ON sec.zero_knowledge_proof_cache(proof_hash);
COMMENT ON TABLE sec.zero_knowledge_proof_cache IS 'Performance optimization layer for cryptographic proof verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 386
-- Table: T386 - data_lineage_impact
-- Schema: data
-- Description: Maps upstream data failures to downstream consequences.
-- Business Case: If the "GeoIP" provider goes down, which downstream ML features break? This table maps the
--dependency of data lineage (T132). It helps Ops prioritize the restoration of upstream services
--based on the impact on the Fraud Model (e.g., "GeoIP down = 15% feature loss = High Impact").
-- KPIs: Impact Assessment Accuracy.
-- Feature Reference: T132
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS data.data_lineage_impact (
    impact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    upstream_source VARCHAR(100) NOT NULL, -- e.g., 'GEOIP_API'
    downstream_consumer VARCHAR(100) NOT NULL, -- e.g., 'LSTM_INFERENCE'
    feature_names TEXT[], -- Which features are affected?
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH'))
);

COMMENT ON TABLE data.data_lineage_impact IS 'Dependency impact matrix prioritizing remediation of data source failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 387
-- Table: T387 - customer_lifetime_value_risk
-- Schema: fraud
-- Description: Adjusts risk tolerance based on customer Lifetime Value (CLV).
-- Business Case: High-value VIPs get more leeway (lower friction). This table integrates CLV data with
--Fraud Risk Tiers (T013). It adjusts the "blocking threshold" dynamically. If a user is a
--Platinum CLV, we might block only at 99% risk, whereas a new user is blocked at 50%.
-- KPIs: Churn Risk vs Fraud Risk Balance.
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.customer_lifetime_value_risk (
    user_hash VARCHAR(64) PRIMARY KEY,
    clv_tier VARCHAR(20), -- 'BRONZE', 'SILVER', 'GOLD', 'PLATINUM'
    risk_adjustment_factor NUMERIC(3,2) DEFAULT 1.0, -- Multiplier for risk threshold

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.customer_lifetime_value_risk IS 'Risk calibration engine balancing loss prevention against customer retention revenue.';

------------------------------------------------------------------------------------------------
-- Serial No: 388
-- Table: T388 - fraud_actor_attribution
-- Schema: fraud
-- Description: Attributing clusters of fraud events to specific "Actors" or organizations.
-- Business Case: Fraud isn't random; it's organized. This table links multiple cases/incidents to a single
--"Actor" (e.g., "The Russian Botnet"). It helps in building a profile of the adversary. Once an
--actor is identified, all future events matching their MOA are automatically linked.
-- KPIs: Actor Identification Accuracy.
-- Feature Reference: F097
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.fraud_actor_attribution (
    attribution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    actor_name VARCHAR(100) NOT NULL,
    linked_case_id UUID REFERENCES dispute.cases(case_id),
    confidence_score NUMERIC(3,2),
    attribution_method VARCHAR(50), -- 'GRAPH_ANALYSIS', 'IP_CLUSTER', 'DEVICE_FINGERPRINT'

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.fraud_actor_attribution IS 'Intelligence dossier linking disparate fraud events to coordinated threat actors.';

------------------------------------------------------------------------------------------------
-- Serial No: 389
-- Table: T389 - dark_web_marketplace_monitoring
-- Schema: fraud
-- Description: Surveillance of specific marketplaces known for selling stolen financial data.
-- Business Case: Threat Intelligence (T048) includes monitoring marketplaces (e.g., "AlphaBay"). This
--table tracks which marketplaces are active and what data types they are selling (Cards, Credentials).
--If a user's credentials appear in a monitored marketplace dump, this table links the breach ID to
--the user for forced password resets.
-- KPIs: Breach Discovery Time-to-Live.
-- Feature Reference: F048
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.dark_web_marketplace_monitoring (
    monitoring_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    marketplace_name VARCHAR(100) NOT NULL,
    onion_address VARCHAR(255),
    status VARCHAR(20) DEFAULT 'MONITORING', -- MONITORING, DOWN, VERIFIED_FAKE
    data_types_seen TEXT[],

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.dark_web_marketplace_monitoring IS 'Operational watchlist for illicit data exchanges facilitating proactive credential protection.';

------------------------------------------------------------------------------------------------
-- Serial No: 390
-- Table: T390 - api_gateway_plugin_configs
-- Schema: api
-- Description: Configuration for plugins running in the API Gateway.
-- Business Case: The Gateway supports plugins (Rate Limiting, Request Transformation). This table stores the
--config for these plugins in JSON format. It allows Ops to inject custom logic into the Gateway
--without a full code deploy (e.g., "Block all requests containing 'curl' in User-Agent").
-- KPIs: Plugin Execution Latency.
-- Feature Reference: F255
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api.api_gateway_plugin_configs (
    plugin_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gateway_name VARCHAR(100) NOT NULL,
    plugin_name VARCHAR(100) NOT NULL,
    config_json JSONB NOT NULL,
    priority INTEGER DEFAULT 1,
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_api_plugin_configs_timestamp
    BEFORE UPDATE ON api.api_gateway_plugin_configs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE api.api_gateway_plugin_configs IS 'Dynamic runtime behavior modifiers for API traffic management.';

------------------------------------------------------------------------------------------------
-- Serial No: 391
-- Table: T391 - container_resource_limits
-- Schema: ops
-- Description: Definitions of CPU/Memory limits for containers.
-- Business Case: Resource starvation causes latency. This table defines the limits (CPU shares, RAM) for each
--container type. It is used by the Orchestration layer (K8s) to ensure that the LSTM Inference
--service gets enough GPU/CPU, while the lightweight web service gets less.
-- KPIs: Resource Utilization vs. Limit.
-- Feature Reference: T355
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.container_resource_limits (
    container_name VARCHAR(255) PRIMARY KEY,
    cpu_limit_millicores INTEGER NOT NULL, -- e.g., 500m = 0.5 cores
    memory_limit_mb INTEGER NOT NULL,
    gpu_limit INTEGER DEFAULT 0, -- Number of GPUs

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.container_resource_limits IS 'Capacity constraint definitions ensuring compute allocation matches workload requirements.';

------------------------------------------------------------------------------------------------
-- Serial No: 392
-- Table: T392 - database_connection_pool_stats
-- Schema: db
-- Description: Statistics on the usage of database connection pools (PgBouncer).
-- Business Case: The Database connection pool is a bottleneck. This table tracks the number of active/idle
--connections and the wait time for a connection. It helps DBAs tune pool sizes. If wait time is
--high, transactions fail (timeouts), directly impacting fraud prevention.
-- KPIs: Connection Wait Time (ms).
-- Feature Reference: F149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.database_connection_pool_stats (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    database_name VARCHAR(100) NOT NULL,
    active_connections INTEGER,
    idle_connections INTEGER,
    waiting_clients INTEGER,
    wait_time_ms NUMERIC(10,2),

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE db.database_connection_pool_stats IS 'Resource utilization telemetry for database connection management.';

------------------------------------------------------------------------------------------------
-- Serial No: 393
-- Table: T393 - cache_hit_miss_history
-- Schema: perf
-- Description: Historical performance data for caching layers (Redis).
-- Business Case: Cache effectiveness fluctuates. This table tracks the Hit/Miss ratio over time. It helps
--determine if the cache size needs tuning or if the caching strategy (e.g., Eviction Policy) is
--working correctly.
-- KPIs: Average Cache Hit Ratio.
-- Feature Reference: F147
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS perf.cache_hit_miss_history (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_name VARCHAR(100) NOT NULL,
    hit_count BIGINT,
    miss_count BIGINT,
    ratio NUMERIC(5,2),

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE perf.cache_hit_miss_history IS 'Time-series performance data for ephemeral data storage optimization.';

------------------------------------------------------------------------------------------------
-- Serial No: 394
-- Table: T394 - distributed_lock_owners
-- Schema: db
-- Description: Current owners of distributed advisory locks.
-- Business Case: Preventing double processing requires locks. This table shows *who* owns a lock (T149).
--It ensures that if a worker crashes, another worker can inspect this table to see if the lock is
--"stale" (held longer than TTL) and steal it.
-- KPIs: Lock Contention Rate.
-- Feature Reference: T149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.distributed_lock_owners (
    lock_key VARCHAR(100) PRIMARY KEY,
    owner_id VARCHAR(100) NOT NULL, -- Worker ID
    acquired_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE db.distributed_lock_owners IS 'State registry for mutual exclusion primitives ensuring job coordination.';

------------------------------------------------------------------------------------------------
-- Serial No: 395
-- Table: T395 - message_queue_depth
-- Schema: ops
-- Description: Depth of message queues (Kafka/RabbitMQ) for various topics.
-- Business Case: Backpressure kills real-time systems. This table logs the depth of queues (number of
--unprocessed messages). If depth grows to 1 million, the system is hours behind. It triggers
--scaling events (spin up more consumers).
-- KPIs: Max Queue Age (ms).
-- Feature Reference: T376
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.message_queue_depth (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL,
    consumer_group VARCHAR(100),
    depth BIGINT,

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_queue_depth_topic ON ops.message_queue_depth(topic_name);
COMMENT ON TABLE ops.message_queue_depth IS 'Throughput bottleneck indicator triggering auto-scaling of consumer groups.';

------------------------------------------------------------------------------------------------
-- Serial No: 396
-- Table: T396 - service_mesh_routing_table
-- Schema: sec
-- Description: Routing weights and targets for Service Mesh traffic.
-- Business Case: Service Mesh (T219) routes traffic. This table defines the routing table (v1 gets
--90% traffic, v2 gets 10%). It enables Canary releases (T176) and Blue/Green deployments (T226) by
--simply updating the weights in this table.
-- KPIs: Routing Configuration Latency.
-- Feature Reference: T219
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_routing_table (
    route_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL, -- 'v1', 'v2'
    target_host TEXT NOT NULL,
    weight INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE sec.service_mesh_routing_table IS 'Network traffic distribution control enabling advanced deployment strategies.';

------------------------------------------------------------------------------------------------
-- Serial No: 397
-- Table: T397 - webhook_signature_validation
-- Schema: security
-- Description: Specifics of validating HMAC signatures on incoming webhooks.
-- Business Case: Partners send webhooks (T179). To ensure they are authentic, they sign the payload with HMAC.
--This table stores the secrets or logic to validate these signatures. It verifies that the webhook
--actually came from the Partner and not an attacker injecting a "Refund Completed" event.
-- KPIs: Signature Verification Failure Rate.
-- Feature Reference: T179
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.webhook_signature_validation (
    webhook_id UUID REFERENCES integration.webhooks_subscriptions(sub_id),
    signature_header_name VARCHAR(100) DEFAULT 'X-Signature',
    secret_key_encrypted BYTEA NOT NULL,
    algorithm VARCHAR(20) DEFAULT 'SHA256'
);

COMMENT ON TABLE security.webhook_signature_validation IS 'Cryptographic credentials for validating integrity of external callbacks.';

------------------------------------------------------------------------------------------------
-- Serial No: 398
-- Table: T398 - ssl_certificate_transparency
-- Schema: security
-- Description: Detailed Certificate Transparency (CT) logs for SSL certificates.
-- Business Case: Extended validation of SSL certs involves checking CT Logs. This table stores the raw SCT
--(Signed Certificate Timestamp) lists and the verification result. It ensures that our SSL
--certificates are trusted by public browsers and CAs, and haven't been mis-issued by a compromised CA.
-- KPIs: CT Log Verification Success Rate.
-- Feature Reference: T229
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security.ssl_certificate_transparency (
    ct_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cert_id UUID REFERENCES sec.certificate_inventory(cert_id),
    sct_list TEXT NOT NULL, -- Base64 encoded SCT list
    validation_status VARCHAR(20) NOT NULL, -- 'VALID', 'WARN', 'INVALID'

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE security.ssl_certificate_transparency IS 'Public audit trail verifying the legitimacy of TLS certificates.';

------------------------------------------------------------------------------------------------
-- Serial No: 399
-- Table: T399 - ip_reputation_score_history
-- Schema: fraud
-- Description: Historical trend of IP Reputation scores.
-- Business Case: IP reputation changes. A residential IP might become a Botnet node overnight. This table
--logs the history of the reputation score (from T021). It allows the system to identify "IP
--Reputation Decay" (Score dropping from 100 to 0) and block it immediately.
-- KPIs: Reputation Decay Detection Speed.
-- Feature Reference: T021
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.ip_reputation_score_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address INET NOT NULL,
    score INTEGER NOT NULL,
    provider VARCHAR(50) NOT NULL,

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ip_rep_hist_ip ON fraud.ip_reputation_score_history(ip_address);
COMMENT ON TABLE fraud.ip_reputation_score_history IS 'Time-series data tracking trustworthiness evolution of network endpoints.';

------------------------------------------------------------------------------------------------
-- Serial No: 400
-- Table: T400 - user_agent_parser_results
-- Schema: fraud
-- Description: Structured data parsed from User-Agent strings.
-- Business Case: User-Agents are messy strings. This table stores the parsed result (Browser, OS, Device
--Type, Version). It allows for faster querying (e.g., "Block all Firefox < 50") without running regex
--on the raw string every time. It optimizes the T410 clickstream analysis.
-- KPIs: Parser Accuracy.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_agent_parser_results (
    hash_id CHAR(32) PRIMARY KEY, -- MD5 of raw user agent
    browser_family VARCHAR(50),
    os_family VARCHAR(50),
    device_type VARCHAR(50),
    is_bot BOOLEAN DEFAULT FALSE,

    -- Metadata
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.user_agent_parser_results IS 'Normalized browser telemetry facilitating high-performance segmentation and bot detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 401
-- Table: T401 - fraud_incident_timeline
-- Schema: incident
-- Description: Chronological timeline of events for a specific fraud incident.
-- Business Case: Investigating a complex incident requires a timeline. This table links all related events
--(Alerts, Transaction Scores, Analyst Notes) in chronological order. It builds the "Story of
--what happened" for the Incident Commander (T197).
-- KPIs: Timeline Construction Speed.
-- Feature Reference: T163
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.fraud_incident_timeline (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incident.incident_tickets(ticket_id),
    event_type VARCHAR(50) NOT NULL, -- 'ALERT', 'SCORE_CHANGE', 'NOTE'
    description TEXT,
    actor_id UUID,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_incident_timeline_inc ON incident.fraud_incident_timeline(incident_id);
COMMENT ON TABLE incident.fraud_incident_timeline IS 'Chronological log reconstructing the sequence of events during a security incident.';

------------------------------------------------------------------------------------------------
-- Serial No: 402
-- Table: T402 - knowledge_graph_node_embeddings
-- Schema: ml
-- Description: Vector embeddings for nodes in the knowledge graph.
-- Business Case: To search the Knowledge Graph (T162) semantically ("Show me similar cases"), we need
--vectors. This table stores the vector embedding (from BERT or similar models) for each node. It allows
--for "Similarity Search" rather than exact match lookups.
-- KPIs: Embedding Recall Rate.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.knowledge_graph_node_embeddings (
    node_uri TEXT PRIMARY KEY,
    vector_embedding NUMERIC[], -- Array of floats
    model_version VARCHAR(50),

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.knowledge_graph_node_embeddings IS 'Vector representation of ontology concepts enabling semantic search and inference.';

------------------------------------------------------------------------------------------------
-- Serial No: 403
-- Table: T403 - transaction_anomaly_score
-- Schema: fraud
-- Description: Single composite score representing overall "weirdness".
-- Business Case: There are many anomaly models. This table aggregates them into one "Anomaly Score".
--It combines Input Anomaly, Time Anomaly, and Graph Anomaly. A single number tells Ops/UI "How
--weird is this?" without overwhelming them with 10 different charts.
-- KPIs: Anomaly Correlation with Fraud.
-- Feature Reference: F067
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.transaction_anomaly_score (
    tx_hash VARCHAR(64) PRIMARY KEY,
    input_anomaly_score NUMERIC(5,2),
    temporal_anomaly_score NUMERIC(5,2),
    graph_anomaly_score NUMERIC(5,2),
    composite_anomaly_score NUMERIC(5,2),

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.transaction_anomaly_score IS 'Aggregated deviation metric providing a unified view of statistical irregularities.';

------------------------------------------------------------------------------------------------
-- Serial No: 404
-- Table: T404 - merchant_compliance_dashboard
-- Schema: compliance
-- Description: Pre-calculated metrics for the regulator-facing merchant dashboard.
-- Business Case: Regulators want to see that merchants are compliant. This table aggregates compliance
--metrics (KYC status, SAR filing volume) for each merchant. It is the backend data source for
--the "Merchant Health Score" (T062).
-- KPIs: Dashboard Load Time (< 200ms).
-- Feature Reference: T062
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.merchant_compliance_dashboard (
    merchant_id UUID PRIMARY KEY,
    kyc_status VARCHAR(20), -- 'VERIFIED', 'PENDING'
    sar filings_count INTEGER,
    last_audit_score CHAR(1),
    compliance_flag VARCHAR(20),

    -- Metadata
    refreshed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.merchant_compliance_dashboard IS 'Optimized data mart supporting regulatory oversight interfaces for partner ecosystems.';

------------------------------------------------------------------------------------------------
-- Serial No: 405
-- Table: T405 - risk_model_versioning
-- Schema: fraud
-- Description: Versioning of the underlying Risk Calculation logic (Rules + ML).
-- Business Case: The "Risk Model" isn't just the ML weights; it's the combination of Rules, ML, and
--Graphs. This table versions the *entire* logic configuration. It links to the specific versions of
--Rules (T004) and Models (T002) that were active at that time. It allows us to re-calculate a
--score from 6 months ago if needed.
-- KPIs: Logic Re-calculation Capability.
-- Feature Reference: F014
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.risk_model_versioning (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_set_id UUID REFERENCES fraud.rule_audit(rule_id),
    model_id UUID REFERENCES ml.lstm_model_versions(model_id),
    graph_config_id UUID,

    -- Metadata
    active_from TIMESTAMP WITH TIME ZONE NOT NULL,
    active_to TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE fraud.risk_model_versioning IS 'Assembly definition for all active risk components enabling point-in-time state reconstruction.';

------------------------------------------------------------------------------------------------
-- Serial No: 406
-- Table: T406 - synthetic_data_quality_metrics
-- Schema: ml
-- Description: Metrics assessing the quality of synthetically generated training data.
-- Business Case: Synthetic data (T130) must be high quality to be useful. This table measures metrics like
--"Fidelity" (how close is it to real data?) and "Diversity" (does it cover all cases?). It prevents
--the training of the model on garbage data.
-- KPIs: Fidelity Score Target.
-- Feature Reference: T130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml.synthetic_data_quality_metrics (
    dataset_id UUID REFERENCES ml.synthetic_data_catalog(dataset_id),
    fidelity_score NUMERIC(3,2),
    diversity_score NUMERIC(3,2),
    coverage_of_classes NUMERIC(3,2),

    -- Metadata
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ml.synthetic_data_quality_metrics IS 'Quality assurance statistics for algorithmically generated training datasets.';

------------------------------------------------------------------------------------------------
-- Serial No: 407
-- Table: T407 - alert_suppression_rules
-- Schema: ops
-- Description: Rules to suppress noisy or non-actionable alerts.
-- Business Case: Too many alerts cause "Alert Fatigue". Ops stop looking. This table defines suppression rules
--(e.g., "Don't alert on 'Low Velocity' for VIP users during Holidays"). It filters noise before
--it hits the Escalation Path (T259).
-- KPIs: Alert Noise Ratio.
-- Feature Reference: T259
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.alert_suppression_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    condition_json JSONB NOT NULL, -- When to suppress
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE ops.alert_suppression_rules IS 'Configuration tuning alert volume to maintain analyst focus on high-value threats.';

------------------------------------------------------------------------------------------------
-- Serial No: 408
-- Table: T408 - incident_root_cause
-- Schema: incident
-- Description: Analysis of the root cause for major incidents.
-- Business Case: Post-Incident Review is mandatory. This table stores the Root Cause Analysis (RCA).
--"Root Cause: Database Lock Contention", "Correction: Add Index". It feeds back into the Process
--Action Team (T165) to ensure the fix is implemented.
-- KPIs: RCA Completeness.
-- Feature Reference: T197
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.incident_root_cause (
    rca_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incident.incident_tickets(ticket_id),
    root_cause TEXT NOT NULL,
    category_5_whys VARCHAR(100), -- 'PEOPLE', 'PROCESS', 'TECHNOLOGY'
    corrective_action TEXT NOT NULL,
    owner_id UUID NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE incident.incident_root_cause IS 'Deep dive analysis documentation for preventing recurrence of operational failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 409
-- Table: T409 - post_mortem_reports
-- Schema: incident
-- Description: Full reports generated after an incident is resolved.
-- Business Case: Knowledge transfer. This table stores the full Post-Mortem Report (Markdown or PDF reference).
--It links to the Incident (T163) and the RCA (T408). It serves as a learning resource for future
--incidents.
-- KPIs: Post-Mortem Report Generation Rate.
-- Feature Reference: T197
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident.post_mortem_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incident.incident_tickets(ticket_id),
    report_storage_path TEXT,
    attendees UUID[],
    follow_up_actions JSONB,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE incident.post_mortem_reports IS 'Formal documentation of lessons learned from security or operational failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 410
-- Table: T410 - change_management_board
-- Schema: ops
-- Description: Ticketing system for approving and documenting system changes.
-- Business Case: No unplanned changes. This table acts as a Change Management Board (CMB). Change requests
--(CR) are logged here: "Change risk threshold from 80 to 85". It requires approval. It ensures
--all changes are reviewed for risk before deployment.
-- KPIs: Change Approval Time.
-- Feature Reference: T328
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.change_management_board (
    change_request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'REQUESTED', -- REQUESTED, APPROVED, REJECTED, IMPLEMENTED
    risk_score VARCHAR(10), -- LOW, MEDIUM, HIGH, CRITICAL
    approver_id UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_cmb_timestamp
    BEFORE UPDATE ON ops.change_management_board
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE ops.change_management_board IS 'Governance workflow controlling the lifecycle of system modifications.';

------------------------------------------------------------------------------------------------
-- Serial No: 411
-- Table: T411 - feature_flag_experiment_results
-- Schema: ops
-- Description: Results of A/B tests or experiments on Feature Flags.
-- Business Case: We test features before full rollout. This table stores the results of the experiment.
--"Variant B (New Fraud Model) increased Recall by 5%". It provides the data to decide the winner
--(T421).
-- KPIs: Experiment Statistical Significance.
-- Feature Reference: T242
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.feature_flag_experiment_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_name VARCHAR(100) NOT NULL,
    variant_name VARCHAR(50) NOT NULL, -- e.g., 'control', 'test_A'
    metrics JSONB NOT NULL,
    is_winner BOOLEAN,

    -- Metadata
    concluded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.feature_flag_experiment_results IS 'Statistical analysis output validating the impact of controlled variable experiments.';

------------------------------------------------------------------------------------------------
-- Serial No: 412
-- Table: T412 - user_journey_mapping
-- Schema: fraud
-- Description: Visualizes the user's steps leading up to a transaction.
-- Business Case: "Show me the journey". This table aggregates the steps a user took (Landing Page -> Add to
--Cart -> Checkout -> Fraud Check). It visualizes this funnel. It helps identify drop-off points
--or suspicious detours (e.g., going back and changing shipping address 5 times).
-- KPIs: Funnel Step Drop-off %.
-- Feature Reference: F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_journey_mapping (
    journey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    step_name VARCHAR(100) NOT NULL,
    step_sequence INTEGER NOT NULL,
    time_spent_ms INTEGER,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_journey_user ON fraud.user_journey_mapping(user_hash);
COMMENT ON TABLE fraud.user_journey_mapping IS 'Sequential reconstruction of user actions supporting friction optimization.';

------------------------------------------------------------------------------------------------
-- Serial No: 413
-- Table: T413 - device_software_inventory
-- Schema: ops
-- Description: Aggregates the versions of software (OS, Browser) in the ecosystem.
-- Business Case: EOL (End of Life) software is a risk. This table aggregates the usage count of specific
--software versions (e.g., "Android 4.4"). If an old version is suddenly popular, it might be a
--Botnet. It also identifies when to force upgrades.
-- KPIs: Version Migration Success Rate.
-- Feature Reference: T292
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.device_software_inventory (
    software_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    software_type VARCHAR(20), -- 'OS', 'BROWSER', 'APP'
    version_name VARCHAR(50),
    user_count BIGINT,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.device_software_inventory IS 'Asset management tracking deployment stats of client-side software.';

------------------------------------------------------------------------------------------------
-- Serial No: 414
-- Table: T414 - latency_percentiles
-- Schema: ops
-- Description: Storage for calculated percentiles (P50, P90, P99, P99.9) of latency.
-- Business Case: "Average" is misleading for latency (outliers skew it). This table stores the
--calculated percentiles (from T196). It gives a better view of the "Long Tail" of latency which
--affects user experience the most.
-- KPIs: P99 Latency Trend.
-- Feature Reference: T196
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.latency_percentiles (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    p50 NUMERIC(10,2),
    p90 NUMERIC(10,2),
    p99 NUMERIC(10,2),
    p99_9 NUMERIC(10,2),

    -- Metadata
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_latency_percentile_metric ON ops.latency_percentiles(metric_name);
COMMENT ON TABLE ops.latency_percentiles IS 'Statistical distribution metrics providing accurate performance baselines.';

------------------------------------------------------------------------------------------------
-- Serial No: 415
-- Table: T415 - error_budget_tracking
-- Schema: ops
-- Description: Site Reliability Engineering (SRE) Error Budget tracking per service.
-- Business Case: "We have 10 minutes of downtime per month". This table tracks the Error Budget (calculated
--from SLA) and how much has been "spent" (incidents). When the budget hits 0, deployments stop.
-- It enforces stability as a first-class feature.
-- KPIs: Error Budget Remaining.
-- Feature Reference: T285
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.error_budget_tracking (
    budget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    monthly_budget_mins INTEGER NOT NULL,
    error_mins_spent INTEGER DEFAULT 0,
    budget_status VARCHAR(20) DEFAULT 'HEALTHY', -- HEALTHY, CONSUMED, DEPLETED

    -- Metadata
    period_start DATE NOT NULL,
    period_end DATE NOT NULL
);

COMMENT ON TABLE ops.error_budget_tracking IS 'Reliability enforcement mechanism linking availability to change approval authority.';

------------------------------------------------------------------------------------------------
-- Serial No: 416
-- Table: T416 - on_call_rotation
-- Schema: ops
-- Description: Schedule of engineers on-call for specific services (PagerDuty).
-- Business Case: Who wakes up at 3 AM? This table maps Engineers to Services for specific weeks. It integrates
--with Alerting (T259) to ensure the right person is called when the Fraud Engine goes down.
-- KPIs: Escalation Contact Speed.
-- Feature Reference: T259
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.on_call_rotation (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    engineer_id UUID NOT NULL,
    week_start DATE NOT NULL,
    week_end DATE NOT NULL
);

COMMENT ON TABLE ops.on_call_rotation IS 'Contact matrix defining primary response personnel for service availability issues.';

------------------------------------------------------------------------------------------------
-- Serial No: 417
-- Table: T417 - disaster_recovery_runbooks
-- Schema: ops
-- Description: Procedures/Playbooks for Disaster Recovery scenarios.
-- Business Case: Don't panic. This table stores the Runbooks (SOPs) for disasters. "If DB is down:
--Step 1...". It provides guidance to the Incident Commander (T197) during a crisis.
-- KPIs: Runbook Execution Success Rate.
-- Feature Reference: T207
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.disaster_recovery_runbooks (
    runbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(100) NOT NULL, -- 'TOTAL_DATA_CENTER_FAILURE', 'RANSOMWARE_ATTACK'
    procedure_steps JSONB NOT NULL,
    last_reviewed DATE,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.disaster_recovery_runbooks IS 'Standardized operational procedures ensuring consistent incident response.';

------------------------------------------------------------------------------------------------
-- Serial No: 418
-- Table: T418 - capacity_planning_forecast
-- Schema: ops
-- Description: Predicted capacity needs based on growth trends.
-- Business Case: Buying servers takes time. This table stores the *forecast* for future capacity needs (CPU,
--Storage) based on T232 data. It allows Finance to budget and Ops to procure hardware 3 months
--in advance.
-- KPIs: Forecast Accuracy (Predicted vs Actual).
-- Feature Reference: T232
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.capacity_planning_forecast (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_date DATE NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- 'CPU_CORES', 'STORAGE_TB'
    predicted_value NUMERIC(15,2),
    confidence_interval VARCHAR(20), -- 'TIGHT', 'WIDE'

    -- Metadata
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.capacity_planning_forecast IS 'Predictive analytics driving infrastructure provisioning and budget planning.';

------------------------------------------------------------------------------------------------
-- Serial No: 419
-- Table: T419 - vendor_contract_management
-- Schema: ops
-- Description: Management of legal contracts with external vendors.
-- Business Case: We have vendors (AWS, Twilio). This table tracks their contracts: Expiry, Terms,
--Renewal dates. It ensures that no vendor service is lost due to a missed contract renewal,
--which would be a catastrophic failure.
-- KPIs: Contract Renewal Compliance.
-- Feature Reference: T329
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.vendor_contract_management (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_name VARCHAR(100) NOT NULL,
    contract_document_ref TEXT,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    auto_renew BOOLEAN DEFAULT FALSE,

    -- Metadata
    alert_days_before_expiry INTEGER DEFAULT 30
);

COMMENT ON TABLE ops.vendor_contract_management IS 'Lifecycle tracker for third-party legal agreements ensuring continuity of services.';

------------------------------------------------------------------------------------------------
-- Serial No: 420
-- Table: T420 - third_party_data_sharing_agreements
-- Schema: legal
-- Description: Legal basis for sharing data with external partners.
-- Business Case: Sharing fraud intel is great, but must be legal. This table stores the Legal
--Agreements (DPAs) and Consent status for sharing data with specific partners (e.g., other
--banks). It ensures compliance with GDPR and data protection laws.
-- KPIs: Legal Agreement Coverage %.
-- Feature Reference: T128
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.third_party_data_sharing_agreements (
    agreement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_name VARCHAR(100) NOT NULL,
    data_categories TEXT[] NOT NULL, -- e.g., 'HASHED_EMAILS', 'RISK_SCORES'
    legal_basis VARCHAR(50), -- 'CONTRACT', 'LEGITIMATE_INTEREST', 'CONSENT'
    expiry_date DATE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE legal.third_party_data_sharing_agreements IS 'Legal framework governing exchange of intelligence with external entities.';

------------------------------------------------------------------------------------------------
-- Serial No: 421
-- Table: T421 - data_subject_access_requests
-- Schema: legal
-- Description: Workflow for GDPR Data Subject Access Requests (DSAR).
-- Business Case: Users have a right to know what data you have. This table manages the DSAR workflow.
--It tracks the request, gathers data from all modules, and packages it for the user. It ensures we
--meet the 30-day GDPR deadline.
-- KPIs: DSAR Completion SLA (<30 days).
-- Feature Reference: T126
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.data_subject_access_requests (
    dsar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'NEW', -- NEW, GATHERING, PACKAGING, SENT
    request_date DATE NOT NULL,
    due_date DATE NOT NULL,

    -- Metadata
    completed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE legal.data_subject_access_requests IS 'Workflow tracker ensuring compliance with consumer data privacy rights.';

------------------------------------------------------------------------------------------------
-- Serial No: 422
-- Table: T422 - consent_receipts
-- Schema: privacy
-- Description: Proof of consent recorded from user interactions.
-- Business Case: "I never consented!" This table stores the immutable receipt of consent. It links the user's
--specific action (e.g., clicking "I Agree") with the version of the consent form and the
--timestamp. It is the legal proof of compliance.
-- KPIs: Receipt Retrieval Rate.
-- Feature Reference: T160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy.consent_receipts (
    receipt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    consent_type VARCHAR(50) NOT NULL, -- 'MARKETING', 'ANALYTICS'
    consent_form_id UUID,
    ip_address INET,

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_consent_receipts_user ON privacy.consent_receipts(user_hash);
COMMENT ON TABLE privacy.consent_receipts IS 'Immutable audit trail of user permission acquisition for legal defensibility.';

------------------------------------------------------------------------------------------------
-- Serial No: 423
-- Table: T423 - privacy_impact_assessment
-- Schema: legal
-- Description: Records of Privacy Impact Assessments (PIA).
-- Business Case: Before changing a feature, we do a PIA. This table records the assessment of risk to privacy.
--"Storing Face Prints = High Risk". It requires mitigation strategies to be approved before the
--feature launches.
-- KPIs: PIA Approval Rate.
-- Feature Reference: T128
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.privacy_impact_assessment (
    pia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    risk_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH
    mitigation_plan TEXT,
    approved_by UUID,

    -- Metadata
    approved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE legal.privacy_impact_assessment IS 'Risk evaluation log ensuring new data processing respects privacy by design.';

------------------------------------------------------------------------------------------------
-- Serial No: 424
-- Table: T424 - security_clearance
-- Schema: sec
-- Description: Background check status for employees with access to sensitive data.
-- Business Case: Trust but Verify. This table tracks the security clearance level (Confidential, Secret,
--Top Secret) of employees. It determines if they can access PII or Audit Logs. Access is automatically
--revoked if clearance expires.
-- KPIs: Clearance Validity Check.
-- Feature Reference: F436
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_clearance (
    employee_id UUID PRIMARY KEY,
    clearance_level VARCHAR(20) NOT NULL, -- 'BASIC', 'PII_ACCESS', 'ADMIN'
    vetting_agency VARCHAR(50), -- 'DHS', 'MIB'
    investigation_date DATE,
    expiry_date DATE NOT NULL
);

COMMENT ON TABLE sec.security_clearance IS 'Authorization attribute matrix ensuring personnel are vetted for data sensitivity levels.';

------------------------------------------------------------------------------------------------
-- Serial No: 425
-- Table: T425 - physical_access_logs
-- Schema: sec
-- Description: Logs of physical access to data centers or secure rooms.
-- Business Case: Physical security. This table logs keycard swipes/badge scans at datacenter doors. It
--detects physical intrusions or "Tailgating" (following someone through a secure door). It is the
--last line of defense for the hardware.
-- KPIs: Access Log Completeness.
-- Feature Reference: F436
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.physical_access_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID,
    door_name VARCHAR(100) NOT NULL,
    access_granted BOOLEAN NOT NULL,
    denial_reason TEXT,

    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_physical_access_emp ON sec.physical_access_logs(employee_id);
COMMENT ON TABLE sec.physical_access_logs IS 'Chronological record of facility entry events supporting physical security protocols.';

------------------------------------------------------------------------------------------------
-- Serial No: 426
-- Table: T426 - employee_offboarding
-- Schema: hr
-- Description: Checklist for revoking access when an employee leaves.
-- Business Case: Insider threat is real. This table is the checklist for offboarding: "Revoke key",
--"Disable account", "Collect Badge". It ensures that when an employee leaves, their access to Fraud
--Logs and PII is immediately and irrevocably terminated.
-- KPIs: Offboarding Completion Time (< 4 hours).
-- Feature Reference: F436
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hr.employee_offboarding (
    offboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID NOT NULL,
    task_name VARCHAR(100) NOT NULL, -- 'REVOKE_CERTS', 'DISABLE_ACCOUNT'
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, DONE
    completed_by UUID,

    -- Metadata
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE hr.employee_offboarding IS 'Decommissioning workflow ensuring immediate removal of access rights upon employment termination.';

------------------------------------------------------------------------------------------------
-- Serial No: 427
-- Table: T427 - key_management_hierarchy
-- Schema: sec
-- Description: Hierarchical tree of cryptographic keys stored in the HSM.
-- Business Case: Keys have parents. This table describes the HSM key hierarchy (Root Key -> Signing Key ->
--Encryption Key). It visualizes the dependency of keys. If the Root Key is rotated, all children
--must be re-wrapped. This table maps that relationship.
-- KPIs: Key Rotation Completeness.
-- Feature Reference: T237
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_management_hierarchy (
    hierarchy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_key_id UUID,
    child_key_id UUID NOT NULL,
    key_type VARCHAR(50) NOT NULL,

    CONSTRAINT pk_key_hier UNIQUE (parent_key_id, child_key_id)
);

COMMENT ON TABLE sec.key_management_hierarchy IS 'Relational map of cryptographic key dependencies facilitating bulk rotations.';

------------------------------------------------------------------------------------------------
-- Serial No: 428
-- Table: T428 - cryptography_standards
-- Schema: sec
-- Description: Approved algorithms and key sizes for different data types.
-- Business Case: Security Standards. This table defines what is allowed. "AES-256 for PII at rest",
--"ECDSA P-521 for Signing". It prevents developers from using weak crypto (like SHA-1) in the
--codebase.
-- KPIs: Standard Compliance Rate.
-- Feature Reference: F008
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cryptography_standards (
    standard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_classification VARCHAR(50) NOT NULL, -- 'PII', 'FINANCIAL', 'PUBLIC'
    approved_algo VARCHAR(50) NOT NULL,
    min_key_size_bits INTEGER NOT NULL,
    approved_date DATE NOT NULL,
    is_mandatory BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE sec.cryptography_standards IS 'Policy definition repository enforcing usage of vetted cryptographic primitives.';

------------------------------------------------------------------------------------------------
-- Serial No: 429
-- Table: T429 - secure_development_lifecycle
-- Schema: sec
-- Description: Checklist and gates in the Secure SDLC (Software Development Lifecycle).
-- Business Case: Security must be built-in, not bolted-on. This table tracks gates in SDLC:
--"Threat Modeling Done?", "Static Scan Pass?". Code cannot be deployed to Prod unless all
--gates are marked "Pass".
-- KPIs: SDLC Gate Pass Rate.
-- Feature Reference: T439
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_development_lifecycle (
    gate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(100) NOT NULL,
    gate_name VARCHAR(100) NOT NULL, -- 'THREAT_MODEL', 'SAST_SCAN'
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, IN_PROGRESS, PASSED, FAILED
    artifact_ref VARCHAR(255),

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.secure_development_lifecycle IS 'Quality assurance gates integrating security checks into the software delivery pipeline.';

------------------------------------------------------------------------------------------------
-- Serial No: 430
-- Table: T430 - code_scanning_results
-- Schema: sec
-- Description: Results from Static (SAST) and Dynamic (DAST) application security scans.
-- Business Case: We scan code for bugs. This table stores the results from tools like SonarQ or
--Burp Suite. It lists vulnerabilities found (CVEs) and their severity. It links to the "Fix" ticket
--(T440).
-- KPIs: Vulnerability Remediation Time.
-- Feature Reference: T439
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.code_scanning_results (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool_name VARCHAR(50) NOT NULL, -- 'SONARQ', 'CHECKMARX'
    project_name VARCHAR(100) NOT NULL,
    critical_vulnerabilities INTEGER DEFAULT 0,
    high_vulnerabilities INTEGER DEFAULT 0,
    medium_vulnerabilities INTEGER DEFAULT 0,
    scan_report_ref TEXT,

    -- Metadata
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.code_scanning_results IS 'Vulnerability detection output enforcing code quality and security standards.';

------------------------------------------------------------------------------------------------
-- Serial No: 431
-- Table: T431 - dependency_vulnerabilities
-- Schema: sec
-- Description: Known CVEs (Common Vulnerabilities and Exposures) in software libraries.
-- Business Case: We use libraries (npm, pip). This table lists known CVEs in our specific library
--versions (e.g., "Lodash 4.17.15 has CVE-2021-23337"). It flags which libraries need
--immediate patching.
-- KPIs: Vulnerability Patch Compliance.
-- Feature Reference: T440
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dependency_vulnerabilities (
    cve_id VARCHAR(50) NOT NULL,
    library_name VARCHAR(100) NOT NULL,
    current_version VARCHAR(50) NOT NULL,
    patched_version VARCHAR(50),
    severity VARCHAR(20) NOT NULL, -- 'CRITICAL', 'HIGH', 'MODERATE'
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, PATCHED, IGNORED

    -- Metadata
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dep_vuln_lib ON sec.dependency_vulnerabilities(library_name);
COMMENT ON TABLE sec.dependency_vulnerabilities IS 'Threat intelligence feed identifying risk in third-party software components.';

------------------------------------------------------------------------------------------------
-- Serial No: 432
-- Table: T432 - supply_chain_risk
-- Schema: ops
-- Description: Risk assessment of our own vendors (Supply Chain).
-- Business Case: If a vendor (e.g., The Datacenter Provider) has a fire, we go down. This table tracks the
--risk of our supply chain. It includes financial health of vendors and disaster recovery scores.
--It enables proactive diversification (don't rely on one vendor).
-- KPIs: Vendor Risk Score.
-- Feature Reference: T442
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.supply_chain_risk (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_name VARCHAR(100) NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    single_point_of_failure BOOLEAN DEFAULT FALSE,

    -- Metadata
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.supply_chain_risk IS 'Operational risk assessment of external dependencies supporting resilience planning.';

------------------------------------------------------------------------------------------------
-- Serial No: 433
-- Table: T433 - business_continuity_plan
-- Schema: ops
-- Description: Business Continuity Plan (BCP) documents and their versions.
-- Business Case: If we have a disaster, do we have a plan? This table stores the BCP document versions
--and their scope (e.g., "BCP v4 covers Fraud Engine"). It ensures that the plan being followed
--is the latest approved version.
-- KPIs: BCP Exercise Frequency.
-- Feature Reference: T443
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.business_continuity_plan (
    bcp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bcp_name VARCHAR(100) NOT NULL,
    version INTEGER NOT NULL,
    storage_ref TEXT,
    last_tested_date DATE,

    -- Metadata
    approved_date DATE NOT NULL
);

COMMENT ON TABLE ops.business_continuity_plan IS 'Version control repository for organizational resilience playbooks.';

------------------------------------------------------------------------------------------------
-- Serial No: 434
-- Table: T434 - crisis_communication
-- Schema: ops
-- Description: Templates and logs of crisis communications.
-- Business Case: In a hack, communication is key. This table stores templates for communications (Email,
--Tweet, Status Page). It logs which template was sent and when. It ensures messaging is
--consistent and managed centrally.
-- KPIs: Communication Delivery Rate.
-- Feature Reference: T444
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.crisis_communication (
    comms_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id UUID NOT NULL,
    channel VARCHAR(20) NOT NULL, -- 'EMAIL', 'SLACK', 'STATUS_PAGE'
    status VARCHAR(20) NOT NULL, -- 'SENT', 'PENDING'

    -- Metadata
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.crisis_communication IS 'Coordination log for public and internal messaging during critical incidents.';

------------------------------------------------------------------------------------------------
-- Serial No: 435
-- Table: T435 - stakeholder_notification_matrix
-- Schema: ops
-- Description: Defines who gets notified for which incident types.
-- Business Case: Different incidents affect different people. A "Database Down" alerts DBAs. A "Fraud
--Model Drift" alerts Data Scientists. This table maps Severity + Type to specific groups (Slack
--Channels, PagerDuty Escalations).
-- KPIs: Notification Routing Accuracy.
-- Feature Reference: T259
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.stakeholder_notification_matrix (
    matrix_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_type VARCHAR(100) NOT NULL,
    stakeholder_group VARCHAR(100) NOT NULL, -- 'DBA_TEAM', 'LEGAL', 'PR'
    channel VARCHAR(20) NOT NULL, -- 'EMAIL', 'SLACK', 'PAGER'
    delay_minutes INTEGER DEFAULT 0
);

COMMENT ON TABLE ops.stakeholder_notification_matrix IS 'Routing configuration ensuring appropriate personnel engagement during incidents.';

------------------------------------------------------------------------------------------------
-- Serial No: 436
-- Table: T436 - regulatory_filing_calendar
-- Schema: compliance
-- Description: Calendar of deadlines for filing regulatory reports (SARs, SOX).
-- Business Case: Missing a filing deadline results in massive fines. This table lists all recurring deadlines
--(e.g., "SAR Report Due 15th of every month"). It triggers reminders and alerts to the Compliance
--Team to ensure no deadline is missed.
-- KPIs: Deadline Miss Rate (Target 0%).
-- Feature Reference: T127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.regulatory_filing_calendar (
    filing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_name VARCHAR(100) NOT NULL,
    due_day SMALLINT NOT NULL, -- e.g., 15
    due_month SMALLINT NOT NULL, -- 1-12 (1=Jan) or 0=All
    jurisdiction VARCHAR(100) NOT NULL, -- 'US_FINCEN', 'UK_FCA'
    assigned_officer UUID NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.regulatory_filing_calendar IS 'Proactive scheduling system ensuring timely submission of mandatory reports.';

------------------------------------------------------------------------------------------------
-- Serial No: 437
-- Table: T437 - audit_evidence_repository
-- Schema: audit
-- Description: Secure storage location for evidence gathered during audits.
-- Business Case: External auditors need evidence. This table stores the index of evidence files uploaded
--to a secure repository (S3). It tracks who uploaded it, when, and if the auditor has downloaded it.
--It simplifies the "Request for Information" (T331) process.
-- KPIs: Evidence Retrieval Success Rate.
-- Feature Reference: T157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.audit_evidence_repository (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id UUID NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    storage_path TEXT NOT NULL,
    uploaded_by UUID NOT NULL,
    accessed_by UUID,

    -- Metadata
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    accessed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE audit.audit_evidence_repository IS 'Managed document store facilitating information exchange with external auditors.';

------------------------------------------------------------------------------------------------
-- Serial No: 438
-- Table: T438 - internal_audit_schedule
-- Schema: audit
-- Description: Schedule for internal self-audits.
-- Business Case: We audit ourselves. This table defines the schedule for internal audits of different
--modules (e.g., "Quarterly Audit of Fraud Rules", "Annual Audit of Access Rights"). It ensures
--self-governance happens regularly and predictably.
-- KPIs: Internal Audit Completion Rate.
-- Feature Reference: T157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.internal_audit_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_name VARCHAR(100) NOT NULL,
    audit_frequency VARCHAR(50) NOT NULL, -- 'QUARTERLY', 'ANNUAL'
    next_audit_date DATE NOT NULL,
    lead_auditor UUID NOT NULL

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit.internal_audit_schedule IS 'Planned maintenance program for internal governance and risk assurance.';

------------------------------------------------------------------------------------------------
-- Serial No: 439
-- Table: T439 - external_audit_findings
-- Schema: audit
-- Description: Findings received from external auditors.
-- Business Case: External auditors write reports. This table tracks their findings. "Observation: User passwords
--not rotated frequently". It tracks the remediation status of these findings (Open -> Closed). It
--ensures that external audit requirements are met.
-- KPIs: Finding Remediation Time.
-- Feature Reference: T189
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.external_audit_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_name VARCHAR(100) NOT NULL,
    report_date DATE NOT NULL,
    finding_text TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'OBSERVATION', 'RECOMMENDATION', 'CRITICAL_DEFICIENCY'
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, REMEDIATION_PLANNED, CLOSED
    remediation_plan TEXT,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_audit_findings_timestamp
    BEFORE UPDATE ON audit.external_audit_findings
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE audit.external_audit_findings IS 'Management system for deficiencies identified by third-party quality assurance providers.';

------------------------------------------------------------------------------------------------
-- Serial No: 440
-- Table: T440 - continuous_improvement_register
-- Schema: ops
-- Description: Log of Kaizen/Continuous Improvement initiatives.
-- Business Case: Better, Faster, Cheaper. This table logs improvement ideas (Kaizen) from the team.
--"Optimized query X to save $500/mo". It tracks the implementation and the realized benefit.
--It creates a culture of continuous improvement (CMMI Level 5).
-- KPIs: Improvement Implementation Rate.
-- Feature Reference: T165
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.continuous_improvement_register (
    improvement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    kaizen_type VARCHAR(50) NOT NULL, -- 'OPTIMIZATION', 'QUALITY', 'UX'
    description TEXT NOT NULL,
    submitted_by UUID NOT NULL,
    implemented_by UUID,
    realized_benefit TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    implemented_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE ops.continuous_improvement_register IS 'Innovation backlog tracking operational excellence and efficiency gains.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 7 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER trg_ml_graph_link_prediction_timestamp
    BEFORE UPDATE ON ml.graph_link_prediction
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_fraud_user_session_heatmap_timestamp
    BEFORE UPDATE ON fraud.user_session_heatmap
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_ml_model_quantization_timestamp
    BEFORE UPDATE ON ml.model_quantization
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_api_gateway_plugin_configs_timestamp
    BEFORE UPDATE ON api.api_gateway_plugin_configs
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_change_management_board_timestamp
    BEFORE UPDATE ON ops.change_management_board
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_fraud_risk_model_versioning_timestamp
    BEFORE UPDATE ON fraud.risk_model_versioning
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ml.knowledge_graph_node_embeddings_timestamp
    BEFORE UPDATE ON ml.knowledge_graph_node_embeddings
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.latency_percentiles_timestamp
    BEFORE UPDATE ON ops.latency_percentiles
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.vendor_contract_management_timestamp
    BEFORE UPDATE ON ops.vendor_contract_management
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.supply_chain_risk_timestamp
    BEFORE UPDATE ON ops.supply_chain_risk
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER sec.code_scanning_results_timestamp
    BEFORE UPDATE ON sec.code_scanning_results
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.business_continuity_plan_timestamp
    BEFORE UPDATE ON ops.business_continuity_plan
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER ops.continuous_improvement_register_timestamp
    BEFORE UPDATE ON ops.continuous_improvement_register
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 7: Tables 351-450)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- =============================================================================================
-- Module M03: Fraud Intelligence & Dispute Resolution - Database Schema Script (Part 8)
-- =============================================================================================
-- Tables T451 - T550
-- =============================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: 451
-- Table: T451 - session_replay_trace
-- Schema: fraud
-- Description: Detailed trace of all user actions within a single session for replay analysis.
-- Business Case: "Session Replay" is a technique where an attacker tries to replicate a legitimate session
// to bypass fraud checks. This table stores the exact sequence of events (Mouse Move, Key Press, Scroll)
// associated with a session ID. By analyzing the entropy and order of these traces, the system can
// distinguish between a human (high entropy, irregular timing) and a bot script (perfect sequence,
// millisecond precision). It is crucial for detecting sophisticated automated attacks that mimic human
// speed.
-- KPIs: Replay Detection Accuracy, Session Entropy Score.
-- Feature Reference: F041, F401
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.session_replay_trace (
    trace_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('MOUSE_MOVE', 'KEY_PRESS', 'SCROLL', 'CLICK')),
    coordinates JSONB, -- {x, y}
    timestamp_ms BIGINT, -- High precision time relative to session start
    event_metadata JSONB, -- Key code, etc.

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_session_replay_session ON fraud.session_replay_trace(session_id);
COMMENT ON TABLE fraud.session_replay_trace IS 'Sequential event log for behavioral biometrics and replay attack detection.';

------------------------------------------------------------------------------------------------
-- Serial No: 452
-- Table: T452 - mouse_dynamics_profile
-- Schema: fraud
-- Description: High-fidelity metrics of mouse movement (jitter, angle, acceleration).
-- Business Case: Mouse movement dynamics (how the mouse curves and accelerates) are extremely hard to
// fake. Bots tend to move in straight lines with constant velocity. This table aggregates these metrics
// (Jitter, Deviation, Mean Absolute Deviation of angle). It builds a profile of the user's "Mouse
// Signature". Deviations from this signature (e.g., suddenly moving in a straight line) trigger a risk
// alert, even if the user is logged in.
-- KPIs: Mouse Signature Stability Score.
-- Feature Reference: F040, F174
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.mouse_dynamics_profile (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    jitter_score NUMERIC(5,2),
    mean_absolute_deviation_angle NUMERIC(5,2),
    acceleration_variance NUMERIC(5,2),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mouse_profile_user ON fraud.mouse_dynamics_profile(user_hash);
COMMENT ON TABLE fraud.mouse_dynamics_profile IS 'Statistical features of motor control behavior distinguishing bots from humans.';

------------------------------------------------------------------------------------------------
-- Serial No: 453
-- Table: T453 - forensic_video_metadata
-- Schema: dispute
-- Description: Metadata attached to video evidence files (format, duration, codec).
-- Business Case: Video evidence (e.g., dashcam footage) is common in high-value disputes. This table stores
// technical metadata (Codec, Resolution, Duration, Audio Tracks) separate from the file blob. It allows
// the system to validate that a video is playable and meets format requirements (e.g., "Must be MP4
// with audio") before accepting it as evidence, ensuring that arbitrators can view it without technical issues.
-- KPIs: Evidence Compatibility Rate.
-- Feature Reference: T010
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.forensic_video_metadata (
    metadata_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES dispute.case_evidence(evidence_id),
    file_format VARCHAR(10), -- MP4, MOV, AVI
    codec VARCHAR(20), -- H264, HEVC
    width_pixels INTEGER,
    height_pixels INTEGER,
    duration_sec NUMERIC(10,2),
    has_audio BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.forensic_video_metadata IS 'Technical descriptor index for video evidence ensuring playback compatibility.';

------------------------------------------------------------------------------------------------
-- Serial No: 454
-- Table: T454 - document_ocr_results
-- Schema: integration
-- Description: Results of Optical Character Recognition (OCR) on uploaded documents (receipts/invoices).
-- Business Case: Users upload photos of receipts. This table stores the results of OCR processing:
// "Date: 2023-10-01", "Merchant: Amazon", "Amount: $50.00". It maps this extracted data to
// structured fields in the Dispute case. If the OCR data contradicts the user's claim, it's strong evidence
// of fraud. It automates the verification of paper evidence.
-- KPIs: OCR Confidence Score.
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.document_ocr_results (
    ocr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES dispute.case_evidence(evidence_id),
    extracted_text TEXT,
    extracted_merchant_name VARCHAR(255),
    extracted_date DATE,
    extracted_amount NUMERIC(15,2),
    confidence_score NUMERIC(3,2) CHECK (confidence_score BETWEEN 0 AND 1),

    -- Metadata
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE integration.document_ocr_results IS 'Structured data output from computer vision analysis of document evidence.';

------------------------------------------------------------------------------------------------
-- Serial No: 455
-- Table: T455 - voice_print_liveness
-- Schema: fraud
-- Description: Detection of replay or synthesized audio in voice biometrics.
-- Business Case: Voice biometrics (T124) are vulnerable to replay attacks (playing a recording of a victim's voice).
// This table stores the analysis of "Liveness" detection. It checks for signs of playback (e.g.,
// background noise consistency, breathing sounds, spectral anomalies). If the system detects a "Dead Air"
// silence typical of a recording, it rejects the authentication attempt.
-- KPIs: Liveness Detection Rate.
-- Feature Reference: F124, F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.voice_print_liveness (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    voice_auth_id UUID NOT NULL REFERENCES fraud.voice_auth_attempts(attempt_id),
    liveness_score NUMERIC(3,2) CHECK (liveness_score BETWEEN 0 AND 1),
    is_live BOOLEAN NOT NULL,
    anomalies_detected TEXT[],

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.voice_print_liveness IS 'Anti-spoofing metrics validating the presence of a real human voice source.';

------------------------------------------------------------------------------------------------
-- Serial No: 456
-- Table: T456 - network_path_analysis
-- Schema: ops
-- Description: Trace route (traceroute) and hop count for network connections.
-- Business Case: Network quality matters for fraud detection. This table stores the results of a traceroute
// or traceroute6 command executed for a user's IP. It records the number of hops, latency per hop, and
// ASN info. An unusually high hop count or routes through specific suspicious ISPs (known for botnets)
// adds a risk factor to the transaction score.
-- KPIs: Network Hop Count Anomaly Rate.
-- Feature Reference: F29, T308
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.network_path_analysis (
    path_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address INET NOT NULL,
    hop_count INTEGER,
    total_latency_ms INTEGER,
    path_summary TEXT, -- e.g., "10.0.0.1 -> 192.168.1.1"
    asns_list TEXT[],

    -- Metadata
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_network_path_ip ON ops.network_path_analysis(ip_address);
COMMENT ON TABLE ops.network_path_analysis IS 'Connectivity telemetry assessing network infrastructure reliability and routing characteristics.';

------------------------------------------------------------------------------------------------
-- Serial No: 457
-- Table: T457 - device_sensor_calibration
-- Schema: fraud
-- Description: Calibration data for device sensors (accelerometer, gyroscope).
-- Business Case: Mobile sensors vary. What "10m/s^2" is on one phone might be "5m/s^2" on another.
// This table stores the calibration baseline for device sensors. It ensures that the behavioral biometric
// algorithms (T174) normalize data correctly per device model, preventing false positives due to different
// hardware sensitivities.
-- KPIs: Calibration Completeness %.
-- Feature Reference: F174
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.device_sensor_calibration (
    calibration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_hash VARCHAR(64) NOT NULL,
    sensor_type VARCHAR(20) NOT NULL CHECK (sensor_type IN ('ACCELEROMETER', 'GYROSCOPE', 'MAGNETOMETER')),
    baseline_noise_level NUMERIC(10,4),
    sensitivity_factor NUMERIC(10,4),
    last_calibrated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.device_sensor_calibration IS 'Reference baselines for hardware telemetry ensuring consistent biometric comparison.';

------------------------------------------------------------------------------------------------
-- Serial No: 458
-- Table: T458 - social_graph_influence
-- Schema: fraud
-- Description: Calculation of how much influence one node has over another.
-- Business Case: In fraud rings, some nodes are "Mules" and some are "Controllers". This table calculates the
// "PageRank" style influence score between nodes. If a small node receives huge volume from a high-risk
// node, it becomes a suspect. It helps identify the leaders of fraud rings versus the foot soldiers.
-- KPIs: Influence Score Accuracy.
-- Feature Reference: T023, T125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.social_graph_influence (
    influence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_node_hash VARCHAR(64) NOT NULL,
    target_node_hash VARCHAR(64) NOT NULL,
    influence_score NUMERIC(5,2) CHECK (influence_score BETWEEN 0 AND 1),

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_social_influence_source ON fraud.social_graph_influence(source_node_hash);
COMMENT ON TABLE fraud.social_graph_influence IS 'Graph analytics metric identifying key actors within transactional networks.';

------------------------------------------------------------------------------------------------
-- Serial No: 459
-- Table: T459 - cluster_migration_history
-- Schema: fraud
-- Description: History of users moving between risk clusters (K-Means) over time.
-- Business Case: User risk changes (e.g., a user becomes compromised). This table tracks the migration of users
// between clusters generated by K-Means algorithms (T091). If a user moves from "Low Risk" to "High Risk"
// cluster, it triggers a security review. It provides a timeline of "Risk Evolution" for the user base.
-- KPIs: Cluster Migration Volatility.
-- Feature Reference: T091, F009
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.cluster_migration_history (
    migration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64) NOT NULL,
    old_cluster_label VARCHAR(50),
    new_cluster_label VARCHAR(50) NOT NULL,
    migration_reason VARCHAR(255), -- 'SIGIFICANT_BEHAVIOR_CHANGE', 'DATA_DRIFT'

    -- Metadata
    migrated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.cluster_migration_history IS 'Chronological audit of changes in user group membership within risk models.';

------------------------------------------------------------------------------------------------
-- Serial No: 460
-- Table: T460 - rule_conflict_matrix
-- Schema: fraud
-- Description: Definition of priority when multiple fraud rules trigger.
-- Business Case: Systems have thousands of rules (T004). Sometimes rules conflict (Rule A says Block, Rule B
// says Allow). This table defines the Conflict Matrix. "If both 'Max_Amount' and 'Geo_Velocity' trigger,
// use Max_Amount score". It ensures deterministic behavior when multiple heuristics agree or disagree.
-- KPIs: Rule Determinism.
-- Feature Reference: F004, F014
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.rule_conflict_matrix (
    rule_group_id VARCHAR(100) NOT NULL, -- A set of conflicting rules
    priority_rule_id VARCHAR(100) NOT NULL, -- The rule that wins
    logic_description TEXT,

    CONSTRAINT pk_rule_conflict UNIQUE (rule_group_id, priority_rule_id)
);

COMMENT ON TABLE fraud.rule_conflict_matrix IS 'Prioritization logic resolving determinism conflicts in multi-rule scoring systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 461
-- Table: T461 - container_node_affinity
-- Schema: ops
-- Description: Rules defining which nodes specific pods should run on.
-- Business Case: Latency matters. Fraud scoring pods should be close to the Database. This table defines
// "Node Affinity" and "Anti-Affinity" rules. "Pod X must run on Node Y (PCI-Compliance)". It ensures
// that critical workloads run on optimized hardware.
-- KPIs: Pod Placement Compliance.
-- Feature Reference: T355
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.container_node_affinity (
    affinity_rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pod_label VARCHAR(100) NOT NULL, -- Usually app:fraud-engine
    node_label VARCHAR(100) NOT NULL, -- kubernetes hostname
    weight INTEGER DEFAULT 100,

    CONSTRAINT pk_node_affinity UNIQUE (pod_label, node_label)
);

COMMENT ON TABLE ops.container_node_affinity IS 'Scheduling constraints optimizing workload placement for performance and compliance.';

------------------------------------------------------------------------------------------------
-- Serial No: 462
-- Table: T462 - pod_resource_snapshots
-- Schema: ops
-- Description: Current real-time resource usage (CPU/RAM) for all pods.
-- Business Case: Need to know if a pod is struggling. This table is the target for metrics scraped from
// cAdvisor. It stores instantaneous CPU/Mem usage. It feeds the Cluster Autoscaler (T463) to decide
// if a pod needs more resources.
-- KPIs: Resource Saturation %.
-- Feature Reference: T355
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.pod_resource_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pod_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    cpu_usage_millicores INTEGER,
    memory_usage_mb INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pod_snapshot_name ON ops.pod_resource_snapshots(pod_name, namespace);
COMMENT ON TABLE ops.pod_resource_snapshots IS 'High-frequency telemetry driving auto-scaling decisions.';

------------------------------------------------------------------------------------------------
-- Serial No: 463
-- Table: T463 - horizontal_pod_autoscaler
-- Schema: ops
-- Description: Decisions made by the Horizontal Pod Autoscaler (HPA).
-- Business Case: Autoscaling shouldn't be a black box. This table logs the decisions made by HPA:
// "Scaled from 2 to 5 replicas because Target=80%". It provides auditability for why the cluster size
// changed and allows Ops to tune the target metrics.
-- KPIs: Autoscaling Effectiveness.
-- Feature Reference: T355
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.horizontal_pod_autoscaler (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_name VARCHAR(100) NOT NULL,
    old_replica_count INTEGER,
    new_replica_count INTEGER,
    metric_trigger VARCHAR(50), -- e.g., 'cpu_utilization_percent', 'memory_utilization_percent'
    metric_value NUMERIC(5,2),

    -- Metadata
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.horizontal_pod_autoscaler IS 'Audit log of auto-scaling events ensuring capacity matches demand.';

------------------------------------------------------------------------------------------------
-- Serial No: 464
-- Table: T464 - cluster_scaling_events
-- Schema: ops
-- Description: History of Cluster (K8s) scaling events.
-- Business Case: The cluster itself scales (Node addition). This table logs events like "New Node Added",
// "Node Removed". It tracks the lifecycle of the underlying infrastructure capacity, separate from pod scaling.
// It helps predict when we will run out of space.
-- KPIs: Cluster Capacity Utilization.
-- Feature Reference: T232
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.cluster_scaling_events (
    scaling_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scaling_action VARCHAR(50) NOT NULL CHECK (scaling_action IN ('SCALE_UP', 'SCALE_DOWN', 'ADD_NODE', 'REMOVE_NODE')),
    cluster_size_before INTEGER,
    cluster_size_after INTEGER,

    -- Metadata
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.cluster_scaling_events IS 'State changes in infrastructure capacity supporting long-term resource planning.';

------------------------------------------------------------------------------------------------
-- Serial No: 465
-- Table: T465 - persistent_volume_claim
-- Schema: storage
-- Description: Tracking of Persistent Volume Claims (PVCs) for data persistence.
-- Business Case: Pods need storage. This table tracks the PVCs (Storage Class, Capacity). It maps which
// application uses which storage and checks for capacity limits. It ensures that storage classes (SSD vs HDD)
// are used correctly for performance-sensitive data like ML training sets.
-- KPIs: Storage Provisioning Time.
-- Feature Reference: T182
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage.persistent_volume_claim (
    claim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pvc_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    storage_class VARCHAR(50) NOT NULL,
    capacity_gb NUMERIC(10,2),
    bound_pvc_name VARCHAR(255), -- If bound to another PVC (common)

    CONSTRAINT pk_pvc UNIQUE (pvc_name, namespace)
);

COMMENT ON TABLE storage.persistent_volume_claim IS 'Registry of storage allocation ensuring IOPS requirements are met.';

------------------------------------------------------------------------------------------------
-- Serial No: 466
-- Table: T466 - ingress_controller_metrics
-- Schema: ops
-- Description: Performance metrics for the Ingress Controller (Load Balancer).
-- Business Case: Ingress is the entry point. If it's slow, everything is slow. This table stores metrics
// (Latency, Error Rate, Throughput) for the Ingress Controller. It helps Ops identify if the bottleneck
// is at the network edge before checking application code.
-- KPIs: Ingress Latency P99.
-- Feature Reference: T255
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.ingress_controller_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ingress_name VARCHAR(100) NOT NULL,
    host VARCHAR(100) NOT NULL,
    requests_per_second INTEGER,
    avg_latency_ms NUMERIC(10,2),
    status_code_5xx INTEGER,

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.ingress_controller_metrics IS 'Edge performance telemetry identifying network-level latency or throttling issues.';

------------------------------------------------------------------------------------------------
-- Serial No: 467
-- Table: T467 - service_mesh_retry_budgets
-- Schema: sec
-- Description: Retry policies (budgets) for calls within the Service Mesh.
-- Business Case: Networks fail. The Mesh should retry, but not forever. This table configures the "Retry Budget":
// "Try 3 times within 1 second". It prevents "Thundering Herd" scenarios where retries add load to an
// already failing system, while still allowing recovery from transient glitches.
-- KPIs: Retry Success Rate.
-- Feature Reference: T219
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_retry_budgets (
    service_name VARCHAR(100) NOT NULL,
    max_attempts INTEGER NOT NULL,
    timeout_ms INTEGER NOT NULL,
    backoff_ms INTEGER NOT NULL, -- Exponential backoff
    per_minute_limit INTEGER DEFAULT 60,

    CONSTRAINT pk_retry_budget UNIQUE (service_name)
);

COMMENT ON TABLE sec.service_mesh_retry_budgets IS 'Resilience configuration preventing cascading failures during service communication.';

------------------------------------------------------------------------------------------------
-- Serial No: 468
-- Table: T468 - dns_resolution_latency
-- Schema: ops
-- Description: Metrics tracking how long DNS resolution takes.
-- Business Case: Fast DNS is critical. This table tracks latency of DNS lookups. If DNS slows down, API
// calls pile up. It is used to detect DNS poisoning or misconfiguration of resolvers.
-- KPIs: DNS Lookup P95.
-- Feature Reference: T094
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.dns_resolution_latency (
    dns_lookup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    resolver_ip INET,
    resolution_time_ms INTEGER,

    -- Metadata
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.dns_resolution_latency IS 'Name resolution performance metrics ensuring low-latency service discovery.';

------------------------------------------------------------------------------------------------
-- Serial No: 469
-- Table: T469 - tls_handshake_duration
-- Schema: sec
-- Description: Time taken to complete TLS handshake.
-- Business Case: TLS handshake requires crypto ops (expensive). This table tracks the duration.
// Excessively long handshakes can indicate resource starvation attacks or poor configuration (slow ciphers).
// Monitoring this helps optimize security settings for speed without compromising safety.
-- KPIs: TLS Setup Time P99.
-- Feature Reference: T172
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.tls_handshake_duration (
    handshake_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,
    cipher_suite VARCHAR(100),
    duration_ms INTEGER,

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.tls_handshake_duration IS 'Cryptographic operation latency metrics balancing security with performance.';

------------------------------------------------------------------------------------------------
-- Serial No: 470
-- Table: T470 - database_connection_pool_aging
-- Schema: db
-- Description: Tracks how long database connections have been in the pool.
-- Business Case: Old connections can be stale or leak memory. This table tracks the "age" of connections
// in the connection pool (T392). It helps optimize connection recycling logic and prevents connections from
// lingering too long (security risk).
-- KPIs: Connection Age Distribution.
-- Feature Reference: T392
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS db.database_connection_pool_aging (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backend_pid INTEGER, -- ID of the DB process serving the connection
    age_seconds INTEGER,
    is_idle BOOLEAN DEFAULT TRUE,

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE db.database_connection_pool_aging IS 'Lifecycle tracking for database connection resources optimizing resource utilization.';

------------------------------------------------------------------------------------------------
-- Serial No: 471
-- Table: T471 - blockchain_transaction_confirmation
-- Schema: integration
-- Description: Status of on-chain transaction confirmations.
-- Business Case: Anchoring (T078) is probabilistic. This table tracks the actual confirmation of the
// transaction by the blockchain. "Submitted -> Pending -> Confirmed". It provides a final guarantee that the
// evidence is immutable on the ledger.
-- KPIs: Confirmation Latency (Blocks).
-- Feature Reference: T078
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.blockchain_transaction_confirmation (
    confirmation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anchor_id UUID NOT NULL REFERENCES contract.blockchain_anchors(anchor_id),
    tx_hash_on_chain VARCHAR(64),
    block_number BIGINT,
    status VARCHAR(20) CHECK (status IN ('SUBMITTED', 'PENDING', 'CONFIRMED', 'FAILED')),
    confirmations_count INTEGER DEFAULT 0,

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE integration.blockchain_transaction_confirmation IS 'State tracker for on-chain settlement of cryptographic evidence.';

------------------------------------------------------------------------------------------------
-- Serial No: 472
-- Table: T472 - smart_contract_event_logs
-- Schema: contract
-- Description: Logs of events emitted by smart contracts.
-- Business Case: Smart contracts emit events (e.g., "RefundExecuted"). This table captures these raw logs.
// It enables the system to react to contract events asynchronously (e.g., "Contract says Refund Failed -> Alert
// Ops"). It decouples the contract engine from the payment processing logic.
-- KPIs: Event Processing Time.
-- Feature Reference: T153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.smart_contract_event_logs (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL REFERENCES contract.smart_contract_executions(exec_id),
    event_name VARCHAR(100) NOT NULL,
    payload_json JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sc_event_contract ON contract.smart_contract_event_logs(contract_id);
COMMENT ON TABLE contract.smart_contract_event_logs IS 'Audit log of blockchain contract lifecycle events.';

------------------------------------------------------------------------------------------------
-- Serial No: 473
-- Table: T473 - gas_price_oracle
-- Schema: ops
-- Description: Predictions of future gas prices for cost optimization.
-- Business Case: Gas prices fluctuate wildly. This table stores predictions from an Oracle model. "Tomorrow at 9 AM, gas
// will be 20 Gwei". It allows the system to schedule anchorings (T078) during low-price windows to save
// significant operational costs.
-- KPIs: Prediction Error (MAE).
-- Feature Reference: T078
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.gas_price_oracle (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    for_block_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    predicted_price_gwei NUMERIC(10,2),
    confidence_score NUMERIC(3,2),
    model_id UUID,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.gas_price_oracle IS 'Forecasting data enabling cost-optimized scheduling of blockchain interactions.';

------------------------------------------------------------------------------------------------
-- Serial No: 474
-- Table: T474 - wallet_balance_snapshot
-- Schema: fraud
-- Description: Periodic snapshots of wallet balances for auditing.
-- Business Case: High volatility wallets (Crypto) need auditing. This table takes snapshots of wallet balances
// at specific intervals. It allows auditors to reconstruct the balance history of a wallet at any point in the
// past, useful for tracing where funds went after a dispute.
-- KPIs: Data Point Density (snapshots per day).
-- Feature Reference: F090
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.wallet_balance_snapshot (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_hash VARCHAR(64) NOT NULL,
    token_symbol VARCHAR(20) NOT NULL,
    balance NUMERIC(25,8),
    block_height BIGINT,

    -- Metadata
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_wallet_snap_hash ON fraud.wallet_balance_snapshot(wallet_hash);
COMMENT ON TABLE fraud.wallet_balance_snapshot IS 'Point-in-time archive of account balances supporting forensic reconstruction.';

------------------------------------------------------------------------------------------------
-- Serial No: 475
-- Table: T475 - nft_metadata
-- Schema: contract
-- Description: Metadata for NFT (Non-Fungible Token) related transactions.
-- Business Case: Disputes aren't just for money; they are for tickets. This table stores metadata for NFTs
// involved in a transaction (TokenID, Collection, Rarity). It helps validate if a user actually owns the
// ticket they claim was fraudulently charged for.
-- KPIs: Metadata Coverage Rate.
-- Feature Reference: T091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contract.nft_metadata (
    nft_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_standard VARCHAR(20), -- ERC-721, ERC-1155
    contract_address VARCHAR(255),
    token_id_on_chain VARCHAR(100),
    metadata_json JSONB
);

COMMENT ON TABLE contract.nft_metadata IS 'Descriptive registry for non-fungible tokens supporting identity and provenance verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 476
-- Table: T476 - cryptographic_key_escrow
-- Schema: sec
-- Description: Escrowing of decryption keys for future use.
-- Business Case: Some encrypted data needs to be read later (e.g., for specific investigations). This table holds
// the escrowed keys and the conditions for release (e.g., "Release to Auditor with signed Court Order").
// It ensures that encrypted data (e.g., PII in logs) can be decrypted only under strict dual-control.
-- KPIs: Key Release Authorization Time.
-- Feature Reference: F008
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cryptographic_key_escrow (
    escrow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_type VARCHAR(50) NOT NULL, -- 'EVIDENCE_FILE', 'TRANSACTION_LOG'
    encrypted_key_part1 BYTEA, -- Shamir's Secret Sharing compatible
    encrypted_key_part2 BYTEA,
    release_conditions JSONB, -- {"requires_audit_signature": true, "court_order_id": "..."}
    released_to_uuid UUID,
    released_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.cryptographic_key_escrow IS 'Zero-knowledge privacy custody of secrets pending authorization for decryption.';

------------------------------------------------------------------------------------------------
-- Serial No: 477
-- Table: T477 - decentralized_identity_did
-- Schema: integration
-- Description: Mapping of Decentralized Identifiers (DIDs) to PARI user hashes.
-- Business Case: In Web3, users are anonymous (Wallet Address). This table maps a Wallet Address to the PARI
// internal User Hash, but only after consent or when proven necessary (e.g., via a trusted Oracle). It bridges
// the gap between anonymous on-chain identity and off-chain compliance.
-- KPIs: Linkage Verification Rate.
-- Feature Reference: T091
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS integration.decentralized_identity_did (
    did_mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_address VARCHAR(255) NOT NULL,
    user_hash VARCHAR(64) NOT NULL,
    confidence_score NUMERIC(3,2), -- How sure are we?
    verification_method VARCHAR(50) -- 'ORACLE', 'SELF_DISCLOSURE'

    -- Metadata
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_did_wallet ON integration.decentralized_identity_did(wallet_address);
COMMENT ON TABLE integration.decentralized_identity_did IS 'Identity resolution bridge connecting anonymous blockchain actors to regulated entities.';

------------------------------------------------------------------------------------------------
-- Serial No: 478
-- Table: T478 - peer_to_peer_dispute_resolution
-- Schema: dispute
-- Description: Workflow logic for P2P (User-to-User) dispute resolution.
-- Business Case: P2P disputes (I sent money to a friend, they claim I didn't) are unique. This table
// defines the rules. "Since both are PARI users, funds are held in escrow until both agree." It tracks
// the votes/actions of both parties in the P2P specific workflow.
-- KPIs: P2P Resolution Consensus Rate.
-- Feature Reference: F052
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispute.peer_to_peer_dispute_resolution (
    resolution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES dispute.cases(case_id),
    sender_user_hash VARCHAR(64) NOT NULL,
    receiver_user_hash VARCHAR(64) NOT NULL,
    sender_decision VARCHAR(20) CHECK (sender_decision IN ('AGREE_REFUND', 'DISAGREE')),
    receiver_decision VARCHAR(20) CHECK (receiver_decision IN ('AGREE_REFUND', 'DISAGREE')),
    auto_refund_triggered BOOLEAN DEFAULT FALSE,

    -- Metadata
    decided_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE dispute.peer_to_peer_dispute_resolution IS 'Consensus tracking for decentralized payment conflicts between two users.';

------------------------------------------------------------------------------------------------
-- Serial No: 479
-- Table: T479 - multi_sig_wallet_verification
-- Schema: sec
-- Description: Logic for verifying transactions with multiple signatures (Threshold Sig).
-- Business Case: Corporate wallets require multiple signatures (M-of-N). This table tracks the status of gathering
// these signatures. "Key 1 signed: Yes, Key 2 signed: Pending". It enforces that all required approvals
// are received before the transaction is considered valid.
-- KPIs: Multi-Sig Completion Time.
-- Feature Reference: F008
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.multi_sig_wallet_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    total_signatures_required INTEGER NOT NULL,
    signatures_collected INTEGER DEFAULT 0,
    signer_ids UUID[],

    -- Metadata
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_multi_sig_verification_timestamp
    BEFORE UPDATE ON sec.multi_sig_wallet_verification
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE sec.multi_sig_wallet_verification IS 'Workflow status tracking for multi-party authorization requirements.';

------------------------------------------------------------------------------------------------
-- Serial No: 480
-- Table: T480 - hardware_security_module_integration
-- Schema: sec
-- Description: Results from Hardware Security Module (HSM) checks (Intel SGX).
-- Business Case: "Confidential Computing" (CoCo) ensures code runs securely. This table stores results of
// verification that the code is actually running in an SGX enclave and hasn't been tampered with.
// It is the highest level of trust verification for the processing environment itself.
-- KPIs: Attestation Success Rate.
-- Feature Reference: T390
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hardware_security_module_integration (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    quote_signed_data BYTEA, -- Signed quote from SGX
    is_verified BOOLEAN,
    quote_timestamp TIMESTAMP WITH TIME ZONE,
    verification_latency_ms INTEGER,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE sec.hardware_security_module_integration IS 'Evidence of Trusted Execution Environment integrity verification.';

------------------------------------------------------------------------------------------------
-- Serial No: 481
-- Table: T481 - user_idle_time_detection
-- Schema: fraud
-- Description: Detection of "Away From Keyboard" (AFK) behavior.
-- Business Case: A user who starts a transaction and then leaves for 2 hours is suspicious (script paused?).
// This table logs "Idle Time" events. If a session is inactive for X minutes but then suddenly completes
// the transaction, it triggers an alert. It distinguishes between genuine human breaks and bot pauses.
-- KPIs: Idle Threshold Accuracy.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.user_idle_time_detection (
    idle_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    last_active_time TIMESTAMP WITH TIME ZONE NOT NULL,
    idle_duration_ms BIGINT,
    action_taken VARCHAR(50), -- 'SESSION_TIMEOUT', 'AFK_ALERT'

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.user_idle_time_detection IS 'Inactivity telemetry detecting anomalous gaps in user interaction flows.';

------------------------------------------------------------------------------------------------
-- Serial No: 482
-- Table: T482 - scroll_velocity_analysis
-- Schema: fraud
-- Description: Analysis of scrolling speed and pattern on web pages.
-- Business Case: Bots scroll instantly to the bottom. Humans scroll unevenly. This table aggregates scroll velocity
// (pixels per second). High scroll velocity indicates non-human interaction. It helps filter out scraping bots
// that try to scrape merchant sites for content.
-- KPIs: Scroll Anomaly Detection Rate.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.scroll_velocity_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    page_url VARCHAR(255),
    max_velocity_pixels_per_sec INTEGER,
    avg_velocity_pixels_per_sec NUMERIC(10,2),
    is_bot_score BOOLEAN,

    -- Metadata
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.scroll_velocity_analysis IS 'UX pattern analysis distinguishing natural reading behavior from automated scraping.';

------------------------------------------------------------------------------------------------
-- Serial No: 483
-- Table: T483 - copy_paste_detection
-- Schema: fraud
-- Description: Clipboard events (Ctrl+V, Paste) during transaction entry.
-- Business Case: Humans enter card numbers one digit at a time or type them. Bots often "paste" a full stolen
// card number. This table logs paste events on sensitive fields (Credit Card input). A "Paste" on the
// Credit Card field is a high-risk indicator.
-- KPIs: Paste Frequency vs. Type.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.copy_paste_detection (
    paste_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    field_name VARCHAR(50) NOT NULL, -- 'credit_card', 'account_number'
    input_method VARCHAR(20) NOT NULL CHECK (input_method IN ('PASTE', 'TYPE')),
    timestamp_ms BIGINT,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.copy_paste_detection IS 'Input method telemetry identifying automation in data entry workflows.';

------------------------------------------------------------------------------------------------
-- Serial No: 484
-- Table: T484 - tab_switching_frequency
-- Schema: fraud
-- Description: Frequency of tab switching or opening multiple tabs during checkout.
-- Business Case: Fraudsters might use scripts to open tabs to different merchants to test cards. This table tracks
// the number of tabs open and switch frequency. Rapid tab switching between unrelated merchants indicates automated
// testing.
-- KPIs: Switch Frequency Anomaly.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.tab_switching_frequency (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    tab_count INTEGER,
    switches_per_minute NUMERIC(10,2),

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.tab_switching_frequency IS 'Multitasking metrics detecting behavior indicative of automated card testing.';

------------------------------------------------------------------------------------------------
-- Serial No: 485
-- Table: T485 - browser_fingerprint_v3
-- Schema: fraud
-- Description: Next-Gen fingerprinting using Canvas and AudioContext.
-- Business Case: Fingerprints (T005) get spoofed. T485 uses advanced browser APIs to detect hardware
// characteristics (Canvas hashing, Audio Context fingerprint) that are much harder to fake. It acts as a
// secondary layer of defense for device identification.
-- KPIs: V3 Match Rate vs V1.
-- Feature Reference: F005
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.browser_fingerprint_v3 (
    v3_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    canvas_hash VARCHAR(100),
    audio_context_hash VARCHAR(100),
    webgl_renderer_hash VARCHAR(100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.browser_fingerprint_v3 IS 'Enhanced device identification metrics leveraging advanced browser hardware interfaces.';

------------------------------------------------------------------------------------------------
-- Serial No: 486
-- Table: T486 - webgl_fingerprinting
-- Schema: fraud
-- Description: 3D fingerprinting of the graphics card using WebGL API.
-- Business Case: GPUs have unique quirks. WebGL allows creating a 3D shape from the GPU. This table stores
// the resulting "3D Fingerprint". It is extremely resistant to emulation (Virtual Machines struggle to
// fake the exact same 3D output), making it a powerful anti-bot tool.
-- KPIs: WebGL Consistency.
-- Feature Reference: F041
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.webgl_fingerprinting (
    fingerprint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    renderer_info JSONB,
    hash_value VARCHAR(255) NOT NULL,

    -- Metadata
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.webgl_fingerprinting IS 'Hardware-specific telemetry creating a unique token for graphics processing units.';

------------------------------------------------------------------------------------------------
-- Serial No: 487
-- Table: T487 - timezone_anomaly
-- Schema: fraud
-- Description: Detection of discrepancies between IP location and User settings.
-- Business Case: A user in "New York" suddenly connecting from "Tokyo" IP is suspicious. This table stores
// the user's reported timezone and compares it to the GeoIP of the connection. Large discrepancies indicate VPN
// usage or IP spoofing to bypass geo-blocks.
-- KPIs: Timezone Delta Threshold Breach Rate.
-- Feature Reference: F006
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.timezone_anomaly (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    user_timezone VARCHAR(50),
    ip_timezone VARCHAR(50),
    delta_hours NUMERIC(5,2),
    is_anomaly BOOLEAN DEFAULT FALSE,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.timezone_anomaly IS 'Cross-referenced temporal data identifying evasion techniques via IP geolocation mismatch.';

------------------------------------------------------------------------------------------------
-- Serial No: 488
-- Table: T488 - language_preference_detection
-- Schema: fraud
-- Description: Auto-detected language preference based on user interaction.
-- Business Case: Localization is key. This table infers the user's language by analyzing the input text
// (dispute description) or browser language settings. It ensures that notifications and templates are sent
// in the correct language automatically, improving user experience.
-- KPIs: Language Detection Accuracy.
-- Feature Reference: F044
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.language_preference_detection (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    detected_language CHAR(2) DEFAULT 'en',
    confidence_score NUMERIC(3,2),

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.language_preference_detection IS 'NLP-derived attribute supporting frictionless localization.';

------------------------------------------------------------------------------------------------
-- Serial No: 489
-- Table: T489 - ad_blocker_engagement
-- Schema: fraud
-- Description: Metrics on usage of AdBlockers by users.
-- Business Case: Some users have AdBlockers. Usually they are savvy (good), but sophisticated scripts might
// use them to avoid tracking pixels. This table flags users who block standard tracking pixels. It
// contextualizes the lack of tracking data (is the user privacy-focused or hiding something?).
-- KPIs: AdBlocker Segment Size.
-- Feature Reference: F401
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.ad_blocker_engagement (
    tracking_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    has_adblocker BOOLEAN NOT NULL,
    detected_via TEXT, -- 'TRACKING_PIXEL_BLOCK', 'AGENT_STRING_ANALYSIS'

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.ad_blocker_engagement IS 'Privacy indicator tracking usage of content filtering browser extensions.';

------------------------------------------------------------------------------------------------
-- Serial No: 490
-- Table: T490 - mobile_device_orientation
-- Schema: fraud
-- Description: Metrics on device orientation (Portrait/Landscape) and gyroscope data.
-- Business Case: Users hold phones in specific ways. Abnormal gyro patterns (shaking without moving)
// can indicate automated scripts or "passive bots" attached to the device. This table tracks accelerometer
// data to validate the user is actually holding the device.
-- KPIs: Orientation Consistency.
-- Feature Reference: F174
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.mobile_device_orientation (
    orientation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_hash VARCHAR(64),
    orientation VARCHAR(10), -- PORTRAIT, LANDSCAPE, UPSIDE_DOWN
    gyro_variance_x NUMERIC(5,2),
    gyro_variance_y NUMERIC(5,2),
    gyro_variance_z NUMERIC(5,2),

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.mobile_device_orientation IS 'Sensor telemetry detecting physical device movement anomalies.';

------------------------------------------------------------------------------------------------
-- Serial No: 491
-- Table: T491 - fx_hedging_positions
-- Schema: finance
-- Description: Tracking of positions taken to mitigate foreign exchange (FX) risk.
-- Business Case: Multi-currency commerce involves FX risk. This table logs the positions (Contracts) the system
// holds to protect against rate swings. It links these hedges to the specific transactions. It ensures that
// profit margins are protected even if the market moves against the trade.
-- KPIs: Hedge Effectiveness (ROI).
-- Feature Reference: T148
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.fx_hedging_positions (
    hedge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    currency_pair CHAR(7) NOT NULL, -- e.g., USD/EUR
    position_type VARCHAR(20) CHECK (position_type IN ('CALL_OPTION', 'SPOT')),
    amount_hedged NUMERIC(15,2),
    entry_rate NUMERIC(5,2),

    -- Metadata
    open_time TIMESTAMP WITH TIME ZONE NOT NULL,
    close_time TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE finance.fx_hedging_positions IS 'Financial risk mitigation records tracking derivative trading strategies.';

------------------------------------------------------------------------------------------------
-- Serial No: 492
-- Table: T492 - multi_currency_wallet_balances
-- Schema: fraud
-- Description: Balances in various tokens/currencies for a single wallet/user.
-- Business Case: Users hold multiple tokens (USDC, EuroCoin). This table stores the balance for each currency
// in a single aggregated view. It simplifies "Total Net Worth" calculations and FX risk assessment by
// centralizing multi-currency holdings.
-- KPIs: Balance Aggregation Accuracy.
-- Feature Reference: T474
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.multi_currency_wallet_balances (
    balance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    wallet_hash VARCHAR(64) NOT NULL,
    currency_symbol VARCHAR(20) NOT NULL,
    balance NUMERIC(25,8),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_multi_curr_wallet ON fraud.multi_currency_wallet_balances(wallet_hash);
COMMENT ON TABLE fraud.multi_currency_wallet_balances IS 'Multi-ledger account view for crypto-assets supporting comprehensive wealth analysis.';

------------------------------------------------------------------------------------------------
-- Serial No: 493
-- Table: T493 - cross_border_tax_calculation
-- Schema: finance
-- Description: Calculation of VAT/GST for cross-border transactions.
-- Business Case: Tax laws are complex. This table stores the calculated tax amount and applied rate for
// specific cross-border flows. It ensures compliance with digital services tax regulations (DAC7) for B2B
// transactions.
-- KPIs: Tax Calculation Accuracy.
-- Feature Reference: F059, M22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.cross_border_tax_calculation (
    tax_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    buyer_country CHAR(2),
    seller_country CHAR(2),
    digital_services_tax_rate NUMERIC(5,4),
    calculated_tax_amount NUMERIC(15,2),

    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE finance.cross_border_tax_calculation IS 'Regulatory computation records ensuring tax compliance in international trade.';

------------------------------------------------------------------------------------------------
-- Serial No: 494
-- Table: T494 - settlement_currency_conversion_audit
-- Schema: finance
-- Description: Audit trail of currency conversion rates used during settlement.
-- Business Case: We refund in EUR but pay in USD. The rate we use matters. This table logs the rates
// used for historical refunds. It provides an audit trail to prove that FX calculations were fair and
// consistent with market mid-price, preventing disputes over pennies on exchange.
-- KPIs: FX Rate Audit Trail Completeness.
-- Feature Reference: T148
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.settlement_currency_conversion_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    settlement_batch_id VARCHAR(100) NOT NULL,
    from_currency CHAR(3),
    to_currency CHAR(3),
    rate_used NUMERIC(15,6),
    provider_reference VARCHAR(50),

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_fx_audit_batch ON finance.settlement_currency_conversion_audit(settlement_batch_id);
COMMENT ON TABLE finance.settlement_currency_conversion_audit IS 'Forensic log of currency exchange rates applied to financial settlements.';

------------------------------------------------------------------------------------------------
-- Serial No: 495
-- Table: T495 - exchange_rate_locking
-- Schema: finance
-- Description: Locking in a specific exchange rate for the duration of a transaction.
-- Business Case: FX rates change continuously. To avoid currency risk, this table allows "locking" a rate at the
// start of a transaction. Even if the market moves, the refund is calculated using the locked rate.
// It guarantees pricing certainty for the duration of the trade.
-- KPIs: Lock Hit Rate.
-- Feature Reference: T148
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.exchange_rate_locking (
    lock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    currency_pair CHAR(7) NOT NULL,
    locked_rate NUMERIC(15,6) NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_rate_lock_tx ON finance.exchange_rate_locking(transaction_hash);
COMMENT ON TABLE finance.exchange_rate_locking IS 'Temporal control mechanism mitigating volatility risk in financial transfers.';

------------------------------------------------------------------------------------------------
-- Serial No: 496
-- Table: T496 - crypto_volatility_adjustments
-- Schema: fraud
-- Description: Risk adjustments based on crypto market volatility.
-- Business Case: Crypto is volatile. If Bitcoin price crashes, fraud (chargebacks) might spike (users claim
// they paid 1 BTC for goods worth 0.5 BTC). This table applies a "Volatility Tax" to the Risk Score.
// It adjusts the risk threshold dynamically based on market conditions.
-- KPIs: Volatility Adjustment Sensitivity.
-- Feature Reference: F027
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.crypto_volatility_adjustments (
    volatility_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_symbol VARCHAR(10) NOT NULL,
    volatility_index NUMERIC(5,2), -- 0.0 = stable, 1.0 = volatile
    threshold_multiplier NUMERIC(3,2) DEFAULT 1.0,

    -- Metadata
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE fraud.crypto_volatility_adjustments IS 'Dynamic risk calibration factors responding to market instability in digital assets.';

------------------------------------------------------------------------------------------------
-- Serial No: 497
-- Table: T497 - payment_method_risk_adjustment
-- Schema: fraud
-- Description: Risk score multipliers for different payment methods.
-- Business Case: Credit Cards have chargebacks. Crypto does not (usually). This table defines the risk adjustment.
// "Crypto Payment = 0.5x Risk of Card". It ensures that the base fraud score is adjusted appropriately
// based on the nature of the payment rails.
-- KPIs: Risk Score Calibration Accuracy.
-- Feature Reference: F014
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud.payment_method_risk_adjustment (
    method_type VARCHAR(50) PRIMARY KEY,
    risk_multiplier NUMERIC(3,2) NOT NULL,
    reason TEXT, -- e.g., 'NO_CHARGEBACK_PROTECTION'

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_payment_method_risk_timestamp
    BEFORE UPDATE ON fraud.payment_method_risk_adjustment
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE fraud.payment_method_risk_adjustment IS 'Global risk parameters modifying scores based on transfer characteristics.';

------------------------------------------------------------------------------------------------
-- Serial No: 498
-- Table: T498 - transaction_fee_variance
-- Schema: ops
-- Description: Monitoring for unusual changes in transaction fees.
-- Business Case: Fees should be predictable. If a transaction fee spikes 10x, it might be a glitch or malicious
// miner/validator action. This table monitors the fees recorded for transactions. It flags outliers that indicate
// system malfeasance or external provider gouging.
-- KPIs: Fee Stability Score.
-- Feature Reference: T090
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.transaction_fee_variance (
    variance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    payment_method VARCHAR(50) NOT NULL,
    expected_fee_range_min NUMERIC(15,2),
    expected_fee_range_max NUMERIC(15,2),
    actual_fee NUMERIC(15,2),
    is_anomaly BOOLEAN DEFAULT FALSE,

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.transaction_fee_variance IS 'Monitoring system identifying cost anomalies in payment processing.';

------------------------------------------------------------------------------------------------
-- Serial No: 499
-- Table: T499 - merchant_fee_tier_history
-- Schema: finance
-- Description: History of fee tier classifications for merchants.
-- Business Case: Merchants pay fees based on volume. This table tracks the history of a merchant moving from
// "Silver Tier" to "Gold Tier". It provides context for financial negotiations and disputes over fee
// charges.
-- KPIs: Tier Migration Frequency.
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.merchant_fee_tier_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    old_tier VARCHAR(20),
    new_tier VARCHAR(20),
    reason_code VARCHAR(50),

    -- Metadata
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    changed_by UUID NOT NULL
);

COMMENT ON TABLE finance.merchant_fee_tier_history IS 'Version control for commercial pricing agreements governing transaction costs.';

------------------------------------------------------------------------------------------------
-- Serial No: 500
-- Table: T500 - financial_reconciliation_summary
-- Schema: finance
-- Description: Daily summary of all financial movements (Disbursements, Fees, Refunds).
-- Business Case: At the end of the day, the books must balance. This table provides a summary of all
// financial movements (Credits, Debits, Fees). It is the "Source of Truth" for daily Profit & Loss
// statement generation for the module.
-- KPIs: Reconciliation Speed (End-of-Day).
-- Feature Reference: T090, T293
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finance.financial_reconciliation_summary (
    summary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_date DATE NOT NULL,
    total_disbursed_amount NUMERIC(15,2),
    total_collected_fees NUMERIC(15,2),
    total_refunds_issued NUMERIC(15,2),
    net_profit_loss NUMERIC(15,2), -- Fees - Refunds - Loss
    settled_transaction_count BIGINT,

    CONSTRAINT pk_recon_summary UNIQUE (report_date)
);

COMMENT ON TABLE finance.financial_reconciliation_summary IS 'Daily aggregation of P&L providing executive visibility into module economics.';

------------------------------------------------------------------------------------------------
-- Serial No: 501
-- Table: T501 - cross_border_tax_compliance
-- Schema: compliance
-- Description: Specific tax rules and compliance status for country pairs.
-- Business Case: EU has VAT, US has Sales Tax. This table defines the tax rules for every
// Country-to-Country pair. It ensures that the system can dynamically calculate the correct tax based on
// the origin and destination of the goods/services.
-- KPIs: Rule Coverage %.
-- Feature Reference: T493, M22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.cross_border_tax_compliance (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    origin_country CHAR(2) NOT NULL,
    dest_country CHAR(2) NOT NULL,
    tax_rate NUMERIC(5,4) NOT NULL,
    requires_einvoicing BOOLEAN DEFAULT FALSE,

    CONSTRAINT pk_tax_comp UNIQUE (origin_country, dest_country)
);

COMMENT ON TABLE compliance.cross_border_tax_compliance IS 'Regulatory definition matrix enabling automated tax calculation in international trade.';

------------------------------------------------------------------------------------------------
-- Serial No: 502
-- Table: T502 - sanctions_screening_audit_trail
-- Schema: compliance
-- Description: Immutable audit of every sanctions list check performed.
-- Business Case: Screening is sensitive. This table logs the request, the list used (OFAC), and
// the hit (if any). It is the legal proof that we "tried our best" to block a sanctioned entity.
// It creates a complete audit trail for regulators examining a specific transaction involving a blocked party.
-- KPIs: Screening Response Time.
-- Feature Reference: T127, F019
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.sanctions_screening_audit_trail (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL,
    list_name VARCHAR(50) NOT NULL,
    screened_entities TEXT[],
    hit_detected BOOLEAN NOT NULL,
    decision VARCHAR(20) CHECK (decision IN ('PASS', 'BLOCK', 'MANUAL_REVIEW')),

    -- Metadata
    screened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.sanctions_screening_audit_trail IS 'Immutable log of AML enforcement actions ensuring regulatory defensibility.';

------------------------------------------------------------------------------------------------
-- Serial No: 503
-- Table: T503 - politically_exposed_person_pep_list
-- Schema: compliance
-- Description: List of Politically Exposed Persons (PEP) - Sensitive Sanctions list.
-- Business Case: PEPs (Politicians) require screening beyond standard AML. This table holds the specific list of
// PEPs and their aliases. It is segregated from standard sanctions to allow finer-grained
// control and higher scrutiny levels for sensitive transactions.
-- KPIs: PEP Match Rate.
-- Feature Reference: T127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.politically_exposed_person_pep_list (
    pep_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    title VARCHAR(255),
    date_of_birth DATE,
    country_of_sanction CHAR(2),
    status VARCHAR(20) DEFAULT 'ACTIVE',

    CONSTRAINT pk_pep_name UNIQUE (name, country_of_sanction)
);

COMMENT ON TABLE compliance.politically_exposed_person_pep_list IS 'High-risk individual watchlist requiring enhanced due diligence.';

------------------------------------------------------------------------------------------------
-- Serial No: 504
-- Table: T504 - regulatory_change_log
-- Schema: compliance
-- Description: Tracking changes in laws (e.g., PSD3, GDPR amendments).
-- Business Case: Regulations change. This table tracks the implementation of new laws or changes. "PSD3
// Strong Customer Authentication (SCA) implementation started". It ensures that the system maintains a
// timeline of becoming compliant with new regulations.
-- KPIs: Regulatory Compliance %.
-- Feature Reference: T501
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.regulatory_change_log (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_name VARCHAR(100) NOT NULL,
    change_type VARCHAR(50) NOT NULL, -- 'NEW_LAW', 'AMENDMENT'
    description TEXT NOT NULL,
    compliance_target_date DATE,
    implemented_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.regulatory_change_log IS 'Project management repository tracking jurisdictional adaptation timelines.';

------------------------------------------------------------------------------------------------
-- Serial No: 505
-- Table: T505 - compliance_training_records
-- Schema: hr
-- Description: Records of compliance training taken by staff.
-- Business Case: Staff must be trained on AML and Privacy. This table stores who took which training, when,
// and their score. It ensures that the "Human Element" of the compliance framework is competent
// and qualified.
-- KPIs: Training Coverage %.
-- Feature Reference: T404
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hr.compliance_training_records (
    training_record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    course_name VARCHAR(100) NOT NULL,
    attendee_id UUID NOT NULL,
    training_date DATE NOT NULL,
    competency_score NUMERIC(5,2) CHECK (competency_score BETWEEN 0 AND 100),

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE hr.compliance_training_records IS 'Employee qualification log ensuring operational compliance competency.';

------------------------------------------------------------------------------------------------
-- Serial No: 506
-- Table: T506 - audit_evidence_sharing_log
-- Schema: compliance
-- Description: Logs of evidence sharing with external auditors/regulators.
-- Business Case: Regulators request evidence. This table logs every share event. "User A's file was
// shared with Agency B". It tracks the expiration of access to ensure shared data is not leaked
// indefinitely.
-- KPIs: Data Access Expiry Enforcement.
-- Feature Reference: T337
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.audit_evidence_sharing_log (
    share_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID REFERENCES dispute.case_evidence(evidence_id),
    requesting_entity VARCHAR(100) NOT NULL,
    purpose TEXT NOT NULL,
    access_granted_until TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metadata
    shared_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.audit_evidence_sharing_log IS 'Temporary grant tracking for third-party data access ensuring privacy compliance.';

------------------------------------------------------------------------------------------------
-- Serial No: 507
-- Table: T507 - whistleblower_reports
-- Schema: compliance
-- Description: Internal reports from employees regarding misconduct or fraud.
-- Business Case: Internal fraud is a risk. This table stores "Whistleblower" reports. It protects the
// reporter (anonymized if desired) and documents the issue. It provides a safe channel for reporting
// unethical behavior that might expose the system to liability.
-- KPIs: Report Processing Time.
-- Feature Reference: T328
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.whistleblower_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    category VARCHAR(50) NOT NULL CHECK (category IN ('FRAUD', 'HARASSMENT', 'SECURITY_BREACH')),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description_anonymized TEXT, -- Stripped of PII
    status VARCHAR(20) DEFAULT 'REVIEWED', -- REVIEWED, INVESTIGATING, CLOSED
    disposition TEXT, -- Outcome of investigation

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_whistleblower_reports_timestamp
    BEFORE UPDATE ON compliance.whistleblower_reports
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE compliance.whistleblower_reports IS 'Protected channel for reporting organizational misconduct and ethical concerns.';

------------------------------------------------------------------------------------------------
-- Serial No: 508
-- Table: T508 - regulatory_fine_register
-- Schema: compliance
-- Description: Tracking of fines paid or accrued due to compliance failures.
-- Business Case: Fines happen. This table records them. It tracks the amount, the authority, and
// whether it was paid. It calculates the total "Compliance Cost" (Financial) for the system,
// which should ideally be zero.
-- KPIs: Fine Reduction Rate.
-- Feature Reference: T127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance.regulatory_fine_register (
    fine_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    authority_name VARCHAR(100) NOT NULL, -- e.g., 'FINMA', 'GDPR_DPA'
    amount_num NUMERIC(15,2) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',
    infraction_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'OUTSTANDING', -- OUTSTANDING, PAID, DISPUTED
    payment_date DATE,

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE compliance.regulatory_fine_register IS 'Financial liability tracker for legal penalties ensuring budget planning for compliance failures.';

------------------------------------------------------------------------------------------------
-- Serial No: 509
-- Table: T509 - compliance_officer_assignments
-- Schema: ops
-- Description: Mapping of compliance officers to regions or business units.
-- Business Case: Compliance officers manage specific territories. This table maps officers to regions (e.g.,
// "Officer X handles EU, Officer Y handles APAC"). It ensures that regulatory queries (T313) are
// routed to the qualified person who understands the local laws.
-- KPIs: Officer Response Time.
-- Feature Reference: T501
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.compliance_officer_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    officer_id UUID NOT NULL,
    region VARCHAR(100) NOT NULL, -- e.g., 'EMEA', 'APAC'
    business_unit VARCHAR(100),

    CONSTRAINT pk_compliance_officer UNIQUE (region, business_unit)
);

COMMENT ON TABLE ops.compliance_officer_assignments IS 'Responsibility matrix ensuring regulatory inquiries are handled by qualified personnel.';

------------------------------------------------------------------------------------------------
-- Serial No: 510
-- Table: T510 - legal_hold_review_board
-- Schema: legal
-- Description: Records of reviews held to release or maintain Legal Holds (T241).
-- Business Case: Legal Holds stop the clock on "Right to be Forgotten". They must be reviewed periodically to
// ensure they are not abused to withhold data unnecessarily. This table logs the reviews: "Hold approved
// for another 90 days", "Hold released". It enforces time limits on data freezing.
-- KPIs: Legal Hold Review SLA Adherence.
-- Feature Reference: T241
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS legal.legal_hold_review_board (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hold_id UUID NOT NULL REFERENCES dispute.legal_hold_notices(hold_id),
    reviewed_by UUID NOT NULL,
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('EXTEND', 'MAINTAIN', 'RELEASE')),
    justification TEXT,

    -- Metadata
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE legal.legal_hold_review_board IS 'Governance oversight ensuring legal data freezes are justified and time-limited.';

------------------------------------------------------------------------------------------------
-- Serial No: 511
-- Table: T511 - ontology_versioning
-- Schema: knowledge
-- Description: Versioning of the Knowledge Graph Schema (T162).
-- Business Case: The Knowledge Graph evolves. This table stores the schema definitions and version numbers. It allows
// the system to reason over data using different versions of the ontology (e.g., v1.0 vs v1.1)
// during historical analysis. It maintains backward compatibility for AI Explainability.
-- KPIs: Schema Migration Success.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.ontology_versioning (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schema_name VARCHAR(100) NOT NULL,
    version_number VARCHAR(20) NOT NULL,
    changes_json JSONB, -- List of concepts added/modified
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DEPRECATED
    compatibility_map JSONB, -- Maps v1 terms to v2 terms
    release_date DATE
);

COMMENT ON TABLE knowledge.ontology_versioning IS 'Schema evolution tracking supporting historical data compatibility and AI model stability.';

------------------------------------------------------------------------------------------------
-- Serial No: 512
-- Table: T512 - concept_retirement_log
-- Schema: knowledge
-- Description: Log of concepts that are deprecated or removed from the KG.
-- Business Case: Concepts change (e.g., "Wire Fraud" -> "Electronic Funds Transfer Fraud"). This table logs the
// retirement of old concepts. It alerts dependent systems that they must update their mapping from the old
// ID to the new ID.
-- KPIs: Deprecation Cascade Success.
-- Feature Reference: T511
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.concept_retirement_log (
    retirement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    old_concept_uri TEXT NOT NULL,
    new_concept_uri TEXT,
    retirement_reason TEXT,
    retirement_date DATE NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE knowledge.concept_retirement_log IS 'Deactivation records for knowledge entities preventing schema drift in AI reasoning.';

------------------------------------------------------------------------------------------------
-- Serial No: 513
-- Table: T513 - semantic_search_cache
-- Schema: knowledge
-- Description: Cache for semantic search results on the Knowledge Graph.
-- Business Case: Traversing a graph is expensive. This table caches results of semantic queries ("Find all
// terms related to 'Money Laundering'"). It speeds up the Knowledge UI/Assistant by storing pre-computed
// results for common queries.
-- KPIs: Cache Hit Ratio.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.semantic_search_cache (
    cache_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    search_term_hash VARCHAR(64) NOT NULL,
    result_node_uris TEXT[],
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sem_search_cache_hash ON knowledge.semantic_search_cache(search_term_hash);
COMMENT ON TABLE knowledge.semantic_search_cache IS 'Performance optimization layer for graph-based information retrieval.';

------------------------------------------------------------------------------------------------
-- Serial No: 514
-- Table: T514 - relationship_strength_weights
-- Schema: knowledge
-- Description: Weighted importance of relationships in the Knowledge Graph.
-- Business Case: Not all relationships are equal. "owns" is stronger than "knows_of". This table assigns
// weights to relationships (predicates) in the graph. It allows the "Inference Engine" (T516) to prioritize
// strong evidence over weak circumstantial evidence when deriving facts.
-- KPIs: Weight Calibration Accuracy.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.relationship_strength_weights (
    weight_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    predicate_uri TEXT NOT NULL, -- e.g., "HAS_MERCHANT_CARD"
    weight NUMERIC(5,2) CHECK (weight BETWEEN 0 AND 1),

    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_rel_strength_weights_timestamp
    BEFORE UPDATE ON knowledge.relationship_strength_weights
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE knowledge.relationship_strength_weights IS 'Tuning parameters for reasoning engines determining the validity of graph-based inferences.';

------------------------------------------------------------------------------------------------
-- Serial No: 515
-- Table: T515 - knowledge_graph_diff
-- Schema: knowledge
-- Description: Delta/Difference of the Knowledge Graph state over time.
-- Business Case: The Knowledge Graph changes daily. This table stores the "Diff" (Additions/Deletions) from the
// previous day's graph. It allows for audit trails of knowledge evolution (e.g., "Who added
// this attribute to this user class?").
-- KPIs: Graph Change Volume.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.knowledge_graph_diff (
    diff_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_date DATE NOT NULL,
    previous_state_hash CHAR(64), -- Hash of the entire graph
    new_state_hash CHAR(64),
    changes_summary JSONB, -- {"nodes_added": 5, "edges_added": 2}

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE knowledge.knowledge_graph_diff IS 'Change tracking for the semantic layer enabling forensic replay of knowledge evolution.';

------------------------------------------------------------------------------------------------
-- Serial No: 516
-- Table: T516 - inference_rule_engine
-- Schema: knowledge
-- Description: Logic definition for rules running over the Knowledge Graph.
-- Business Case: We need to derive facts from the graph. This table defines rules in a declarative language.
// "IF User -> Buys -> 'High_Risk_Item', THEN Flag". It drives the automated analysis of graph data
// to surface insights.
-- KPIs: Rule Execution Time.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.inference_rule_engine (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    rule_logic JSONB NOT NULL, -- Graph traversal pattern
    confidence_threshold NUMERIC(3,2),
    active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);

CREATE TRIGGER trg_inference_rule_engine_timestamp
    BEFORE UPDATE ON knowledge.inference_rule_engine
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

COMMENT ON TABLE knowledge.inference_rule_engine IS 'Definition of graph traversal patterns for automated hypothesis generation.';

------------------------------------------------------------------------------------------------
-- Serial No: 517
-- Table: T517 - entity_resolution_service
-- Schema: knowledge
-- Description: Logs of attempts to resolve entities (e.g., linking a hash to a user name).
-- Business Case: Entity Resolution is hard. This table logs the service's attempts to resolve "User X" to
// "Entity Y". It tracks success/failure and resolution time. It measures the effectiveness of
// the "Knowledge Graph" in connecting fragmented data.
-- KPIs: Entity Resolution Rate.
-- Feature Reference: T477
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.entity_resolution_service (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    raw_identifier VARCHAR(255) NOT NULL,
    resolved_entity_uri TEXT,
    confidence_score NUMERIC(3,2),
    resolution_method VARCHAR(50), -- 'GRAPH_MATCH', 'MANUAL'

    -- Metadata
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE knowledge.entity_resolution_service IS 'Operational log linking unstructured data identifiers to canonical graph entities.';

------------------------------------------------------------------------------------------------
-- Serial No: 518
-- Table: T518 - graph_query_performance
-- Schema: ops
-- Description: Performance logs for queries executed against the Knowledge Graph.
-- Business Case: Slow queries degrade the UX. This table tracks the latency and cost of graph queries (Gremlin/Neo4j).
// It identifies "Hot Spots" in the graph that need optimization (indexing) or caching.
-- KPIs: Query P99 Latency.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.graph_query_performance (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_name VARCHAR(255) NOT NULL,
    nodes_scanned BIGINT,
    execution_time_ms INTEGER,
    memory_usage_mb NUMERIC(10,2),

    -- Metadata
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.graph_query_performance IS 'Performance monitoring for graph database operations identifying optimization targets.';

------------------------------------------------------------------------------------------------
-- Serial No: 519
-- Table: T519 - external_knowledge_import
-- Schema: knowledge
-- Description: Logs of importing external taxonomies or standards into the KG.
-- Business Case: We don't build everything from scratch. This table logs the import of external standards (e.g.,
// ISO 20022). It maps external terms to internal concepts, enriching the Knowledge Graph and ensuring
// interoperability.
-- KPIs: Import Success Rate.
-- Feature Reference: T511
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.external_knowledge_import (
    import_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_source VARCHAR(100) NOT NULL,
    external_term_identifier VARCHAR(255) NOT NULL,
    internal_uri TEXT NOT NULL, -- Mapped URI
    confidence_score NUMERIC(3,2),
    import_date DATE NOT NULL
);

COMMENT ON TABLE knowledge.external_knowledge_import IS 'Data integration logs enriching the internal semantic model with industry standards.';

------------------------------------------------------------------------------------------------
-- Serial No: 520 - Table: T520 - natural_language_query_logs
-- Schema: knowledge
-- Description: Logs of natural language queries made by users/agents to the Knowledge Graph.
-- Business Case: Users/Analysts ask questions in plain English ("Who is the CEO of Fraud?"). This table logs the query
// text and the returned match. It improves the NLP model by understanding the types of questions users ask.
-- KPIs: Query Intent Classification Accuracy.
-- Feature Reference: T162
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS knowledge.natural_language_query_logs (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_text TEXT NOT NULL,
    result_entity_uri TEXT,
    confidence_score NUMERIC(3,2),
    latency_ms INTEGER,

    -- Metadata
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE knowledge.natural_language_query_logs IS 'Interaction telemetry for semantic search interfaces improving language understanding models.';

------------------------------------------------------------------------------------------------
-- Serial No: 521
-- Table: T521 - disaster_recovery_failover_log
-- Schema: ops
-- Description: Specific log of failover events during Disaster Recovery.
-- Business Case: When the primary region fails, we failover to DR. This table logs that event: "Zone A failed,
// Traffic redirected to Zone B". It tracks the timeline of the failover and the resulting RTO (Recovery
// Time Objective).
-- KPIs: RTO Achievement (Target vs Actual).
-- Feature Reference: T207
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.disaster_recovery_failover_log (
    failover_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    primary_region VARCHAR(50) NOT NULL,
    backup_region VARCHAR(50) NOT NULL,
    trigger_reason VARCHAR(100),
    triggered_by UUID NOT NULL,
    failover_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, IN_PROGRESS, SUCCESS, FAILED
    actual_rto_ms BIGINT,

    -- Metadata
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.disaster_recovery_failover_log IS 'Incident-specific tracking of resilience engineering actions during service continuity threats.';

------------------------------------------------------------------------------------------------
-- Serial No: 522
-- Table: T522 - region_sync_lag
-- Schema: ops
-- Description: Lag between the primary region and the DR/Backup region.
-- Business Case: Data must be synced to be usable. This table measures the "Sync Lag" (Replication Lag)
// in milliseconds. If the backup region is seconds behind, failover to it might result in lost transactions.
// It warns Ops of split-brain situations.
-- KPIs: Replication Lag P99.
-- Feature Reference: T394
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.region_sync_lag (
    sync_event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    primary_region VARCHAR(50) NOT NULL,
    dr_region VARCHAR(50) NOT NULL,
    lag_ms BIGINT,
    is_acceptable BOOLEAN DEFAULT FALSE,

    -- Metadata
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.region_sync_lag IS 'Data consistency metric for distributed system state ensuring high availability of standby systems.';

------------------------------------------------------------------------------------------------
-- Serial No: 523
-- Table: T523 - data_corruption_detection
-- Schema: ops
-- Description: Detection of "Bit Rot" or silent data corruption in backups/archives.
-- Business Case: Backups can rot. This table runs periodic checks on stored data (checksum validation). If the checksum
// today differs from yesterday, it flags potential "Bit Rot" (hardware degradation). It is the last line of
// defense for data integrity.
-- KPIs: Corruption Detection Latency.
-- Feature Reference: T145
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.data_corruption_detection (
    integrity_check_id UUID DEFAULT uuid_generate_vonv4() PRIMARY KEY,
    storage_bucket_path TEXT NOT NULL,
    object_key VARCHAR(255) NOT NULL,
    stored_checksum CHAR(64),
    current_checksum CHAR(64),
    is_corrupted BOOLEAN DEFAULT FALSE,

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.data_corruption_detection IS 'Automated validation of archived data integrity preventing undetected data degradation.';

------------------------------------------------------------------------------------------------
-- Serial No: 524
-- Table: T524 - rto_rpo_simulation_results
-- Schema: ops
-- Description: Results of simulating disaster scenarios to test RTO/RPO.
-- Business Case: We promise RTO of 1 minute. This table stores results of practice drills. "Took 2 mins".
// It proves (or disproves) that our disaster plan actually works as designed. It identifies bottlenecks in the
// recovery process.
-- KPIs: RTO vs. Target Deviation.
-- Feature Reference: T207
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.rto_rpo_simulation_results (
    simulation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(100) NOT NULL,
    target_rto_sec BIGINT NOT NULL,
    actual_rto_sec BIGINT,
    rpo_bytes BIGINT, -- Data lost in the gap
    success_rate NUMERIC(3,2),

    -- Metadata
    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.rto_rpo_simulation_results IS 'Test records validating resilience targets and calculating true downtime costs.';

------------------------------------------------------------------------------------------------
-- Serial No: 525
-- Table: T525 - fire_drill_audit
-- Schema: ops
-- Description: Audit of "Fire Drills" (simulated incidents) performed to test readiness.
-- Business Case: Practice makes perfect. This table audits the execution of a Fire Drill. "Did we panic?
// Did we follow the playbook?". It provides a scorecard for the organization's response readiness and
// areas for improvement.
-- KPIs: Readiness Score.
-- Feature Reference: T207
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.fire_drill_audit (
    drill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(100) NOT NULL,
    scheduled_time TIMESTAMP WITH TIME ZONE NOT NULL,
    participants_uuid UUID[],
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    observations TEXT, -- "Alert system failed to trigger"

    -- Metadata
    reported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.fire_drill_audit IS 'Assessment records for practice scenarios evaluating team preparedness for real crises.';

------------------------------------------------------------------------------------------------
-- Table: T526 - backup_integrity_checksums
-- Schema: ops
-- Description: Storage of checksums for backup files to prevent silent corruption.
-- Business Case: Verification requires a reference. This table stores the expected checksums of backup
// files. It allows the "Bit Rot" checker (T523) to verify the current file against the
// original hash to guarantee data integrity.
-- KPIs: Checksum Verification Speed.
-- Feature Reference: T200
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.backup_integrity_checksums (
    backup_set_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_path TEXT NOT NULL,
    algorithm_type VARCHAR(20) CHECK (algorithm_type IN ('SHA256', 'MD5')),
    expected_hash CHAR(64) NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.backup_integrity_checksums is 'Reference repository for validating the sanctity of long-term storage assets.';

------------------------------------------------------------------------------------------------
-- Table: T527 - site_reliability_engagement_score
-- Schema: ops
-- Description: Tracking of engineer engagement with Site Reliability Engineering (SRE) practices.
-- Business Case: SRE is a culture, not just tools. This table tracks engagement. "Did engineers participate
// in Blameless Post-Mortems?", "Did they run drills?". It quantifies the "Human Element" of
// reliability.
-- KPIs: SRE Participation Rate.
-- Feature Reference: T197
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.site_reliability_engagement_score (
    engagement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    engineer_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- 'TRAINING', 'DRILL', 'POST_MORTEM'
    participation_quality_score NUMERIC(3,2),

    -- Metadata
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.site_reliability_engagement_score IS 'Cultural metrics tracking adherence to operational excellence standards.';

------------------------------------------------------------------------------------------------
-- Table: T528 - incident_lessons_learned
-- Schema: ops
-- Description: "Lessons Learned" from post-incident reviews.
-- Business Case: Failing is learning. This table stores the lessons. "Root cause: Configuration Error. Action: Add
// Config Approval Check". It feeds back into training (F082) and runbooks (T417) to prevent recurrence.
-- KPIs: Lesson Application Rate.
-- Feature Reference: T525
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.incident_lessons_learned (
    lesson_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incident.incident_tickets(ticket_id),
    category VARCHAR(50), -- 'PROCESS', 'TECHNOLOGY', 'COMMUNICATION'
    lesson_text TEXT NOT NULL,
    action_owner UUID,

    -- Metadata
    documented_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.incident_lessons_learned IS 'Wisdom repository ensuring operational improvements are captured and propagated after failures.';

------------------------------------------------------------------------------------------------
-- Table: T529 - on_call_handover_failures
-- Schema: ops
-- Description: Logs of failures where on-call (PagerDuty) systems failed to route calls.
-- Business Case: If the bank is on fire at 3 AM, and calls don't get routed, we are blind. This table logs
// incidents where the alerting system failed to escalate. It identifies gaps in the notification chain.
-- KPIs: Alert Handover Success Rate.
-- Feature Reference: T530
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.on_call_handover_failures (
    failover_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES incident.security_alert_queue(alert_id),
    escalation_target VARCHAR(100), -- Who was supposed to get the alert?
    failure_reason TEXT, -- 'ON_CALL_PROVIDER_DOWN', 'INVALID_PAGER_CONFIG'
    compensation_status VARCHAR(20),

    -- Metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.on_call_handover_failures IS 'Error log identifying gaps in critical escalation pathways.';

------------------------------------------------------------------------------------------------
-- Table: T530 - communication_outage_impact
-- Schema: ops
-- Description: Analysis of impact when email/SMS/Slack channels are down.
-- Business Case: "Users can't reset passwords" is an outage. This table assesses the impact of communication
// outages. It estimates "Users affected", "Transactions Blocked", and "Revenue Risk". It helps
// Ops prioritize fixing the channel (e.g., fix Email before fixing Slack).
-- KPIs: Impact Assessment Accuracy.
-- Feature Reference: T529
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.communication_outage_impact (
    impact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    channel_type VARCHAR(20) NOT NULL, -- 'EMAIL', 'SMS', 'PUSH', 'WEBHOOK'
    outage_start TIMESTAMP WITH TIME ZONE NOT NULL,
    outage_end TIMESTAMP WITH TIME ZONE,
    estimated_users_affected BIGINT,
    transaction_count_blocked BIGINT,
    revenue_impact_estimate NUMERIC(15,2),

    -- Metadata
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE ops.communication_outage_impact IS 'Business impact analysis of system unavailability on user-facing communication channels.';

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- 7. TRIGGER APPLICATION FOR PART 8 TABLES
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------

CREATE TRIGGER trg_multi_sig_verification_timestamp
    BEFORE UPDATE ON sec.multi_sig_wallet_verification
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_compliance_officer_assignments_timestamp
    BEFORE UPDATE ON ops.compliance_officer_assignments
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_inference_rule_engine_timestamp
    BEFORE UPDATE ON knowledge.inference_rule_engine
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_region_sync_lag_timestamp
    BEFORE UPDATE ON ops.region_sync_lag
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_fire_drill_audit_timestamp
    BEFORE UPDATE ON ops.fire_drill_audit
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_compliance_whistleblower_reports_timestamp
    BEFORE UPDATE ON compliance.whistleblower_reports
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_compliance_training_records_timestamp
    BEFORE UPDATE ON hr.compliance_training_records
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

CREATE TRIGGER trg_natural_language_query_logs_timestamp
    ON INSERT INTO knowledge.natural_language_query_logs
    FOR EACH STATEMENT EXECUTE FUNCTION trigger_set_created_at_timestamp();

CREATE TRIGGER trg_disaster_recovery_failover_log_timestamp
    BEFORE UPDATE ON ops.disaster_recovery_failover_log
    FOR EACH ROW EXECUTE FUNCTION common.manage_timestamps();

-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
-- END OF SCRIPT (Part 8: Tables 451-550)
-- ----------------------------------------------------------------------------------------------------------------------------------------------------------
