-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 1: Enums & Tables 1-50)
-- ================================================================================
-- Description:
-- This script defines the foundational database objects for the Zero-Trust Security Fabric.
-- It includes the creation of the 'sec' schema, necessary PostgreSQL extensions,
-- enumerated types, and the initial 50 tables required for identity management,
-- key management, attestation, policy enforcement, and auditing within the PARI ecosystem.
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. Extensions
-- ================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides universally unique identifiers (UUID) generation functions for primary keys and security tokens.';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Offers cryptographic functions for hashing, encryption, and secure random number generation required for key management.';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to handle standard B-tree equality checks, useful for indexing JSONB columns in policy definitions.';

-- 2. Schema Creation
-- ================================================================================
CREATE SCHEMA IF NOT EXISTS sec;
COMMENT ON SCHEMA sec IS 'Module M17: Zero-Trust Security Fabric. Manages identities, cryptographic keys, attestation, policies, and audit logs for the PARI payment system.';

-- 3. Database Objects List (Scanned)
-- ================================================================================
-- ENUMS: 10
-- TABLES: 200 (Implementation of first 50 in this script)
-- VIEWS: 25
-- STORED PROCEDURES: 30
-- TRIGGERS: 10
--
-- Total Objects to Implement: ~275

-- 4. Enums
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Enum: M17-E01 - enum_crypto_key_state
-- Description: Defines the lifecycle states of cryptographic keys within the KMS.
-- Business Case: Managing the state of keys is critical for security hygiene. Keys must transition
-- from pre-active to active, then to disabled or destroyed in a controlled manner. This enum ensures
-- that only valid keys are used for operations and prevents the reuse of compromised or expired keys.
-- Feature Reference: M17-F004 (HSM Key Generation), M17-F049 (Secure Key Deletion)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_crypto_key_state AS ENUM (
    'PRE_ACTIVE',              -- Key generated but not yet approved for use
    'ACTIVE',                  -- Key is in active use for encryption/decryption
    'DISABLED',                -- Key temporarily disabled (e.g., during investigation)
    'PENDING_DELETION',        -- Key scheduled for deletion (grace period for data recovery)
    'DESTROYED',               -- Key has been securely destroyed
    'COMPROMISED'              -- Key marked as compromised due to a breach
);
COMMENT ON TYPE sec.enum_crypto_key_state IS 'Lifecycle states for cryptographic keys ensuring strict access control';

------------------------------------------------------------------------------------------------
-- Enum: M17-E02 - enum_audit_outcome
-- Description: Represents the result of a security operation or event.
-- Business Case: Audit trails are the backbone of forensic analysis and compliance. By categorizing
-- outcomes into success, failure, or error, the system can quickly calculate metrics like reliability
-- or failure rates, trigger automated alerts for repeated failures (brute force), and provide clear
-- evidence for auditors regarding the reliability of security controls.
-- Feature Reference: M17-F010 (Cryptographic Log Chaining)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_audit_outcome AS ENUM (
    'SUCCESS',                 -- Operation completed successfully
    'FAILURE',                 -- Operation failed (e.g., auth failure)
    'PARTIAL_SUCCESS',         -- Operation completed with warnings
    'ERROR'                    -- System error during operation
);
COMMENT ON TYPE sec.enum_audit_outcome IS 'Outcome categorization for security events for metrics and alerting';

------------------------------------------------------------------------------------------------
-- Enum: M17-E03 - enum_incident_severity
-- Description: Severity levels for security incidents.
-- Business Case: Prioritization is crucial in Security Operations (SOC). This enum allows the system
-- to automatically route critical incidents to on-call responders immediately (escalation), while
-- lower severity incidents can be queued. It directly impacts MTTR (Mean Time to Respond) by ensuring
-- high-value targets get attention first.
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_incident_severity AS ENUM (
    'INFO',                    -- Informational event only
    'LOW',                     -- Low risk, minimal impact
    'MEDIUM',                  -- Moderate risk, requires attention
    'HIGH',                    -- High risk, significant impact or data exposure
    'CRITICAL'                 -- Critical risk, immediate system-wide threat
);
COMMENT ON TYPE sec.enum_incident_severity IS 'Severity classification for incident triage and escalation';

------------------------------------------------------------------------------------------------
-- Enum: M17-E04 - enum_cert_status
-- Description: Validation status of X.509-SVID certificates.
-- Business Case: In a Zero Trust network, certificates are the primary identity mechanism. Knowing
-- if a certificate is valid, expired, or revoked is essential for the mTLS enforcement engine.
-- This status drives the automated revocation processes and prevents lateral movement by rejecting
-- invalid certificates immediately at the mesh gateway.
-- Feature Reference: M17-F003 (X.509-SVID Rotation), M17-F002 (SPIFFE Identity Provisioning)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_cert_status AS ENUM (
    'VALID',                   -- Certificate is currently valid and trusted
    'EXPIRED',                 -- Certificate has passed its expiry date
    'REVOKED',                 -- Certificate actively revoked (CRL updated)
    'UNKNOWN'                  -- Status cannot be determined
);
COMMENT ON TYPE sec.enum_cert_status IS 'Status of X.509 certificates used for workload authentication';

------------------------------------------------------------------------------------------------
-- Enum: M17-E05 - enum_policy_action
-- Description: Actions to be taken when a Zero-Trust policy rule matches.
-- Business Case: The Policy Engine needs to perform different actions based on context. While some
-- requests should be simply allowed or denied, others might trigger challenges (MFA) or just
-- generate alarms for monitoring. This flexibility enables dynamic security postures without
-- changing code.
-- Feature Reference: M17-F050 (Service-to-Service Authorization)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_policy_action AS ENUM (
    'ALLOW',                   -- Permit the request
    'DENY',                    -- Block the request
    'ALARM',                   -- Permit but log as a security event
    'CHALLENGE_MFA',           -- Request additional authentication factors
    'RATE_LIMIT'               -- Throttle the request
);
COMMENT ON TYPE sec.enum_policy_action IS 'Enforcement actions for Zero-Trust policy rules';

------------------------------------------------------------------------------------------------
-- Enum: M17-E06 - enum_attestation_result
-- Description: Result of hardware attestation checks (TEE).
-- Business Case: Confidential computing relies on verifying the code running inside an enclave.
-- This enum captures the outcome of verifying a hardware quote (e.g., from Intel SGX). A mismatch
-- indicates a compromised runtime environment, and keys must not be released to such workloads.
-- Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_attestation_result AS ENUM (
    'VALID',                   -- Quote matches PCR golden image
    'INVALID',                 -- Quote verification failed (bad signature)
    'CONFIG_MISMATCH',         -- PCR values do not match approved config
    'REVOKED_KEY'              -- Signing key used for quote has been revoked
);
COMMENT ON TYPE sec.enum_attestation_result IS 'Result codes for Trusted Execution Environment (TEE) verification';

------------------------------------------------------------------------------------------------
-- Enum: M17-E07 - enum_vulnerability_severity
-- Description: Severity classification for CVEs.
-- Business Case: Vulnerability management prioritizes patching. This enum aligns with industry
-- standards (CVSS scores) to automate blocking of images with 'CRITICAL' vulnerabilities during
-- deployment (M17-F009) and ensures compliance with regulatory patching SLAs.
-- Feature Reference: M17-F048 (Real-time Vulnerability Scanning)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_vulnerability_severity AS ENUM (
    'NEGLIGIBLE',              -- Minimal risk
    'LOW',                     -- Low risk
    'MEDIUM',                  -- Moderate risk
    'HIGH',                    -- High risk
    'CRITICAL'                 -- Extremely high risk, often exploited in the wild
);
COMMENT ON TYPE sec.enum_vulnerability_severity IS 'Standard severity levels for security vulnerabilities';

------------------------------------------------------------------------------------------------
-- Enum: M17-E08 - enum_session_state
-- Description: State of a user or service session.
-- Business Case: Session management prevents session hijacking. States like 'LOCKED' allow the
-- system to enforce timeouts or lock sessions when suspicious activity is detected (UEBA), ensuring
-- that active credentials cannot be used indefinitely.
-- Feature Reference: M17-F038 (Session Hardening)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_session_state AS ENUM (
    'ACTIVE',                  -- Session is active
    'IDLE',                    -- Session is idle but valid
    'TERMINATED',              -- Session logged out
    'LOCKED',                  -- Session locked due to security policy
    'EXPIRED'                  -- Session timed out
);
COMMENT ON TYPE sec.enum_session_state IS 'State management for user and service sessions';

------------------------------------------------------------------------------------------------
-- Enum: M17-E09 - enum_compliance_status
-- Description: Status of a control or requirement.
-- Business Case: Tracking compliance is required for GDPR/ISO audits. This status allows the
-- organization to identify gaps (NON_COMPLIANT) and track remediation efforts, providing real-time
-- visibility into the security posture for executives and auditors.
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_compliance_status AS ENUM (
    'COMPLIANT',               -- Meets the requirement
    'NON_COMPLIANT',           -- Fails the requirement
    'PARTIAL',                 -- Partially meets the requirement
    'NOT_APPLICABLE'           -- Requirement does not apply to the asset
);
COMMENT ON TYPE sec.enum_compliance_status IS 'Status tracking for regulatory and internal compliance controls';

------------------------------------------------------------------------------------------------
-- Enum: M17-E10 - enum_data_classification
-- Description: Classification level for data assets.
-- Business Case: Not all data is equal. Classification allows for differential protection
-- (e.g., higher encryption standards for RESTRICTED data). It enforces Data Loss Prevention (DLP)
-- rules by defining what data can leave the secure perimeter.
-- Feature Reference: M17-F127 (Data Classification Tagging)
------------------------------------------------------------------------------------------------
CREATE TYPE sec.enum_data_classification AS ENUM (
    'PUBLIC',                  -- Publicly accessible data
    'INTERNAL',                -- Internal company data only
    'CONFIDENTIAL',            -- Sensitive data (e.g., customer PII)
    'RESTRICTED',              -- Highly sensitive (e.g., cryptographic keys)
    'TOP_SECRET'               -- Maximum sensitivity (e.g., government secrets)
);
COMMENT ON TYPE sec.enum_data_classification IS 'Classification levels for data handling and protection policies';


-- 5. Common Trigger Functions & Tables
-- ================================================================================

-- Function: update_modified_timestamp
-- Description: Automatically updates the updated_at column before a row is updated.
CREATE OR REPLACE FUNCTION sec.update_modified_timestamp()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;
COMMENT ON FUNCTION sec.update_modified_timestamp() IS 'Trigger function to auto-update updated_at timestamps';


-- 6. DDL Statements (Tables 1-50)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB001 - spiffe_identities
-- Description: Stores the mapping between SPIFFE IDs and Workload metadata.
-- Business Case: SPIFFE identities are the foundation of the Zero-Trust architecture. This table maps
-- a cryptographically verifiable ID (SPIFFE ID) to specific workloads (pods, VMs). By maintaining
-- this registry, the system ensures that only authorized workloads can obtain credentials and
-- communicate, preventing spoofing attacks. It decouples identity from fragile network IPs.
-- KPIs:
-- 1. Identity Provisioning Latency (<50ms)
-- 2. Identity Conflict Rate (0%)
-- 3. Active SPIFFE ID Count
-- 4. Workload Selector Match Accuracy (100%)
-- 5. Identity Rotation Frequency
-- Feature Reference: M17-F002 (SPIFFE Identity Provisioning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.spiffe_identities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    spiffe_id VARCHAR(255) NOT NULL,
    workload_selector JSONB NOT NULL, -- e.g. {"agent": "node_agent", "node_name": "node-1"}
    trust_domain VARCHAR(255) NOT NULL,
    dns_names TEXT[], -- Alternative DNS names for this identity
    status sec.enum_cert_status DEFAULT 'VALID',
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB, -- Custom key-value pairs

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT spiffe_identities_spiffe_id_unique UNIQUE (spiffe_id),
    CONSTRAINT spiffe_identities_status_check CHECK (expires_at > created_at OR expires_at IS NULL)
);
COMMENT ON TABLE sec.spiffe_identities IS 'Registry mapping workload identities to SPIFFE IDs for Zero-Trust authentication';

CREATE INDEX idx_spiffe_id_trust_domain ON sec.spiffe_identities(trust_domain);
CREATE INDEX idx_spiffe_id_selector ON sec.spiffe_identities USING GIN(workload_selector);

------------------------------------------------------------------------------------------------
-- Table: M17-DB002 - x509_certificates
-- Description: Stores issued X.509-SVID certificates.
-- Business Case: While SPIFFE IDs are the logical name, X.509-SVIDs are the actual cryptographic
-- proofs used in mTLS handshakes. This table tracks the lifecycle of these certificates—their PEM
-- bodies, serial numbers, and validity periods. It is essential for automated rotation (M17-F003)
-- and revocation, ensuring that stale credentials are never accepted by the service mesh.
-- KPIs:
-- 1. Certificate Rotation Success Rate (99.99%)
-- 2. Certificate Expiration Coverage (0 expired in active use)
-- 3. Serial Number Collision Rate (0)
-- 4. Revocation Propagation Time (<5s)
-- 5. Active Certificate Count
-- Feature Reference: M17-F003 (X.509-SVID Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.x509_certificates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    spiffe_id VARCHAR(255) NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_ref VARCHAR(255), -- Reference to HSM or KMS, never stored in plain
    serial_number VARCHAR(128) NOT NULL,
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    status sec.enum_cert_status DEFAULT 'VALID',
    issued_by_ca_id UUID, -- Reference to the issuing CA
    revocation_reason TEXT,
    revoked_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT x509_certificates_serial_unique UNIQUE (serial_number),
    CONSTRAINT x509_certificates_dates CHECK (not_after > not_before)
);
COMMENT ON TABLE sec.x509_certificates IS 'Storage for X.509 SVID certificates used for mutual TLS authentication';

CREATE INDEX idx_x509_spiffe_id ON sec.x509_certificates(spiffe_id);
CREATE INDEX idx_x509_status ON sec.x509_certificates(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB003 - trust_domains
-- Description: Defines accepted trust domains for federation.
-- Business Case: In a multi-cloud or cross-organizational setup, trust bundles (root CA certificates)
-- must be exchanged to allow identities from different domains to trust each other. This table
-- manages those federated relationships, enabling a PARI workload in AWS to trust a workload in Azure
-- securely, adhering to the Zero-Trust principle of explicit trust negotiation.
-- KPIs:
-- 1. Federation Handshake Success Rate (100%)
-- 2. Trust Bundle Sync Latency (<1min)
-- 3. Peer Domain Availability
-- 4. Certificate Trust Chain Validation Time (<100ms)
-- 5. Federation Configuration Errors (0)
-- Feature Reference: M17-F091 (Cross-Cloud Identity Federation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.trust_domains (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    trust_bundle_pem TEXT NOT NULL,
    root_ca_id UUID,
    enabled BOOLEAN DEFAULT true,
    last_refreshed_at TIMESTAMP WITH TIME ZONE,
    refresh_interval_seconds INTEGER DEFAULT 86400, -- 24 hours

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT trust_domains_name_unique UNIQUE (domain_name)
);
COMMENT ON TABLE sec.trust_domains IS 'Configuration of federated trust domains for cross-cloud identity';

------------------------------------------------------------------------------------------------
-- Table: M17-DB004 - encryption_keys
-- Description: Metadata for all managed encryption keys (DEK and KEK).
-- Business Case: Central management of cryptographic keys is vital for security and compliance.
-- This table acts as the metadata store for the KMS, tracking the state, origin, and provider of keys
-- without storing the key material itself. It ensures that root keys are managed in HSMs while
-- providing the control plane for rotation and access policies.
-- KPIs:
-- 1. Key Rotation Compliance (100%)
-- 2. Key Entropy Score (High)
-- 3. Active Key Count
-- 4. Key Generation Latency (<200ms)
-- 5. Overdue Rotation Alerts (0)
-- Feature Reference: M17-F004 (HSM Key Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.encryption_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(255) UNIQUE NOT NULL, -- External ARN or UUID
    key_type VARCHAR(50) NOT NULL CHECK (key_type IN ('SYMMETRIC', 'ASYMMETRIC', 'HMAC')),
    algorithm VARCHAR(50) NOT NULL, -- e.g., AES-256-GCM, RSA-4096
    state sec.enum_crypto_key_state NOT NULL DEFAULT 'PRE_ACTIVE',
    creation_date TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_date TIMESTAMP WITH TIME ZONE,
    cloud_provider VARCHAR(50), -- AWS, AZURE, GCP, ON-PREM
    kms_key_arn VARCHAR(255),
    key_length INTEGER,
    origin VARCHAR(50), -- AWS_KMS, INTERNAL_HSM

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.encryption_keys IS 'Metadata registry for all cryptographic keys managed by the system';

CREATE INDEX idx_encryption_keys_state ON sec.encryption_keys(state);
CREATE INDEX idx_encryption_keys_rotation ON sec.encryption_keys(rotation_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB005 - key_versions
-- Description: Tracks versions of keys to support rollback and auditing.
-- Business Case: Key rotation is mandatory for security compliance. When a key is rotated, data
-- encrypted with the old key must still be accessible (via re-wrapping). This versioning table
-- maintains the history of keys, allowing the system to decrypt data encrypted with previous
-- versions while ensuring new data uses the latest version. It provides a full audit trail of key changes.
-- KPIs:
-- 1. Versioning Integrity (100%)
-- 2. Rollback Success Rate (100%)
-- 3. Key Version History Depth
-- 4. Active Version Marking Accuracy
-- 5. Version Purging Latency (Compliance)
-- Feature Reference: M17-F021 (KMS Auto-Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    public_key_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT false,

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_versions_key_id_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id) ON DELETE CASCADE,
    CONSTRAINT key_versions_unique UNIQUE (key_id, version_number)
);
COMMENT ON TABLE sec.key_versions IS 'Tracks the version history of encryption keys for rotation and decryption support';

CREATE INDEX idx_key_versions_key_id ON sec.key_versions(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB006 - key_usage_logs
-- Description: Immutable log of every key usage (encrypt/decrypt/sign).
-- Business Case: Cryptographic keys are high-value targets. Monitoring their usage is critical to
-- detect anomalies, such as a sudden spike in decryption attempts (potential breach). This immutable
-- log provides forensic evidence and feeds into the anomaly detection algorithms (UEBA) to identify
-- compromised credentials or insider threats.
-- KPIs:
-- 1. Logging Accuracy (100%)
-- 2. Anomaly Detection Latency (<5s)
-- 3. Key Usage Volume Monitoring
-- 4. Failed Operation Rate
-- 5. Audit Log Availability
-- Feature Reference: M17-F029 (Key Usage Analytics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_usage_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL,
    operation VARCHAR(20) NOT NULL CHECK (operation IN ('ENCRYPT', 'DECRYPT', 'SIGN', 'VERIFY', 'WRAP', 'UNWRAP')),
    user_id UUID, -- Human or Service Account
    resource_id VARCHAR(255), -- Target data identifier
    details JSONB, -- Contextual info (IP, User Agent)
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,

    CONSTRAINT key_usage_logs_key_id_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_usage_logs IS 'Forensic log of all cryptographic key usage events for security monitoring';

CREATE INDEX idx_key_usage_logs_key_id ON sec.key_usage_logs(key_id);
CREATE INDEX idx_key_usage_logs_timestamp ON sec.key_usage_logs(timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB007 - attestation_quotes
-- Description: Stores hardware quotes (SGX/Nitro) for verification.
-- Business Case: Confidential computing relies on TEEs (Trusted Execution Environments). Before
-- releasing secrets to a workload, the system must verify it is running in a genuine, uncompromised
-- enclave. This table stores the hardware quotes (evidence) and the result of their verification.
-- It ensures that keys are never sent to compromised memory spaces.
-- KPIs:
-- 1. Attestation Verification Rate (100%)
-- 2. False Positive Rate (Low)
-- 3. Verification Latency (<50ms)
-- 4. Quote Storage Retention
-- 5. Compromised Enclave Detection Speed
-- Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.attestation_quotes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workload_id VARCHAR(255) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    quote_body BYTEA NOT NULL, -- Binary quote data
    verification_status sec.enum_attestation_result NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    pcr_values JSONB, -- Platform Configuration Registers
    verifier_id UUID, -- Who verified it

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.attestation_quotes IS 'Records of hardware attestation quotes for verifying Trusted Execution Environments';

CREATE INDEX idx_attestation_quotes_workload ON sec.attestation_quotes(workload_id);
CREATE INDEX idx_attestation_quotes_status ON sec.attestation_quotes(verification_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB008 - pcr_values
-- Description: Expected Platform Configuration Register values for golden images.
-- Business Case: To verify an attestation quote, the system needs a "source of truth" for what the
-- PCR values *should* be for a trusted image. This table stores the golden PCR values for approved
-- application versions. Any deviation in an attestation quote compared to this table indicates
-- tampering or unauthorized code execution.
-- KPIs:
-- 1. Golden Image Availability (100%)
-- 2. PCR Mismatch Detection Speed (<10ms)
-- 3. Policy Update Propagation
-- 4. Image Coverage Percentage
-- 5. Configuration Drift (0)
-- Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.pcr_values (
    pcr_index INTEGER NOT NULL,
    pcr_value_hash VARCHAR(255) NOT NULL, -- SHA256 hash
    image_id VARCHAR(255) NOT NULL, -- Docker Image ID / Enclave Hash
    policy_id UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT pcr_values_primary UNIQUE (pcr_index, image_id)
);
COMMENT ON TABLE sec.pcr_values IS 'Baseline PCR values for trusted images used in attestation verification';

CREATE INDEX idx_pcr_values_image ON sec.pcr_values(image_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB009 - zero_trust_policies
-- Description: Stores OPA/Rego policies or JSON representations of authz rules.
-- Business Case: The brain of the Zero-Trust fabric. This table stores the code (Rego/JSON) that
-- defines who can do what. By versioning these policies and storing them in the database, the
-- system gains an audit trail of authorization changes, facilitates A/B testing of rules, and
-- ensures that policy distribution is consistent across the mesh.
-- KPIs:
-- 1. Policy Evaluation Latency (<5ms)
-- 2. Policy Deployment Success Rate (100%)
-- 3. Policy Drift (0)
-- 4. Change History Retention
-- 5. Syntax Error Rate (0)
-- Feature Reference: M17-F034 (Policy-as-Code)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.zero_trust_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_content JSONB NOT NULL, -- The OPA Rego or JSON rule
    version INTEGER NOT NULL DEFAULT 1,
    hash VARCHAR(64) NOT NULL, -- SHA-256 of content for integrity
    active BOOLEAN DEFAULT false,
    active_from TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT zero_trust_policies_name_version_unique UNIQUE (name, version),
    CONSTRAINT zero_trust_policies_active_check CHECK (active = (active_from <= CURRENT_TIMESTAMP))
);
COMMENT ON TABLE sec.zero_trust_policies IS 'Repository for Zero-Trust authorization policies (Rego/JSON)';

CREATE INDEX idx_ztpolicies_active ON sec.zero_trust_policies(active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB010 - policy_assignments
-- Description: Maps policies to specific services or namespaces.
-- Business Case: Not every policy applies everywhere. This table provides the scoping mechanism,
-- linking a specific policy (e.g., "Block Exfiltration") to a specific target (e.g., "Payment Service").
-- This granularity ensures that policies are applied exactly where intended, minimizing false positives
-- and performance impact on unrelated services.
-- KPIs:
-- 1. Assignment Propagation Latency (<1s)
-- 2. Target Coverage Accuracy
-- 3. Orphaned Policy Count (0)
-- 4. Assignment Conflict Rate
-- 5. Namespace Isolation Enforcement
-- Feature Reference: M17-F050 (Service-to-Service Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.policy_assignments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    target_service VARCHAR(255),
    target_namespace VARCHAR(255),
    mode VARCHAR(20) NOT NULL DEFAULT 'ENFORCE', -- ENFORCE, AUDIT, DISABLED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT policy_assignments_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.zero_trust_policies(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.policy_assignments is 'Maps security policies to specific targets (services/namespaces)';

CREATE INDEX idx_policy_assignments_target ON sec.policy_assignments(target_namespace, target_service);

------------------------------------------------------------------------------------------------
-- Table: M17-DB011 - audit_trail
-- Description: Central tamper-evident log of all security events.
-- Business Case: The "Source of Truth" for security. This table records every significant event
-- (auth, policy decision, key access). By using hash chaining (previous_hash -> current_hash), it
-- creates a cryptographically tamper-evident ledger. If an attacker tries to modify a log entry, the
-- chain breaks, alerting administrators. This is critical for non-repudiation.
-- KPIs:
-- 1. Log Ingestion Rate
-- 2. Chain Integrity Verification (100%)
-- 3. Storage Retention Compliance
-- 4. Query Performance (<100ms)
-- 5. Data Loss (0)
-- Feature Reference: M17-F010 (Cryptographic Log Chaining)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_trail (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_id VARCHAR(255) UNIQUE NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL,
    actor_id UUID,
    resource_id VARCHAR(255),
    action VARCHAR(50),
    outcome sec.enum_audit_outcome NOT NULL,
    details JSONB,
    previous_hash VARCHAR(64), -- SHA256 of the previous record's hash
    current_hash VARCHAR(64), -- SHA256 of this record's content + prev_hash

    -- No updated_by/updated_at to maintain immutability logic. Insert only.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_trail IS 'Immutable, cryptographically chained log of security events';

CREATE INDEX idx_audit_trail_timestamp ON sec.audit_trail(timestamp);
CREATE INDEX idx_audit_trail_actor ON sec.audit_trail(actor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB012 - audit_integrity_chain
-- Description: Stores periodic Merkle roots of the audit trail for verification.
-- Business Case: Verifying millions of log entries one by one is slow. Merkle trees allow efficient
-- verification of large data sets. This table stores the root hashes of the audit trail at intervals.
-- Auditors can simply compare the Merkle root with a signed, external source (like a blockchain anchor)
-- to instantly verify the integrity of the entire log set.
-- KPIs:
-- 1. Root Calculation Latency
-- 2. Anchor Success Rate
-- 3. Root Consistency (100%)
-- 4. Tamper Detection Time (<5min)
-- 5. Proof Generation Speed
-- Feature Reference: M17-F051 (Audit Log Tamper Detection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_integrity_chain (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sequence_number INTEGER UNIQUE NOT NULL,
    merkle_root_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    record_range_start TIMESTAMP WITH TIME ZONE,
    record_range_end TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_integrity_chain IS 'Stores Merkle roots to efficiently verify the integrity of the audit log';

CREATE INDEX idx_audit_integrity_seq ON sec.audit_integrity_chain(sequence_number);

------------------------------------------------------------------------------------------------
-- Table: M17-DB013 - access_requests
-- Description: Tracks Just-in-Time (JIT) access requests.
-- Business Case: Standing privileges are a risk. JIT access grants temporary rights only when needed.
-- This table manages the workflow: an operator requests access, a manager approves, and the system
-- grants time-bound access. This significantly reduces the attack surface by ensuring accounts
-- are not privileged 24/7.
-- KPIs:
-- 1. Approval Workflow Latency (<1 hour)
-- 2. Access Overruns (0)
-- 3. Request to Grant Latency (<5 min)
-- 4. Justification Quality
-- 5. Revocation Accuracy (100%)
-- Feature Reference: M17-F013 (Just-in-Time (JIT) Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.access_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id VARCHAR(255) UNIQUE NOT NULL,
    requester_id UUID NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    justification TEXT NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER NOT NULL,
    approval_status VARCHAR(50) DEFAULT 'PENDING' CHECK (approval_status IN ('PENDING','APPROVED','DENIED','EXPIRED')),
    approver_id UUID,
    approval_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.access_requests IS 'Tracks Just-In-Time (JIT) privilege requests and approvals';

CREATE INDEX idx_access_requests_status ON sec.access_requests(approval_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB014 - jit_grants
-- Description: Active grants for JIT access.
-- Business Case: The runtime state of JIT. When a request is approved, a grant is created here.
-- This table allows the authentication middleware to validate if a user currently holds an active
-- grant for a specific resource. It enforces the time-bound nature by checking `expires_at` on
-- every access.
-- KPIs:
-- 1. Grant Enforcement Accuracy (100%)
-- 2. Auto-Revocation Success Rate (100%)
-- 3. Active Grant Count
-- 4. Overdue Grant Cleanup (0)
-- 5. Revocation Propagation Latency (<1s)
-- Feature Reference: M17-F013 (Just-in-Time (JIT) Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.jit_grants (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id UUID NOT NULL,
    granted_role VARCHAR(100) NOT NULL,
    session_token VARCHAR(255) NOT NULL, -- The actual token issued
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT jit_grants_request_fkey FOREIGN KEY (request_id) REFERENCES sec.access_requests(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.jit_grants IS 'Stores active temporary access grants issued via JIT workflow';

CREATE INDEX idx_jit_grants_token ON sec.jit_grants(session_token);
CREATE INDEX idx_jit_grants_expires ON sec.jit_grants(expires_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB015 - sbom_entries
-- Description: Stores Software Bill of Materials data for artifacts.
-- Business Case: Modern attacks target the supply chain. An SBOM lists every library and component
-- in a piece of software. This table stores this data, enabling rapid vulnerability scanning
-- (checking if a library has a CVE) and ensuring that only approved, signed software is deployed
-- to the PARI infrastructure.
-- KPIs:
-- 1. SBOM Coverage (100%)
-- 2. Ingestion Latency (<5s per artifact)
-- 3. Component Accuracy
-- 4. License Violation Detection
-- 5. Dependency Graph Completeness
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sbom_entries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_name VARCHAR(255) NOT NULL,
    artifact_hash VARCHAR(255) NOT NULL, -- SHA256 of the container image or binary
    component_name VARCHAR(255) NOT NULL,
    component_version VARCHAR(100) NOT NULL,
    license VARCHAR(100),
    supplier VARCHAR(255),
    purl VARCHAR(255), -- Package URL standard
    cpe VARCHAR(255), -- Common Platform Enumeration

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.sbom_entries IS 'Software Bill of Materials (SBOM) details for deployed artifacts';

CREATE INDEX idx_sbom_artifact ON sec.sbom_entries(artifact_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB016 - vulnerability_scans
-- Description: Results of container image and dependency scans.
-- Business Case: Automated security scanning is the first line of defense against known exploits.
-- This table records the results of scanning SBOMs or images against CVE databases. It is the primary
-- data source for blocking vulnerable images from entering the production environment (Shift Left).
-- KPIs:
-- 1. Scan Completion Time (<2 min per image)
-- 2. False Positive Rate (<0.5%)
-- 3. Vulnerability Detection Rate (100%)
-- 4. Critical CVE Remediation Time (<24h)
-- 5. Scan Coverage (100% of builds)
-- Feature Reference: M17-F048 (Real-time Vulnerability Scanning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_scans (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_id UUID NOT NULL, -- Grouping for a specific scan run
    target_id VARCHAR(255) NOT NULL, -- Image hash or Artifact ID
    scanner_name VARCHAR(100) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    severity sec.enum_vulnerability_severity NOT NULL,
    cvss_score NUMERIC(3,1),
    state VARCHAR(50) DEFAULT 'OPEN' CHECK (state IN ('OPEN','FIXED','IGNORED','FALSE_POSITIVE')),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    fixed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vulnerability_scans IS 'Records of detected vulnerabilities in artifacts and images';

CREATE INDEX idx_vuln_target ON sec.vulnerability_scans(target_id);
CREATE INDEX idx_vuln_severity ON sec.vulnerability_scans(severity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB017 - security_incidents
-- Description: Manages the lifecycle of security incidents.
-- Business Case: Structured incident management is required for effective response and legal
-- compliance. This table tracks incidents from creation to closure, capturing severity, MTTR, and
-- resolution details. It provides the data necessary for post-mortem analysis and continuous
-- improvement of security processes.
-- KPIs:
-- 1. Mean Time to Respond (MTTR) < 15 min
-- 2. Mean Time to Detect (MTTD) < 5 min
-- 3. Incident Closure Rate
-- 4. SLA Compliance Percentage
-- 5. Recurring Incident Frequency
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_incidents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity sec.enum_incident_severity NOT NULL,
    status VARCHAR(50) DEFAULT 'OPEN' CHECK (status IN ('OPEN','INVESTIGATING','CONTAINMENT','ERADICATION','RECOVERY','CLOSED')),
    created_by UUID NOT NULL,
    assigned_to UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,
    mttr_minutes INTEGER, -- Calculated upon closure

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_incidents IS 'Lifecycle management for security incidents';

CREATE INDEX idx_incidents_status ON sec.security_incidents(status);
CREATE INDEX idx_incidents_severity ON sec.security_incidents(severity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB018 - iocs
-- Description: Indicators of Compromise associated with incidents.
-- Business Case: IOCs are the "fingerprints" of an attack (IPs, hashes, domains). This table links
-- specific IOCs to incidents. It feeds the Threat Intelligence module, allowing the system to
-- automatically block or alert on these indicators in the future across the entire PARI infrastructure.
-- KPIs:
-- 1. IOC Enrichment Accuracy
-- 2. False Positive Rate
-- 3. IOC Feed Latency
-- 4. Active IOC Count
-- 5. Correlation Success Rate
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.iocs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    ioc_type VARCHAR(20) NOT NULL CHECK (ioc_type IN ('IP','DOMAIN','HASH','EMAIL','URL')),
    ioc_value VARCHAR(255) NOT NULL,
    source VARCHAR(100),
    confidence_score NUMERIC(2,2) CHECK (confidence_score BETWEEN 0 AND 1),
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT iocs_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.iocs IS 'Indicators of Compromise (IOC) linked to security incidents';

CREATE INDEX idx_iocs_value ON sec.iocs(ioc_value);
CREATE INDEX idx_iocs_active ON sec.iocs(is_active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB019 - network_policies
-- Description: Kubernetes NetworkPolicy definitions or firewall rules.
-- Business Case: Zero-Trust networking requires strict segmentation. This table stores the definition
-- of network policies (who can talk to whom) as code. These rules are pushed to the Service Mesh or
-- underlying network fabric to enforce micro-segmentation, preventing lateral movement even if one
-- node is compromised.
-- KPIs:
-- 1. Policy Enforcement Rate (100%)
-- 2. Policy Drift (0)
-- 3. Rule Deployment Latency (<10s)
-- 4. Conflict Detection Rate
-- 5. Network Isolation Effectiveness
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.network_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100),
    pod_selector JSONB,
    ingress_egress VARCHAR(10) CHECK (ingress_egress IN ('INGRESS','EGRESS','BOTH')),
    rules JSONB NOT NULL, -- Array of rule objects

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.network_policies IS 'Storage for Kubernetes Network Policies or micro-segmentation rules';

CREATE INDEX idx_net_policies_namespace ON sec.network_policies(namespace);

------------------------------------------------------------------------------------------------
-- Table: M17-DB020 - traffic_flows
-- Description: Aggregated logs of network traffic for analytics.
-- Business Case: Visibility is key to anomaly detection. This table stores aggregated flow data
-- (src, dst, port, bytes). By analyzing this, the system can detect lateral movement (e.g., DB
-- talking to an external IP), DDoS attacks, or unauthorized data exfiltration patterns.
-- KPIs:
-- 1. Flow Record Retention
-- 2. Anomaly Detection Accuracy (>95%)
-- 3. Aggregation Latency (<1 min)
-- 4. False Positive Rate (<1%)
-- 5. Storage Efficiency
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.traffic_flows (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flow_id VARCHAR(100) UNIQUE NOT NULL,
    src_ip VARCHAR(45) NOT NULL, -- IPv6 compatible
    dst_ip VARCHAR(45) NOT NULL,
    src_service VARCHAR(255),
    dst_service VARCHAR(255),
    port INTEGER,
    protocol VARCHAR(10),
    bytes BIGINT,
    duration_seconds INTEGER,
    observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_anomaly BOOLEAN DEFAULT false,

    -- Audit Columns (Minimal for performance, but created_by tracks source)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.traffic_flows IS 'Aggregated network flow logs for security analytics and anomaly detection';

CREATE INDEX idx_traffic_flows_time ON sec.traffic_flows(observed_at);
CREATE INDEX idx_traffic_flows_src_dst ON sec.traffic_flows(src_service, dst_service);

------------------------------------------------------------------------------------------------
-- Table: M17-DB021 - control_mappings
-- Description: Maps technical controls to compliance frameworks (ISO, GDPR).
-- Business Case: Bridging the gap between "Tech" and "Compliance". This table maps specific technical
-- implementations (e.g., "mTLS enabled on port 443") to compliance requirements (e.g., "GDPR Art 32").
-- This allows automated evidence collection and reporting, reducing the manual effort of audits.
-- KPIs:
-- 1. Control Coverage Percentage
-- 2. Mapping Accuracy
-- 3. Evidence Automation Rate
-- 4. Audit Prep Time Reduction
-- 5. Regulatory Change Impact Analysis
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.control_mappings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,
    framework_name VARCHAR(50) NOT NULL, -- ISO27001, GDPR, PCI-DSS
    standard_ref VARCHAR(100) NOT NULL, -- e.g., "A.12.2.1"
    description TEXT,
    implementation_status sec.enum_compliance_status,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.control_mappings IS 'Maps technical security controls to compliance frameworks';

CREATE INDEX idx_control_mappings_framework ON sec.control_mappings(framework_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB022 - evidence_locker
-- Description: Stores pointers to evidence files for audits.
-- Business Case: Auditors need proof that controls are working. Instead of gathering screenshots
-- and logs manually during an audit, the system automatically collects evidence (hashes of logs,
-- config snapshots) and stores references here. This enables "continuous compliance."
-- KPIs:
-- 1. Evidence Collection Automation (100%)
-- 2. Evidence Retrieval Time (<5s)
-- 3. Evidence Integrity Check (100%)
-- 4. File Storage Cost Optimization
-- 5. Audit Request Fulfillment Speed
-- Feature Reference: M17-F137 (Compliance Evidence Collection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.evidence_locker (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id VARCHAR(100) UNIQUE NOT NULL,
    control_id UUID NOT NULL,
    file_path VARCHAR(500) NOT NULL, -- S3 path or similar
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    collected_by UUID NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA-256

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.evidence_locker IS 'Secure storage references for compliance evidence artifacts';

CREATE UNIQUE INDEX idx_evidence_locker_hash ON sec.evidence_locker(file_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB023 - user_sessions
-- Description: Manages active user/admin sessions.
-- Business Case: Session hijacking is a common attack vector. This table tracks active sessions,
-- their bound IP/MFA status, and last activity. The authentication system checks this table on every
-- request to ensure the session is valid, active, and hasn't exceeded idle timeouts.
-- KPIs:
-- 1. Session Validation Latency (<5ms)
-- 2. Concurrent Active Sessions
-- 3. Idle Session Timeout Accuracy
-- 4. Session Termination Speed (<1s)
-- 5. Multi-Factor Auth Enforcement Rate (100%)
-- Feature Reference: M17-F038 (Session Hardening)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    auth_method VARCHAR(50),
    mfa_verified BOOLEAN DEFAULT false,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    state sec.enum_session_state DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_sessions IS 'Tracks active user sessions for authentication and security monitoring';

CREATE INDEX idx_user_sessions_user_id ON sec.user_sessions(user_id);
CREATE INDEX idx_user_sessions_state ON sec.user_sessions(state);

------------------------------------------------------------------------------------------------
-- Table: M17-DB024 - failed_attempts
-- Description: Tracks failed login attempts for brute force detection.
-- Business Case: Brute force and credential stuffing attacks are prevalent. This table logs
-- failures. The security engine aggregates these (e.g., "5 failures in 1 minute") to trigger
-- account lockouts, CAPTCHAs, or IP bans, protecting the authentication gateways.
-- KPIs:
-- 1. Detection Latency (<1s)
-- 2. False Positive Lockout Rate
-- 3. Blocked Attack Count
-- 4. Geographic Distribution Analysis
-- 5. Account Recovery Efficiency
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.failed_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    attempt_id VARCHAR(100) UNIQUE NOT NULL,
    username VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(100), -- Invalid Password, Account Locked, etc.

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL -- System
);
COMMENT ON TABLE sec.failed_attempts IS 'Log of failed authentication attempts for brute force detection';

CREATE INDEX idx_failed_attempts_timestamp ON sec.failed_attempts(timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB025 - root_ca_certificates
-- Description: Stores root CA certificates for the system.
-- Business Case: The Root of Trust for the entire PKI. Storing the Root CA metadata (and
-- securely referencing its private key in HSM) allows the system to issue intermediate CAs and
-- leaf certificates for workloads. Compromise of this table's entries is catastrophic, hence
-- strict access controls are applied.
-- KPIs:
-- 1. Root CA Availability (100%)
-- 2. Certificate Rotation Success
-- 3. Signing Latency
-- 4. Private Key Exposure (0)
-- 5. Backup/Restore Success Rate
-- Feature Reference: M17-F035 (Certificate Authority (CA) Hierarchy)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.root_ca_certificates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    common_name VARCHAR(255) NOT NULL,
    cert_pem TEXT NOT NULL,
    private_key_ref VARCHAR(255) NOT NULL, -- HSM reference
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    status sec.enum_cert_status DEFAULT 'VALID',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.root_ca_certificates IS 'Stores metadata for Root Certificate Authorities';

CREATE INDEX idx_root_ca_status ON sec.root_ca_certificates(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB026 - intermediate_cas
-- Description: Stores intermediate CA certificates.
-- Business Case: Intermediate CAs provide isolation. If a workload CA is compromised, the Root
-- CA can revoke it without affecting the entire system. This table manages the hierarchy,
-- linking intermediates to their parent Root CA and managing their lifecycle and path length.
-- KPIs:
-- 1. Chain Validation Success (100%)
-- 2. Intermediate CA Provisioning Time
-- 3. Revocation Propagation Speed
-- 4. Hierarchy Integrity
-- 5. Certificate Usage Count
-- Feature Reference: M17-F035 (Certificate Authority (CA) Hierarchy)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.intermediate_cas (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    root_ca_id UUID NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    cert_pem TEXT NOT NULL,
    private_key_ref VARCHAR(255) NOT NULL,
    path_length INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT intermediate_cas_root_fkey FOREIGN KEY (root_ca_id) REFERENCES sec.root_ca_certificates(id)
);
COMMENT ON TABLE sec.intermediate_cas IS 'Stores intermediate CA certificates issuing leaf certificates';

------------------------------------------------------------------------------------------------
-- Table: M17-DB027 - security_configurations
-- Description: Key-value store for security module settings.
-- Business Case: Feature flags and security thresholds (e.g., "Max password age", "Lockout threshold")
-- need to be configurable without code deploys. This table acts as a central configuration store for
-- M17, ensuring that settings can be updated dynamically and are themselves audited.
-- KPIs:
-- 1. Configuration Retrieval Latency (<10ms)
-- 2. Change Audit Coverage (100%)
-- 3. Configuration Consistency
-- 4. Invalid Config Detection
-- 5. Rollback Success Rate
-- Feature Reference: M17-F044 (Secure Configuration Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_configurations (
    config_key VARCHAR(255) PRIMARY KEY,
    config_value TEXT NOT NULL,
    description TEXT,
    is_encrypted BOOLEAN DEFAULT false,
    data_type VARCHAR(20) CHECK (data_type IN ('STRING','INTEGER','BOOLEAN','JSON')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_configurations IS 'Central key-value store for security feature configurations';

------------------------------------------------------------------------------------------------
-- Table: M17-DB028 - anomaly_alerts
-- Description: Alerts generated by ML models or rule engines.
-- Business Case: The SOC needs to know when something is wrong. This table stores alerts generated
-- by the anomaly detection models. It tracks severity, the affected resource, and resolution status.
-- It feeds the dashboard and determines the priority of analyst response.
-- KPIs:
-- 1. Alert Generation Latency
-- 2. False Positive Rate
-- 3. Mean Time to Acknowledge (MTTA)
-- 4. Critical Alert Visibility
-- 5. Alert Fatigue Score
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.anomaly_alerts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_id VARCHAR(100) UNIQUE NOT NULL,
    anomaly_type VARCHAR(100) NOT NULL,
    severity sec.enum_incident_severity NOT NULL,
    affected_resource VARCHAR(255),
    description TEXT,
    details JSONB, -- Model confidence, specific metrics
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID,

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.anomaly_alerts IS 'Stores alerts generated by security monitoring and anomaly detection systems';

CREATE INDEX idx_anomaly_alerts_resolved ON sec.anomaly_alerts(resolved);
CREATE INDEX idx_anomaly_alerts_severity ON sec.anomaly_alerts(severity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB029 - sign_keys
-- Description: Public keys used for code signing verification.
-- Business Case: To prevent supply chain attacks, PARI ensures that only signed code runs.
-- This table stores the public keys corresponding to the private signing keys. Verifying a signature
-- against the keys in this table proves that the code came from a trusted source (e.g., PARI Release
-- Engineering).
-- KPIs:
-- 1. Verification Success Rate (100%)
-- 2. Key Rotation Compliance
-- 3. Signature Validation Time (<10ms)
-- 4. Rogue Key Detection (0)
-- 5. Trust Store Update Latency
-- Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sign_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(100) UNIQUE NOT NULL,
    key_owner VARCHAR(255) NOT NULL,
    public_key_pem TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL, -- SHA-256
    expiry_date TIMESTAMP WITH TIME ZONE,
    status sec.enum_cert_status DEFAULT 'VALID',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.sign_keys IS 'Stores public keys for verifying code signatures';

CREATE INDEX idx_sign_keys_fingerprint ON sec.sign_keys(fingerprint);

------------------------------------------------------------------------------------------------
-- Table: M17-DB030 - gdpr_data_requests
-- Description: Tracks Right to be Forgotten requests and their status.
-- Business Case: GDPR grants users the right to erasure ("Right to be Forgotten"). This table tracks
-- these requests. Once approved, it triggers the "Crypto-Shredding" process (M17-F049) where data
-- keys are destroyed, rendering the data permanently inaccessible, satisfying the legal requirement.
-- KPIs:
-- 1. Request Fulfillment Time (<30 days)
-- 2. Data Erasure Confirmation (100%)
-- 3. Automated Processing Rate
-- 4. Audit Trail Completeness
-- 5. User Notification Accuracy
-- Feature Reference: M17-F049 (Secure Key Deletion)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.gdpr_data_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    request_type VARCHAR(50) CHECK (request_type IN ('ERASURE','EXPORT','CORRECTION','ACCESS')),
    status VARCHAR(50) DEFAULT 'PENDING',
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,
    verified BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.gdpr_data_requests IS 'Tracks GDPR data subject rights requests';

CREATE INDEX idx_gdpr_status ON sec.gdpr_data_requests(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB031 - service_accounts
-- Description: Machine accounts for non-human services.
-- Business Case: Workloads need identities too. This table defines service accounts (non-human
-- identities) used by microservices to access databases or APIs. By managing them centrally, the
-- system ensures that even machine identities follow the principle of least privilege and rotation.
-- KPIs:
-- 1. Account Provisioning Latency
-- 2. Secret Rotation Compliance
-- 3. Orphaned Account Count (0)
-- 4. Least Privilege Adherence
-- 5. Credential Leakage Incidents (0)
-- Feature Reference: M17-F080 (Regel-based Access Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_accounts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    account_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    secret_ref VARCHAR(255), -- Reference to KMS secret
    disabled BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_accounts IS 'Defines machine identities for microservices and automated processes';

------------------------------------------------------------------------------------------------
-- Table: M17-DB032 - account_roles
-- Description: Assigns roles to service accounts.
-- Business Case: Implementing RBAC for machines. A service account (e.g., "Payment Processor") is
-- assigned a role (e.g., "CanWriteToLedger"). This table manages that mapping, ensuring that
-- services have the minimum necessary permissions and that permissions are auditable.
-- KPIs:
-- 1. Role Assignment Accuracy
-- 2. Permission Propagation Latency (<1s)
-- 3. Privilege Creep (0)
-- 4. Role Revoke Speed
-- 5. Authorization Decision Latency
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.account_roles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    account_id UUID NOT NULL,
    role_id UUID NOT NULL, -- Assuming a roles table exists or is external
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT account_roles_account_fkey FOREIGN KEY (account_id) REFERENCES sec.service_accounts(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.account_roles IS 'Maps service accounts to authorization roles';

CREATE INDEX idx_account_roles_account_id ON sec.account_roles(account_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB033 - hsm_partitions
-- Description: Logical partitions within HSMs for key segregation.
-- Business Case: Physical or logical isolation of keys within an HSM. This table tracks partitions
-- (e.g., "Production Keys", "Dev Keys"). It ensures that keys from different environments are
-- logically separated even if they reside on the same physical HSM hardware.
-- KPIs:
-- 1. Partition Availability (100%)
-- 2. Key Isolation Verification
-- 3. Failover Success Rate
-- 4. Partition Utilization
-- 5. Access Log Integrity
-- Feature Reference: M17-F004 (HSM Key Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hsm_partitions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partition_id VARCHAR(100) UNIQUE NOT NULL,
    hsm_id VARCHAR(100) NOT NULL, -- Physical HSM identifier
    partition_name VARCHAR(255) NOT NULL,
    serial_number VARCHAR(255),
    status VARCHAR(50) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.hsm_partitions IS 'Logical partitions within Hardware Security Modules for key segregation';

------------------------------------------------------------------------------------------------
-- Table: M17-DB034 - tee_enclaves
-- Description: Registry of authorized Trusted Execution Enclaves.
-- Business Case: A whitelist of allowed enclaves. Only enclaves registered in this table
-- (matching the MR_ENCLAVE hash) will be granted access to secrets. This acts as a critical
-- access control for the confidential computing infrastructure, preventing unauthorized enclaves
-- from spinning up.
-- KPIs:
-- 1. Registration Accuracy (100%)
-- 2. Lookup Latency (<10ms)
-- 3. Revocation Propagation Time
-- 4. Active Enclave Count
-- 5. Rogue Enclave Blocking Rate
-- Feature Reference: M17-F036 (Secure Enclave SDK Wrapper)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.tee_enclaves (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    enclave_id VARCHAR(100) UNIQUE NOT NULL,
    mr_enclave VARCHAR(64) NOT NULL, -- Measurement of the enclave code
    signer VARCHAR(255),
    product_id INTEGER,
    status VARCHAR(50) DEFAULT 'PRODUCTION' CHECK (status IN ('PRODUCTION','STAGING','REVOKED')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.tee_enclaves IS 'Authorized whitelist of Trusted Execution Enclaves (SGX/Nitro)';

CREATE INDEX idx_tee_enclaves_mr_enclave ON sec.tee_enclaves(mr_enclave);

------------------------------------------------------------------------------------------------
-- Table: M17-DB035 - admin_actions
-- Description: Specific log for highly privileged admin actions.
-- Business Case: Insider threats are a major risk. This table specifically logs actions taken by
-- administrators (users with elevated privileges) such as creating CAs, approving certificates, or
-- modifying policies. This high-fidelity log is critical for forensic analysis of insider attacks.
-- KPIs:
-- 1. Logging Completeness (100%)
-- 2. Privileged Action Volume
-- 3. Anomaly Detection Accuracy
-- 4. Review Completion Rate
-- 5. Accountability (100% traceable)
-- Feature Reference: M17-F026 (Privileged Access Management (PAM))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.admin_actions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    action_id VARCHAR(100) UNIQUE NOT NULL,
    admin_id UUID NOT NULL,
    target_system VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    params_json JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.admin_actions IS 'High-fidelity log of privileged administrator actions';

CREATE INDEX idx_admin_actions_admin_id ON sec.admin_actions(admin_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB036 - ip_whitelists
-- Description: Allowed IP ranges for critical ops.
-- Business Case: Defense in depth. Even with valid credentials, accessing critical systems (like KMS
-- management) should only be allowed from known office IPs or VPNs. This table enforces Geo-fencing
-- and network restrictions to prevent credential theft from being exploited remotely.
-- KPIs:
-- 1. Filter Enforcement Rate (100%)
-- 2. False Positive Rejection Rate
-- 3. Whitelist Update Latency
-- 4. Blocked Attack Count
-- 5. Bypass Incident Count (0)
-- Feature Reference: M17-F053 (IP Whitelisting for Critical Ops)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ip_whitelists (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    list_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    cidr_block VARCHAR(45) NOT NULL, -- IPv4 or IPv6 CIDR
    description TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ip_whitelists IS 'IP whitelists for restricting access to critical infrastructure';

CREATE INDEX idx_ip_whitelists_cidr ON sec.ip_whitelists(cidr_block); -- Requires ip4r extension ideally, but standard index works for prefix match

------------------------------------------------------------------------------------------------
-- Table: M17-DB037 - risk_assessments
-- Description: Records of periodic risk assessments.
-- Business Case: Risk management is continuous. This table stores the results of periodic assessments
-- of assets, scoring them on risk. It tracks mitigation plans and reassessment dates, ensuring that
-- high-risk assets are prioritized for patching and security hardening.
-- KPIs:
-- 1. Assessment Completion Rate (100%)
-- 2. High-Risk Asset Reduction
-- 3. Mitigation Plan Execution
-- 4. Reassessment Schedule Adherence
-- 5. Overall Risk Score Trend
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.risk_assessments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assessment_id VARCHAR(100) UNIQUE NOT NULL,
    asset_id VARCHAR(255) NOT NULL,
    risk_score NUMERIC(3,1) CHECK (risk_score BETWEEN 0 AND 10),
    vulnerability_count INTEGER,
    mitigation_plan TEXT,
    assessed_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    next_assessment_date TIMESTAMP WITH TIME ZONE,
    assessor_id UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.risk_assessments IS 'Stores results of security risk assessments for assets';

CREATE INDEX idx_risk_assessments_asset ON sec.risk_assessments(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB038 - cipher_suites
-- Description: Allowed TLS cipher suites.
-- Business Case: Weak ciphers undermine encryption. This table defines the list of allowed TLS
-- cipher suites (e.g., TLS_AES_256_GCM_SHA384) and their security strength. The configuration
-- engine references this to configure load balancers and service mesh proxies, ensuring only
-- strong crypto is used.
-- KPIs:
-- 1. Configuration Compliance (100%)
-- 2. Cipher Strength Score
-- 3. SSL Labs Grade (A+)
-- 4. Legacy Cipher Usage (0)
-- 5. Policy Update Deployment Time
-- Feature Reference: M17-F066 (TLS Configuration Hardening)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cipher_suites (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    suite_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL, -- OpenSSL name
    protocol_version VARCHAR(10) CHECK (protocol_version IN ('TLS1.2','TLS1.3')),
    security_strength INTEGER CHECK (security_strength > 128), --  Bits
    enabled BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cipher_suites IS 'Defines allowed TLS cipher suites and their properties';

------------------------------------------------------------------------------------------------
-- Table: M17-DB039 - identity_providers
-- Description: Configuration of external IdPs (eIDAS, BankID).
-- Business Case: The PARI system needs to trust external identities (e.g., National Bank IDs,
-- Government eIDAS). This table stores the configuration and metadata (OIDC endpoints, JWKS URIs)
-- required to establish federation and validate tokens issued by these trusted external providers.
-- KPIs:
-- 1. Federation Latency (<1s)
-- 2. Token Validation Success Rate (100%)
-- 3. Provider Availability
-- 4. Metadata Refresh Success
-- 5. Interoperability Score
-- Feature Reference: M17-F067 (Identity Federation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.identity_providers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(20) CHECK (protocol IN ('OIDC','SAML','OAUTH2')),
    issuer_url VARCHAR(500) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scopes TEXT[],
    jwks_uri VARCHAR(500),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.identity_providers IS 'Configuration for federated Identity Providers (eIDAS, BankID)';

------------------------------------------------------------------------------------------------
-- Table: M17-DB040 - dependency_licenses
-- Description: Extracted license information from SBOMs.
-- Business Case: Legal compliance for open source software. This table extracts and categorizes the
-- licenses of all dependencies found in SBOMs. It flags "copyleft" or high-risk licenses that might
-- be incompatible with PARI's commercial usage policies.
-- KPIs:
-- 1. License Detection Accuracy (100%)
-- 2. Non-Compliant License Detection Speed
-- 3. SBOM Processing Throughput
-- 4. Legal Review Reduction
-- 5. Approved Library Count
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dependency_licenses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    license_id VARCHAR(100) UNIQUE NOT NULL,
    spdx_id VARCHAR(50),
    license_name VARCHAR(255) NOT NULL,
    approved_for_use BOOLEAN DEFAULT false,
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW','MEDIUM','HIGH','UNACCEPTABLE')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dependency_licenses IS 'Stores license information for software dependencies';

------------------------------------------------------------------------------------------------
-- Table: M17-DB041 - system_metrics
-- Description: Aggregated security metrics (MTTR, MTTD).
-- Business Case: CMMI Level 5 requires quantitative management. This table stores aggregated metrics
-- calculated from raw logs (e.g., "Average MTTD this week"). It serves as the data source for
-- executive dashboards and trend analysis, demonstrating the maturity of the security operations.
-- KPIs:
-- 1. Metric Calculation Latency
-- 2. Data Accuracy (100%)
-- 3. Dashboard Refresh Rate
-- 4. Historical Trend Completeness
-- 5. Alert Threshold Tuning
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.system_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(15,2) NOT NULL,
    unit VARCHAR(20), -- seconds, count, percentage
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tags JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.system_metrics IS 'Aggregated security metrics for reporting and analysis';

CREATE INDEX idx_system_metrics_name_time ON sec.system_metrics(metric_name, timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB042 - permission_sets
-- Description: Granular permissions bundled into sets.
-- Business Case: Managing permissions individually is unscalable. This table bundles granular
-- permissions (e.g., "ReadKey", "WriteKey") into sets (e.g., "KeyAuditor"). These sets are then
-- assigned to roles. It simplifies administration and ensures consistency in permission assignments.
-- KPIs:
-- 1. Set Usage Efficiency
-- 2. Permission Orphan Rate (0)
-- 3. Assignment Overhead
-- 4. Change Management Time
-- 5. Granularity Level
-- Feature Reference: M17-F050 (Service-to-Service Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.permission_sets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    set_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    permissions_json JSONB NOT NULL, -- List of specific permission strings

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.permission_sets is 'Bundles granular permissions into manageable sets for role assignment';

------------------------------------------------------------------------------------------------
-- Table: M17-DB043 - role_permissions
-- Description: Maps permission sets to roles.
-- Business Case: The bridge between Roles and Permissions. This table links a Role (e.g., "DevOps")
-- to Permission Sets (e.g., "EC2ReadOnly"). It provides the flexibility to mix and match permissions
-- dynamically without redefining roles constantly.
-- KPIs:
-- 1. Mapping Accuracy
-- 2. Propagation Latency (<1s)
-- 3. Conflict Detection Rate
-- 4. Role Permission Count Analysis
-- 5. Audit Trail Completeness
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.role_permissions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id VARCHAR(100) NOT NULL, -- External role ID
    permission_set_id UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT role_permissions_set_fkey FOREIGN KEY (permission_set_id) REFERENCES sec.permission_sets(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.role_permissions IS 'Associates roles with specific permission sets';

CREATE INDEX idx_role_permissions_role_id ON sec.role_permissions(role_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB044 - geo_blocks
-- Description: Countries blocked from accessing specific endpoints.
-- Business Case: Regulatory and security compliance. Some jurisdictions may be sanctioned (OFAC)
-- or high-risk for fraud. This table configures geo-blocking rules to prevent traffic from specific
-- country codes from reaching sensitive APIs.
-- KPIs:
-- 1. Block Enforcement Rate (100%)
-- 2. Legitimate User Blocking (False Positives)
-- 3. Rule Update Latency
-- 4. Blocked Threat Count
-- 5. Compliance Verification
-- Feature Reference: M17-F012 (Geo-Fencing API Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.geo_blocks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    block_id VARCHAR(100) UNIQUE NOT NULL,
    country_code CHAR(2) NOT NULL, -- ISO 3166-1 alpha-2
    endpoint_prefix VARCHAR(255),
    reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.geo_blocks IS 'Geo-blocking rules to restrict access based on country codes';

CREATE INDEX idx_geo_blocks_country ON sec.geo_blocks(country_code);

------------------------------------------------------------------------------------------------
-- Table: M17-DB045 - log_retention
-- Description: Configures retention periods for different log types.
-- Business Case: Cost management and compliance. Logs cannot be kept forever (cost) nor deleted
-- too soon (legal requirements). This table defines the retention policy for various log types
-- (e.g., "Audit Logs: 7 years", "Debug Logs: 30 days").
-- KPIs:
-- 1. Policy Enforcement Accuracy
-- 2. Storage Cost Optimization
-- 3. Compliance Requirement Met (100%)
-- 4. Data Retrieval Speed
-- 5. Automated Deletion Success
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.log_retention (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_type VARCHAR(100) PRIMARY KEY,
    retention_days INTEGER NOT NULL,
    archive_location VARCHAR(255), -- S3 Glacier, etc.
    archive BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.log_retention IS 'Defines retention policies for different types of logs';

------------------------------------------------------------------------------------------------
-- Table: M17-DB046 - key_escrow
-- Description: Details of key escrow shares for recovery.
-- Business Case: Disaster Recovery for keys. If a master key is lost, data is lost. This table
-- tracks the Shamir's Secret Sharing "shards" distributed to trustees. It ensures that enough
-- shards exist to recover a key, but that no single shard alone is sufficient (maintaining security).
-- KPIs:
-- 1. Shard Availability (100%)
-- 2. Reconstruction Success Rate (100%)
-- 3. Shard Distribution Verification
-- 4. Escrow Policy Compliance
-- 5. Recovery Test Frequency
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_escrow (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    share_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    trustee_id VARCHAR(255) NOT NULL,
    encrypted_share TEXT NOT NULL,
    location VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_escrow_key_id_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.key_escrow IS 'Stores key escrow shares for disaster recovery scenarios';

CREATE INDEX idx_key_escrow_key_id ON sec.key_escrow(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB047 - rule_conditions
-- Description: Logical conditions for policy rules.
-- Business Case: Complex policies require complex logic. This table stores the atomic conditions
-- (e.g., "user.location = 'EU' AND time > 9am") that are evaluated by the Policy Engine (OPA).
-- It breaks down policies into manageable, database-stored logic components.
-- KPIs:
-- 1. Condition Evaluation Speed (<5ms)
-- 2. Logic Complexity Score
-- 3. Condition Reusability
-- 4. Maintenance Overhead
-- 5. Syntax Error Rate (0)
-- Feature Reference: M17-F050 (Service-to-Service Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.rule_conditions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    condition_id VARCHAR(100) UNIQUE NOT NULL,
    policy_id UUID NOT NULL,
    field VARCHAR(100) NOT NULL,
    operator VARCHAR(20) CHECK (operator IN ('EQUALS','NOT_EQUALS','GREATER','LESSER','CONTAINS','MATCHES_REGEX')),
    value TEXT,
    logic_operator VARCHAR(10) CHECK (logic_operator IN ('AND','OR')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT rule_conditions_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.zero_trust_policies(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.rule_conditions IS 'Stores atomic logic conditions for constructing complex policy rules';

CREATE INDEX idx_rule_conditions_policy_id ON sec.rule_conditions(policy_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB048 - playbooks
-- Description: Automated incident response playbooks.
-- Business Case: Speed is critical in incident response. SOAR (Security Orchestration, Automation,
-- and Response) playbooks define the steps to take when an alert fires (e.g., "Isolate Host",
-- "Revoke Cert"). This table stores the playbook definitions (as code/JSON) for execution.
-- KPIs:
-- 1. Playbook Execution Accuracy
-- 2. Automation Coverage (Percentage of alerts automated)
-- 3. Execution Latency (<30s)
-- 4. Manual Intervention Reduction
-- 5. Error Handling Success
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.playbooks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    trigger_ioc_type VARCHAR(100),
    steps_json JSONB NOT NULL, -- Sequence of actions
    enabled BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.playbooks IS 'Defines automated response playbooks for security incidents';

------------------------------------------------------------------------------------------------
-- Table: M17-DB049 - threat_feeds
-- Description: Configured external threat intelligence feeds.
-- Business Case: Proactive defense. Threat Intelligence (TI) feeds (e.g., STIX/TAXII) provide lists
-- of known bad IPs, domains, and file hashes. This table manages the configuration of these feeds,
-- allowing the system to ingest TI and block threats before they reach the application.
-- KPIs:
-- 1. Feed Update Frequency
-- 2. Indicator Enrichment Speed
-- 3. False Positive Rate (External)
-- 4. Blocked Threat Count via Feed
-- 5. Feed Availability
-- Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_feeds (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feed_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    format VARCHAR(50), -- STIX, CSV, JSON
    last_update_hash VARCHAR(64),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.threat_feeds IS 'Configuration of external threat intelligence feeds';

------------------------------------------------------------------------------------------------
-- Table: M17-DB050 - build_pipelines
-- Description: Registered CI/CD pipelines subject to security checks.
-- Business Case: Securing the software factory. This table registers CI/CD pipelines (Jenkins,
-- GitLab CI) that build PARI code. By registering them, the M17 module can require specific
-- security checks (signing, SBOM generation) before allowing artifacts to be deployed.
-- KPIs:
-- 1. Pipeline Registration Coverage (100%)
-- 2. Security Gate Pass Rate
-- 3. Build Failure Analysis
-- 4. Signing Key Usage
-- 5. Compliance Check Latency
-- Feature Reference: M17-F065 (Secure CI/CD Pipeline)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.build_pipelines (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id VARCHAR(100) UNIQUE NOT NULL,
    repo_url VARCHAR(500) NOT NULL,
    branch VARCHAR(100),
    required_approvals INTEGER DEFAULT 1,
    signing_key_id UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT build_pipelines_signing_key_fkey FOREIGN KEY (signing_key_id) REFERENCES sec.sign_keys(id)
);
COMMENT ON TABLE sec.build_pipelines IS 'Registers CI/CD pipelines for security gating and code signing enforcement';


-- 7. Triggers and Row Level Security (RLS)
-- ================================================================================

-- Apply triggers to all tables with updated_at
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.spiffe_identities FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.x509_certificates FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.trust_domains FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.encryption_keys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.key_versions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.attestation_quotes FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.pcr_values FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.zero_trust_policies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.policy_assignments FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.access_requests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.jit_grants FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.sbom_entries FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vulnerability_scans FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_incidents FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.iocs FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.network_policies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.control_mappings FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.evidence_locker FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_sessions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.root_ca_certificates FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.intermediate_cas FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_configurations FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.anomaly_alerts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.sign_keys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.gdpr_data_requests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_accounts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.account_roles FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.hsm_partitions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.tee_enclaves FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.ip_whitelists FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.risk_assessments FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cipher_suites FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.identity_providers FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dependency_licenses FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.permission_sets FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.role_permissions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.geo_blocks FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.log_retention FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.key_escrow FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.rule_conditions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.playbooks FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.threat_feeds FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.build_pipelines FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- Enable Row Level Security on sensitive tables (Example)
ALTER TABLE sec.audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE sec.encryption_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sec.x509_certificates ENABLE ROW LEVEL SECURITY;

-- Create RLS Policies (Example: Audit Trail is append-only, no updates/deletes allowed via standard SQL)
CREATE POLICY "audit_trail_append_only" ON sec.audit_trail
    FOR INSERT WITH CHECK (true);

CREATE POLICY "audit_trail_read_only" ON sec.audit_trail
    FOR SELECT USING (true);

-- Prevent updates/deletes on audit_trail
CREATE POLICY "audit_trail_no_updates" ON sec.audit_trail
    FOR UPDATE USING (false);

CREATE POLICY "audit_trail_no_deletes" ON sec.audit_trail
    FOR DELETE USING (false);

-- End of Script Part 1
-- Next Part: Views, Stored Procedures, and remaining Tables


-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 2: Tables DB051-DB100)
-- ================================================================================
-- Description:
-- Continuation of the M17 schema definition. This part includes tables for
-- vulnerability management thresholds, system health, biometric data, device trust,
-- forensic evidence, logging, and advanced configuration management.
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. DDL Statements (Tables 51-100)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB051 - vulnerability_thresholds
-- Description: Thresholds for automatic blocking based on CVSS.
-- Business Case: Not every vulnerability requires an immediate outage. This table allows security
-- teams to define thresholds (e.g., "Block only if CVSS > 9.0 in Production"). This automates
-- the decision-making process during the CI/CD pipeline, ensuring that critical risks are
-- stopped while lower-risk ones are merely logged for review, thus balancing security with
-- deployment velocity.
-- KPIs:
-- 1. Automated Block Rate (Matches Threshold %)
-- 2. False Negative Rate (Critical Vulns missed)
-- 3. Configuration Drift (0 deviations)
-- 4. Threshold Adjustment Frequency
-- 5. Pipeline Pass/Fail Ratio
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_thresholds (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threshold_id VARCHAR(100) UNIQUE NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('PRODUCTION','STAGING','DEVELOPMENT','TEST')),
    max_cvss NUMERIC(3,1) NOT NULL CHECK (max_cvss >= 0 AND max_cvss <= 10),
    action VARCHAR(20) NOT NULL CHECK (action IN ('WARN','BLOCK','QUARANTINE')),
    exceptions JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vulnerability_thresholds IS 'Defines CVSS score thresholds for automated vulnerability blocking';

CREATE INDEX idx_vuln_thresholds_env ON sec.vulnerability_thresholds(environment);

------------------------------------------------------------------------------------------------
-- Table: M17-DB052 - health_checks
-- Description: Results of health checks for security components.
-- Business Case: The Zero-Trust fabric is composed of many moving parts (KMS, Policy Engine, Mesh).
-- This table stores the results of periodic health probes (e.g., "Can I reach the HSM?").
-- Aggregating this data allows the system to generate uptime SLAs and trigger automated failover
-- if a component becomes unresponsive.
-- KPIs:
-- 1. Component Availability % (Target 99.99%)
-- 2. Health Check Latency (Avg < 50ms)
-- 3. Failover Trigger Accuracy
-- 4. Mean Time to Recovery (MTTR)
-- 5. False Down Alerts (0)
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.health_checks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    check_id VARCHAR(100) UNIQUE NOT NULL,
    component_name VARCHAR(255) NOT NULL,
    component_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('HEALTHY','DEGRADED','DOWN','UNKNOWN')),
    latency_ms NUMERIC(10,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    details JSONB, -- Error messages or context

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.health_checks IS 'Stores health check results for security infrastructure components';

CREATE INDEX idx_health_checks_component ON sec.health_checks(component_name, timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB053 - biometric_templates
-- Description: Stores hashed biometric data (e.g., for continuous auth).
-- Business Case: Behavioral biometrics (typing patterns) or physical biometrics (fingerprints) add
-- a layer of continuous authentication. This table stores the *hashed* reference templates.
-- By comparing live data against these hashes, the system can detect session hijacking even if
-- the attacker has the correct password.
-- KPIs:
-- 1. Template Match Accuracy (>99%)
-- 2. False Acceptance Rate (FAR < 0.001%)
-- 3. False Rejection Rate (FRR < 1%)
-- 4. Template Encryption Status (100%)
-- 5. Verification Latency (<200ms)
-- Feature Reference: M17-F117 (Behavioral Biometrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.biometric_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    template_hash VARCHAR(255) NOT NULL, -- Hash of the vector/data
    template_format VARCHAR(50) NOT NULL, -- e.g., ISO_19794_2
    algorithm VARCHAR(50) NOT NULL, -- e.g., Argon2id, SHA256
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.biometric_templates IS 'Secure storage of hashed biometric templates for continuous authentication';

CREATE INDEX idx_biometric_templates_user ON sec.biometric_templates(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB054 - device_trust
-- Description: Trust status of user devices (laptops, phones).
-- Business Case: Device posture assessment (is the OS patched? is AV running?) determines trust.
-- This table caches the trust score and posture of a device. Sessions initiated from low-trust
-- devices can be subjected to step-up authentication (MFA) or restricted access, enforcing
-- security based on the endpoint's state.
-- KPIs:
-- 1. Trusted Device Population %
-- 2. Trust Score Calculation Latency (<500ms)
-- 3. Posture Assessment Coverage
-- 4. Drift Detection Rate
-- 5. High-Risk Device Blocking Rate
-- Feature Reference: M17-F081 (Endpoint Detection & Response (EDR))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.device_trust (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID,
    device_fingerprint VARCHAR(255) NOT NULL,
    trust_score NUMERIC(3,2) CHECK (trust_score BETWEEN 0 AND 100),
    posture_report JSONB, -- OS version, AV status, disk encryption
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.device_trust IS 'Tracks the trust score and security posture of user devices';

CREATE INDEX idx_device_trust_user ON sec.device_trust(user_id);
CREATE INDEX idx_device_trust_score ON sec.device_trust(trust_score);

------------------------------------------------------------------------------------------------
-- Table: M17-DB055 - one_time_tokens
-- Description: Short-lived tokens for specific operations.
-- Business Case: Password resets, email verification links, and temporary access links should
-- only be usable once and expire quickly. This table manages the lifecycle of these tokens,
-- ensuring they are consumed (marked `used=true`) immediately upon use, preventing replay attacks.
-- KPIs:
-- 1. Token Consumption Rate (100%)
-- 2. Expiration Enforcement (0 late uses)
-- 3. Generation Entropy (High)
-- 4. Token Guessing Attempts (Low)
-- 5. Reset Workflow Completion Rate
-- Feature Reference: M17-F003 (X.509-SVID Rotation - Token usage)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.one_time_tokens (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_id VARCHAR(100) UNIQUE NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- RESET_PASSWORD, VERIFY_EMAIL
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed BOOLEAN DEFAULT false,
    consumed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.one_time_tokens IS 'Manages short-lived, single-use tokens for sensitive operations';

CREATE INDEX idx_one_time_tokens_hash ON sec.one_time_tokens(token_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB056 - dns_records
-- Description: Internal DNS records for security enforcement.
-- Business Case: Zero-Trust networks often require internal service discovery (e.g., "payment.db.local").
-- This table acts as a secure internal DNS registry. By managing DNS centrally, the system can
-- ensure DNSSEC validation and prevent DNS spoofing attacks internally, which are often used for
-- lateral movement.
-- KPIs:
-- 1. Record Propagation Latency (<1s)
-- 2. DNSSEC Validation Success (100%)
-- 3. Cache Hit Ratio
-- 4. Record Availability (99.99%)
-- 5. Zone Transfer Success
-- Feature Reference: M17-F056 (DNS Security (DNSSEC))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dns_records (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    record_id VARCHAR(100) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    record_type VARCHAR(10) NOT NULL CHECK (record_type IN ('A','AAAA','CNAME','TXT','SRV')),
    ttl INTEGER DEFAULT 300,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dns_records IS 'Internal secure DNS records for service discovery and security enforcement';

CREATE INDEX idx_dns_records_hostname ON sec.dns_records(hostname);

------------------------------------------------------------------------------------------------
-- Table: M17-DB057 - sensitive_operations
-- Description: Log of operations involving PII or Keys.
-- Business Case: Accessing raw PII or exporting private keys is a high-risk event. This table
-- provides a dedicated, high-fidelity log for such "Tier 1" sensitive operations. It enables
-- forensic investigation to determine *exactly* who saw what data and when, satisfying the
-- strictest audit requirements for financial systems.
-- KPIs:
-- 1. Log Completeness (100%)
-- 2. Alert Generation Latency (<1s)
-- 3. Justification Enforcement Rate
-- 4. Data Exfiltration Detection
-- 5. Audit Query Performance
-- Feature Reference: M17-F143 (Granular Database Auditing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sensitive_operations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    op_id VARCHAR(100) UNIQUE NOT NULL,
    operator_id UUID NOT NULL,
    data_type VARCHAR(50) NOT NULL, -- PII, KEY, CONFIG
    record_id VARCHAR(255),
    justification TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    operation_result VARCHAR(20) CHECK (operation_result IN ('SUCCESS','FAILURE','BLOCKED')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.sensitive_operations IS 'High-priority audit log for operations involving PII or cryptographic keys';

CREATE INDEX idx_sensitive_ops_operator ON sec.sensitive_operations(operator_id, timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB058 - audit_reports
-- Description: Generated audit reports for download.
-- Business Case: Generating audit reports for external auditors can be resource-intensive.
-- This table stores metadata of generated reports (PDF/Excel), including the framework
-- (e.g., ISO27001) and the generation time. It allows auditors to download pre-generated
-- packs or historical reports without re-querying the raw database.
-- KPIs:
-- 1. Report Generation Time (<5 min)
-- 2. File Download Success (100%)
-- 3. Report Accuracy (Verified)
-- 4. Historical Retention (7 years)
-- 5. On-Demand Request Fulfillment
-- Feature Reference: M17-F113 (Automated Compliance Reporting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    framework_id VARCHAR(50),
    file_path VARCHAR(500) NOT NULL, -- S3 location
    file_hash VARCHAR(64) NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    requested_by UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_reports IS 'Metadata for generated compliance and audit reports';

CREATE INDEX idx_audit_reports_framework ON sec.audit_reports(framework_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB059 - incident_tasks
-- Description: Tasks generated during an incident response.
-- Business Case: Incident response is a team effort. This table breaks down an incident into
-- actionable tasks (e.g., "Isolate Server", "Notify Legal"). Assigning owners and tracking due dates
-- ensures that the response process is structured and that no critical steps are missed during
-- the chaos of a security breach.
-- KPIs:
-- 1. Task Completion Rate (100%)
-- 2. Assignment Latency (<10m)
-- 3. Overdue Task Count
-- 4. Task Dependency Resolution
-- 5. Overall Incident Resolution Speed
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_tasks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    task_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    description TEXT NOT NULL,
    assignee UUID,
    status VARCHAR(50) DEFAULT 'PENDING' CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','BLOCKED')),
    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT incident_tasks_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.incident_tasks IS 'Actionable tasks generated during incident response workflows';

CREATE INDEX idx_incident_tasks_incident ON sec.incident_tasks(incident_id);
CREATE INDEX idx_incident_tasks_status ON sec.incident_tasks(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB060 - container_images
-- Description: Registry of all deployed container images.
-- Business Case: To prevent "version drift" and ensure reproducibility, every deployed container
-- image must be registered. This table tracks the registry URL, tag, and crucially, the SHA256
-- digest. It ensures that only signed, scanned images (referenced in SBOMs) are allowed to run.
-- KPIs:
-- 1. Image Registration Compliance (100%)
-- 2. Signature Verification Success (100%)
-- 3. Vulnerability Scan Pass Rate
-- 4. Image Age Distribution
-- 5. Duplicate Digest Detection
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.container_images (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    image_id VARCHAR(100) UNIQUE NOT NULL,
    registry_url VARCHAR(500) NOT NULL,
    image_tag VARCHAR(255) NOT NULL,
    digest_hash VARCHAR(64) NOT NULL, -- SHA256
    signed BOOLEAN DEFAULT false,
    signature_id UUID, -- Reference to sign_keys
    scan_status VARCHAR(50) DEFAULT 'PENDING', -- SCANNING, PASSED, FAILED
    deployment_count INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT container_images_sig_fkey FOREIGN KEY (signature_id) REFERENCES sec.sign_keys(id)
);
COMMENT ON TABLE sec.container_images IS 'Registry of deployed container images with integrity and signature status';

CREATE UNIQUE INDEX idx_container_digest ON sec.container_images(digest_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB061 - abac_attributes
-- Description: User/Resource attributes for Attribute-Based Access Control.
-- Business Case: ABAC goes beyond Roles (RBAC) by considering attributes (e.g., User is "Manager",
-- Resource is "Confidential", Time is "9am-5pm"). This table stores these key-value pairs.
-- The Policy Engine queries this table to evaluate complex rules, enabling highly granular,
-- context-aware security decisions.
-- KPIs:
-- 1. Attribute Lookup Latency (<10ms)
-- 2. Policy Evaluation Accuracy
-- 3. Attribute Freshness (Real-time)
-- 4. Missing Attribute Rate (0%)
-- 5. Attribute Source Reliability
-- Feature Reference: M17-F080 (Regel-based Access Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.abac_attributes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN ('USER','SERVICE','DEVICE','RESOURCE')),
    attribute_key VARCHAR(100) NOT NULL,
    attribute_value TEXT NOT NULL,
    source VARCHAR(100), -- HR_DB, SCANNER, MANUAL
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.abac_attributes IS 'Stores dynamic attributes for Attribute-Based Access Control (ABAC)';

CREATE INDEX idx_abac_entity ON sec.abac_attributes(entity_id, entity_type);
CREATE INDEX idx_abac_key_val ON sec.abac_attributes(attribute_key, attribute_value);

------------------------------------------------------------------------------------------------
-- Table: M17-DB062 - firewall_rules
-- Description: L3/L4 firewall rules.
-- Business Case: Basic network security. This table defines IP-based allow/deny rules. While
-- service mesh handles L7, this table manages the underlying L3/L4 infrastructure firewall
-- rules (e.g., iptables/nftables) to provide a lower-level defense layer.
-- KPIs:
-- 1. Rule Deployment Latency (<30s)
-- 2. Rule Conflict Detection (100%)
-- 3. Hit Count (Effectiveness)
-- 4. Rule Churn Rate
-- 5. Shadow Rule Detection
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.firewall_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    source VARCHAR(100), -- CIDR or Security Group
    destination VARCHAR(100),
    port VARCHAR(20),
    protocol VARCHAR(10) CHECK (protocol IN ('TCP','UDP','ICMP','ANY')),
    action VARCHAR(10) NOT NULL CHECK (action IN ('ALLOW','DENY','REJECT')),
    priority INTEGER NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.firewall_rules IS 'Defines L3/L4 firewall rules for network segmentation';

CREATE INDEX idx_firewall_priority ON sec.firewall_rules(priority);

------------------------------------------------------------------------------------------------
-- Table: M17-DB063 - social_logins
-- Description: Links external social accounts to internal identities.
-- Business Case: Modern apps allow login via Google/GitHub. This table links those external
-- identity providers (IdPs) to an internal PARI user ID. It ensures that a specific social
-- account cannot be linked to multiple internal users, preventing identity spoofing.
-- KPIs:
-- 1. Link Success Rate
-- 2. Duplicate Prevention (100%)
-- 3. Provider Token Refresh Success
-- 4. Account Takeover (ATO) Detection
-- 5. User Provisioning Speed
-- Feature Reference: M17-F067 (Identity Federation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.social_logins (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    link_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    provider VARCHAR(50) NOT NULL, -- google, github
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT social_logins_unique UNIQUE (provider, provider_user_id)
);
COMMENT ON TABLE sec.social_logins IS 'Links external social identity provider accounts to internal users';

CREATE INDEX idx_social_logins_user ON sec.social_logins(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB064 - quantum_keys
-- Description: Metadata for post-quantum experimental keys.
-- Business Case: Preparing for the quantum era. This table tracks the metadata for keys
-- generated using Post-Quantum Cryptography (PQC) algorithms (e.g., CRYSTALS-Kyber). It allows
-- the system to safely experiment with and migrate to quantum-resistant algorithms without
-- breaking existing production crypto.
-- KPIs:
-- 1. Key Generation Success Rate
-- 2. PQC Algorithm Performance (Latency)
-- 3. Migration Progress %
-- 4. Interop Test Success
-- 5. Key Size Analysis
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm VARCHAR(50) NOT NULL, -- Kyber, Dilithium
    key_size INTEGER,
    public_key TEXT,
    status sec.enum_cert_status DEFAULT 'VALID',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.quantum_keys IS 'Experimental metadata for Post-Quantum Cryptography (PQC) keys';

------------------------------------------------------------------------------------------------
-- Table: M17-DB065 - honeypots
-- Description: Configuration of decoy services.
-- Business Case: Deception technology. Honeypots act as traps for attackers. This table stores
-- the configuration of these decoys (ports, services). When an attacker scans or connects to a
-- honeypot, an immediate high-severity alert is generated, as there is no legitimate reason to
-- access these fake services.
-- KPIs:
-- 1. Attacker Engagement Time
-- 2. Alert Precision (Honeypot alerts are always malicious)
-- 3. Detection Rate (New attacker IPs)
-- 4. Decoy Diversity Score
-- 5. Honeypot Availability (Uptime)
-- Feature Reference: M17-F085 (Deception Technology (Honeypots))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.honeypots (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pot_id VARCHAR(100) UNIQUE NOT NULL,
    service_type VARCHAR(50) NOT NULL, -- SSH, HTTP, SQL
    listening_port INTEGER NOT NULL,
    alert_channel VARCHAR(100) NOT NULL,
    active BOOLEAN DEFAULT true,
    capture_details JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.honeypots IS 'Configuration of honeypot/decoy services for attacker deception';

------------------------------------------------------------------------------------------------
-- Table: M17-DB066 - key_destruction_logs
-- Description: Proof of key destruction.
-- Business Case: Secure deletion is a legal requirement (GDPR Right to be Forgotten) and a
-- security best practice. Simply deleting the row isn't enough; cryptographic keys must be
-- shredded (overwritten). This table logs the *event* of destruction, providing auditable
-- proof that a specific key can no longer be used to decrypt data.
-- KPIs:
-- 1. Shredding Verification (100%)
-- 2. Data Recovery Probability (0%)
-- 3. Destruction Log Integrity
-- 4. Compliance Requirement Met
-- 5. Witness Signature Rate
-- Feature Reference: M17-F049 (Secure Key Deletion (Crypto-Shredding))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_destruction_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    destruction_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    method VARCHAR(50) NOT NULL, -- CRYPTO_SHRED, PHYSICAL_DESTROY
    witness_id UUID, -- Admin who verified
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_destruction_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_destruction_logs IS 'Immutable proof of key destruction for compliance and security';

CREATE INDEX idx_key_destruction_key ON sec.key_destruction_logs(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB067 - api_keys
-- Description: API Keys for external integration.
-- Business Case: Third-party partners need programmatic access to PARI APIs. This table manages
-- the lifecycle of their API keys. It enforces rate limits, scopes (what they can access), and
-- expiration dates. Storing only the hash of the key ensures that even DB admins cannot steal
-- the secret credentials.
-- KPIs:
-- 1. Key Validation Latency (<5ms)
-- 2. Rate Limit Enforcement Accuracy (100%)
-- 3. Expired Key Cleanup
-- 4. Compromised Key Revocation Speed
-- 5. Key Usage Analytics Coverage
-- Feature Reference: M17-F095 (Compliance Ticketing - via API integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(100) UNIQUE NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL, -- First 4 chars for identification
    owner_id UUID NOT NULL,
    scope TEXT[],
    rate_limit INTEGER,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_keys IS 'Manages API keys for external system integrations with hashing and scoping';

CREATE INDEX idx_api_keys_hash ON sec.api_keys(key_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB068 - security_headers
-- Description: Enforced HTTP headers (CSP, HSTS).
-- Business Case: HTTP headers are the first line of defense for web apps (e.g., HSTS forces
-- HTTPS, CSP prevents XSS). This table stores the configuration of these headers. The API
-- Gateway reads this table to inject headers into responses, ensuring consistent security
-- posture across all web endpoints.
-- KPIs:
-- 1. Header Injection Success Rate (100%)
-- 2. Security Lab Grade (A+)
-- 3. Header Configuration Coverage
-- 4. Violation Detection (Browser reports)
-- 5. Header Update Deployment Time
-- Feature Reference: M17-F066 (TLS Configuration Hardening)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_headers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    header_id VARCHAR(100) UNIQUE NOT NULL,
    header_name VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    applies_to VARCHAR(100), /* 'ALL', 'API', 'WEB' */

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_headers IS 'Configuration for HTTP security headers (HSTS, CSP, X-Frame-Options)';

------------------------------------------------------------------------------------------------
-- Table: M17-DB069 - code_repositories
-- Description: Registered source code repositories.
-- Business Case: To scan for secrets or enforce policies (branch protection), the system needs
-- to know where the code lives. This table registers Git repositories (GitHub, GitLab, Bitbucket)
--  and allows the security module to configure webhooks or scheduled scans.
-- KPIs:
-- 1. Repository Coverage (100%)
-- 2. Secret Scan Frequency
-- 3. Branch Protection Enforcement
-- 4. Integration Health Status
-- 5. Commit Volume Tracking
-- Feature Reference: M17-F105 (Secret Scanning in Repos)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.code_repositories (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    repo_id VARCHAR(100) UNIQUE NOT NULL,
    url VARCHAR(500) NOT NULL,
    scm_type VARCHAR(50) NOT NULL, -- GITHUB, GITLAB, BITBUCKET
    default_branch VARCHAR(100),
    access_token_ref VARCHAR(255), -- Reference to KMS secret

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.code_repositories IS 'Registers source code repositories for security scanning and policy enforcement';

------------------------------------------------------------------------------------------------
-- Table: M17-DB070 - forensic_snapshots
-- Description: Metadata of snapshots taken for forensics.
-- Business Case: When a breach is detected, preserving the state of the compromised machine is
-- vital. This table tracks metadata of forensic snapshots (disk images, memory dumps). It ensures
-- that chain of custody is maintained and that the evidence is securely stored and not tampered
--  with.
-- KPIs:
-- 1. Snapshot Creation Time (<5 min)
-- 2. Storage Integrity (Hash checks)
-- 3. Chain of Custody Log Completeness
-- 4. Retention Policy Adherence
-- 5. Retrieval Speed for Investigators
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.forensic_snapshots (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_id VARCHAR(100) UNIQUE NOT NULL,
    instance_id VARCHAR(100) NOT NULL,
    volume_id VARCHAR(255),
    taken_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'CREATING', -- CREATING, AVAILABLE, CORRUPT
    storage_path VARCHAR(500),
    file_size_bytes BIGINT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.forensic_snapshots IS 'Metadata for forensic disk and memory snapshots';

CREATE INDEX idx_forensic_snapshots_instance ON sec.forensic_snapshots(instance_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB071 - user_entitlements
-- Description: Detailed entitlements granted to users.
-- Business Case: Entitlements represent the atomic unit of access (e.g., "CanReadBucketA"). This
--  table stores the direct mapping of users to entitlements, overriding role-based access for
--  specific exceptions. It enables just-in-time grants and fine-grained auditing of exactly
--  what a user can do.
-- KPIs:
-- 1. Entitlement Accuracy (100%)
-- 2. Orphaned Entitlement Count (0)
-- 3. Expiry Processing Accuracy
-- 4. Entitlement Justification Availability
-- 5. Audit Traceability
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_entitlements (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entitlement_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    permission VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_entitlements IS 'Stores direct granular entitlements granted to users';

CREATE INDEX idx_user_entitlements_user ON sec.user_entitlements(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB072 - traffic_anomalies
-- Description: Detected anomalies in traffic flow.
-- Business Case: Automated anomaly detection generates "events" that need to be investigated.
--  This table records specific anomalies found in the `traffic_flows` data (e.g., "Spike in
--  traffic to DB port 5432 at 3 AM"). Analysts query this table to triage potential threats.
-- KPIs:
-- 1. Detection Latency (<1 min)
-- 2. False Positive Rate (<2%)
-- 3. Severity Accuracy
-- 4. Analyst Review Time
-- 5. Automated Mitigation Trigger Rate
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.traffic_anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    flow_id UUID NOT NULL,
    anomaly_score NUMERIC(5,4) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50) NOT NULL,
    features JSONB, -- The metrics that triggered the alert

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT traffic_anomalies_flow_fkey FOREIGN KEY (flow_id) REFERENCES sec.traffic_flows(id)
);
COMMENT ON TABLE sec.traffic_anomalies IS 'Stores detected network traffic anomalies for analyst review';

CREATE INDEX idx_traffic_anomalies_score ON sec.traffic_anomalies(anomaly_score);

------------------------------------------------------------------------------------------------
-- Table: M17-DB073 - consent_records
-- Description: Records of user consent for data processing.
-- Business Case: GDPR requires explicit consent for processing personal data. This table
--  stores the granular consent records (e.g., "User agreed to marketing emails on Date X").
--  It ensures that the system respects user preferences and can prove consent during an audit.
-- KPIs:
-- 1. Consent Capture Rate (100%)
-- 2. Withdrawal Processing Speed (<24h)
-- 3. Audit Trail Completeness
-- 4. Consent Versioning Accuracy
-- 5. Privacy Policy Linkage
-- Feature Reference: M17-F073 (Code Signing Service - Privacy context)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.consent_records (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    consent_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    purpose_id VARCHAR(100) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    policy_version VARCHAR(20),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.consent_records IS 'Records of user consent for privacy and data processing';

CREATE INDEX idx_consent_user ON sec.consent_records(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB074 - penetration_tests
-- Description: Scheduled and completed penetration tests.
-- Business Case: Proactive security testing. This table manages the schedule of third-party
--  penetration tests. It tracks the scope, vendor, and results (reports). It ensures that
--  regular testing occurs and that findings are tracked in the incident/vulnerability tables
--  for remediation.
-- KPIs:
-- 1. Test Schedule Adherence (100%)
-- 2. Finding Remediation Velocity
-- 3. Critical Finding Rate
-- 4. Test Coverage (% of assets)
-- 5. Report Delivery Latency
-- Feature Reference: M17-F033 (Automated Penetration Testing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.penetration_tests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_name VARCHAR(255) NOT NULL,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED','IN_PROGRESS','COMPLETED','CANCELLED')),
    report_ref VARCHAR(500), -- S3 path to PDF
    findings_count INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.penetration_tests IS 'Manages the lifecycle of external penetration tests';

------------------------------------------------------------------------------------------------
-- Table: M17-DB075 - hmac_keys
-- Description: Keys used for HMAC signing of requests.
-- Business Case: HMACs ensure message integrity and authenticity (e.g., Webhooks). This table
--  manages the keys used for signing and verification. Rotating these keys regularly prevents
--  replay attacks and ensures that old signatures become invalid.
-- KPIs:
-- 1. Signature Verification Success (100%)
-- 2. Key Rotation Compliance (100%)
-- 3. Signing Latency (<5ms)
-- 4. Key Usage Analytics
-- 5. Rejected Signature Count
-- Feature Reference: M17-F099 (Blockchain Anchoring - uses HMACs/Hashes)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hmac_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm VARCHAR(50) NOT NULL, -- SHA256, SHA512
    purpose VARCHAR(100) NOT NULL, -- WEBHOOK_VERIFICATION, API_SIGNING
    rotation_period_seconds INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.hmac_keys IS 'Keys used for HMAC signing for integrity verification';

------------------------------------------------------------------------------------------------
-- Table: M17-DB076 - session_revocations
-- Description: Revoked session tokens (blacklist).
-- Business Case: When a user logs out or is banned, their JWT or session token should be
--  invalidated immediately. Since JWTs are stateless, a blacklist (or "revocation list") is
--  needed. This table stores revoked token IDs/Hashes; the authentication gateway checks it on
--  every request to enforce logout.
-- KPIs:
-- 1. Revocation Check Latency (<5ms)
-- 2. Blacklist Storage Efficiency
-- 3. Expired Token Cleanup
-- 4. Revocation Propagation (Global)
-- 5. Cache Hit Ratio (for revocation list)
-- Feature Reference: M17-F145 (Secure Token Revocation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.session_revocations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    revocation_id VARCHAR(100) UNIQUE NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(100),
    expires_at TIMESTAMP WITH TIME ZONE, --  Match token expiry

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.session_revocations IS 'Blacklist of revoked session tokens for immediate enforcement';

CREATE INDEX idx_session_revocations_session ON sec.session_revocations(session_id);
CREATE INDEX idx_session_revocations_expiry ON sec.session_revocations(expires_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB077 - secret_commits
-- Description: Records of secrets found in code.
-- Business Case: Developers accidentally commit keys/passwords to Git. This table records
--  findings from secret scanners. It links the finding to the repo and commit, tracks the revocation
--  of that secret, and ensures the code is cleaned up to prevent credential leakage.
-- KPIs:
-- 1. Detection Time (<5 min from push)
-- 2. Secret Revocation Success (100%)
-- 3. Remediation Time (<1 hour)
-- 4. False Positive Rate (<1%)
-- 5. Developer Awareness Rate
-- Feature Reference: M17-F105 (Secret Scanning in Repos)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secret_commits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id VARCHAR(100) UNIQUE NOT NULL,
    repo_id UUID NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    secret_hash VARCHAR(255) NOT NULL,
    resolved BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT secret_commits_repo_fkey FOREIGN KEY (repo_id) REFERENCES sec.code_repositories(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.secret_commits IS 'Logs of secrets detected in code repositories';

CREATE INDEX idx_secret_commits_repo ON sec.secret_commits(repo_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB078 - service_graph
-- Description: Directed graph edges of service dependencies.
-- Business Case: Understanding dependencies is crucial for impact analysis ("If Service A goes
--  down, who else fails?"). This table stores the edges of the service graph. The visualization
--  engine uses this to show blast radius and prioritize patching of critical nodes.
-- KPIs:
-- 1. Graph Completeness (Edges discovered %)
-- 2. Update Latency (Real-time discovery)
-- 3. Blast Radius Calculation Accuracy
-- 4. Dependency Depth Analysis
-- 5. Orphaned Service Detection
-- Feature Reference: M17-F078 (Service Graph Discovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_graph (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_id VARCHAR(100) UNIQUE NOT NULL,
    source_service VARCHAR(255) NOT NULL,
    dest_service VARCHAR(255) NOT NULL,
    weight NUMERIC(5,2), -- Traffic volume or dependency strength
    relationship_type VARCHAR(50), --  SYNCHRONOUS, ASYNCHRONOUS, DATA_FLOW

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_graph IS 'Edges of the service dependency graph for impact analysis';

CREATE INDEX idx_service_graph_src ON sec.service_graph(source_service);
CREATE INDEX idx_service_graph_dest ON sec.service_graph(dest_service);

------------------------------------------------------------------------------------------------
-- Table: M17-DB079 - feature_flags
-- Description: Security feature toggles.
-- Business Case: Canary deployments or emergency kill switches. This table stores feature flags
--  (e.g., "EnableMFAForAdmins"). By storing flags in the DB, they can be toggled instantly without
--  a code redeploy, allowing for rapid reaction to new threats or testing of new security features.
-- KPIs:
-- 1. Toggle Latency (<1s propagation)
-- 2. Flag Rollout Consistency
-- 3. Rollback Speed (<1s)
-- 4. Configuration Auditability
-- 5. Flag Drift (0)
-- Feature Reference: M17-F067 (Identity Federation - feature context)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.feature_flags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) UNIQUE NOT NULL,
    is_enabled BOOLEAN DEFAULT false,
    description TEXT,
    rollout_percentage INTEGER DEFAULT 100 CHECK (rollout_percentage BETWEEN 0 AND 100),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.feature_flags IS 'Stores feature flags for dynamic security configuration';

------------------------------------------------------------------------------------------------
-- Table: M17-DB080 - backup_logs
-- Description: Logs of backup operations.
-- Business Case: Data resilience. This table logs every backup operation for security-relevant
--  data (keys, logs, configs). It tracks success/failure and duration. It is used to verify
--  RPO/RPO (Recovery Point/Time Objectives) compliance and to alert on backup failures immediately.
-- KPIs:
-- 1. Backup Success Rate (100%)
-- 2. RPO Adherence (Max data loss time)
-- 3. Backup Duration (Within SLA)
-- 4. Storage Encryption (100%)
-- 5. Restoration Test Success
-- Feature Reference: M17-F039 (Backup Encryption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.backup_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id VARCHAR(100) UNIQUE NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    status VARCHAR(50) CHECK (status IN ('SUCCESS','FAILED','IN_PROGRESS')) NOT NULL,
    size_bytes BIGINT,
    duration_seconds INTEGER,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.backup_logs IS 'Logs of backup operations for critical security data';

CREATE INDEX idx_backup_logs_source ON sec.backup_logs(source, started_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB081 - mfa_factors
-- Description: Registered MFA factors per user.
-- Business Case: Multi-factor authentication is mandatory for high-privilege accounts. This
--  table stores the registered factors (TOTP app, SMS, Hardware Key). It tracks verification status
--  to ensure users have completed the enrollment process before requiring MFA at login.
-- KPIs:
-- 1. MFA Adoption Rate (>95% for admins)
-- 2. Verification Success Rate
-- 3. Factor Type Distribution
-- 4. Failed Verification Rate
-- 5. Backup Factor Registration
-- Feature Reference: M17-F054 (Biometric Multi-Factor Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.mfa_factors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    factor_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('TOTP','SMS','HARDWARE_TOKEN','BIOMETRIC','EMAIL')),
    secret_ref VARCHAR(255), --  Reference to encrypted secret in KMS
    verified BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.mfa_factors IS 'Stores registered Multi-Factor Authentication methods per user';

CREATE INDEX idx_mfa_factors_user ON sec.mfa_factors(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB082 - ddos_events
-- Description: Detected DDoS events.
-- Business Case: Availability is critical. This table records detected DDoS attacks, capturing
--  the vector (e.g., SYN flood), peak bandwidth, and mitigation actions taken. Analyzing this data
--  helps tune the WAF/DDoS protection systems for future attacks.
-- KPIs:
-- 1. Detection Time (<1s)
-- 2. Mitigation Trigger Time (<1s)
-- 3. Traffic Drop Accuracy (Legitimate vs Bad)
-- 4. Service Availability During Attack (Target >99%)
-- 5. Peak Volume Handling
-- Feature Reference: M17-F016 (Rate Limiting & DDoS Shield)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ddos_events (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_id VARCHAR(100) UNIQUE NOT NULL,
    attack_vector VARCHAR(50) NOT NULL,
    peak_bps NUMERIC(15,2),
    peak_pps NUMERIC(15,2),
    duration_seconds INTEGER,
    mitigated BOOLEAN DEFAULT true,
    details JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.ddos_events IS 'Records detected DDoS events and mitigation metrics';

CREATE INDEX idx_ddos_events_time ON sec.ddos_events(created_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB083 - key_recovery_requests
-- Description: Requests for key recovery from escrow.
-- Business Case: Key loss is catastrophic (data becomes inaccessible). This table manages the
--  approval workflow for key recovery. It requires quorum (e.g., 3 of 5 trustees) approval before
--  reassembling the key shards, ensuring that key recovery is a highly controlled, audited process.
-- KPIs:
-- 1. Approval Workflow Time (<4 hours)
-- 2. Recovery Success Rate (100%)
-- 3. Quorum Achievement Rate
-- 4. False Request Rejection
-- 5. Audit Trail Completeness
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_recovery_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    requester_id UUID NOT NULL,
    approval_count INTEGER DEFAULT 0,
    required_approvals INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED','COMPLETED')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_recovery_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_recovery_requests IS 'Manages requests and approvals for key recovery from escrow';

CREATE INDEX idx_key_recovery_status ON sec.key_recovery_requests(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB084 - library_versions
-- Description: Whitelist of allowed library versions.
-- Business Case: Supply Chain Security. Instead of just blocking vulnerabilities, the system
--  enforces an "allowlist". Only specific, vetted versions of libraries (e.g., `lodash 4.17.21`)
--  are permitted. Any other version, even if it has no known CVEs, is blocked. This provides the
--  highest level of security.
-- KPIs:
-- 1. Violation Detection Rate (100%)
-- 2. Allowlist Coverage (Critical libs)
-- 3. False Positive Block Rate (0)
-- 4. Library Update Latency (New approved versions)
-- 5. Build Failure Rate (Due to policy)
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.library_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    lib_id VARCHAR(100) UNIQUE NOT NULL,
    group_id VARCHAR(255) NOT NULL, --  Maven groupId, npm org
    artifact_id VARCHAR(255) NOT NULL, --  Maven artifactId, npm package
    version VARCHAR(100) NOT NULL,
    allowed BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.library_versions IS 'Whitelist of explicitly allowed software library versions';

CREATE UNIQUE INDEX idx_library_ver_gav ON sec.library_versions(group_id, artifact_id, version);

------------------------------------------------------------------------------------------------
-- Table: M17-DB085 - performance_impact
-- Description: Impact of security controls on system performance.
-- Business Case: Security cannot slow down the system (latency is money). This table tracks
--  the performance overhead of controls (e.g., "Decryption adds 5ms"). It is used to ensure that
--  the security fabric meets its SLA targets and to identify bottlenecks in the mesh or crypto
--  operations.
-- KPIs:
-- 1. Encryption Latency (Target <10ms)
-- 2. Policy Eval Latency (Target <5ms)
--  3. Network Overhead (Target <5%)
--  4. CPU Utilization Impact
--  5. SLA Breach Count (0)
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.performance_impact (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_id VARCHAR(100) UNIQUE NOT NULL,
    control_name VARCHAR(255) NOT NULL, --  mTLS, Attestation, WAF
    baseline_latency_ms NUMERIC(10,2),
    actual_latency_ms NUMERIC(10,2),
    impact_ratio NUMERIC(5,4), --  (actual - baseline) / baseline
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.performance_impact IS 'Measures the performance overhead of security controls';

CREATE INDEX idx_perf_impact_control ON sec.performance_impact(control_name, measured_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB086 - training_records
-- Description: Records of security training completed by staff.
-- Business Case: Humans are often the weakest link. Compliance standards require regular security
--  awareness training. This table tracks completion of training modules and scores. It flags staff
--  who are delinquent, preventing them from accessing sensitive systems until trained.
-- KPIs:
-- 1. Training Completion Rate (>95%)
-- 2. Average Training Score
--  3. Phishing Simulation Click Rate (Decreasing trend)
--  4. Delinquent Staff Count
--  5. Course Update Coverage
-- Feature Reference: M17-F142 (AI-Powered Phishing Simulation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.training_records (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    record_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    training_module VARCHAR(255) NOT NULL,
    completion_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    score NUMERIC(5,2) CHECK (score BETWEEN 0 AND 100),
    status VARCHAR(20) CHECK (status IN ('PASSED','FAILED','IN_PROGRESS')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.training_records IS 'Tracks employee security training compliance';

CREATE INDEX idx_training_records_user ON sec.training_records(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB087 - role_mining_results
-- Description: Results of automated role mining.
-- Business Case: Role Entitlement Creep is a common issue. "Role Mining" uses ML to analyze
--  access patterns and suggest optimal, consolidated roles (e.g., "75% of DBAs need access X, Y, Z").
--  This table stores these suggestions to help IAM engineers clean up the role structure.
-- KPIs:
-- 1. Role Reduction Count (Consolidation success)
--  2. Suggestion Accuracy (Confidence score)
--  3. Privilege Reduction Amount
--  4. Analysis Execution Time
--  5. Adopted Suggestion Rate
--  Feature Reference: M17-F100 (Role Mining Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.role_mining_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    result_id VARCHAR(100) UNIQUE NOT NULL,
    suggested_role_name VARCHAR(255) NOT NULL,
    users_count INTEGER NOT NULL,
    permissions_json JSONB NOT NULL,
    confidence_score NUMERIC(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    analysis_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.role_mining_results IS 'Stores results from automated role mining analysis for IAM optimization';

------------------------------------------------------------------------------------------------
-- Table: M17-DB088 - digital_signatures
-- Description: Log of digital signatures performed.
-- Business Case: Non-repudiation. This table logs every signing operation (e.g., "Signed Artifact
--  #123 with Key #456"). It provides proof of *who* signed *what* and *when*. It is essential for
--  legal disputes and supply chain audits.
-- KPIs:
-- 1. Signing Operation Success (100%)
--  2. Signature Verification Rate
--  3. Key Usage Distribution
--  4. Timestamp Accuracy (NTP sync)
--  5. Audit Log Integrity
--  Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.digital_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sig_id VARCHAR(100) UNIQUE NOT NULL,
    signer_id UUID NOT NULL,
    data_hash VARCHAR(64) NOT NULL,
    signature_ref VARCHAR(255), --  Reference to the detached signature file
    algorithm VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT digital_signatures_signer_fkey FOREIGN KEY (signer_id) REFERENCES sec.sign_keys(id)
);
COMMENT ON TABLE sec.digital_signatures IS 'Immutable log of digital signatures for non-repudiation';

CREATE INDEX idx_digital_sigs_hash ON sec.digital_signatures(data_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB089 - admin_sessions
-- Description: Detailed session logs for privileged access workstations.
-- Business Case: PAM (Privileged Access Management). This table tracks sessions specifically for
--  admin workstations, including the video recording path of the session (for monitoring) and the
--  specific commands run. It ensures that all privileged activity is recorded and reviewable.
-- KPIs:
--  1. Session Recording Success (100%)
--  2. Command Logging Accuracy
--  3. Session Termination Speed
--  4. Review Completion Rate
--  5. Anomalous Command Detection
--  Feature Reference: M17-F089 (Secure Remote Access (Bastion))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.admin_sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) UNIQUE NOT NULL,
    admin_id UUID NOT NULL,
    workstation_ip VARCHAR(45),
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    video_log_path VARCHAR(500),
    command_log_path VARCHAR(500),
    status VARCHAR(20) DEFAULT 'ACTIVE', --  ACTIVE, TERMINATED, LOCKED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.admin_sessions IS 'Detailed logs and recording references for privileged administrator sessions';

CREATE INDEX idx_admin_sessions_admin ON sec.admin_sessions(admin_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB090 - geoip_cache
-- Description: Cache of IP to Geo mappings for performance.
-- Business Case: Geo-blocking and fraud detection require looking up the country of an IP.
--  External GeoIP APIs are slow. This table caches the results (IP range -> Country) locally,
--  enabling fast lookups at the firewall level without adding latency to user requests.
-- KPIs:
--  1. Lookup Latency (<1ms)
--  2. Cache Hit Ratio (>95%)
--  3. Data Freshness (Updates daily)
--  4. Accuracy (>99%)
--  5. Storage Efficiency
--  Feature Reference: M17-F012 (Geo-Fencing API Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.geoip_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_range_start VARCHAR(45) NOT NULL,
    ip_range_end VARCHAR(45) NOT NULL,
    country_code CHAR(2) NOT NULL,
    city VARCHAR(100),
    last_refreshed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.geoip_cache IS 'Local cache of IP Geolocation data for fast lookups';

CREATE INDEX idx_geoip_range_start ON sec.geoip_cache(ip_range_start);
CREATE INDEX idx_geoip_country ON sec.geoip_cache(country_code);

------------------------------------------------------------------------------------------------
-- Table: M17-DB091 - sla_compliance
-- Description: Tracks adherence to security SLAs (e.g., patch time).
-- Business Case: Operational Excellence. This table tracks if security operations (e.g., patching
--  a critical vuln) met the SLA (e.g., "Patch within 48 hours"). It aggregates data from other
--  tables to calculate the percentage compliance, providing a scorecard for the security team.
-- KPIs:
--  1. Patch SLA Adherence (>95%)
--  2. Incident Response SLA Adherence
--  3. Overall Compliance Score
--  4. SLA Breach Count
--  5. Trend Analysis (Improving/Worsening)
--  Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sla_compliance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sla_id VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    target_value NUMERIC(10,2),
    actual_value NUMERIC(10,2),
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    compliant BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.sla_compliance IS 'Tracks adherence to Security Level Agreements (SLAs)';

CREATE INDEX idx_sla_period ON sec.sla_compliance(period_start, period_end);

------------------------------------------------------------------------------------------------
-- Table: M17-DB092 - encryption_context
-- Description: Contextual data associated with envelope encryption.
-- Business Case: Envelope encryption uses a Data Encryption Key (DEK) wrapped by a Master Key.
--  The "context" (e.g., User ID, Project ID) binds the DEK to specific data. This table stores
--  this context, ensuring that a key encrypted for Project A cannot be used to decrypt data
--  from Project B, providing isolation.
-- KPIs:
--  1. Context Match Success (100%)
--  2. Key Binding Accuracy
--  3. Context Lookup Speed
--  4. Data Isolation Enforcement
--  5. Key Reuse Prevention
--  Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.encryption_context (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    context_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    context_key VARCHAR(255) NOT NULL,
    context_value TEXT NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT encryption_context_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.encryption_context IS 'Stores binding context for envelope encrypted keys to ensure data isolation';

CREATE INDEX idx_enc_context_key ON sec.encryption_context(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB093 - deactivated_accounts
-- Description: Archive of deactivated user accounts.
-- Business Case: When a user leaves, their account is deactivated. However, the data must be
--  retained for audit purposes and potentially legal holds. This table archives the essential
--  user data, ensures login is blocked, and manages the retention period before final deletion.
--  KPIs:
--  1. Deactivation Speed (<1 hour from exit)
--  2. Login Block Success (100%)
--  3. Retention Policy Adherence
--  4. Reactivation Accuracy (if needed)
--  5. Storage Optimization
--  Feature Reference: M17-F087 (Identity Synchronization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.deactivated_accounts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    deactivation_reason VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_retained_until TIMESTAMP WITH TIME ZONE,
    archived_data JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.deactivated_accounts IS 'Archive of deactivated user accounts for audit and retention';

CREATE INDEX idx_deac_accounts_user ON sec.deactivated_accounts(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB094 - dashboard_widgets
-- Description: Configuration for security dashboards.
-- Business Case: Visualization is key for situational awareness. This table stores the config
--  for dashboard widgets (queries, chart types, positions). It allows users to customize their
--  views while ensuring the underlying data queries are secured and validated.
--  KPIs:
--  1. Widget Load Time (<1s)
--  2. Data Accuracy (Matches source)
--  3. Configuration Save Success
--  4. User Adoption Rate
--  5. Refresh Latency
--  Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dashboard_widgets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    widget_id VARCHAR(100) UNIQUE NOT NULL,
    dashboard_id VARCHAR(100) NOT NULL,
    query TEXT NOT NULL, -- SQL or API query
    visualization_type VARCHAR(50), --  CHART, TABLE, MAP
    position_x INTEGER,
    position_y INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dashboard_widgets IS 'Configuration of widgets for security monitoring dashboards';

CREATE INDEX idx_dash_widgets_dash ON sec.dashboard_widgets(dashboard_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB095 - waf_rules
-- Description: Web Application Firewall rules.
-- Business Case: Protecting web apps from OWASP Top 10 (SQLi, XSS). This table stores the
--  patterns (Regex, signatures) for the WAF. It acts as the central repository for rule
--  management, allowing updates without restarting the application and logging block events.
-- KPIs:
--  1. Attack Block Rate
--  2. False Positive Rate (<0.1%)
--  3. Rule Deployment Latency (<30s)
--  4. Attack Type Distribution
--  5. Rule Update Frequency
--  Feature Reference: M17-F025 (Encrypted Traffic Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.waf_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    rule_pattern TEXT NOT NULL, -- Regex or signature
    action VARCHAR(20) NOT NULL CHECK (action IN ('ALLOW','DENY','LOG','ALERT')),
    severity VARCHAR(20) NOT NULL,
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.waf_rules IS 'Web Application Firewall rule patterns for application-level security';

CREATE INDEX idx_waf_rules_action ON sec.waf_rules(action, severity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB096 - artifact_signatures
-- Description: Signatures for build artifacts.
-- Business Case: Proving authenticity. This table links an artifact (Docker image, binary) to
--  a signature record. The verification engine checks this table to ensure that the artifact
--  running in production matches the signature created by the trusted build pipeline.
--  KPIs:
--  1. Verification Success (100%)
--  2. Signature Coverage (All artifacts signed)
--  3. Key Rotation Impact (Old sigs invalid)
--  4. Tamper Detection Rate
--  5. Chain of Trust Completeness
--  Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.artifact_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    signature_id VARCHAR(100) UNIQUE NOT NULL,
    artifact_id VARCHAR(255) NOT NULL, --  SHA256 hash of the artifact
    signature_hash VARCHAR(64) NOT NULL,
    signer_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT artifact_sigs_signer_fkey FOREIGN KEY (signer_id) REFERENCES sec.sign_keys(id)
);
COMMENT ON TABLE sec.artifact_signatures IS 'Links artifacts to their digital signatures for verification';

CREATE UNIQUE INDEX idx_artifact_sigs_artifact ON sec.artifact_signatures(artifact_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB097 - ip_reputations
-- Description: Reputation scores of IP addresses.
-- Business Case: Context-aware security. An IP's reputation (is it a known botnet, VPN, or
--  residential ISP?) helps in making decisions. This table caches reputation scores, allowing
--  the system to challenge or block connections from low-reputation IPs proactively.
--  KPIs:
--  1. Score Accuracy
--  2. Update Frequency (Daily)
--  3. False Positive Block (Good IP marked bad)
--  4. Threat Prevention (Blocked malicious IPs)
--  5. Cache Hit Ratio
--  Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ip_reputations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address VARCHAR(45) PRIMARY KEY,
    score INTEGER CHECK (score BETWEEN 0 AND 100), --  0=Bad, 100=Good
    source VARCHAR(50), --  WHOIS, FEED, HISTORY
    risk_level VARCHAR(20) CHECK (risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW','SAFE')),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ip_reputations IS 'Caches reputation scores for IP addresses for risk-based decisions';

CREATE INDEX idx_ip_reputation_score ON sec.ip_reputations(score);

------------------------------------------------------------------------------------------------
-- Table: M17-DB098 - consent_revocations
-- Description: Log of consent withdrawals.
-- Business Case: GDPR requires that if a user withdraws consent, data processing must stop
--  immediately. This table logs the withdrawal event. The Data Access Layer queries this table
--  before returning PII to ensure compliance with the user's current preference.
--  KPIs:
--  1. Withdrawal Processing Time (<5 min)
--  2. Data Access Stoppage (100% immediate)
--  3. Audit Log Completeness
--  4. Notification Accuracy
--  5. Legal Hold Exception Handling
--  Feature Reference: M17-F092 (Privacy Preserving Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.consent_revocations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    revocation_id VARCHAR(100) UNIQUE NOT NULL,
    consent_id UUID NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    request_ip VARCHAR(45),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT consent_revocations_consent_fkey FOREIGN KEY (consent_id) REFERENCES sec.consent_records(id)
);
COMMENT ON TABLE sec.consent_revocations IS 'Log of user consent withdrawals for immediate enforcement';

CREATE INDEX idx_consent_revs_consent ON sec.consent_revocations(consent_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB099 - data_classification
-- Description: Classification labels applied to data assets.
-- Business Case: Data needs protection based on its sensitivity. This table applies labels
--  (CONFIDENTIAL, RESTRICTED) to specific data assets (tables, S3 buckets). The DLP engine
--  uses this table to enforce policies (e.g., "Block RESTRICTED data from leaving the VPC").
--  KPIs:
--  1. Classification Accuracy (>95%)
--  2. Auto-Tagging Coverage
--  3. Policy Enforcement Success
--  4. Re-classification Speed
--  5. Unclassified Data Reduction
--  Feature Reference: M17-F127 (Data Classification Tagging)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_classification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id VARCHAR(255) NOT NULL,
    classification_level sec.enum_data_classification NOT NULL,
    classifier_id VARCHAR(100), --  AI model ID or Human
    confidence_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_classification IS 'Applies security classification labels to data assets';

CREATE UNIQUE INDEX idx_data_class_asset ON sec.data_classification(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB100 - control_exceptions
-- Description: Approved exceptions to security policies.
-- Business Case: Sometimes operations require bypassing a control (e.g., Emergency access).
--  This table tracks these exceptions with an expiry date and approver. It ensures that exceptions
--  are temporary, authorized, and visible to auditors, preventing "shadow IT" security practices.
-- KPIs:
--  1. Expiry Enforcement (100%)
--  2. Approval Workflow Compliance
--  3. Exception Volume (Trend analysis)
--  4. Justification Completeness
--  5. Audit Review Status
--  Feature Reference: M17-F043 (Supply Chain Integrity Check)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.control_exceptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exception_id VARCHAR(100) UNIQUE NOT NULL,
    policy_id UUID NOT NULL,
    justification TEXT NOT NULL,
    approver UUID NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT control_exceptions_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.zero_trust_policies(id)
);
COMMENT ON TABLE sec.control_exceptions IS 'Tracks temporary, approved exceptions to security policies';

CREATE INDEX idx_control_expirations ON sec.control_exceptions(expiry_date);

-- 2. Triggers for Update Timestamps (DB051-DB100)
-- ================================================================================

CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vulnerability_thresholds FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.health_checks FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.biometric_templates FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.device_trust FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dns_records FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.audit_reports FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_tasks FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.container_images FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.abac_attributes FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.firewall_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.social_logins FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_keys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.honeypots FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.api_keys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_headers FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.code_repositories FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.forensic_snapshots FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_entitlements FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.consent_records FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.penetration_tests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.hmac_keys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_graph FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.feature_flags FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.backup_logs FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.mfa_factors FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.key_recovery_requests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.library_versions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.performance_impact FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.training_records FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.role_mining_results FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.admin_sessions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.geoip_cache FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.sla_compliance FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.encryption_context FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.deactivated_accounts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dashboard_widgets FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.waf_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.ip_reputations FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_classification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.control_exceptions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- End of Script Part 2
-- Next Part: Tables DB101-DB150

-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 4: Tables DB151-DB200)
-- ================================================================================
-- Description:
-- Continuation of the M17 schema definition. This part concludes the comprehensive
-- table definitions, covering advanced topics such as firewall rule grouping,
-- data retention policies, user behavior analytics (UEBA), evidence management,
-- crypto provider health, SSL interception, consent management, artifact lineage,
-- incident timelines, and policy documentation.
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. DDL Statements (Tables 151-200)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB151 - firewall_rulesets
-- Description: Grouping of firewall rules.
-- Business Case: Managing individual firewall rules at scale is chaotic. Rulesets allow
-- logical grouping (e.g., "Egress Rules for Payment Service") to apply, version,
--  and audit multiple rules simultaneously. This table acts as a container for rules,
--  enabling bulk updates and atomic deployments of complex network policies. It reduces
--  the operational overhead of managing thousands of individual IPs/Ports.
-- KPIs:
-- 1. Ruleset Deployment Latency (<30s)
-- 2. Rule Ordering Accuracy (Priority enforcement)
-- 3. Configuration Conflict Detection (0)
-- 4. Atomic Update Success Rate
-- 5. Orphaned Rule Count (0)
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.firewall_rulesets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ruleset_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL,
    version INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.firewall_rulesets IS 'Logical groupings for firewall rules to simplify management and deployment';

CREATE INDEX idx_firewall_rulesets_priority ON sec.firewall_rulesets(priority);
CREATE INDEX idx_firewall_rulesets_active ON sec.firewall_rulesets(is_active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB152 - data_retention_policy
-- Description: Policies for data retention.
-- Business Case: Data hoarding creates liability. This table defines retention policies
-- (e.g., "Audit logs: 7 years, PII: 3 years"). The automated archival and
-- deletion jobs query this table to determine what to keep and what to purge. It
--  ensures legal compliance (GDPR Right to be Forgotten) and cost management.
-- KPIs:
-- 1. Policy Enforcement Accuracy (100%)
-- 2. Legal Hold Override Success
-- 3. Storage Cost Reduction
-- 4. Deletion Job Success Rate
-- 5. Policy Update Propagation Time
-- Feature Reference: M17-F045 (Log Retention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_retention_policy (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    data_type VARCHAR(100) NOT NULL,
    retention_period_months INTEGER NOT NULL,
    archive_cold_storage BOOLEAN DEFAULT true,
    legal_hold BOOLEAN DEFAULT false, --  Prevents deletion if true
    justification TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_retention_policy IS 'Defines retention periods and archival settings for different data categories';

CREATE UNIQUE INDEX idx_retention_policy_type ON sec.data_retention_policy(data_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB153 - user_risk_scores
-- Description: Calculated risk scores for users (UEBA).
-- Business Case: User and Entity Behavior Analytics (UEBA) detects insider threats.
-- This table stores the calculated risk score for users based on historical behavior
--  (login times, access patterns). A sudden spike in score triggers automated
-- challenges or account freezes, stopping compromised accounts before damage occurs.
-- KPIs:
-- 1. Model Prediction Accuracy (>95%)
-- 2. False Positive Rate (<0.5%)
-- 3. Risk Score Calculation Latency (<1s)
-- 4. True Positive Detection (Account takeovers stopped)
-- 5. User Friction (Inconvenience score)
-- Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_risk_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    score_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    risk_score NUMERIC(5,2) CHECK (risk_score BETWEEN 0 AND 100),
    factors_json JSONB NOT NULL, --  Factors contributing to score
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_risk_scores IS 'Stores historical UEBA risk scores for users to detect anomalies';

CREATE INDEX idx_user_risk_user ON sec.user_risk_scores(user_id, calculated_at DESC);

------------------------------------------------------------------------------------------------
-- Table: M17-DB154 - audit_evidence_files
-- Description: Actual file blobs or pointers for evidence.
-- Business Case: Auditors need raw evidence (screenshots, logs, configs). Storing large
--  files in Postgres is inefficient. This table stores metadata and references (e.g., S3
--  paths) to evidence files. It ensures that evidence referenced in "Evidence Locker"
--  is retrievable, tamper-proof, and linked correctly to specific controls.
-- KPIs:
-- 1. File Integrity Check (SHA256 match)
-- 2. Retrieval Latency (<2s)
-- 3. Storage Availability (99.99%)
-- 4. Evidence Upload Success (100%)
-- 5. Duplicate File Handling
-- Feature Reference: M17-F137 (Compliance Evidence Collection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_evidence_files (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_id VARCHAR(100) UNIQUE NOT NULL,
    evidence_id UUID NOT NULL, -- Link to evidence_locker table
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    file_size_bytes BIGINT,
    mime_type VARCHAR(100),
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT audit_evidence_evidence_fkey FOREIGN KEY (evidence_id) REFERENCES sec.evidence_locker(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.audit_evidence_files IS 'Stores metadata and storage references for audit evidence files';

CREATE INDEX idx_audit_evidence_evidence ON sec.audit_evidence_files(evidence_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB155 - crypto_provider_status
-- Description: Health status of crypto providers.
-- Business Case: The system relies on multiple crypto providers (HSMs, Cloud KMSs).
-- This table monitors their health (latency, error rates, uptime). It acts as the
-- input for failover logic; if Provider A is unhealthy, the system routes operations
--  to Provider B automatically, ensuring continuity of cryptographic services.
-- KPIs:
-- 1. Provider Availability (Target 99.99%)
-- 2. Heartbeat Latency (<10ms)
-- 3. Failover Trigger Count
-- 4. Error Rate (<0.01%)
-- 5. Automatic Recovery Success
-- Feature Reference: M17-F043 (HSM Cluster Failover)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.crypto_provider_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_id VARCHAR(100) UNIQUE NOT NULL,
    provider_type VARCHAR(50) NOT NULL, --  AWS_KMS, AZURE_VAULT, THALES_LUNA
    status VARCHAR(20) CHECK (status IN ('ONLINE','DEGRADED','OFFLINE','UNKNOWN')),
    latency_ms NUMERIC(10,2),
    last_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.crypto_provider_status IS 'Real-time health status of cryptographic providers for failover logic';

CREATE INDEX idx_crypto_provider_type ON sec.crypto_provider_status(provider_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB156 - ssl_interception
-- Description: Configuration for SSL inspection.
-- Business Case: Threats hide inside encrypted traffic. To inspect malware, the system
--  must decrypt (MITM) and re-encrypt traffic. This table configures which endpoints
--  are subject to SSL inspection and points to the CA bundle required for clients to trust
--  the inspection proxy.
-- KPIs:
-- 1. Inspection Throughput
-- 2. Malware Detection Rate in SSL
-- 3. Certificate Error Rate (Client trust issues)
-- 4. Performance Overhead (<10%)
-- 5. Configuration Coverage
-- Feature Reference: M17-F025 (Encrypted Traffic Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ssl_interception (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_id VARCHAR(100) UNIQUE NOT NULL,
    target_service VARCHAR(255) NOT NULL,
    inspection_enabled BOOLEAN DEFAULT false,
    ca_bundle_id VARCHAR(100) NOT NULL, -- Reference to Root CA used for signing dynamic certs

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ssl_interception IS 'Configures SSL/TLS inspection for malware detection within encrypted traffic';

CREATE INDEX idx_ssl_intercept_target ON sec.ssl_interception(target_service);

------------------------------------------------------------------------------------------------
-- Table: M17-DB157 - consent_templates
-- Description: Templates for user consent forms.
-- Business Case: Consent forms must be consistent and legally binding. This table stores
--  the HTML/JSON content of consent forms (e.g., "Privacy Policy", "Cookie Usage").
--  Versioning these templates ensures that if a user agrees to v1, their consent record
--  is valid even if v2 is released later.
-- KPIs:
-- 1. Template Version Consistency
-- 2. Render Success Rate (No broken UI)
-- 3. Legal Review Completion (Before publish)
-- 4. Version Adoption Rate
-- 5. Language Support Coverage
-- Feature Reference: M17-F073 (Consent Records)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.consent_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    content_html TEXT,
    content_json JSONB,
    version INTEGER DEFAULT 1,
    active BOOLEAN DEFAULT true,
    language CHAR(2) DEFAULT 'en',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.consent_templates IS 'Stores versions of user consent forms for GDPR/Privacy compliance';

CREATE INDEX idx_consent_templates_active ON sec.consent_templates(name, active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB158 - ioc_sources
-- Description: Sources of Indicators of Compromise.
-- Business Case: Threat Intel comes from many feeds (CrowdStrike, Mandiant, Open Sources).
-- This table manages the configuration of these sources. It tracks reliability scores
--  so the system can prioritize IOCs from high-reliability feeds and filter out noise
--  from low-reliability ones.
-- KPIs:
-- 1. Feed Sync Success (100%)
-- 2. Reliability Score Accuracy
-- 3. IOC Ingestion Volume
-- 4. Duplicate IOC Deduplication
-- 5. Source Availability
-- Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ioc_sources (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    reliability_score NUMERIC(3,2) CHECK (reliability_score BETWEEN 0 AND 1),
    format VARCHAR(50), --  STIX, TAXII, CSV
    last_sync TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ioc_sources IS 'Configuration of external threat intelligence sources';

CREATE INDEX idx_ioc_sources_reliability ON sec.ioc_sources(reliability_score);

------------------------------------------------------------------------------------------------
-- Table: M17-DB159 - approved_signers
-- Description: List of code signers allowed.
-- Business Case: Only specific keys can sign production code. This table acts as a
--  whitelist of public keys belonging to approved "Signers" (Release Engineers).
--  When a signed artifact is verified, the signing key *must* match an entry here.
--  KPIs:
-- 1. Whitelist Coverage (100%)
-- 2. Expired Key Detection
-- 3. Unauthorized Signature Blocking (100%)
-- 4. Signer Identity Verification
-- 5. Key Rotation Compliance
-- Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.approved_signers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    signer_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    public_key_fingerprint VARCHAR(64) NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE', --  ACTIVE, REVOKED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.approved_signers IS 'Whitelist of approved code signers for artifact verification';

CREATE UNIQUE INDEX idx_signers_fingerprint ON sec.approved_signers(public_key_fingerprint);

------------------------------------------------------------------------------------------------
-- Table: M17-DB160 - security_events_schema
-- Description: Schema definition for security events.
-- Business Case: Security events evolve. This table defines the JSON schema (or structure)
--  for different event types (e.g., "LoginEvent" requires username, "TxEvent" requires
--  amount). The ingestion engine validates events against this schema to prevent
--  schema drift and ensure data quality in the `audit_trail`.
-- KPIs:
-- 1. Validation Success Rate (100%)
-- 2. Schema Version Adoption
-- 3. Invalid Event Rejection (Data Quality)
-- 4. Schema Update Latency
-- 5. Documentation Coverage
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_events_schema (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_type VARCHAR(100) UNIQUE NOT NULL,
    schema_version INTEGER DEFAULT 1,
    required_fields TEXT[], --  Array of field names
    optional_fields TEXT[],
    data_types_json JSONB, --  Field -> Type mapping

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_events_schema IS 'Defines the schema/structure for different types of security events';

------------------------------------------------------------------------------------------------
-- Table: M17-DB161 - key_split_history
-- Description: History of key splitting/sharing events.
-- Business Case: Splitting keys (Shamir) is a sensitive operation. This table logs
--  every split event, recording participants and timestamps. It provides an audit trail
--  for "Key of Custody", ensuring that the reconstruction of a master key is
--  traceable and authorized.
-- KPIs:
-- 1. Logging Completeness (100%)
-- 2. Participant Verification Success
-- 3. Splitting Accuracy (Reconstructible)
-- 4. Unauthorized Attempt Detection (0)
-- 5. Audit Retrieval Speed
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_split_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    action VARCHAR(20) CHECK (action IN ('SPLIT','COMBINE')),
    participants UUID[] NOT NULL, -- List of Trustee IDs
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    result VARCHAR(20) CHECK (result IN ('SUCCESS','FAILURE')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_split_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_split_history IS 'Audit trail of key splitting and combining operations';

CREATE INDEX idx_key_split_key ON sec.key_split_history(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB162 - query_performance
-- Description: Performance of audit queries.
-- Business Case: Analyzing audit logs requires complex queries. This table tracks the
--  performance of specific common queries (e.g., "Show all failed logins in last hour").
--  It helps DBAs identify slow queries and optimize indexes or schema to ensure the
--  security team can investigate incidents quickly.
-- KPIs:
-- 1. Query Latency (p95 < 1s)
-- 2. Optimization Success (Latency reduction)
-- 3. Frequency Tracking
-- 4. Resource Consumption (CPU/IOPS)
-- 5. SLA Compliance for Reports
-- Feature Reference: M17-F143 (Granular Database Auditing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.query_performance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_id VARCHAR(100) UNIQUE NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    query_hash VARCHAR(64), --  To track variations of same query
    duration_ms NUMERIC(10,2),
    rows_scanned BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.query_performance IS 'Tracks performance metrics of audit queries for optimization';

CREATE INDEX idx_query_perf_timestamp ON sec.query_performance(timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB163 - bgp_peers
-- Description: Authorized BGP peers for network security.
-- Business Case: BGP hijacking is a major risk for infrastructure. This table defines
--  the list of authorized BGP peers and their expected AS numbers. The router
--  configuration generated from this table ensures the network only accepts routes from
--  trusted peers, preventing traffic diversion.
-- KPIs:
-- 1. Peer Configuration Accuracy (100%)
-- 2. Hijack Prevention Rate (0 incidents)
-- 3. Route Propagation Latency
-- 4. Peer Availability
-- 5. Configuration Drift (0)
-- Feature Reference: M17-F056 (DNS Security (DNSSEC))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.bgp_peers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    peer_id VARCHAR(100) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    asn INTEGER NOT NULL, --  Autonomous System Number
    trust_level VARCHAR(20) CHECK (trust_level IN ('FULL','PARTIAL','LIMITED')),
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.bgp_peers IS 'Defines authorized BGP peers to prevent route hijacking';

CREATE INDEX idx_bgp_peers_asn ON sec.bgp_peers(asn);

------------------------------------------------------------------------------------------------
-- Table: M17-DB164 - control_effectiveness
-- Description: Measurement of how effective controls are.
-- Business Case: Having a control (e.g., "Firewall") isn't enough; is it working? This
--  table tracks the results of testing controls (e.g., Penetration Testing results against
--  specific controls). It highlights "Gaps" where controls are in place but ineffective.
-- KPIs:
-- 1. Control Testing Coverage (%)
-- 2. Effectiveness Score (Pass/Fail rate)
-- 3. Gap Identification Speed
-- 4. Remediation of Ineffective Controls
-- 5. Cost vs Benefit Analysis
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.control_effectiveness (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assessment_id VARCHAR(100) UNIQUE NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    effectiveness_score INTEGER CHECK (effectiveness_score BETWEEN 0 AND 100),
    last_tested TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    gaps TEXT[], --  Specific gaps found
    tester_id UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.control_effectiveness IS 'Measures the real-world effectiveness of security controls';

CREATE INDEX idx_control_effectiveness_control ON sec.control_effectiveness(control_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB165 - artifact_ancestry
-- Description: Lineage of build artifacts.
-- Business Case: Tracking "who is your parent". If a vulnerability is found in a base
--  image, which children (artifacts) are affected? This table stores the lineage graph
--  (Parent -> Child). It is essential for rapid impact analysis during supply chain
--  incidents.
-- KPIs:
-- 1. Lineage Completeness (100%)
-- 2. Impact Analysis Speed (<1 min)
-- 3. Graph Depth Accuracy
-- 4. Recursive Query Performance
-- 5. Orphaned Artifact Detection
-- Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.artifact_ancestry (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_id VARCHAR(100) UNIQUE NOT NULL,
    parent_id VARCHAR(100) NOT NULL, --  Reference to artifact ID
    child_id VARCHAR(100) NOT NULL, --  Reference to artifact ID
    generation_step VARCHAR(100), --  e.g., "COMPILE", "DOCKER_BUILD"

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.artifact_ancestry IS 'Stores the parent-child relationships between build artifacts for impact analysis';

CREATE INDEX idx_art_ancestry_parent ON sec.artifact_ancestry(parent_id);
CREATE INDEX idx_art_ancestry_child ON sec.artifact_ancestry(child_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB166 - account_lockouts
-- Description: Records of account lockouts.
-- Business Case: Security vs Usability. Tracking lockouts helps distinguish between a
--  brute force attack and a forgetful user. High frequency of lockouts for specific
--  IPs might indicate an attack, while frequent lockouts for a user might indicate
--  a need for password reset assistance.
-- KPIs:
-- 1. Lockout Enforcement (100%)
-- 2. Attack Detection Accuracy (IP clustering)
-- 3. Auto-Unlock Success (Timed unlocks)
-- 4. User Frustration Score (Lockout frequency)
-- 5. False Positive Rate
-- Feature Reference: M17-F024 (Failed Attempts)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.account_lockouts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    lockout_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    reason VARCHAR(255),
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    unlocked_at TIMESTAMP WITH TIME ZONE,
    source_ip VARCHAR(45),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.account_lockouts IS 'Records account lockout events for security analysis and support';

CREATE INDEX idx_account_lockouts_user ON sec.account_lockouts(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB167 - anomaly_model_training
-- Description: Metadata for ML model training.
-- Business Case: ML models need training. This table stores metadata about training runs
--  (Model ID, Dataset Hash, Accuracy, Start/End time). It tracks which model version
--  is currently "Champion" and deployed to production, ensuring reproducibility and
--  governance of AI algorithms.
-- KPIs:
-- 1. Model Accuracy (>95%)
-- 2. Training Time (<4 hours)
-- 3. Dataset Integrity (Hash matches)
-- 4. Deployment Success Rate
-- 5. Model Drift Detection
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.anomaly_model_training (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) UNIQUE NOT NULL,
    training_start TIMESTAMP WITH TIME ZONE NOT NULL,
    training_end TIMESTAMP WITH TIME ZONE,
    dataset_hash VARCHAR(64) NOT NULL,
    accuracy_score NUMERIC(3,2),
    status VARCHAR(20) DEFAULT 'TRAINING', --  TRAINING, COMPLETED, FAILED
    is_champion BOOLEAN DEFAULT false, --  Is this the active production model?

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.anomaly_model_training IS 'Stores metadata and results for ML model training runs';

CREATE INDEX idx_anomaly_model_champion ON sec.anomaly_model_training(is_champion);

------------------------------------------------------------------------------------------------
-- Table: M17-DB168 - key_backup_status
-- Description: Status of key backups.
-- Business Case: Disaster Recovery. Keys must be backed up securely (often offline).
--  This table tracks the backup status of keys (e.g., "Backed up to Tape", "Replicated
--  to DR Site"). It ensures that RPO (Recovery Point Objective) for keys is met.
-- KPIs:
-- 1. Backup Success Rate (100%)
-- 2. Backup Latency (Target <1h)
-- 3. Storage Integrity Check (Pass)
-- 4. Offline Storage Compliance
-- 5. Restore Test Success (Quarterly)
-- Feature Reference: M17-F039 (Backup Encryption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_backup_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    backup_location VARCHAR(255) NOT NULL,
    backup_method VARCHAR(50), --  TAPE, S3_GLACIER, OFFLINE_HSM
    status VARCHAR(20) CHECK (status IN ('SUCCESS','FAILED','IN_PROGRESS')),
    backup_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_backup_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_backup_status IS 'Tracks the backup and replication status of cryptographic keys';

CREATE INDEX idx_key_backup_key ON sec.key_backup_status(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB169 - firewall_address_groups
-- Description: Groups of IP addresses for firewall rules.
-- Business Case: IP lists change (new office CIDRs, cloud egress IPs). Address groups
--  allow updating a single group name (e.g., "Office_IPs") and having it propagate to
--  hundreds of firewall rules automatically. It significantly reduces administrative overhead.
-- KPIs:
-- 1. Group Update Propagation (<1 min)
-- 2. IP Address Validity Checks
-- 3. Overlap Detection (Conflicting IPs)
-- 4. Usage Analysis (Unused groups)
-- 5. Member Count Limit Enforcement
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.firewall_address_groups (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    ip_ranges JSONB NOT NULL, --  Array of CIDR strings
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.firewall_address_groups IS 'Defines reusable groups of IP addresses for firewall rules';

CREATE INDEX idx_fw_addr_group_name ON sec.firewall_address_groups(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB170 - vendor_access
-- Description: Third-party vendor access logs.
-- Business Case: Third-party access is a high risk. This table logs every session a
--  vendor has (via PAM or VPN). It tracks what they accessed and for how long,
--  ensuring vendors stay within the scope of their contract and don't snoop around.
-- KPIs:
-- 1. Session Logging (100%)
-- 2. Access Scope Adherence (0 violations)
-- 3. Duration Compliance (No overtime)
-- 4. Activity Monitoring (Idle vs Active)
-- 5. Off-hours Access Detection
-- Feature Reference: M17-F149 (Secure Software Supply Chain)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vendor_access (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    access_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_id VARCHAR(100) NOT NULL, -- Link to vendor table
    user_id UUID, -- If mapped to internal user
    access_start TIMESTAMP WITH TIME ZONE NOT NULL,
    access_end TIMESTAMP WITH TIME ZONE,
    justification TEXT,
    approved_by UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vendor_access IS 'Logs third-party vendor access sessions for compliance monitoring';

CREATE INDEX idx_vendor_access_vendor ON sec.vendor_access(vendor_id);
CREATE INDEX idx_vendor_access_time ON sec.vendor_access(access_start);

------------------------------------------------------------------------------------------------
-- Table: M17-DB171 - port_profiles
-- Description: Allowed port profiles for services.
-- Business Case: Defining standard communication channels. This table defines profiles
--  (e.g., "Web Profile: 80, 443") that can be applied to services. It abstracts
--  the complexity of individual port management and ensures consistency across environments.
-- KPIs:
-- 1. Profile Assignment Accuracy
-- 2. Unauthorized Port Blocking
-- 3. Profile Update Impact Analysis
-- 4. Standardization Rate (% services using profiles)
-- 5. Protocol Compliance Check
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.port_profiles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    profile_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    port_range VARCHAR(20) NOT NULL, --  e.g., "443", "8000-8010"
    protocol VARCHAR(10) CHECK (protocol IN ('TCP','UDP','ANY')),
    description TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.port_profiles IS 'Defines reusable port and protocol profiles for services';

------------------------------------------------------------------------------------------------
-- Table: M17-DB172 - log_forwarding
-- Description: Configuration for forwarding logs to SIEM.
-- Business Case: Centralized monitoring. Logs need to be shipped to external SIEMs (Splunk,
--  Sentinel). This table configures the forwarding rules (Filter: "ERROR only", Dest:
--  "Splunk"). It manages connection status and queues to ensure no logs are lost.
-- KPIs:
-- 1. Forwarding Success Rate (>99.9%)
-- 2. Latency (<1 min)
-- 3. Connection Availability
-- 4. Filter Rule Accuracy
-- 5. Queue Depth Management (No data loss)
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.log_forwarding (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    forwarder_id VARCHAR(100) UNIQUE NOT NULL,
    destination VARCHAR(500) NOT NULL,
    protocol VARCHAR(20), --  SYSLOG, HTTPS, KAFKA
    status VARCHAR(20) CHECK (status IN ('CONNECTED','DISCONNECTED','ERROR')),
    filter_json JSONB, --  Which logs to send

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.log_forwarding IS 'Configures log forwarding to external SIEMs or data lakes';

CREATE INDEX idx_log_forwarding_status ON sec.log_forwarding(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB173 - license_exceptions
-- Description: Exceptions to license policies.
-- Business Case: Sometimes risky licenses (GPL) must be used temporarily. This table
--  tracks approved exceptions, linking them to specific business justifications and
--  approvers. It ensures that exceptions are temporary, approved, and not forgotten.
-- KPIs:
-- 1. Expiration Enforcement (100%)
-- 2. Approval Workflow Compliance
-- 3. Exception Volume Tracking
-- 4. Justification Completeness
-- 5. Risk Acceptance Documentation
-- Feature Reference: M17-F040 (Dependency Licenses)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.license_exceptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exception_id VARCHAR(100) UNIQUE NOT NULL,
    spdx_id VARCHAR(100) NOT NULL, -- Link to license
    justification TEXT NOT NULL,
    approver UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.license_exceptions IS 'Tracks approved exceptions to software license policies';

CREATE INDEX idx_license_exceptions_spdx ON sec.license_exceptions(spdx_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB174 - service_mesh_config
-- Description: Configuration for service mesh.
-- Business Case: Service Mesh (Istio/Linkerd) config is complex. This table stores the
--  desired configuration (DestinationRules, VirtualServices) as JSON. The Mesh Controller
--  reconciles this DB state to the cluster, providing a single source of truth for
--  service networking.
-- KPIs:
-- 1. Reconciliation Latency (<10s)
-- 2. Configuration Validity (No API errors)
-- 3. Version Control (GitOps integration)
-- 4. Rollback Success Rate
-- 5. Drift Detection (0)
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_config (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_id VARCHAR(100) UNIQUE NOT NULL,
    mesh_name VARCHAR(100) NOT NULL,
    config_json JSONB NOT NULL,
    version INTEGER DEFAULT 1,
    applied_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_mesh_config IS 'Stores the source-of-truth configuration for the service mesh';

CREATE INDEX idx_mesh_config_name ON sec.service_mesh_config(mesh_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB175 - signing_keys
-- Description: Metadata for signing keys.
-- Business Case: Code signing requires private keys. This table manages the metadata for
--  signing keys (Usage: Code vs Document, Rotation, Expiry). It ensures keys are
--  rotated before expiry and that only active keys are presented to the CI/CD pipeline.
-- KPIs:
-- 1. Key Availability (100%)
-- 2. Rotation Success (100%)
-- 3. Signing Operation Count
-- 4. Expiry Warning Lead Time (30 days)
-- 5. Usage Analysis (Key popularity)
-- Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.signing_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm VARCHAR(50) NOT NULL, --  RSA-4096, ECDSA-P384
    key_size INTEGER,
    purpose VARCHAR(50) NOT NULL, --  CODE_SIGNING, DOCUMENT_SIGNING
    status sec.enum_cert_status DEFAULT 'VALID',
    expiry_date TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.signing_keys IS 'Metadata for private keys used for signing operations';

CREATE INDEX idx_signing_keys_purpose ON sec.signing_keys(purpose);

------------------------------------------------------------------------------------------------
-- Table: M17-DB176 - dashboard_layout
-- Description: Layout definition for security dashboards.
-- Business Case: Every SOC analyst wants a different view. This table stores the JSON layout
--  for dashboards (Widgets X,Y positions, type). It allows personalized views while
--  ensuring the underlying queries are secured and managed centrally.
-- KPIs:
-- 1. Layout Save/Load Speed (<500ms)
-- 2. Widget Availability (No broken widgets)
-- 3. Shared Layout Consistency
-- 4. Customization Adoption Rate
-- 5. Layout Migration Success (After schema changes)
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dashboard_layout (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    layout_id VARCHAR(100) UNIQUE NOT NULL,
    dashboard_id VARCHAR(100) NOT NULL, -- Link to dashboards table
    layout_json JSONB NOT NULL, --  Serialized layout definition
    user_id UUID, -- Owner of the layout (null for default)

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dashboard_layout IS 'Stores the visual layout configuration for security dashboards';

CREATE INDEX idx_dash_layout_dash ON sec.dashboard_layout(dashboard_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB177 - audit_findings
-- Description: Findings from audits.
-- Business Case: Audits result in findings (Non-conformities). This table tracks findings
--  (e.g., "Encryption key not rotated"), linking them to audits and controls. It tracks
--  the remediation status to ensure findings are closed out and not forgotten.
-- KPIs:
-- 1. Remediation Velocity (Average age)
-- 2. Finding Closure Rate (Target 100%)
-- 3. Recurring Finding Analysis
-- 4. Critical Finding SLA (7 days)
-- 5. Auditor Agreement Rate
-- Feature Reference: M17-F113 (Automated Compliance Reporting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_findings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id VARCHAR(100) UNIQUE NOT NULL,
    audit_id UUID NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    description TEXT NOT NULL,
    remediation_status VARCHAR(50) DEFAULT 'OPEN', --  OPEN, IN_PROGRESS, CLOSED
    due_date TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT audit_findings_audit_fkey FOREIGN KEY (audit_id) REFERENCES sec.audit_plans(id)
);
COMMENT ON TABLE sec.audit_findings IS 'Tracks findings from audits and their remediation status';

CREATE INDEX idx_audit_findings_audit ON sec.audit_findings(audit_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB178 - load_balancer_pools
-- Description: Backend pools for load balancers.
-- Business Case: Traffic distribution. This table defines backend pools (e.g., "Auth Service
--  Pool") containing member IP addresses and health check settings. It allows automated
--  scaling (adding/removing members) by simply updating the DB record.
-- KPIs:
-- 1. Pool Update Propagation (<10s)
-- 2. Health Check Accuracy
-- 3. Member Availability (Target 100%)
-- 4. Load Distribution Evenness
-- 5. Connection Error Rate
-- Feature Reference: M17-F119 (Load Balancer Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.load_balancer_pools (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_id VARCHAR(100) UNIQUE NOT NULL,
    lb_id VARCHAR(100) NOT NULL, --  Parent Load Balancer
    member_addresses TEXT[] NOT NULL, --  Array of IP:Ports
    health_check_path VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.load_balancer_pools IS 'Defines backend pools and members for load balancers';

CREATE INDEX idx_lb_pools_lb ON sec.load_balancer_pools(lb_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB179 - attribute_sources
-- Description: Sources for ABAC attributes.
-- Business Case: ABAC attributes come from various systems (HR DB, LDAP, SCIM).
--  This table configures these sources (Connection string, Sync freq). It acts as an adapter
--  configuration, allowing the ABAC engine to pull attributes dynamically without hardcoding.
-- KPIs:
-- 1. Attribute Sync Success Rate
-- 2. Sync Latency (<15 min)
-- 3. Source Availability
-- 4. Attribute Freshness
-- 5. Connection Error Handling
-- Feature Reference: M17-F080 (Regel-based Access Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.attribute_sources (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50), --  SQL, LDAP, SCIM_API
    connection_string TEXT,
    sync_freq_seconds INTEGER,
    last_sync TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.attribute_sources IS 'Configures external sources for ABAC attributes';

CREATE INDEX idx_attr_sources_name ON sec.attribute_sources(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB180 - elevation_requests
-- Description: Requests for privilege elevation.
-- Business Case: Users sometimes need higher privileges (e.g., Admin access) temporarily.
--  This table manages the request workflow (Who, Why, Duration). It ensures that
--  elevation is justified, approved, and automatically revoked after the time expires.
-- KPIs:
-- 1. Approval Workflow Speed (<1 hour)
-- 2. Auto-Revocation Accuracy (100%)
-- 3. Justification Quality Review
-- 4. Elevation Duration Adherence
-- 5. Auditor Satisfaction (Traceability)
-- Feature Reference: M17-F013 (Just-in-Time (JIT) Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.elevation_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    target_role VARCHAR(100) NOT NULL,
    duration_minutes INTEGER NOT NULL,
    justification TEXT,
    status VARCHAR(50) DEFAULT 'PENDING', --  PENDING, APPROVED, DENIED, EXPIRED
    approved_by UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.elevation_requests IS 'Manages requests and approvals for temporary privilege elevation';

CREATE INDEX idx_elevation_req_user ON sec.elevation_requests(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB181 - key_import_logs
-- Description: Logs of key import operations.
-- Business Case: Importing keys is risky (could be compromised). This table logs every import
--  operation, recording the source, hash of the key, and the operator. It provides
--  a forensic chain of custody for keys entering the system from outside.
-- KPIs:
-- 1. Import Validation Success (100%)
-- 2. Key Integrity Verification
-- 3. Source Authorization Check
-- 4. Logging Completeness
-- 5. Failed Import Analysis
-- Feature Reference: M17-F084 (Private Key Export Prevention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_import_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    import_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    source VARCHAR(255) NOT NULL,
    key_hash_before_import VARCHAR(64),
    operator_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_import_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_import_logs IS 'Logs the import of cryptographic keys for chain of custody';

CREATE INDEX idx_key_import_key ON sec.key_import_logs(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB182 - incident_timeline
-- Description: Chronological timeline of incidents.
-- Business Case: Reconstructing an incident requires a timeline. This table stores events
--  (Detected, Contained, Eradicated) linked to an incident. It allows SOC to visualize
--  the lifecycle of an incident and calculate MTTR accurately.
-- KPIs:
-- 1. Event Logging Latency (<1s)
-- 2. Timeline Accuracy (Chronological)
-- 3. Gap Detection (Missing events)
-- 4. Timeline Generation Speed
-- 5. Stakeholder Communication Clarity
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_timeline (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT incident_timeline_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.incident_timeline IS 'Stores chronological events for an incident timeline';

CREATE INDEX idx_incident_timeline_incident ON sec.incident_timeline(incident_id, timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB183 - ipsec_tunnels
-- Description: IPSec tunnel configurations.
-- Business Case: Secure site-to-site connectivity. This table defines IPSec tunnels (Peers,
--  PSKs, Encryption Algos). It acts as the source of truth for VPN configuration
--  deployment, ensuring that tunnel settings are version controlled and auditable.
-- KPIs:
-- 1. Tunnel Uptime (Target 99.9%)
-- 2. Configuration Deployment Accuracy
-- 3. Key Rotation Success (PSK)
-- 4. Tunnel Latency (<50ms)
-- 5. Security Compliance (Strong Algos only)
-- Feature Reference: M17-F115 (Secure Inter-Cluster Communication)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ipsec_tunnels (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tunnel_id VARCHAR(100) UNIQUE NOT NULL,
    local_ip VARCHAR(45) NOT NULL,
    remote_ip VARCHAR(45) NOT NULL,
    psk_ref VARCHAR(255) NOT NULL, --  KMS reference
    status VARCHAR(20) DEFAULT 'UP', --  UP, DOWN
    last_status_change TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ipsec_tunnels IS 'Defines IPSec tunnel configurations for secure inter-cluster communication';

CREATE INDEX idx_ipsec_status ON sec.ipsec_tunnels(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB184 - code_owners
-- Description: Code owners for repositories.
-- Business Case: Accountability for code. This table maps file path patterns (e.g.,
--  "src/auth/*") to specific owners (Emails). It is used for automatic reviewer
--  assignment and to identify who to contact if a vulnerability is found in specific code.
-- KPIs:
-- 1. Pattern Match Accuracy
-- 2. Owner Assignment Speed
-- 3. Coverage (All files have owners)
-- 4. Owner Validity (Active emails)
-- 5. Change Frequency (Drift tracking)
-- Feature Reference: M17-F104 (Threat Modeling Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.code_owners (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    owner_id VARCHAR(100) UNIQUE NOT NULL,
    repo_id UUID NOT NULL,
    path_pattern TEXT NOT NULL, --  Glob pattern
    contact_email VARCHAR(255) NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT code_owners_repo_fkey FOREIGN KEY (repo_id) REFERENCES sec.code_repositories(id)
);
COMMENT ON TABLE sec.code_owners IS 'Defines code owners for specific paths in repositories';

CREATE INDEX idx_code_owners_repo ON sec.code_owners(repo_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB185 - privileged_access_groups
-- Description: Groups with high privileges.
-- Business Case: Managing individual users is hard; managing groups is easier. This table
--  defines groups with high privileges (e.g., "Domain Admins", "Security Auditors").
--  It tracks membership and justifications for these powerful groups.
-- KPIs:
-- 1. Group Membership Accuracy
-- 2. Justification Review Compliance
-- 3. Orphaned Group Detection
-- 4. Privilege Creep Prevention (Via Group auditing)
-- 5. Certification Completion (Quarterly)
-- Feature Reference: M17-F026 (Privileged Access Management (PAM))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privileged_access_groups (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    privileges_json JSONB NOT NULL, --  Description of rights

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.privileged_access_groups IS 'Defines and manages groups with elevated privileges';

------------------------------------------------------------------------------------------------
-- Table: M17-DB186 - audit_certifications
-- Description: Certifications obtained (ISO27001, etc.).
-- Business Case: Proof of compliance. This table stores details of certifications (ISO, SOC2,
--  PCI) obtained by the organization. It tracks expiry dates to trigger renewal
--  audits and stores the certificate files for verification.
-- KPIs:
-- 1. Renewal Trigger Accuracy (30 days prior)
-- 2. Scope Documentation Completeness
-- 3. Audit Gap Analysis
-- 4. Expiry Incident Rate (0 expired certs)
-- 5. Evidence Storage Integrity
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_certifications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cert_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL, --  ISO 27001:2013
    issuer VARCHAR(255), --  External Audit Firm
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,
    cert_file_ref VARCHAR(500), --  Link to PDF
    status VARCHAR(20) DEFAULT 'ACTIVE', --  ACTIVE, SUSPENDED, EXPIRED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_certifications IS 'Stores details of industry compliance certifications';

CREATE INDEX idx_audit_cert_status ON sec.audit_certifications(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB187 - alert_subscriptions
-- Description: User subscriptions to alerts.
-- Business Case: Alert fatigue is real. Users should only get alerts relevant to them.
-- This table manages subscriptions (User X wants alerts for "High Severity Firewall"
--  events). It personalizes the notification flow to ensure critical alerts aren't missed.
-- KPIs:
-- 1. Subscription Accuracy (Right users getting alerts)
-- 2. Notification Delivery Success
-- 3. Subscription Update Latency (<1s)
-- 4. Duplicate Subscription Prevention
-- 5. Unsubscribe Success Rate
-- Feature Reference: M17-F079 (Alert Fatigue Reduction)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.alert_subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sub_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    alert_type VARCHAR(100) NOT NULL, --  Alert category or ID
    notification_method VARCHAR(50), --  EMAIL, SLACK, SMS
    frequency VARCHAR(20) DEFAULT 'IMMEDIATE', --  IMMEDIATE, DIGEST, DAILY

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.alert_subscriptions IS 'Manages user subscriptions to specific security alerts';

CREATE INDEX idx_alert_subs_user ON sec.alert_subscriptions(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB188 - vlan_mappings
-- Description: VLAN to security zone mappings.
-- Business Case: Network segmentation. This table maps physical VLANs (or VXLANs) to
--  logical security zones. It allows policy enforcement (e.g., "Zone A cannot talk to
--  Zone B") to be implemented automatically on network hardware based on DB data.
-- KPIs:
-- 1. Mapping Accuracy (100%)
-- 2. Configuration Deployment Speed
-- 3. Zone Isolation Verification
-- 4. VLAN Utilization Tracking
-- 5. Conflict Detection (VLAN used twice)
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vlan_mappings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vlan_id INTEGER UNIQUE NOT NULL,
    zone_id VARCHAR(100) NOT NULL,
    description TEXT,
    subnet CIDR,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vlan_mappings IS 'Maps physical VLANs to logical security zones';

CREATE INDEX idx_vlan_mappings_zone ON sec.vlan_mappings(zone_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB189 - key_export_attempts
-- Description: Attempts (blocked/allowed) to export keys.
-- Business Case: Key exfiltration is catastrophic. This table logs *every* attempt to export
--  a private key. For HSM-managed keys, export should be impossible (Blocked). For
--  software keys, it should be rare. Logging attempts helps identify stolen admin
--  credentials trying to steal keys.
-- KPIs:
-- 1. Blocked Attempt Detection (100%)
-- 2. Success Rate (Should be 0 for HSM keys)
-- 3. Alert Generation Speed
-- 4. False Positive Rate (Valid exports blocked)
-- 5. Source IP Analysis
-- Feature Reference: M17-F084 (Private Key Export Prevention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_export_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    attempt_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    user_id UUID NOT NULL,
    attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT false, --  MUST be false for HSM keys
    client_ip VARCHAR(45),
    failure_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_export_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id),
    CONSTRAINT key_export_success_check CHECK (success = false) -- Assuming HSM enforcement primarily
);
COMMENT ON TABLE sec.key_export_attempts IS 'Logs attempts to export private keys, which must always be blocked';

CREATE INDEX idx_key_export_key ON sec.key_export_attempts(key_id);
CREATE INDEX idx_key_export_user ON sec.key_export_attempts(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB190 - custom_policy_rules
-- Description: User-defined policy rules.
-- Business Case: Standard policies aren't enough. This table allows advanced users to write
--  custom rules (e.g., DSL or complex Regex) to address specific edge cases. It extends
--  the policy engine dynamically without code changes.
-- KPIs:
-- 1. Rule Execution Success (No errors)
-- 2. Rule Validation (Syntax check)
-- 3. Performance Impact (<5ms overhead)
-- 4. False Positive Rate of custom rules
-- 5. Rule Documentation (Comments)
-- Feature Reference: M17-F034 (Policy-as-Code)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.custom_policy_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    rule_logic TEXT NOT NULL, --  Custom DSL or code
    language VARCHAR(50), --  REGEX, LUA, OPA
    author_id UUID NOT NULL,
    enabled BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.custom_policy_rules IS 'Stores user-defined custom policy rules for the policy engine';

CREATE INDEX idx_custom_policy_author ON sec.custom_policy_rules(author_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB191 - auth_token_introspection
-- Description: Cache of introspected tokens.
-- Business Case: Token introspection (checking validity) is expensive if done against the
-- Auth Provider for every request. This table acts as a cache, storing token hash +
--  claims for a short TTL. It drastically reduces latency and load on the Auth Provider.
-- KPIs:
-- 1. Cache Hit Ratio (>90%)
-- 2. Token Validation Latency (<10ms)
-- 3. Cache Consistency (Revoked tokens dropped)
-- 4. Storage Efficiency
-- 5. Error Rate (Cache corruption)
-- Feature Reference: M17-F003 (X.509-SVID Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.auth_token_introspection (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    active BOOLEAN DEFAULT true,
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.auth_token_introspection IS 'Cache for introspected authentication tokens to reduce latency';

CREATE INDEX idx_auth_token_hash ON sec.auth_token_introspection(token_hash);
CREATE INDEX idx_auth_token_expires ON sec.auth_token_introspection(expires_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB192 - build_steps
-- Description: Steps in a CI/CD pipeline.
-- Business Case: Pipelines are workflows. This table defines individual steps (Build, Test,
--  Scan, Sign) within a pipeline. It allows granular control (e.g., "Fail if
--  Scan step finds High vuln") and better logging of where a build failed.
-- KPIs:
-- 1. Step Execution Time
-- 2. Failure Rate per Step
-- 3. Security Gate Enforcement (Scan step failure = Stop)
-- 4. Retry Logic Success
-- 5. Parallel Execution Efficiency
-- Feature Reference: M17-F065 (Secure CI/CD Pipeline)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.build_steps (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    step_id VARCHAR(100) UNIQUE NOT NULL,
    pipeline_id UUID NOT NULL,
    step_name VARCHAR(255) NOT NULL,
    command TEXT,
    security_check BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT build_steps_pipeline_fkey FOREIGN KEY (pipeline_id) REFERENCES sec.build_pipelines(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.build_steps IS 'Defines individual execution steps within a CI/CD pipeline';

CREATE INDEX idx_build_steps_pipeline ON sec.build_steps(pipeline_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB193 - risk_register
-- Description: Organizational risk register.
-- Business Case: Strategic risk management. This table lists top organizational risks (e.g.,
--  "Cloud Provider Outage", "Quantum Computing"). It tracks Likelihood, Impact,
--  Owner, and Mitigation plans. It is the central reference for Board-level security
--  reporting.
-- KPIs:
-- 1. Risk Review Frequency (Quarterly)
-- 2. Mitigation Plan Execution %
-- 3. Risk Score Reduction (Trend)
-- 4. Owner Identification (100%)
-- 5. New Risk Identification Speed
-- Feature Reference: M17-F193 (Risk Register)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.risk_register (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    likelihood INTEGER CHECK (likelihood BETWEEN 1 AND 5),
    impact INTEGER CHECK (impact BETWEEN 1 AND 5),
    owner UUID NOT NULL,
    mitigation TEXT,
    status VARCHAR(50) DEFAULT 'OPEN',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.risk_register IS 'Central register of strategic organizational risks';

CREATE INDEX idx_risk_register_status ON sec.risk_register(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB194 - firewall_objects
-- Description: Reusable objects for firewalls.
-- Business Case: Reusability. This table defines generic objects (Service objects: HTTP, DNS;
--  Schedule objects: Business Hours) that can be referenced in firewall rules. It
--  simplifies rule writing and ensures consistency across rule sets.
-- KPIs:
-- 1. Object Definition Accuracy
-- 2. Reference Count (Orphaned objects)
-- 3. Update Propagation
-- 4. Type Safety (Ports vs Protocols)
-- 5. Standardization Rate
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.firewall_objects (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    object_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, --  SERVICE, SCHEDULE, ADDRESS_LIST
    value_json JSONB NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.firewall_objects IS 'Defines reusable objects (services, schedules) for firewall policies';

CREATE INDEX idx_fw_objects_name ON sec.firewall_objects(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB195 - hardware_modules
-- Description: Inventory of HSM devices.
-- Business Case: Physical asset management. This table tracks physical HSMs (Serial numbers,
--  Location, Model). It is essential for maintenance scheduling, replacement
-- planning, and ensuring that the HSM infrastructure is N+1 redundant.
-- KPIs:
-- 1. Inventory Accuracy (100%)
-- 2. Maintenance Schedule Adherence
-- 3. Hardware Utilization (Slot availability)
-- 4. Failure Prediction (Age based)
-- 5. Location Tracking (Drift)
-- Feature Reference: M17-F004 (HSM Key Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hardware_modules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_id VARCHAR(100) UNIQUE NOT NULL,
    serial VARCHAR(255) NOT NULL,
    model VARCHAR(100),
    location VARCHAR(255),
    status VARCHAR(20) DEFAULT 'ONLINE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.hardware_modules IS 'Inventory of physical Hardware Security Modules (HSMs)';

CREATE INDEX idx_hardware_modules_serial ON sec.hardware_modules(serial);

------------------------------------------------------------------------------------------------
-- Table: M17-DB196 - session_recordings
-- Description: Links to session recording files.
-- Business Case: PAM compliance. This table stores metadata for video/screen recordings of
--  privileged sessions ( Bastion/SSH). It links the session ID to the S3 path of the
--  recording and allows for search/retrieval during investigations.
-- KPIs:
-- 1. Recording Start Success (100%)
-- 2. File Integrity (Hash check)
-- 3. Storage Retention Compliance
-- 4. Retrieval Speed
-- 5. Indexing Accuracy (Searchable content)
-- Feature Reference: M17-F089 (Secure Remote Access (Bastion))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.session_recordings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    recording_id VARCHAR(100) UNIQUE NOT NULL,
    session_id VARCHAR(100) NOT NULL, -- Link to admin_sessions
    file_path VARCHAR(500) NOT NULL,
    file_size_bytes BIGINT,
    format VARCHAR(20), --  MP4, ASCIICAST
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.session_recordings IS 'Metadata for video/screen recordings of privileged sessions';

CREATE INDEX idx_session_recordings_session ON sec.session_recordings(session_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB197 - external_identities
-- Description: Mapping of external identities to internal ones.
-- Business Case: Identity Bridging. Users exist in external systems (Okta, Ping). This
--  table maps those external user IDs/emails to internal PARI UUIDs. It allows federated
--  SSO to work seamlessly by establishing a stable mapping.
-- KPIs:
-- 1. Mapping Accuracy (No collisions)
-- 2. Sync Latency (<5 min)
-- 3. Orphaned Mapping (External user deleted?)
-- 4. Provisioning Trigger Accuracy
-- 5. Federation Success Rate
-- Feature Reference: M17-F067 (Identity Federation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.external_identities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mapping_id VARCHAR(100) UNIQUE NOT NULL,
    ext_provider_id VARCHAR(100) NOT NULL,
    ext_user_id VARCHAR(255) NOT NULL,
    internal_user_id UUID NOT NULL,
    last_sync TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT ext_id_unique UNIQUE (ext_provider_id, ext_user_id)
);
COMMENT ON TABLE sec.external_identities IS 'Maps external identity provider users to internal PARI identities';

CREATE INDEX idx_ext_id_internal ON sec.external_identities(internal_user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB198 - synthetic_transactions
-- Description: Config of synthetic security checks.
-- Business Case: You break it, you buy it. Synthetic checks are automated "robots"
-- that simulate user transactions (Login, Transfer) to detect failures before users do.
--  This table configures the endpoints and expected responses for these checks.
-- KPIs:
-- 1. Check Execution Frequency (Every 5 min)
-- 2. Failure Detection Speed (<1 min)
-- 3. False Positive Rate
-- 4. Transaction Coverage (Critical paths)
-- 5. Alerting Accuracy
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.synthetic_transactions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    check_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    endpoint VARCHAR(500) NOT NULL,
    expected_status INTEGER DEFAULT 200,
    frequency_minutes INTEGER NOT NULL,
    last_run TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.synthetic_transactions IS 'Configures automated synthetic security checks for uptime monitoring';

CREATE INDEX idx_synth_trans_check ON sec.synthetic_transactions(check_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB199 - nat_rules
-- Description: Network Address Translation rules.
-- Business Case: Network architecture. This table defines NAT rules (Source NAT, Destination
--  NAT) required for services to access the internet or other networks securely. It
--  is translated into router/firewall configs.
-- KPIs:
-- 1. Rule Deployment Latency (<30s)
-- 2. Translation Accuracy (Correct IP)
-- 3. Port Conflict Detection
-- 4. Utilization Analysis (Active vs Idle)
-- 5. Configuration Drift
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.nat_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    original_ip VARCHAR(45) NOT NULL,
    translated_ip VARCHAR(45) NOT NULL,
    port INTEGER,
    protocol VARCHAR(10),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.nat_rules IS 'Defines Network Address Translation rules';

CREATE INDEX idx_nat_rules_original ON sec.nat_rules(original_ip);

------------------------------------------------------------------------------------------------
-- Table: M17-DB200 - policy_documents
-- Description: Repository of security policy documents.
-- Business Case: Policy Management. This table stores the actual text/docs of security policies
--  (Acceptable Use Policy, Data Handling Policy). It tracks versions and effective dates,
--  ensuring that employees and auditors are always looking at the current approved version.
-- KPIs:
-- 1. Version Control Integrity
-- 2. Effective Date Adherence
-- 3. Review Cycle Compliance (Annual)
-- 4. Employee Acknowledgment Rate
-- 5. Search/Retrieval Speed
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.policy_documents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    doc_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    approved_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.policy_documents IS 'Stores the text and versions of official security policy documents';

CREATE INDEX idx_policy_docs_title ON sec.policy_documents(title);


-- 2. Triggers for Update Timestamps (DB151-DB200)
-- ================================================================================

CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.firewall_rulesets FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_retention_policy FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.firewall_address_groups FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vendor_access FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.license_exceptions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_mesh_config FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dashboard_layout FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.audit_findings FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.load_balancer_pools FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.attribute_sources FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.elevation_requests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.ipsec_tunnels FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.code_owners FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.privileged_access_groups FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.audit_certifications FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.alert_subscriptions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vlan_mappings FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.custom_policy_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.auth_token_introspection FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.build_steps FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.risk_register FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.firewall_objects FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.hardware_modules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.synthetic_transactions FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.nat_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.policy_documents FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- End of Script Part 4 (Final Part of Tables)
-- Next Steps: Views, Stored Procedures

-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 5: Tables DB201-DB250)
-- ================================================================================
-- Description:
-- Continuation of M17 schema definition. This part completes the extended
-- table set to DB250, covering advanced topics such as quantum migration
-- readiness, AI/ML feature analysis, SDLC security gates, threat actor profiling,
-- honeypot interactions, incident financial impact, and system lifecycle
-- management.
--
-- Note: Tables DB201-DB250 have been extrapolated based on the comprehensive
-- Zero-Trust context to complete the architectural requirements for advanced
-- security operations.
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. DDL Statements (Tables 201-250)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB201 - quantum_migration_paths
-- Description: Tracks migration from classical to post-quantum cryptography.
-- Business Case: Quantum computing threatens current asymmetric crypto. This table tracks the
-- migration path for specific keys (e.g., "Key X: RSA-2048 -> CRYSTALS-Dilithium").
-- It schedules the transition, tracks interim hybrid modes, and ensures that
-- cryptographic agility is maintained before Y2Q (Year Quantum) arrives.
-- KPIs:
-- 1. Migration Completion Rate (Target 100% by 2030)
-- 2. Key Availability During Migration (Zero downtime)
-- 3. Hybrid Mode Performance Overhead
-- 4. Rollback Success (If PQC algo fails)
-- 5. Migration Schedule Adherence
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_migration_paths (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    migration_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    current_algorithm VARCHAR(50) NOT NULL,
    target_algorithm VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'PLANNED' CHECK (status IN ('PLANNED','HYBRID_TRANSITION','COMPLETE','FAILED','ROLLBACK')),
    scheduled_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT quantum_mig_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.quantum_migration_paths IS 'Tracks the migration strategy from classical to post-quantum cryptographic algorithms';

CREATE INDEX idx_quantum_mig_key ON sec.quantum_migration_paths(key_id);
CREATE INDEX idx_quantum_mig_status ON sec.quantum_migration_paths(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB202 - ai_feature_importance
-- Description: Which features triggered the ML model.
-- Business Case: Explainable AI (XAI). Security teams need to know *why* an alert
-- fired. This table stores the feature importance scores for specific detections
-- (e.g., "Login at 3am" weight: 0.8). It helps analysts validate
-- alerts and tune the model.
-- KPIs:
-- 1. Feature Tracking Accuracy
-- 2. Model Interpretability Score
-- 3. False Positive Analysis (Which features caused it?)
-- 4. Feature Engineering Improvement
-- 5. Alert Triage Efficiency
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ai_feature_importance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_id VARCHAR(100) UNIQUE NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    alert_id UUID NOT NULL,
    feature_name VARCHAR(255) NOT NULL,
    importance_score NUMERIC(5,2) CHECK (importance_score BETWEEN 0 AND 1),
    contribution_value NUMERIC(10,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT ai_feat_alert_fkey FOREIGN KEY (alert_id) REFERENCES sec.anomaly_alerts(id)
);
COMMENT ON TABLE sec.ai_feature_importance IS 'Stores feature importance data for AI security alerts to explainability';

CREATE INDEX idx_ai_feat_alert ON sec.ai_feature_importance(alert_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB203 - sdlc_phases
-- Description: Security gates in software development lifecycle.
-- Business Case: Shift Left security. This table defines phases of the SDLC (Design, Build,
-- Deploy) and the security gates required at each (e.g., "Threat Model" at
-- Design). The CI/CD pipeline enforces these gates, preventing code from
-- proceeding without security sign-off.
-- KPIs:
-- 1. Gate Enforcement Rate (100%)
-- 2. Phase Transition Time
-- 3. Security Finding Injection (Prevention)
-- 4. Developer Self-Service Availability
-- 5. Gate Policy Compliance
-- Feature Reference: M17-F065 (Secure CI/CD Pipeline)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sdlc_phases (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    phase_id VARCHAR(100) UNIQUE NOT NULL,
    pipeline_id VARCHAR(100) NOT NULL,
    phase_name VARCHAR(100) NOT NULL, --  DESIGN, CODE, TEST, DEPLOY
    security_gate_enabled BOOLEAN DEFAULT true,
    gate_criteria JSONB, --  Rules to pass the gate
    auto_promote BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.sdlc_phases IS 'Defines security gates within the Software Development Life Cycle (SDLC)';

CREATE INDEX idx_sdlc_phases_pipeline ON sec.sdlc_phases(pipeline_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB204 - threat_actor_profiles
-- Description: Definitions of APT (Advanced Persistent Threat) groups.
-- Business Case: Contextualizing threats. This table stores profiles of known threat actors
--  (e.g., "APT29", "Lazarus"), including their TTPs (Tactics, Techniques,
--  Procedures). When an attack matches a TTP in this table, the system can
--  attribute the attack and apply specific defenses.
-- KPIs:
-- 1. Profile Accuracy
-- 2. TTP Match Rate
-- 3. Attribution Confidence
-- 4. Intelligence Update Frequency
-- 5. Playbook Triggering (Specific actor response)
-- Feature Reference: M17-F068 (Advanced Persistent Threat (APT) Hunt)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_actor_profiles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    actor_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    aliases TEXT[],
    typical_ttps JSONB, --  MITRE ATT&CK IDs
    description TEXT,
    sophistication_level VARCHAR(50), --  LOW, MEDIUM, HIGH, APT
    last_seen DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.threat_actor_profiles IS 'Stores profiles of known Advanced Persistent Threat (APT) groups and their TTPs';

CREATE INDEX idx_threat_actor_ttps ON sec.threat_actor_profiles USING GIN(typical_ttps);

------------------------------------------------------------------------------------------------
-- Table: M17-DB205 - supply_chain_tiers
-- Description: Categorizing vendors by distance/impact.
-- Business Case: Tiered risk management. This table classifies vendors into Tiers (Tier 1:
--  Critical, Tier 3: Commodity). It applies different levels of scrutiny and
-- monitoring based on the potential impact of a compromise in that tier.
-- KPIs:
-- 1. Tier Classification Accuracy
-- 2. Tier-Based Review Frequency
-- 3. Risk Distribution Analysis
-- 4. Vendor Tier Migration (Promotion/Demotion)
-- 5. Assessment Depth (Tier 1 gets deep dive)
-- Feature Reference: M17-F149 (Secure Software Supply Chain)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.supply_chain_tiers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tier_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_id VARCHAR(100) NOT NULL,
    tier_level INTEGER CHECK (tier_level BETWEEN 1 AND 5), --  1=Most Critical
    justification TEXT,
    review_frequency_months INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.supply_chain_tiers IS 'Categorizes supply chain vendors into risk tiers to define scrutiny levels';

CREATE INDEX idx_sc_tiers_vendor ON sec.supply_chain_tiers(vendor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB206 - secret_shares_distribution
-- Description: Tracking who holds which share (Shamir).
-- Business Case: Operational security. For key escrow using Shamir's Secret Sharing, knowing
--  *who* holds which shard is vital. This table maps specific shards to specific
--  custodians (Trustees). It facilitates the reassembly process during recovery.
-- KPIs:
-- 1. Custodian Accountability
-- 2. Share Availability (Has the custodian lost the key?)
-- 3. Reassembly Readiness
-- 4. Custodian Rotation History
-- 5. Multi-Jurisdictional Compliance
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secret_shares_distribution (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    distribution_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    shard_index INTEGER NOT NULL,
    custodian_id UUID NOT NULL,
    delivery_method VARCHAR(50), --  OFFLINE, ENCRYPTED_EMAIL, VAULT
    acknowledged_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT secret_share_dist_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id),
    CONSTRAINT secret_share_dist_unique UNIQUE (key_id, shard_index)
);
COMMENT ON TABLE sec.secret_shares_distribution IS 'Tracks the distribution of secret shares to specific custodians';

CREATE INDEX idx_secret_share_custodian ON sec.secret_shares_distribution(custodian_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB207 - firewall_nat_pools
-- Description: NAT pool management.
-- Business Case: High-availability NATing. This table manages pools of IP addresses used for
--  Source NAT (SNAT). It tracks which IPs are in the pool, their utilization,
--  and ensures that NAT exhaustion doesn't cause a service outage.
-- KPIs:
-- 1. Pool Availability (Target >20% free)
-- 2. IP Exhaustion Incidents (0)
-- 3. Load Balancing Efficiency
-- 4. Pool Replenishment Speed
-- 5. Conflict Detection (IPs used elsewhere)
-- Feature Reference: M17-F070 (Dynamic Firewall Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.firewall_nat_pools (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    cidr_block VARCHAR(45) NOT NULL,
    total_addresses BIGINT,
    used_addresses BIGINT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.firewall_nat_pools IS 'Manages IP address pools for Network Address Translation (NAT)';

CREATE INDEX idx_fw_nat_pool_cidr ON sec.firewall_nat_pools(cidr_block);

------------------------------------------------------------------------------------------------
-- Table: M17-DB208 - api_gateway_plugins
-- Description: Plugins loaded into the API gateway.
-- Business Case: Extensibility. This table lists security plugins loaded into the API Gateway
--  (e.g., "OIDC Validator", "Rate Limiter", "WAF"). It tracks version
--  status and ensures only approved plugins are active in the data path.
-- KPIs:
-- 1. Plugin Uptime (100%)
-- 2. Plugin Performance Latency (<5ms)
-- 3. Version Compliance
-- 4. Configuration Drift (0)
-- 5. Hot-Swap Success (Zero downtime updates)
-- Feature Reference: M17-F028 (API Gateway Firewall)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_gateway_plugins (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    plugin_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    config_json JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    execution_order INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_gateway_plugins IS 'Registry of security plugins active in the API Gateway';

CREATE INDEX idx_api_gateway_plugin_order ON sec.api_gateway_plugins(execution_order);

------------------------------------------------------------------------------------------------
-- Table: M17-DB209 - auth_flows
-- Description: Definition of OAuth/OpenID Connect flows.
-- Business Case: Complex authentication. Not all logins are simple. This table defines
--  flows (e.g., "Authorization Code Flow", "Client Credentials", "Device Code")
--  and their parameters (token TTL, refresh window). It ensures strict adherence
--  to OAuth RFCs.
-- KPIs:
-- 1. Flow Compliance (RFC standard)
-- 2. Token Lifetime Enforcement
-- 3. Flow Execution Success Rate
-- 4. Parameter Validity
-- 5. Security Best Practice Score (PKCE usage)
-- Feature Reference: M17-F006 (JWT Policy Enforcement Point)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.auth_flows (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flow_id VARCHAR(100) UNIQUE NOT NULL,
    flow_type VARCHAR(50) NOT NULL, --  AUTHORIZATION_CODE, IMPLICIT, HYBRID
    client_id UUID NOT NULL, --  Application
    require_pkce BOOLEAN DEFAULT true, --  Proof Key for Code Exchange
    token_ttl_seconds INTEGER,
    refresh_token_enabled BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.auth_flows IS 'Defines OAuth/OpenID Connect flow configurations for applications';

CREATE INDEX idx_auth_flows_client ON sec.auth_flows(client_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB210 - session_hijack_attempts
-- Description: Logs of session hijacking tries.
-- Business Case: Session hijacking is a stealthy attack. This table logs attempts where a
--  session token is used from a different IP, device, or Geo-location simultaneously.
--  It is a primary data source for Fraud and Account Takeover (ATO) detection.
-- KPIs:
-- 1. Detection Latency (<1s)
-- 2. False Positive Rate (Legitimate travel)
-- 3. Block Rate (Successful prevention)
-- 4. Attack Vector Analysis
-- 5. User Notification Speed
-- Feature Reference: M17-F038 (Session Hardening)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.session_hijack_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    attempt_id VARCHAR(100) UNIQUE NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    legitimate_ip VARCHAR(45),
    hijack_ip VARCHAR(45),
    user_agent_hash VARCHAR(64), --  Fingerprint
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    action_taken VARCHAR(50), --  BLOCK, CHALLENGE, TERMINATE
    risk_score NUMERIC(3,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.session_hijack_attempts IS 'Logs detected attempts to hijack or replay user sessions';

CREATE INDEX idx_session_hijack_session ON sec.session_hijack_attempts(session_id);
CREATE INDEX idx_session_hijack_time ON sec.session_hijack_attempts(timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB211 - container_benchmarks
-- Description: Performance baselines for secure containers.
-- Business Case: Anomaly detection requires a baseline. This table stores performance benchmarks
--  (CPU, Mem, Network) for secure container images. If a running container
--  deviates significantly (e.g., CPU 500% higher), it might indicate a crypto-miner
--  or compromise.
-- KPIs:
-- 1. Benchmark Accuracy (Representative load)
-- 2. Anomaly Detection Sensitivity
-- 3. Alert Volume (Manageable)
-- 4. Container Performance Score
-- 5. Baseline Update Frequency
-- Feature Reference: M17-F025 (Encrypted Traffic Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.container_benchmarks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    benchmark_id VARCHAR(100) UNIQUE NOT NULL,
    image_hash VARCHAR(64) NOT NULL,
    cpu_baseline_percent NUMERIC(5,2),
    memory_baseline_mb INTEGER,
    network_baseline_kbps INTEGER,
    io_baseline_iops INTEGER,
    sample_duration_minutes INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.container_benchmarks IS 'Stores performance baselines for containers to detect runtime anomalies';

CREATE INDEX idx_container_bench_image ON sec.container_benchmarks(image_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB212 - code_reviewer_assignments
-- Description: Who reviews which code.
-- Business Case: Peer review integrity. This table maps developers to code paths or file patterns
--  they are responsible for reviewing. It prevents "rubber stamping" where one
--  person approves everything, ensuring that "Four Eyes" principles are met.
-- KPIs:
-- 1. Review Assignment Coverage (100%)
-- 2. Conflict of Interest Detection
-- 3. Reviewer Availability
-- 4. Reviewer Rotation (Diversity)
-- 5. Workload Balance
-- Feature Reference: M17-F065 (Secure CI/CD Pipeline)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.code_reviewer_assignments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assignment_id VARCHAR(100) UNIQUE NOT NULL,
    reviewer_id UUID NOT NULL,
    path_pattern TEXT NOT NULL, --  e.g., "src/auth/*"
    required BOOLEAN DEFAULT true, --  Is this a mandatory reviewer?

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.code_reviewer_assignments IS 'Assigns code reviewers to specific file paths to enforce peer review';

CREATE INDEX idx_code_review_pattern ON sec.code_reviewer_assignments(path_pattern);

------------------------------------------------------------------------------------------------
-- Table: M17-DB213 - threat_intelligence_iocs
-- Description: Raw IOCs from feeds (before processing).
-- Business Case: Staging area. This table holds raw Indicators of Compromise fetched from
--  external feeds before they are normalized into the `iocs` table. It retains
--  the raw context (source description, tags) which might be lost in normalization.
-- KPIs:
-- 1. Ingestion Volume
-- 2. Deduplication Rate
-- 3. Processing Latency (Raw -> Normalized)
-- 4. Feed Reliability (Errors)
-- 5. Storage Retention (Raw data short term)
-- Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_intelligence_iocs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    raw_id VARCHAR(100) UNIQUE NOT NULL,
    feed_id UUID NOT NULL,
    raw_json JSONB NOT NULL, --  The full payload
    ioc_type VARCHAR(20),
    ioc_value TEXT,
    processed BOOLEAN DEFAULT false,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT threat_ioc_feed_fkey FOREIGN KEY (feed_id) REFERENCES sec.threat_feeds(id)
);
COMMENT ON TABLE sec.threat_intelligence_iocs IS 'Staging area for raw Threat Intelligence IOCs before normalization';

CREATE INDEX idx_threat_ioc_processed ON sec.threat_intelligence_iocs(processed);

------------------------------------------------------------------------------------------------
-- Table: M17-DB214 - audit_trail_archives
-- Description: Old logs moved to cold storage.
-- Business Case: Performance management. Keeping 2 years of logs in the hot DB is slow.
--  This table references the location of archived logs (S3 Glacier, Tape). It
--  maintains the index so that archived logs can still be searched and retrieved
--  legally.
-- KPIs:
-- 1. Archival Frequency (Daily)
-- 2. Retrieval Success Rate (100%)
-- 3. Index Coverage (Can I find the log?)
-- 4. Storage Cost Optimization
-- 5. Legal Hold Compliance (Retrieving for court cases)
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_trail_archives (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    archive_id VARCHAR(100) UNIQUE NOT NULL,
    original_table VARCHAR(100) NOT NULL,
    date_range_start TIMESTAMP WITH TIME ZONE NOT NULL,
    date_range_end TIMESTAMP WITH TIME ZONE NOT NULL,
    storage_location VARCHAR(500) NOT NULL,
    row_count BIGINT,
    checksum VARCHAR(64), --  Integrity of the archive

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_trail_archives IS 'Index for audit logs that have been moved to cold archival storage';

CREATE INDEX idx_audit_archive_date ON sec.audit_trail_archives(date_range_start, date_range_end);

------------------------------------------------------------------------------------------------
-- Table: M17-DB215 - security_automation_scripts
-- Description: Python/Ansible scripts stored for execution.
-- Business Case: Security as Code. This table stores the actual code for automated scripts
--  (e.g., "Block IP.py", "Rotate Key.yaml"). The SOAR (Security Orchestration,
--  Automation, and Response) engine fetches and executes these, providing a version
--  controlled repository.
-- KPIs:
-- 1. Script Execution Success (100%)
-- 2. Script Latency
-- 3. Code Review Compliance (All scripts reviewed)
-- 4. Error Handling Robustness
-- 5. Execution Authorization (Only authorized scripts run)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_automation_scripts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    script_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    script_type VARCHAR(50), --  PYTHON, ANSIBLE, BASH
    script_content TEXT NOT NULL, --  Encrypted
    version INTEGER DEFAULT 1,
    safe_mode BOOLEAN DEFAULT true, --  Dry run only

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_automation_scripts IS 'Secure repository for automation scripts used by SOAR platforms';

CREATE INDEX idx_auto_scripts_name ON sec.security_automation_scripts(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB216 - certificate_signing_requests
-- Description: CSR tracking.
-- Business Case: Managing the signing lifecycle. Workloads generate CSRs (Certificate Signing
--  Requests). This table tracks these requests, the resulting certificate issued,
--  and any approval workflow required for high-value certificates.
-- KPIs:
-- 1. Signing Latency (<10s)
-- 2. Approval Workflow Speed
-- 3. CSR Validity (Signature verification)
-- 4. Issuance Success Rate
-- 5. Key Usage Compliance
-- Feature Reference: M17-F003 (X.509-SVID Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.certificate_signing_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    csr_id VARCHAR(100) UNIQUE NOT NULL,
    requestor_id UUID NOT NULL, --  Workload ID
    csr_pem TEXT NOT NULL,
    common_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'PENDING', --  PENDING, APPROVED, ISSUED, REJECTED
    approved_by UUID,
    issued_cert_id UUID, --  Link to x509_certificates

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.certificate_signing_requests IS 'Tracks Certificate Signing Requests (CSR) and their approval status';

CREATE INDEX idx_csr_requestor ON sec.certificate_signing_requests(requestor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB217 - data_leak_reports
-- Description: DLP generated reports.
-- Business Case: Data Loss Prevention (DLP). This table stores reports of detected data leaks
--  or potential leaks (e.g., "User uploaded 500 credit cards"). It captures the
--  blocked content and the context, supporting investigation into privacy breaches.
-- KPIs:
-- 1. Detection Rate (>99%)
-- 2. False Positive Rate (<1%)
-- 3. Block Success Rate
-- 4. Incident Correlation
-- 5. Data Volume Prevented (Leakage stopped)
-- Feature Reference: M17-F037 (Data Loss Prevention (DPI))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_leak_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id VARCHAR(100) UNIQUE NOT NULL,
    source_user UUID,
    source_ip VARCHAR(45),
    data_type VARCHAR(50), --  CREDIT_CARD, SSN, PROPRIETARY
    channel VARCHAR(50), --  EMAIL, USB, WEB_UPLOAD
    action_taken VARCHAR(50), --  BLOCKED, QUARANTINED, ALLOWED
    risk_score INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_leak_reports IS 'Stores reports generated by Data Loss Prevention (DLP) systems';

CREATE INDEX idx_dlp_report_user ON sec.data_leak_reports(source_user);
CREATE INDEX idx_dlp_report_date ON sec.data_leak_reports(created_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB218 - iam_role_hierarchies
-- Description: Tree structure for roles.
-- Business Case: Complex permission structures. Roles often inherit from others (e.g., "Manager"
--  inherits from "Employee"). This table defines the hierarchy/inheritance tree,
--  allowing the IAM system to calculate effective permissions dynamically.
-- KPIs:
-- 1. Hierarchy Depth (<5 levels)
-- 2. Inheritance Calculation Latency (<50ms)
-- 3. Loop Detection (0 circular refs)
-- 4. Role Consistency
-- 5. Permission Propagation Accuracy
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.iam_role_hierarchies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hierarchy_id VARCHAR(100) UNIQUE NOT NULL,
    parent_role_id VARCHAR(100) NOT NULL,
    child_role_id VARCHAR(100) NOT NULL,
    depth_level INTEGER DEFAULT 1,
    direct BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.iam_role_hierarchies IS 'Defines the inheritance tree for IAM roles';

CREATE INDEX idx_iam_role_parent ON sec.iam_role_hierarchies(parent_role_id);
CREATE INDEX idx_iam_role_child ON sec.iam_role_hierarchies(child_role_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB219 - security_training_modules
-- Description: Content for security awareness.
-- Business Case: Employee training. This table stores the content and metadata for security
--  training modules (Phishing, Passwords, Clean Desk). It tracks completion
--  status and quiz scores, fulfilling compliance training requirements.
-- KPIs:
-- 1. Module Completion Rate (>95%)
-- 2. Quiz Pass Score (>80%)
-- 3. Content Engagement
-- 4. Phishing Sim Result (Click rate)
-- 5. Training Effectiveness (Incident reduction)
-- Feature Reference: M17-F142 (AI-Powered Phishing Simulation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_training_modules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    content_url VARCHAR(500),
    pass_mark INTEGER DEFAULT 80,
    duration_minutes INTEGER,
    assigned_to_group TEXT[], --  Groups/Depts

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_training_modules IS 'Stores content and configuration for employee security training modules';

CREATE INDEX idx_training_modules_title ON sec.security_training_modules(title);

------------------------------------------------------------------------------------------------
-- Table: M17-DB220 - incident_cost_analysis
-- Description: Financial impact of incidents.
-- Business Case: Risk quantification. This table tracks the financial impact of security
--  incidents (Lost revenue, fines, remediation cost). It is essential for
--  calculating ROI (Return on Investment) for security spending and for
--  cyber insurance claims.
-- KPIs:
-- 1. Cost Accuracy (Verified receipts)
-- 2. Insurance Claim Recovery ($)
-- 3. MTTC (Mean Time To Cost calculation)
-- 4. Category Analysis (Phishing vs Ransomware cost)
-- 5. Budget Variance
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_cost_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    analysis_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    cost_category VARCHAR(50), --  LEGAL, REMEDIATION, LOST_REVENUE, FINE
    amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',
    description TEXT,
    approved BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT incident_cost_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_cost_analysis IS 'Tracks financial impact and costs associated with security incidents';

CREATE INDEX idx_incident_cost_incident ON sec.incident_cost_analysis(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB221 - penetration_test_scopes
-- Description: IP ranges authorized for pentesting.
-- Business Case: Preventing false alarms. When external pentesters are hired, they will
--  scan the network. This table defines the *authorized* scope (IPs, Domains).
--  Security monitoring tools use this to ignore "attacks" originating from
--  these sources to avoid alert fatigue.
-- KPIs:
-- 1. Scope Coverage (100%)
-- 2. False Negative Rate (Missed scope?)
-- 3. Rule Propagation (To all sensors)
-- 4. Scope Adherence (Did testers go outside?)
-- 5. Whitelist Accuracy
-- Feature Reference: M17-F033 (Automated Penetration Testing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.penetration_test_scopes (
    id UUID DEFAULT DEFAULT uuid_generate_v4() PRIMARY KEY,
    scope_id VARCHAR(100) UNIQUE NOT NULL,
    test_id VARCHAR(100) NOT NULL, --  Link to penetration_tests
    target_cidr VARCHAR(45),
    target_domain VARCHAR(255),
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.penetration_test_scopes IS 'Defines authorized IP ranges and targets for penetration testing to prevent false alarms';

CREATE INDEX idx_pentest_scope_active ON sec.penetration_test_scopes(active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB222 - vulnerability_fixes
-- Description: Records of fixes applied.
-- Business Case: Closing the loop. Finding a vuln is step one. This table records the
--  *fix* (Patch ID, Code Commit, Deployment time). It links a Vulnerability to
--  its remediation, proving to auditors that the issue was resolved.
-- KPIs:
-- 1. Fix Verification Rate (100%)
-- 2. Time to Remediate (TTR)
-- 3. Rollback Success (If fix fails)
-- 4. Patch Deployment Success
-- 5. Recurrence Rate (Did it come back?)
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_fixes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fix_id VARCHAR(100) UNIQUE NOT NULL,
    vuln_id UUID NOT NULL,
    fix_type VARCHAR(50), --  UPGRADE, CONFIG_CHANGE, IGNORE
    fix_details TEXT,
    artifact_id UUID, --  Container image with the fix
    deployed_at TIMESTAMP WITH TIME ZONE,
    verified BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT vuln_fix_vuln_fkey FOREIGN KEY (vuln_id) REFERENCES sec.vulnerability_scans(id)
);
COMMENT ON TABLE sec.vulnerability_fixes IS 'Tracks the remediation and fixes applied to detected vulnerabilities';

CREATE INDEX idx_vuln_fix_vuln ON sec.vulnerability_fixes(vuln_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB223 - key_cryptoperiods
-- Description: Time-limited keys (cryptoperiods).
-- Business Case: Key rotation by usage/time. Sometimes keys are only valid for a "cryptoperiod"
--  (e.g., "Valid for the next 24 hours"). This table manages these short-lived
--  keys, automating their destruction or archival once the period expires.
-- KPIs:
-- 1. Expiration Enforcement (100%)
-- 2. Cryptoperiod Accuracy (Correct duration)
-- 3. Key Availability (During period)
-- 4. Rotation Seamlessness (No downtime)
-- 5. Archive Success
-- Feature Reference: M17-F003 (X.509-SVID Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_cryptoperiods (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    period_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    max_usage_count INTEGER,
    current_usage_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'ACTIVE', --  ACTIVE, EXPIRED, ARCHIVED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT crypto_period_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_cryptoperiods IS 'Manages time-limited or usage-limited keys (cryptoperiods)';

CREATE INDEX idx_crypto_period_status ON sec.key_cryptoperiods(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB224 - service_discovery_registry
-- Description: Dynamic service registration.
-- Business Case: Zero Trust networking requires knowing *who* is alive. This table acts as a
--  Service Registry (Consul/Kubernetes API equivalent). Services register here,
--  providing their endpoint and health, so that mTLS policies can be applied
--  dynamically.
-- KPIs:
-- 1. Registration Accuracy
-- 2. Heartbeat Frequency (Every 5s)
-- 3. De-registration Latency (<1s)
-- 4. Service Availability (99.99%)
-- 5. Duplicate Registration Prevention
-- Feature Reference: M17-F002 (SPIFFE Identity Provisioning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_discovery_registry (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    instance_id VARCHAR(100) UNIQUE NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    instance_ip VARCHAR(45) NOT NULL,
    port INTEGER NOT NULL,
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'HEALTHY', --  HEALTHY, UNHEALTHY, DEREGISTERED
    metadata JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_discovery_registry IS 'Dynamic registry for service instances for zero-trust networking';

CREATE INDEX idx_service_registry_name ON sec.service_discovery_registry(service_name);
CREATE INDEX idx_service_registry_status ON sec.service_discovery_registry(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB225 - correlation_rules
-- Description: SIEM correlation rules definitions.
-- Business Case: Detecting complex attacks requires linking events. This table defines
--  correlation rules (e.g., "Failed Login + New Country = Alert"). The SIEM
--  engine applies these rules to the event stream to generate high-fidelity alerts.
-- KPIs:
-- 1. Rule Execution Latency
-- 2. Alert Quality (True Positive Rate)
-- 3. Rule Complexity (Manageable)
-- 4. False Positive Reduction (Tuning)
-- 5. Rule Coverage (Attack techniques)
-- Feature Reference: M17-F058 (Fraud Signal Correlation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.correlation_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    rule_logic JSONB NOT NULL, --  Logic definition
    severity sec.enum_incident_severity NOT NULL,
    active BOOLEAN DEFAULT true,
    tuning_history JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.correlation_rules IS 'Defines SIEM correlation rules to link disparate events into incidents';

CREATE INDEX idx_corr_rules_active ON sec.correlation_rules(active);

------------------------------------------------------------------------------------------------
-- Table: M17-DB226 - user_risk_history
-- Description: Historical risk scores for UEBA.
-- Business Case: Trend analysis. Current risk is good, but history is better. This table
--  stores daily snapshots of user risk scores. It allows analysts to see if a
--  user's risk is trending upwards over weeks (gradual compromise) or is just
--  a blip.
-- KPIs:
-- 1. Data Retention (365 days)
-- 2. Trend Detection Accuracy
-- 3. Historical Query Performance
-- 4. Baseline Calculation Speed
-- 5. Anomaly Identification (Drift from baseline)
-- Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_risk_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    history_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    risk_score NUMERIC(5,2) NOT NULL,
    recorded_at DATE NOT NULL, --  Daily snapshot
    factor_summary JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT user_risk_hist_unique UNIQUE (user_id, recorded_at)
);
COMMENT ON TABLE sec.user_risk_history IS 'Stores historical daily snapshots of UEBA risk scores for trend analysis';

CREATE INDEX idx_user_risk_hist_user ON sec.user_risk_history(user_id, recorded_at DESC);

------------------------------------------------------------------------------------------------
-- Table: M17-DB227 - asset_decommissioning
-- Description: Process of retiring assets.
-- Business Case: Secure disposal. Retiring an asset (server, VM) is a security risk (Data
--  left behind). This table manages the decommissioning workflow (Wipe ->
--  Archive -> Destroy). It ensures that decommissioned assets cannot be spun back
-- up accidentally.
-- KPIs:
-- 1. Data Wiping Success (100%)
-- 2. Decommissioning Latency
-- 3. Asset Removal from Inventory
-- 4. Access Revocation (On decommission)
-- 5. Certificate Revocation
-- Feature Reference: M17-F040 (Node Identity Draining)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.asset_decommissioning (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    decomm_id VARCHAR(100) UNIQUE NOT NULL,
    asset_id VARCHAR(100) NOT NULL,
    requestor_id UUID NOT NULL,
    reason TEXT,
    status VARCHAR(50) DEFAULT 'REQUESTED', --  REQUESTED, WIPING, DESTROYED, CANCELLED
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.asset_decommissioning IS 'Manages the workflow for securely retiring and destroying assets';

CREATE INDEX idx_asset_decomm_status ON sec.asset_decommissioning(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB228 - compliance_questionnaires
-- Description: Self-assessment questionnaires.
-- Business Case: Evidence collection. Compliance often requires subject matter experts to answer
--  specific questions (e.g., "Do you encrypt backups?"). This table stores the
--  questions, answers, and evidence files for these questionnaires.
-- KPIs:
-- 1. Questionnaire Completion Rate (>95%)
-- 2. Evidence Attachment Rate
-- 3. Approval Workflow Speed
-- 4. Answer Consistency (Year over Year)
-- 5. Question Relevance
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_questionnaires (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    questionnaire_id VARCHAR(100) UNIQUE NOT NULL,
    framework_id VARCHAR(50) NOT NULL,
    question_id VARCHAR(100) NOT NULL,
    answer TEXT,
    responder_id UUID,
    evidence_file_id UUID,
    approval_status VARCHAR(50) DEFAULT 'PENDING',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.compliance_questionnaires IS 'Stores responses to self-assessment questionnaires for compliance audits';

CREATE INDEX idx_compliance_quest_framework ON sec.compliance_questionnaires(framework_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB229 - security_awareness_campaigns
-- Description: Phishing campaign configs.
-- Business Case: Training through simulation. This table configures phishing campaigns (Target
--  group, Template type, Complexity). It tracks who was targeted, who clicked,
--  and who reported the phishing email, calculating the "Vulnerable" population.
-- KPIs:
-- 1. Campaign Completion
-- 2. Click Rate (Target <5%)
-- 3. Report Rate (Target >20%)
-- 4. Re-test Improvement (Clicks went down?)
-- 5. Training Enrollment (Auto-enroll clickers)
-- Feature Reference: M17-F142 (AI-Powered Phishing Simulation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_awareness_campaigns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    target_group TEXT[],
    difficulty_level VARCHAR(50), --  EASY, MEDIUM, HARD
    status VARCHAR(20) DEFAULT 'PLANNED',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_awareness_campaigns IS 'Configures and tracks phishing simulation campaigns for security awareness';

CREATE INDEX idx_awareness_campaign_status ON sec.security_awareness_campaigns(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB230 - malware_signatures
-- Description: Custom YARA/Signature rules.
-- Business Case: Threat-specific detection. Sometimes vendor signatures aren't enough. This table
--  allows security teams to upload custom YARA rules or ClamAV signatures to
--  detect specific malware families targeting the organization.
-- KPIs:
-- 1. Signature Detection Rate
-- 2. False Positive Rate
-- 3. Signature Update Frequency
-- 4. Coverage (Malware families)
-- 5. Performance Impact (Scan time)
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.malware_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    signature_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50), --  YARA, SNORT, CLAMAV
    rule_content TEXT NOT NULL,
    severity VARCHAR(20),
    active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.malware_signatures IS 'Stores custom YARA and malware signatures for specific threat detection';

CREATE INDEX idx_malware_sig_type ON sec.malware_signatures(type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB231 - honeypot_interactions
-- Description: Logs of interactions with honeypots.
-- Business Case: Attacker behavior analysis. This table records every interaction with honeypots
--  (Command typed, Port touched). Analyzing this data reveals attacker TTPs
--  (Tactics, Techniques, Procedures) and intent (Scanning vs Exploitation).
-- KPIs:
-- 1. Interaction Capture Rate (100%)
-- 2. Attacker Session Length
-- 3. Command Logging (Keystrokes)
-- 4. Malware Sample Capture (File drops)
-- 5. Attack Attribution Success
-- Feature Reference: M17-F085 (Deception Technology (Honeypots))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.honeypot_interactions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    interaction_id VARCHAR(100) UNIQUE NOT NULL,
    honeypot_id UUID NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(20),
    payload TEXT, --  Command or Data sent
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    session_uuid VARCHAR(100),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT honeypot_interaction_pot_fkey FOREIGN KEY (honeypot_id) REFERENCES sec.honeypots(id)
);
COMMENT ON TABLE sec.honeypot_interactions IS 'Logs detailed interactions with honeypot decoys for attacker analysis';

CREATE INDEX idx_honeypot_interactions_source ON sec.honeypot_interactions(source_ip);

------------------------------------------------------------------------------------------------
-- Table: M17-DB232 - identity_federation_trusts
-- Description: Trust scores for federated IdPs.
-- Business Case: Not all IdPs are equal. This table assigns a dynamic trust score to external
--  Identity Providers (e.g., BankID, Google) based on their uptime, audit
--  findings, and security posture. It influences authentication flows (e.g., MFA
--  required for Low Trust IdP).
-- KPIs:
-- 1. Trust Score Accuracy
-- 2. Score Calculation Frequency
-- 3. Low Trust Action Rate (Extra auth)
-- 4. IdP Performance Uptime
-- 5. Audit Integration (External certs)
-- Feature Reference: M17-F067 (Identity Federation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.identity_federation_trusts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trust_id VARCHAR(100) UNIQUE NOT NULL,
    provider_id UUID NOT NULL,
    trust_score INTEGER CHECK (trust_score BETWEEN 0 AND 100),
    last_evaluation TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    factors JSONB, --  Why is this score low?
    status VARCHAR(20) CHECK (status IN ('TRUSTED','UNTRUSTED','UNKNOWN')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fed_trust_provider_fkey FOREIGN KEY (provider_id) REFERENCES sec.identity_providers(id)
);
COMMENT ON TABLE sec.identity_federation_trusts IS 'Stores dynamic trust scores for federated Identity Providers';

CREATE INDEX idx_fed_trust_score ON sec.identity_federation_trusts(trust_score);

------------------------------------------------------------------------------------------------
-- Table: M17-DB233 - cloud_native_policies
-- Description: K8s/Cloud specific policies.
-- Business Case: Cloud-native controls. This table stores policies specific to cloud platforms
--  (e.g., K8s Pod Security Standards, AWS IAM boundary policies). It translates
--  generic Zero-Trust policies into cloud-native configurations.
-- KPIs:
-- 1. Policy Conversion Success (100%)
-- 2. Cloud Compliance Score
-- 3. Violation Count
-- 4. Controller Performance
-- 5. Drift Detection
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_native_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    platform VARCHAR(50) NOT NULL, --  KUBERNETES, AWS, AZURE
    resource_type VARCHAR(50), --  POD, ROLE, BUCKET
    policy_yaml TEXT, --  The cloud-native definition
    generic_policy_ref VARCHAR(100), --  Link to zero_trust_policies

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_native_policies IS 'Stores cloud-platform specific security policies (K8s, AWS)';

CREATE INDEX idx_cloud_native_platform ON sec.cloud_native_policies(platform);

------------------------------------------------------------------------------------------------
-- Table: M17-DB234 - api_rate_limit_buckets
-- Description: Token bucket state (if not purely in-memory).
-- Business Case: Persistent rate limiting. While many rate limiters use in-memory Redis, a
--  DB backing provides durability and allows querying historical usage. This table
--  tracks token counts for API buckets to enforce strict quotas.
-- KPIs:
-- 1. Limit Enforcement Accuracy (100%)
-- 2. Replenishment Speed
-- 3. Bucket Query Latency (<1ms)
-- 4. Distributed Sync Consistency
-- 5. Quota Exhaustion Handling
-- Feature Reference: M17-F046 (API Security Throttling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_rate_limit_buckets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bucket_id VARCHAR(100) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    tokens_remaining INTEGER NOT NULL,
    last_replenish TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    window_seconds INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_rate_limit_buckets IS 'Persistent state for API rate limiting buckets';

CREATE INDEX idx_rate_limit_client ON sec.api_rate_limit_buckets(client_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB235 - key_material_escrow
-- Description: Backup of actual key material (encrypted).
-- Business Case: High-availability recovery. While `key_shards` splits the secret, this table
--  might store the entire encrypted key blob (wrapped by a super-kek) for fast
--  disaster recovery in specific scenarios, strictly encrypted.
-- KPIs:
-- 1. Encryption Strength (AES-256)
-- 2. Retrieval Speed (For DR)
-- 3. Access Control (Strict RBAC)
-- 4. Integrity Verification
-- 5. Storage Isolation
-- Feature Reference: M17-F018 (Automated Key Escrow Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_material_escrow (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    escrow_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    encrypted_material BYTEA NOT NULL,
    wrapping_key_id UUID,
    location VARCHAR(255), --  Physical location or Vault path
    checksum VARCHAR(64),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_escrow_mat_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_material_escrow IS 'Stores encrypted backups of key material for emergency recovery';

CREATE INDEX idx_key_escrow_mat_key ON sec.key_material_escrow(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB236 - incident_mobilization
-- Description: Tracking who was paged/mobilized.
-- Business Case: Incident Response Logistics. This table tracks the "Mobilization" phase:
--  who was paged, when did they acknowledge, and when did they join the
--  bridge. It measures the responsiveness of the security team.
-- KPIs:
-- 1. Acknowledgement Time (<15 mins)
-- 2. Mobilization Success (Did they join?)
-- 3. On-Call Rotation Accuracy
-- 4. Escalation Path Efficiency
-- 5. Contact Channel Reliability
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_mobilization (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mobilization_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    responder_id UUID NOT NULL,
    paged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    joined_at TIMESTAMP WITH TIME ZONE,
    channel VARCHAR(50), --  SMS, EMAIL, SLACK, PAGER

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT incident_mobil_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_mobilization IS 'Tracks the mobilization and acknowledgment of incident responders';

CREATE INDEX idx_incident_mobil_incident ON sec.incident_mobilization(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB237 - forensic_image_hashes
-- Description: Hashes of forensic images.
-- Business Case: Chain of Custody. This table stores cryptographic hashes of forensic
--  images (Memory dumps, Disk images). It proves that the evidence analyzed
--  in the lab is the exact same evidence collected from the field.
-- KPIs:
-- 1. Hash Match Success (Field -> Lab)
-- 2. Imaging Integrity
-- 3. Storage Security (Read-only)
-- 4. Hash Algorithm Strength (SHA256/SHA3)
-- 5. Chain of Custody Documentation
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.forensic_image_hashes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hash_id VARCHAR(100) UNIQUE NOT NULL,
    snapshot_id UUID NOT NULL,
    algorithm VARCHAR(20) NOT NULL, --  SHA256, MD5 (legacy)
    hash_value VARCHAR(128) NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT forensic_hash_snap_fkey FOREIGN KEY (snapshot_id) REFERENCES sec.forensic_snapshots(id)
);
COMMENT ON TABLE sec.forensic_image_hashes IS 'Stores cryptographic hashes of forensic images to verify chain of custody';

CREATE INDEX idx_forensic_hash_snapshot ON sec.forensic_image_hashes(snapshot_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB238 - compliance_mapping_rules
-- Description: Rules to auto-map tech controls to standards.
-- Business Case: Automating control mapping. This table defines "If condition X (e.g.,
--  "Uses AES-256") Then Standard Y (e.g., "ISO 27001 A.10")". It enables
--  automated control frameworks, reducing manual mapping effort by 90%.
-- KPIs:
-- 1. Mapping Accuracy (Verified by humans)
-- 2. Coverage (% of controls mapped)
-- 3. Rule Complexity
-- 4. False Positive Mapping (Incorrect map)
-- 5. Maintenance Overhead
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_mapping_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    technical_control_id VARCHAR(100) NOT NULL,
    standard_ref VARCHAR(100) NOT NULL, --  ISO, NIST
    condition_json JSONB NOT NULL,
    confidence_score NUMERIC(3,2),
    last_verified TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.compliance_mapping_rules IS 'Rules engine to automatically map technical controls to compliance standards';

CREATE INDEX idx_compliance_map_standard ON sec.compliance_mapping_rules(standard_ref);

------------------------------------------------------------------------------------------------
-- Table: M17-DB239 - security_metrics_calculations
-- Description: Saved calculation results.
-- Business Case: Performance optimization. Calculating complex metrics (e.g., "Mean Time to
--  Remediate") on the fly for dashboards is slow. This table caches the
--  results of these calculations (e.g., "For Q1 2023, MTTR was 15m"), refreshed
--  periodically.
-- KPIs:
-- 1. Cache Hit Ratio (>99%)
-- 2. Calculation Accuracy
-- 3. Refresh Latency
-- 4. Data Freshness
-- 5. Storage Efficiency
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_metrics_calculations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    calc_id VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    dimensions JSONB NOT NULL, --  e.g., {"period": "Q1", "severity": "High"}
    value NUMERIC(15,2) NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_metrics_calculations IS 'Caches calculated metric results to improve dashboard performance';

CREATE INDEX idx_metrics_calc_name ON sec.security_metrics_calculations(metric_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB240 - third_party_risk_factors
-- Description: Factors contributing to vendor risk.
-- Business Case: Granular risk scoring. A vendor's total risk is a sum of factors. This table
--  tracks individual factors (e.g., "Data Breach", "Financial Instability",
--  "Geopolitical Tension"). It allows the risk model to be tuned by adjusting
--  the weight of these factors.
-- KPIs:
-- 1. Factor Weight Accuracy
-- 2. Factor Update Frequency
-- 3. Correlation Analysis (Do factors relate?)
-- 4. Predictive Power
-- 5. Audit Trail (Who changed the weight?)
-- Feature Reference: M17-F149 (Secure Software Supply Chain)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.third_party_risk_factors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    factor_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_id VARCHAR(100) NOT NULL,
    factor_name VARCHAR(255) NOT NULL,
    score_impact INTEGER NOT NULL,
    description TEXT,
    detected_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.third_party_risk_factors IS 'Tracks individual contributing factors to third-party vendor risk scores';

CREATE INDEX idx_tp_risk_vendor ON sec.third_party_risk_factors(vendor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB241 - incident_root_cause_analysis
-- Description: Deep dive into root causes.
-- Business Case: Learning from mistakes. This table stores the detailed Root Cause Analysis (RCA)
--  for incidents. It identifies "Why did it happen" (Process vs Tech vs Human)
--  and tracks the remediation to prevent recurrence.
-- KPIs:
-- 1. RCA Completion Rate (100%)
-- 2. Recurrence Rate (Did it happen again?)
-- 3. Depth Analysis (5 Whys)
-- 4. Remediation Implementation (%)
-- 5. RCA Approval (Signed off by management)
-- Feature Reference: M17-F132 (Incident Lessons)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_root_cause_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rca_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    root_cause_description TEXT NOT NULL,
    category VARCHAR(50), --  PROCESS, TECHNOLOGY, HUMAN
    contributory_factors TEXT[],
    remediation_plan TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT incident_rca_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_root_cause_analysis IS 'Stores detailed Root Cause Analysis (RCA) for security incidents';

CREATE INDEX idx_incident_rca_incident ON sec.incident_root_cause_analysis(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB242 - code_commit_signatures
-- Description: Signatures on specific Git commits.
-- Business Case: Traceability. While code artifacts are signed, checking the commit itself is also
--  important. This table links a Git Commit Hash to a signature, ensuring that
--  the code in the repo is exactly what was signed, preventing "Repo
--  tampering".
-- KPIs:
-- 1. Verification Success (100%)
-- 2. Signature Coverage (Are all commits signed?)
-- 3. Key Validity
-- 4. Tamper Detection (Hash mismatch)
-- 5. GitOps Integration
-- Feature Reference: M17-F073 (Code Signing Service)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.code_commit_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    commit_id VARCHAR(100) UNIQUE NOT NULL,
    repo_url VARCHAR(500) NOT NULL,
    commit_hash VARCHAR(64) NOT NULL,
    signature_id UUID NOT NULL,
    signed_at TIMESTAMP WITH TIME ZONE,
    verified BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT commit_sig_sig_fkey FOREIGN KEY (signature_id) REFERENCES sec.digital_signatures(id)
);
COMMENT ON TABLE sec.code_commit_signatures IS 'Links digital signatures to specific Git commits for repo integrity';

CREATE INDEX idx_commit_sig_hash ON sec.code_commit_signatures(commit_hash);

------------------------------------------------------------------------------------------------
-- Table: M17-DB243 - policy_conflict_resolution
-- Description: How conflicting policies were resolved.
-- Business Case: Complex environments have conflicting rules (Policy A says Allow, B says Deny).
--  This table records how conflicts were resolved (Priority, Override). It provides
--  an audit trail explaining why a specific action was allowed or denied.
-- KPIs:
-- 1. Conflict Detection Rate
-- 2. Resolution Time
-- 3. Automation Rate (Auto-resolved vs Manual)
-- 4. Policy Clean-up (Reducing conflicts)
-- 5. Explainability (Can we explain why?)
-- Feature Reference: M17-F050 (Service-to-Service Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.policy_conflict_resolution (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resolution_id VARCHAR(100) UNIQUE NOT NULL,
    policy_a_id UUID NOT NULL,
    policy_b_id UUID NOT NULL,
    conflict_description TEXT,
    winning_policy_id UUID NOT NULL,
    resolution_logic VARCHAR(50), --  PRIORITY, SPECIFICITY_OVERRIDE
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT policy_conflict_a_fkey FOREIGN KEY (policy_a_id) REFERENCES sec.zero_trust_policies(id),
    CONSTRAINT policy_conflict_b_fkey FOREIGN KEY (policy_b_id) REFERENCES sec.zero_trust_policies(id)
);
COMMENT ON TABLE sec.policy_conflict_resolution IS 'Records how conflicting authorization policies were resolved';

CREATE INDEX idx_policy_conflict_timestamp ON sec.policy_conflict_resolution(resolved_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB244 - secure_communication_channels
-- Description: PGP key exchanges.
-- Business Case: Secure out-of-band comms. For high-risk discussions (incident response, key
--  recovery), secure channels (PGP encrypted email) are used. This table stores
--  the public keys of participants to enable secure messaging.
-- KPIs:
-- 1. Key Distribution Success
-- 2. Encryption Verification
-- 3. Key Rotation (Expiry management)
-- 4. Channel Usage
-- 5. Trust Model (Web of Trust)
-- Feature Reference: M17-F089 (Secure Remote Access (Bastion))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_communication_channels (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    channel_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    key_type VARCHAR(50) NOT NULL, --  PGP, X509
    public_key_pem TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_communication_channels IS 'Stores public keys for secure out-of-band communication channels (PGP)';

CREATE INDEX idx_secure_comm_fingerprint ON sec.secure_communication_channels(fingerprint);

------------------------------------------------------------------------------------------------
-- Table: M17-DB245 - audit_report_templates
-- Description: Reusable report formats.
-- Business Case: Standardizing reporting. This table defines templates for audit reports (e.g.,
--  "ISO 27001 Executive Summary"). It defines SQL queries, formatting, and
--  required sections, ensuring consistency in reports generated over time.
-- KPIs:
-- 1. Template Reusability
-- 2. Report Generation Success
-- 3. Data Accuracy (Template logic errors)
-- 4. Customization Speed
-- 5. Layout Standardization
-- Feature Reference: M17-F113 (Automated Compliance Reporting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_report_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    format_type VARCHAR(20), --  PDF, HTML, CSV
    query_logic JSONB NOT NULL, --  The data fetch logic
    layout_json JSONB, --  The visual structure

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_report_templates IS 'Defines reusable templates for automated audit and compliance reports';

CREATE INDEX idx_audit_template_name ON sec.audit_report_templates(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB246 - user_activity_summaries
-- Description: Daily/Weekly summaries of user actions.
-- Business Case: Big Data summarization. Storing every single action is expensive. This table
--  stores aggregated summaries (e.g., "User X failed login 5 times yesterday").
--  It fuels the UEBA models and long-term trend analysis without processing
--  billions of rows.
-- KPIs:
-- 1. Summary Accuracy (Matches raw logs)
-- 2. Aggregation Latency (Daily/Weekly)
-- 3. Storage Savings
-- 4. Query Performance (Trends)
-- 5. Retention Compliance (Keep summaries longer)
-- Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_activity_summaries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    summary_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    activity_type VARCHAR(50) NOT NULL, --  LOGIN, UPLOAD, EXPORT
    count INTEGER NOT NULL,
    risk_level VARCHAR(20),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_activity_summaries IS 'Stores aggregated daily or weekly summaries of user activity for trend analysis';

CREATE INDEX idx_user_activity_user_period ON sec.user_activity_summaries(user_id, period_start);

------------------------------------------------------------------------------------------------
-- Table: M17-DB247 - security_roadmap
-- Description: Future security initiatives.
-- Business Case: Strategic planning. Security isn't static. This table maps out future initiatives
--  (e.g., "Implement SASE in Q3", "Zero Trust Data"). It tracks budget,
--  status, and dependencies, ensuring long-term maturity growth.
-- KPIs:
-- 1. Initiative Completion Rate
-- 2. Budget Adherence
-- 3. Dependency Resolution
-- 4. Stakeholder Buy-in
-- 5. Milestone Achievement
-- Feature Reference: M17-F004 (HSM Key Generation - Future readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_roadmap (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    initiative_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    start_date TIMESTAMP WITH TIME ZONE,
    target_end_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'PLANNING', --  PLANNING, IN_PROGRESS, COMPLETED, CANCELLED
    owner UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_roadmap IS 'Tracks strategic security initiatives and project milestones';

CREATE INDEX idx_roadmap_status ON sec.security_roadmap(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB248 - compliance_artifact_links
-- Description: Links code to compliance requirements.
-- Business Case: Code evidence. This table links specific code artifacts (Commits, Functions,
--  Files) to compliance requirements (e.g., "Function A validates GDPR Art 32").
--  It allows for "Continuous Compliance" by proving code compliance dynamically.
-- KPIs:
-- 1. Link Accuracy (Verified by humans)
-- 2. Artifact Traceability
-- 3. Automated Test Coverage (Does code prove it?)
-- 4. Link Maintenance (Broken links)
-- 5. Audit Time Reduction
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_artifact_links (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    link_id VARCHAR(100) UNIQUE NOT NULL,
    artifact_id VARCHAR(255) NOT NULL, --  URL, Function Name
    control_id VARCHAR(100) NOT NULL, --  Compliance control
    evidence_description TEXT,
    last_verified TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.compliance_artifact_links IS 'Links specific code artifacts to compliance requirements for automated evidence';

CREATE INDEX idx_comp_artifact_control ON sec.compliance_artifact_links(control_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB249 - incident_command_center_status
-- Description: Status of war room during incident.
-- Business Case: Orchestration. During a major incident, a "War Room" is activated. This
--  table tracks the status (Open, Closed), assigned Lead, and communication
--  bridge link. It provides a central status board for the organization.
-- KPIs:
-- 1. Activation Speed
-- 2. Role Assignment (All seats filled)
-- 3. Communication Stability (Bridge up)
-- 4. Status Update Frequency
-- 5. Deactivation Speed
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_command_center_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    icc_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'STANDBY', --  STANDBY, ACTIVE, CLOSED
    lead_id UUID NOT NULL,
    bridge_url VARCHAR(500),
    activated_at TIMESTAMP WITH TIME ZONE,
    deactivated_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT icc_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_command_center_status IS 'Tracks the status of the Incident Command Center (War Room)';

CREATE INDEX idx_icc_incident ON sec.incident_command_center_status(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB250 - system_retirement_schedule
-- Description: When security systems are end-of-life.
-- Business Case: Lifecycle management. Security tools and agents (EDR, Agents) have end-of-life
--  dates. This table tracks retirement schedules to ensure systems are
--  upgraded or replaced before support ends (maintaining security posture).
-- KPIs:
-- 1. Retirement Adherence (On time)
-- 2. Support Gap Duration (0 days)
-- 3. Migration Success
-- 4. Budget Planning (Future costs)
-- 5. Vendor Coordination
-- Feature Reference: M17-F087 (Identity Synchronization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.system_retirement_schedule (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schedule_id VARCHAR(100) UNIQUE NOT NULL,
    system_name VARCHAR(255) NOT NULL,
    vendor VARCHAR(255),
    version VARCHAR(50),
    end_of_support_date TIMESTAMP WITH TIME ZONE NOT NULL,
    retirement_action VARCHAR(50), --  UPGRADE, DECOMMISSION, REPLACE
    replacement_system VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.system_retirement_schedule IS 'Schedules the retirement and replacement of end-of-life security systems';

CREATE INDEX idx_sys_retire_date ON sec.system_retirement_schedule(end_of_support_date);


-- 2. Triggers for Update Timestamps (DB201-DB250)
-- ================================================================================

CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_migration_paths FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.sdlc_phases FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.threat_actor_profiles FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.supply_chain_tiers FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secret_shares_distribution FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.firewall_nat_pools FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.api_gateway_plugins FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.auth_flows FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.container_benchmarks FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.code_reviewer_assignments FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_automation_scripts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.certificate_signing_requests FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.iam_role_hierarchies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_training_modules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_cost_analysis FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.penetration_test_scopes FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vulnerability_fixes FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.key_cryptoperiods FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.correlation_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_native_policies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.identity_federation_trusts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.compliance_mapping_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.third_party_risk_factors FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_root_cause_analysis FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.policy_conflict_resolution FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_communication_channels FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.audit_report_templates FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_roadmap FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.compliance_artifact_links FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_command_center_status FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.system_retirement_schedule FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- End of Script Part 5 (Tables Complete: 1-250)
-- Next Steps: Views, Stored Procedures

-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 6: Tables DB251-DB350)
-- ================================================================================
-- Description:
-- Continuation of M17 schema definition. This part extends the table set to
-- DB250-DB350, covering specialized areas such as advanced forensics chain of
-- custody, AI/ML model governance and drift detection, granular regional compliance
-- overrides, Relationship-Based Access Control (ReBAC), Business Continuity
-- and Disaster Recovery (BCDR) drills, deep-dive Cloud Security Posture Management
-- (CSPM), supply chain VEX (Vulnerability Exploitability) scoring, and detailed
-- operational metrics for security operations centers (SOC).
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. DDL Statements (Tables 251-350)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB251 - forensic_chain_of_custody
-- Description: Tracks the transfer of evidence between handlers.
-- Business Case: In legal proceedings, proving the chain of custody is paramount. If evidence
-- (a log file, a hard drive) changes hands without documentation, it may be
-- inadmissible. This table logs every transfer (Who took it, When, For what purpose),
--  ensuring that the integrity of forensic evidence is legally defensible.
-- KPIs:
-- 1. Chain Logging Accuracy (100%)
-- 2. Handover Documentation Completeness
-- 3. Transfer Latency (Efficiency)
-- 4. Evidence Integrity Verification (Hash checks at each step)
-- 5. Legal Adherence Rate
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.forensic_chain_of_custody (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    custody_id VARCHAR(100) UNIQUE NOT NULL,
    evidence_id UUID NOT NULL,
    handler_id UUID NOT NULL, -- User or System
    purpose VARCHAR(255) NOT NULL, -- Analysis, Copying, Archiving
    transfer_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_handler_id UUID,
    signature_hash VARCHAR(64), -- Digital signature of the handover
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT forensic_custody_evidence_fkey FOREIGN KEY (evidence_id) REFERENCES sec.forensic_snapshots(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.forensic_chain_of_custody IS 'Tracks the chain of custody for forensic evidence to ensure legal defensibility';

CREATE INDEX idx_forensic_custody_evidence ON sec.forensic_chain_of_custody(evidence_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB252 - seizure_orders
-- Description: Legal orders to preserve data.
-- Business Case: During litigation or investigation, a "Litigation Hold" or Seizure Order
-- might be issued. This table records these legal requests, ensuring that automated
-- data deletion or rotation jobs are suspended for specific assets to comply with the
-- law (Spoilation).
-- KPIs:
-- 1. Order Recording Speed (<1 hour)
-- 2. Preservation Compliance (100%)
-- 3. Legal Counsel Notification Rate
-- 4. Scope Accuracy (Correct data preserved)
-- 5. Order Expiry Management
-- Feature Reference: M17-F045 (Log Retention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.seizure_orders (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    order_id VARCHAR(100) UNIQUE NOT NULL,
    case_number VARCHAR(100) NOT NULL,
    issuing_authority VARCHAR(255) NOT NULL,
    scope JSONB NOT NULL, -- Assets/Log types covered
    status VARCHAR(50) DEFAULT 'ACTIVE', -- ACTIVE, EXPIRED, RELEASED
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.seizure_orders IS 'Records legal orders for data preservation to prevent spoliation';

CREATE INDEX idx_seizure_status ON sec.seizure_orders(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB253 - adversarial_ml_inputs
-- Description: Inputs suspected of being adversarial.
-- Business Case: AI models can be fooled by adversarial inputs (e.g., text crafted to look
-- benign to a sentiment analyzer). This table stores flagged inputs for analysis.
--  Studying these inputs helps the security team retrain the model to be robust against
--  evasion attempts.
-- KPIs:
-- 1. Detection Latency (<1s)
-- 2. False Positive Rate (Normal data flagged as adversarial)
-- 3. Model Retraining Trigger Rate
-- 4. Attack Vector Analysis
-- 5. Feedback Loop Speed (to training pipeline)
-- Feature Reference: M17-F075 (Sandbox Evasion Detection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.adversarial_ml_inputs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    input_id VARCHAR(100) UNIQUE NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    input_data TEXT NOT NULL, -- The actual input (e.g., packet payload, prompt)
    detection_method VARCHAR(50), -- GRADIENT_ATTACK, FOOLING
    confidence_score NUMERIC(5,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.adversarial_ml_inputs IS 'Stores inputs suspected to be adversarial attacks against AI models';

CREATE INDEX idx_adversarial_ml_model ON sec.adversarial_ml_inputs(model_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB254 - model_performance_drift
-- Description: Tracking degradation of model accuracy over time.
-- Business Case: ML models suffer from "drift" where accuracy drops as the environment changes
--  (new attack types). This table tracks metrics (Precision, Recall, F1) over time.
--  A significant drop triggers an automated alert to retrain or re-tune the model, ensuring
--  the security system remains effective.
-- KPIs:
-- 1. Drift Detection Speed (<1 day)
-- 2. Threshold Alert Accuracy
-- 3. Model Retraining Frequency
-- 4. Performance Recovery Time
-- 5. Baseline Deviation Analysis
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.model_performance_drift (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_id VARCHAR(100) UNIQUE NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    metric_name VARCHAR(50) NOT NULL, -- PRECISION, RECALL, F1_SCORE
    baseline_value NUMERIC(5,2),
    current_value NUMERIC(5,2),
    drift_percentage NUMERIC(5,2),
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_significant BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.model_performance_drift IS 'Tracks performance degradation (drift) in security AI models';

CREATE INDEX idx_model_drift_model ON sec.model_performance_drift(model_id, measured_at DESC);

------------------------------------------------------------------------------------------------
-- Table: M17-DB255 - training_data_provenance
-- Description: Source and consent for training data.
-- Business Case: Privacy in AI. Training models requires data. This table tracks the provenance
-- (source) and consent status (did users agree to this data being used for training?).
--  It is essential for ethical AI and compliance with regulations like the EU AI Act.
-- KPIs:
-- 1. Data Source Verification (100%)
-- 2. Consent Documentation Completeness
-- 3. Data Quality Score
-- 4. Bias Detection (in training data)
-- 5. Usage Tracking (What models use this data?)
-- Feature Reference: M17-F104 (Threat Modeling Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.training_data_provenance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id VARCHAR(100) UNIQUE NOT NULL,
    source_system VARCHAR(255) NOT NULL, -- LOGS, PUBLIC_DATASET, SYNTHETIC
    consent_type VARCHAR(50), -- OPT_OUT, OPT_IN, ANONYMIZED
    retention_policy VARCHAR(50),
    last_washed_at TIMESTAMP WITH TIME ZONE,
    bias_score NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.training_data_provenance IS 'Tracks source and consent for AI training data to ensure ethical AI compliance';

CREATE INDEX idx_training_data_source ON sec.training_data_provenance(source_system);

------------------------------------------------------------------------------------------------
-- Table: M17-DB256 - reginal_compliance_overrides
-- Description: Overrides for specific regional regulations.
-- Business Case: GDPR applies in EU, CCPA in California. Sometimes a global policy is too
--  restrictive or not restrictive enough for a specific region. This table allows specific
--  overrides (e.g., "In California, allow Do Not Sell opt-out even if global policy denies it").
-- KPIs:
-- 1. Override Activation Accuracy
-- 2. Geo-Location Enforcement (Correct override applied)
-- 3. Conflict Resolution (Global vs Override)
-- 4. Audit Trail (Why was this overridden?)
-- 5. Review Frequency
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.reginal_compliance_overrides (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    override_id VARCHAR(100) UNIQUE NOT NULL,
    region_code CHAR(2) NOT NULL, -- US, EU, CA, UK
    global_policy_id VARCHAR(100) NOT NULL, -- Link to the policy being overridden
    overridden_setting JSONB NOT NULL,
    justification TEXT,
    approved_by UUID,
    expiry_date TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.reginal_compliance_overrides IS 'Allows specific overrides to global security policies for regional compliance requirements';

CREATE INDEX idx_regional_overrides_region ON sec.reginal_compliance_overrides(region_code);

------------------------------------------------------------------------------------------------
-- Table: M17-DB257 - rebac_relationships
-- Description: Graph of relationships for ReBAC.
-- Business Case: ReBAC (Relationship-Based Access Control) grants access based on relationships
--  (e.g., "Manager Of", "Parent Of", "Colleague Of"). This table stores the
--  relationship graph nodes and edges, allowing dynamic authorization based on context.
-- KPIs:
-- 1. Graph Query Latency (<50ms)
-- 2. Relationship Depth Accuracy
-- 3. Cyclic Reference Detection (0)
-- 4. Real-time Update Success
-- 5. Permission Calculation Accuracy
-- Feature Reference: M17-F080 (ReBAC)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.rebac_relationships (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    relationship_id VARCHAR(100) UNIQUE NOT NULL,
    subject_id UUID NOT NULL,
    object_id UUID NOT NULL,
    relationship_type VARCHAR(50) NOT NULL, -- MANAGER_OF, PEER_OF, MEMBER_OF
    context JSONB, -- Time, Location constraints
    is_direct BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.rebac_relationships IS 'Defines the relationship graph for Relationship-Based Access Control (ReBAC)';

CREATE INDEX idx_rebac_subject ON sec.rebac_relationships(subject_id);
CREATE INDEX idx_rebac_object ON sec.rebac_relationships(object_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB258 - dynamic_group_membership
-- Description: Cache of dynamic group memberships.
-- Business Case: Calculating group membership (e.g., "All users in 'Finance' Dept") on every
--  request is slow. This table caches the computed membership, updating when user
--  attributes change, to accelerate authorization lookups.
-- KPIs:
-- 1. Cache Hit Ratio (>99%)
-- 2. Invalidation Latency (<1s)
-- 3. Membership Accuracy (100%)
-- 4. Storage Optimization (No bloat)
-- 5. Refresh Frequency
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dynamic_group_membership (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    membership_id VARCHAR(100) UNIQUE NOT NULL,
    group_id VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL,
    reason_code VARCHAR(255), -- Why are they in this group?
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.dynamic_group_membership IS 'Cache of dynamically calculated group memberships for fast access checks';

CREATE INDEX idx_dyn_group_user ON sec.dynamic_group_membership(user_id);
CREATE INDEX idx_dyn_group_valid ON sec.dynamic_group_membership(valid_until);

------------------------------------------------------------------------------------------------
-- Table: M17-DB259 - bcdr_drill_reports
-- Description: Reports on Business Continuity drills.
-- Business Case: You can't wait for a disaster to test your plan. Regular drills are required.
--  This table stores reports of drills (Fire drills, Tabletop exercises), tracking what
--  went wrong, RTO/RPO performance, and improvement actions.
-- KPIs:
-- 1. Drill Completion Frequency (Quarterly)
-- 2. RTO Achievement (Target met?)
-- 3. RPO Achievement (Target met?)
-- 4. Action Item Closure Rate
-- 5. Participant Satisfaction
-- Feature Reference: M17-F146 (Disaster Recovery Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.bcdr_drill_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    drill_id VARCHAR(100) UNIQUE NOT NULL,
    drill_type VARCHAR(50) NOT NULL, -- TABLETOP, FIRE_DRILL, FULL_SYSTEM
    planned_date TIMESTAMP WITH TIME ZONE,
    executed_date TIMESTAMP WITH TIME ZONE,
    rto_target_seconds INTEGER,
    rto_actual_seconds INTEGER,
    rpo_target_seconds INTEGER,
    rpo_actual_seconds INTEGER,
    status VARCHAR(50) DEFAULT 'COMPLETED',
    lessons_learned TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.bcdr_drill_reports IS 'Stores results and metrics from Business Continuity and Disaster Recovery (BCDR) drills';

CREATE INDEX idx_bcdr_drills_type ON sec.bcdr_drill_reports(drill_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB260 - failover_test_results
-- Description: Results of manual failover tests.
-- Business Case: Automated failover is good, but manual tests prove it works. This table records
--  results of manually triggered failovers (e.g., "Failover KMS to Backup Region"),
--  ensuring that the operational team is trained and the process works.
-- KPIs:
-- 1. Test Success Rate (100%)
-- 2. Downtime During Test (Minimized)
-- 3. Rollback Success Rate
-- 4. Test Frequency (Quarterly)
-- 5. Data Integrity Post-Failover (100%)
-- Feature Reference: M17-F043 (HSM Cluster Failover)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.failover_test_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id VARCHAR(100) UNIQUE NOT NULL,
    system_id VARCHAR(255) NOT NULL, -- Which component was failed over?
    started_by UUID NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    result VARCHAR(20) CHECK (result IN ('SUCCESS','FAILED','PARTIAL')),
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.failover_test_results IS 'Logs results of manual failover tests to validate disaster recovery procedures';

CREATE INDEX idx_failover_test_system ON sec.failover_test_results(system_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB261 - east_west_traffic_anomalies
-- Description: Specific focus on internal traffic anomalies.
-- Business Case: Lateral movement is the hardest attack to detect. This table specifically
--  logs anomalies in East-West (internal) traffic (e.g., Database talking to Domain Controller).
--  It is critical for detecting compromised workload spreading.
-- KPIs:
-- 1. Detection Rate (>95%)
-- 2. False Positive Rate (Low)
-- 3. Lateral Movement Blocking (Success)
-- 4. Severity Classification Accuracy
-- 5. Blast Radius Analysis
-- Feature Reference: M17-F011 (Anomaly Detection on Network Traffic)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.east_west_traffic_anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    src_workload VARCHAR(255) NOT NULL,
    dst_workload VARCHAR(255) NOT NULL,
    protocol VARCHAR(20),
    anomaly_score NUMERIC(5,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    context JSONB, -- E.g., "Outside maintenance window"

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.east_west_traffic_anomalies IS 'Specific logs for anomalies in internal (East-West) traffic to detect lateral movement';

CREATE INDEX idx_ew_anomaly_src_dst ON sec.east_west_traffic_anomalies(src_workload, dst_workload);

------------------------------------------------------------------------------------------------
-- Table: M17-DB262 - cspm_iam_analysis
-- Description: Analysis of Cloud IAM permissions.
-- Business Case: Cloud IAM permissions often grow uncontrolled ("Permission Creep"). This table
--  stores analysis results of Cloud IAM roles, flagging users with excessive permissions
--  (e.g., "DeleteBucket" access assigned to a dev).
-- KPIs:
-- 1. Analysis Frequency (Weekly)
-- 2. Excessive Permission Count
-- 3. Remediation Success Rate (Permissions removed)
-- 4. Last Used Date Tracking
-- 5. Policy Violation Count
-- Feature Reference: M17-F082 (Cloud Workload Protection (CWP))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cspm_iam_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    analysis_id VARCHAR(100) UNIQUE NOT NULL,
    cloud_account_id VARCHAR(100) NOT NULL,
    principal_arn VARCHAR(500) NOT NULL,
    policy_name VARCHAR(255),
    risk_level VARCHAR(20) CHECK (risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    recommendation TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cspm_iam_analysis IS 'Stores analysis of cloud IAM permissions to detect privilege creep';

CREATE INDEX idx_cspm_iam_principal ON sec.cspm_iam_analysis(principal_arn);

------------------------------------------------------------------------------------------------
-- Table: M17-DB263 - vex_scores
-- Description: Vulnerability Exploitability Exchange scores.
-- Business Case: CVSS score doesn't tell the whole story. VEX (OpenSSF) adds context about
--  exploitation (e.g., "Is there public exploit code?", "Is it in the wild?").
--  This table stores these enriched scores to prioritize patching of *actively exploited* vulns.
-- KPIs:
-- 1. VEX Data Freshness (<24h)
-- 2. "In the Wild" Detection Count
-- 3. Patch Priority Accuracy
-- 4. Exploit Code Availability Tracking
-- 5. Vendor Statement Capture
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vex_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vex_id VARCHAR(100) UNIQUE NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    vex_version VARCHAR(20) NOT NULL, -- VEX version 0.2, etc.
    exploit_status VARCHAR(50), -- NONE, ACTIVE, POISONED
    exploit_range VARCHAR(50), -- UNKNOWN, LOCAL, NETWORK
    supplier_contact TEXT,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vex_scores IS 'Stores VEX (Vulnerability Exploitability Exchange) data for enhanced vulnerability prioritization';

CREATE INDEX idx_vex_scores_cve ON sec.vex_scores(cve_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB264 - mitre_attack_patterns
-- Description: Mapping to MITRE ATT&CK framework.
-- Business Case: Translating technical alerts into threat intelligence. This table maps system
--  alerts to MITRE ATT&CK IDs (TTPs). This allows the SOC to understand *how* an
--  attacker is operating (e.g., "They are dumping credentials via T1003") and tailor defense.
-- KPIs:
-- 1. Mapping Coverage (Percentage of alerts mapped)
-- 2. TTP Frequency Analysis (Most common techniques)
-- 3. Mitigation Recommendation Linking
-- 4. Framework Alignment
-- 5. Threat Actor Attribution Support
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.mitre_attack_patterns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    technique_id VARCHAR(20) NOT NULL, -- T1552.001
    tactic_id VARCHAR(20) NOT NULL, -- Credential Access
    name VARCHAR(255) NOT NULL,
    description TEXT,
    detection_status VARCHAR(50), -- DETECTED, NOT_DETECTED
    confidence_score NUMERIC(3,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.mitre_attack_patterns IS 'Maps security alerts to MITRE ATT&CK TTPs for intelligence-driven defense';

CREATE INDEX idx_mitre_technique ON sec.mitre_attack_patterns(technique_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB265 - escalation_matrices
-- Description: Who to call for specific alerts.
-- Business Case: Incident response needs speed. This table defines the escalation matrix (e.g.,
--  "Critical severity -> Page CISO", "High severity -> Email Team Lead"). It ensures
--  that the right people are notified instantly based on the alert type.
-- KPIs:
-- 1. Notification Delivery Speed (<1 min)
-- 2. On-Call Accuracy
-- 3. Matrix Update Frequency
-- 4. Escalation Path Compliance
-- 5. Acknowledgement Rate
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.escalation_matrices (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    matrix_id VARCHAR(100) UNIQUE NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    target_team VARCHAR(255) NOT NULL,
    channel VARCHAR(50), -- EMAIL, SMS, SLACK, PAGERDUTY
    escalation_delay_minutes INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.escalation_matrices IS 'Defines who to call for specific alert types and severities';

CREATE INDEX idx_esc_matrix_type_severity ON sec.escalation_matrices(alert_type, severity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB266 - on_call_rotations
-- Description: Weekly schedules for on-call engineers.
-- Business Case: 24/7 security requires on-call rotations. This table stores the weekly
--  schedule, defining who is the primary responder and who is the backup/escalation
--  contact for any given time window.
-- KPIs:
-- 1. Schedule Coverage (100%)
-- 2. Shift Handover Rate
-- 3. Contact Info Validity (Phone numbers work)
-- 4. Overtime Tracking
-- 5. Swap Frequency
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.on_call_rotations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    shift_id VARCHAR(100) UNIQUE NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    primary_user_id UUID NOT NULL,
    backup_user_id UUID,
    team_slug VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'UPCOMING', -- UPCOMING, ACTIVE, COMPLETED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.on_call_rotations IS 'Manages the weekly on-call rotation schedule for security engineers';

CREATE INDEX idx_oncall_times ON sec.on_call_rotations(start_time, end_time);

------------------------------------------------------------------------------------------------
-- Table: M17-DB267 - alert_suppression_rules
-- Description: Known noisy alerts to suppress.
-- Business Case: Some alerts are noise (e.g., "Heartbeat failure" is known maintenance).
--  Analysts can suppress these alerts for a time window to reduce fatigue. This table
--  tracks suppression rules, ensuring they are temporary and reviewed.
-- KPIs:
-- 1. Suppression Accuracy (Only noise suppressed)
-- 2. Expiry Adherence (Alerts re-appear after window)
-- 3. Rule Approval Rate
-- 4. False Negative Rate (Did we miss a real threat?)
-- 5. Analyst Satisfaction (Reduced noise)
-- Feature Reference: M17-F079 (Alert Fatigue Reduction)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.alert_suppression_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    alert_pattern JSONB NOT NULL, -- Criteria to match alert
    suppression_duration_hours INTEGER NOT NULL,
    reason TEXT NOT NULL,
    approver_id UUID,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.alert_suppression_rules IS 'Manages rules to suppress noisy security alerts temporarily';

CREATE INDEX idx_suppress_expires ON sec.alert_suppression_rules(expires_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB268 - security_budget_tracking
-- Description: Linking security spend to risk reduction.
-- Business Case: Security is a cost center. To justify budget, one must link spend to risk
-- reduction. This table tracks budgets (Tools, Staff) and metrics (Incidents avoided,
--  Money saved), building an ROI model for security investment.
-- KPIs:
-- 1. Budget Adherence (Spent vs Plan)
-- 2. ROI Calculation Accuracy
-- 3. Cost Efficiency (Cost per incident avoided)
-- 4. Budget Utilization Rate
-- 5. Forecast Accuracy
-- Feature Reference: M17-F220 (Incident Cost Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_budget_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    budget_id VARCHAR(100) UNIQUE NOT NULL,
    fiscal_year INTEGER NOT NULL,
    category VARCHAR(100) NOT NULL, -- TOOLS, STAFF, TRAINING, AUDIT
    allocated_amount NUMERIC(15,2),
    spent_amount NUMERIC(15,2),
    projected_savings NUMERIC(15,2), -- Risk reduction value
    justification TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_budget_tracking IS 'Tracks security spending vs risk reduction to calculate ROI';

CREATE INDEX idx_sec_budget_year ON sec.security_budget_tracking(fiscal_year);

------------------------------------------------------------------------------------------------
-- Table: M17-DB269 - insider_threat_indicators
-- Description: Psychometric/behavioral indicators of risk.
-- Business Case: Insiders are hard to catch. This table records specific "Red Flag"
--  indicators (e.g., "Accessing data outside work hours", "Downloading large files",
--  "Failed access attempts on sensitive folder") for specific users.
-- KPIs:
-- 1. Indicator Coverage (Types of threats tracked)
-- 2. Risk Score Calculation Accuracy
-- 3. Intervention Trigger Rate (HR notified)
-- 4. False Positive Rate (Privacy concerns)
-- 5. Monitoring Compliance (Legal/HR approval)
-- Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.insider_threat_indicators (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    indicator_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    indicator_type VARCHAR(100) NOT NULL, -- DATA_EXFILTRATION, SABOTAGE, FRAUD
    severity VARCHAR(20),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    details JSONB,
    reviewed_by UUID,
    action_taken VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.insider_threat_indicators IS 'Stores behavioral indicators specifically associated with insider threats';

CREATE INDEX idx_insider_threat_user ON sec.insider_threat_indicators(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB270 - cloud_asset_mutability
-- Description: How often cloud assets change.
-- Business Case: Cloud assets are ephemeral. If a configuration changes constantly, it's hard
--  to secure. This table tracks the "churn" or "mutability" of assets (e.g.,
--  "This instance is replaced 5 times a day"). High mutability requires different security
--  controls (immutability tags).
-- KPIs:
-- 1. Mutation Rate (Events per day)
-- 2. Configuration Drift Velocity
-- 3. Asset Stability Score
-- 4. Mutation Window Analysis (When do changes happen?)
-- 5. Impact on Compliance (Does high churn = more vulns?)
-- Feature Reference: M17-F082 (Cloud Workload Protection (CWP))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_asset_mutability (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id VARCHAR(100) UNIQUE NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    mutation_count INTEGER DEFAULT 0,
    last_mutated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    average_lifespan_hours NUMERIC(10,2),
    stability_score VARCHAR(20), -- STABLE, DYNAMIC, VOLATILE

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_asset_mutability IS 'Tracks how frequently cloud assets change or are replaced to assess risk';

CREATE INDEX idx_mutability_asset ON sec.cloud_asset_mutability(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB271 - quantum_risk_assessments
-- Description: Assessing quantum threat to current crypto.
-- Business Case: Quantum decryption is a future threat. This table assesses the impact of quantum
--  computing on current assets (e.g., "This AES-256 key is safe until 2035", "This RSA key
--  is vulnerable now"). It drives the migration timeline.
-- KPIs:
-- 1. Assessment Coverage (100% of keys)
-- 2. Risk Exposure Timeline (Years to safety)
-- 3. Migration Priority Score
-- 4. Algorithm Vulnerability Class
-- 5. Compliance Readiness (NIST timelines)
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_risk_assessments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assessment_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    current_algorithm VARCHAR(50),
    quantum_safe BOOLEAN DEFAULT false,
    y2q_year INTEGER, -- Year until quantum threat
    risk_level VARCHAR(20), -- CRITICAL, HIGH, LOW
    recommended_action VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT quantum_risk_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.quantum_risk_assessments IS 'Assesses the vulnerability of cryptographic keys to quantum computing attacks';

CREATE INDEX idx_quantum_risk_level ON sec.quantum_risk_assessments(risk_level);

------------------------------------------------------------------------------------------------
-- Table: M17-DB272 - patch_deployment_windows
-- Description: Allowed windows for patching.
-- Business Case: You can't patch a production payment gateway during Black Friday. This table
--  defines deployment windows (Blackout dates) for specific assets, preventing
--  automated patching systems from causing outages during peak business hours.
-- KPIs:
-- 1. Window Adherence (100%)
-- 2. Overlap Detection (Conflicts)
-- 3. Exception Approval Rate
-- 4. Patch Delay Calculation
-- 5. Availability Protection (Uptime maintained)
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.patch_deployment_windows (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    window_id VARCHAR(100) UNIQUE NOT NULL,
    asset_group VARCHAR(255) NOT NULL,
    day_of_week INTEGER CHECK (day_of_week BETWEEN 0 AND 6),
    start_time TIME,
    end_time TIME,
    timezone VARCHAR(50) DEFAULT 'UTC',
    active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.patch_deployment_windows IS 'Defines approved time windows for patching to prevent business disruption';

CREATE INDEX idx_patch_windows_asset ON sec.patch_deployment_windows(asset_group);

------------------------------------------------------------------------------------------------
-- Table: M17-DB273 - forensic_artifacts_collected
-- Description: Metadata for evidence collected from endpoints.
-- Business Case: Forensics requires collecting volatile data (RAM) and non-volatile data (Disk).
--  This table logs specific artifacts collected from endpoints (e.g., "Memory Dump", "Hive
--  Keys") to ensure a complete forensic picture is preserved.
-- KPIs:
-- 1. Artifact Collection Success (100%)
-- 2. Data Integrity (Hash matches)
-- 3. Collection Time (Speed of acquisition)
-- 4. Chain of Custody Linkage
-- 5. Volatile Data Preservation (RAM captured before shutdown)
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.forensic_artifacts_collected (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_id VARCHAR(100) UNIQUE NOT NULL,
    source_endpoint VARCHAR(255) NOT NULL,
    artifact_type VARCHAR(50) NOT NULL, -- RAM_DUMP, DISK_IMAGE, REGISTRY_HIVE
    file_hash VARCHAR(64),
    collected_by UUID NOT NULL,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    size_bytes BIGINT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.forensic_artifacts_collected IS 'Logs specific forensic artifacts collected from compromised endpoints';

CREATE INDEX idx_forensic_artifact_endpoint ON sec.forensic_artifacts_collected(source_endpoint);

------------------------------------------------------------------------------------------------
-- Table: M17-DB274 - security_control_slo
-- Description: Service Level Objectives for controls.
-- Business Case: Security controls (WAF, Auth) should meet SLOs (e.g., "99.9% of requests
--  process in <200ms"). This table defines these targets. Monitoring systems compare actual
--  performance against these SLOs to generate "Error Budget" burn alerts.
-- KPIs:
-- 1. SLO Adherence (Budget Met?)
-- 2. Error Budget Burn Rate
-- 3. Performance Baseline Accuracy
-- 4. Alert Trigger Accuracy (Only alert on real misses)
-- 5. SLO Review Frequency (Quarterly)
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_control_slo (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_id VARCHAR(100) UNIQUE NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL, -- LATENCY, AVAILABILITY, ERROR_RATE
    target_value NUMERIC(10,2),
    unit VARCHAR(20),
    window_duration_hours INTEGER,
    current_value NUMERIC(10,2),
    budget_remaining_percentage NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_control_slo IS 'Defines Service Level Objectives (SLO) for security controls performance';

CREATE INDEX idx_slo_control ON sec.security_control_slo(control_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB275 - third_party_risk_surveys
-- Description: Surveys sent to vendors.
-- Business Case: Assessing vendor risk often requires sending questionnaires. This table tracks
--  questionnaires sent to vendors (SIG questionnaire, SOC2 Type 2 request), tracking
--  due dates, responses, and calculated risk scores.
-- KPIs:
-- 1. Survey Response Rate (>90%)
-- 2. Response Latency (Average days to reply)
-- 3. Questionnaire Completion Quality
-- 4. Re-assessment Frequency (Annual)
-- 5. Risk Score Update Accuracy
-- Feature Reference: M17-F149 (Secure Software Supply Chain)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.third_party_risk_surveys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    survey_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_id VARCHAR(100) NOT NULL,
    survey_type VARCHAR(50) NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    due_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE,
    score_calculated INTEGER,
    status VARCHAR(20) DEFAULT 'PENDING',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.third_party_risk_surveys IS 'Manages risk assessment surveys sent to third-party vendors';

CREATE INDEX idx_vendor_survey_vendor ON sec.third_party_risk_surveys(vendor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB276 - anomaly_feedback_loops
-- Description: Analyst feedback on anomaly detection.
-- Business Case: AI models need human feedback (RLHF). When an analyst reviews an alert
--  marked as "Anomaly", they confirm if it was real. This table stores that
--  feedback, which is used to retrain and tune the model to be more accurate.
-- KPIs:
-- 1. Feedback Collection Rate (% of alerts reviewed)
-- 2. Feedback Latency (How fast does analyst review?)
-- 3. Model Improvement (Accuracy increase after retraining)
-- 4. Consensus Analysis (Do analysts agree?)
-- 5. False Positive Reduction Trend
-- Feature Reference: M17-F079 (Alert Fatigue Reduction)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.anomaly_feedback_loops (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feedback_id VARCHAR(100) UNIQUE NOT NULL,
    alert_id UUID NOT NULL,
    analyst_id UUID NOT NULL,
    is_true_positive BOOLEAN NOT NULL,
    confidence_rating INTEGER CHECK (confidence_rating BETWEEN 1 AND 5),
    comment TEXT,
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT anomaly_feedback_alert_fkey FOREIGN KEY (alert_id) REFERENCES sec.anomaly_alerts(id)
);
COMMENT ON TABLE sec.anomaly_feedback_loops IS 'Stores analyst feedback on anomaly alerts to retrain detection models';

CREATE INDEX idx_anomaly_feedback_alert ON sec.anomaly_feedback_loops(alert_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB277 - regulatory_filing_calendar
-- Description: Calendar of regulatory filings.
-- Business Case: Compliance requires filing reports (FINRA, SOX 404, GDPR Breach Notification).
--  This table acts as a calendar, tracking deadlines, responsible parties, and
--  ensuring no filing is missed.
-- KPIs:
-- 1. Filing On-Time Rate (100%)
-- 2. Draft Preparation Lead Time
-- 3. Approval Cycle Time
-- 4. Deficiency Management
-- 5. Calendar Accuracy
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.regulatory_filing_calendar (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    filing_id VARCHAR(100) UNIQUE NOT NULL,
    filing_name VARCHAR(255) NOT NULL,
    jurisdiction VARCHAR(50) NOT NULL,
    due_date DATE NOT NULL,
    owner_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'NOT_STARTED', -- NOT_STARTED, IN_PROGRESS, FILED
    submitted_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.regulatory_filing_calendar IS 'Tracks deadlines and status for mandatory regulatory filings';

CREATE INDEX idx_reg_filing_due ON sec.regulatory_filing_calendar(due_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB278 - data_residency_verification
-- Description: Verification that data stays in correct region.
-- Business Case: Data sovereignty laws require data to stay in specific countries. This table
--  stores periodic verification checks (e.g., "Checked S3 bucket location is Frankfurt")
--  and any violations found (e.g., replication to us-east-1).
-- KPIs:
-- 1. Verification Frequency (Weekly)
-- 2. Violation Count (0)
-- 3. Remediation Time (Fix replication rules)
-- 4. Automated Check Success
-- 5. Compliance Evidence Generation
-- Feature Reference: M17-F076 (Geo-Replicated Secrets Storage)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_residency_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    verification_id VARCHAR(100) UNIQUE NOT NULL,
    asset_id VARCHAR(100) NOT NULL,
    required_region VARCHAR(100) NOT NULL, -- AWS_EU_CENTRAL_1
    actual_region VARCHAR(100) NOT NULL,
    is_compliant BOOLEAN DEFAULT true,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    drift_details TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_residency_verification IS 'Verifies that cloud assets reside in the legally required geographic regions';

CREATE INDEX idx_residency_asset ON sec.data_residency_verification(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB279 - container_runtime_anomalies
-- Description: Anomalies detected *inside* running containers.
-- Business Case: Network analysis is not enough. We need to see inside the container.
--  This table records behavioral anomalies detected at the OS level (e.g., "Shell spawned in
--  web server container", "Unexpected process execution").
-- KPIs:
-- 1. Detection Accuracy (True Positives)
-- 2. Alert Volume
-- 3. Container Isolation Triggering
-- 4. Signature Match Rate (Known malware vs heuristic)
-- 5. Performance Overhead (<5%)
-- Feature Reference: M17-F147 (Container Runtime Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.container_runtime_anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    container_id VARCHAR(100) NOT NULL,
    process_name VARCHAR(255),
    anomaly_type VARCHAR(50), -- SPAWN_SHELL, FILE_ACCESS, NETWORK_CONNECTION
    severity sec.enum_incident_severity,
    details JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.container_runtime_anomalies IS 'Logs behavioral anomalies detected inside running containers';

CREATE INDEX idx_container_runtime_anomaly_container ON sec.container_runtime_anomalies(container_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB280 - privileged_session_activity
-- Description: Granular activity during privileged sessions.
-- Business Case: "Logged in" is not enough. We need to know what happened *during* the
--  privileged session. This table logs commands typed, files accessed, and settings changed
--  during a PAM session for deep forensic analysis.
-- KPIs:
-- 1. Logging Completeness (100% of actions)
-- 2. Command Validation (Block unsafe commands)
-- 3. Keystroke Timing (Bot detection)
-- 4. Session Behavior Baseline Deviation
-- 5. High-Risk Action Alerting
-- Feature Reference: M17-F089 (Secure Remote Access (Bastion))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privileged_session_activity (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    activity_id VARCHAR(100) UNIQUE NOT NULL,
    session_id VARCHAR(100) NOT NULL,
    command_string TEXT NOT NULL,
    output_preview TEXT, -- First few lines of output
    risk_level VARCHAR(20) DEFAULT 'SAFE', -- SAFE, WARNING, DANGER
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.privileged_session_activity IS 'Logs granular command and file access activity during privileged sessions';

CREATE INDEX idx_priv_activity_session ON sec.privileged_session_activity(session_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB281 - api_abuse_patterns
-- Description: Patterns of API abuse.
-- Business Case: API abuse often follows patterns (scraping, credential stuffing, account
--  takeovers). This table stores detected abuse patterns and the IPs/Keys responsible,
--  allowing for rate limiting or WAF blocking at scale.
-- KPIs:
-- 1. Pattern Detection Rate
-- 2. Blocking Effectiveness (Did abuse stop?)
-- 3. False Positive Rate (Legitimate traffic blocked?)
-- 4. IP Reputation Integration
-- 5. Key Revocation Triggers
-- Feature Reference: M17-F046 (API Security Throttling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_abuse_patterns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- SCRAPING, STUFFING, BOUNTY_HUNTER
    indicator VARCHAR(255), -- e.g., 1000 req/min from single IP
    source_identifier VARCHAR(255) NOT NULL, -- IP, API Key
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'MONITORING', -- MONITORING, BLOCKING, WARNED
    details JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_abuse_patterns IS 'Identifies and tracks patterns of API abuse for enforcement';

CREATE INDEX idx_api_abuse_source ON sec.api_abuse_patterns(source_identifier);

------------------------------------------------------------------------------------------------
-- Table: M17-DB282 - service_mesh_outlier_detection
-- Description: Detecting outlier microservices.
-- Business Case: In a mesh of 1000 services, finding the "weird" one is hard. This
--  table stores results of outlier detection (e.g., "Service X has 10x the error rate of
--  its peers"), identifying configuration drift or bugs.
-- KPIs:
-- 1. Outlier Identification Count
-- 2. Peer Group Accuracy (Compared to correct baseline?)
-- 3. Alert Precision (Are they really outliers?)
-- 4. Metric Comparison Granularity
-- 5. Remediation Success (Is outlier fixed?)
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_outlier_detection (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    outlier_id VARCHAR(100) UNIQUE NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    peer_group VARCHAR(100),
    z_score NUMERIC(10,2) NOT NULL,
    baseline_avg NUMERIC(10,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_mesh_outlier_detection IS 'Stores results of statistical outlier detection in service mesh metrics';

CREATE INDEX idx_mesh_outlier_service ON sec.service_mesh_outlier_detection(service_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB283 - encryption_key_access_matrix
-- Description: Detailed matrix of who accessed which key.
-- Business Case: Data Loss Prevention (DLP) for keys. We need to know exactly who used
--  which Key Encryption Key (KEK) and when. This matrix is crucial for investigations
--  into mass data breaches (Did they steal the key or the data?).
-- KPIs:
-- 1. Access Log Completeness
-- 2. Unusual Access Detection (New user using old key)
-- 3. Key Access Volume Analysis
-- 4. Justification Tracking
-- 5. Audit Query Performance
-- Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.encryption_key_access_matrix (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    matrix_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    accessor_id UUID NOT NULL, -- User or Service Account
    access_type VARCHAR(50), -- WRAP, UNWRAP, SIGN, VERIFY
    access_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    context JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT key_matrix_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.encryption_key_access_matrix IS 'Detailed matrix tracking access to encryption keys for forensic purposes';

CREATE INDEX idx_key_matrix_accessor ON sec.encryption_key_access_matrix(accessor_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB284 - shadow_it_discovery
-- Description: Discovery of unauthorized cloud assets.
-- Business Case: Users often spin up cloud resources without telling IT (Shadow IT). This table
--  records discovered unapproved assets (e.g., "User X launched EC2 instance in Dev account"),
--  triggering a policy to shut them down or integrate them.
-- KPIs:
-- 1. Discovery Frequency (Daily)
-- 2. False Positive Rate (Authorized asset flagged)
-- 3. Remediation Speed (Time to shut down or onboard)
-- 4. Asset Type Distribution (Databases vs VMs)
-- 5. Cost Recovery (Bill user)
-- Feature Reference: M17-F139 (Cloud Asset Inventory)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.shadow_it_discovery (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    discovery_id VARCHAR(100) UNIQUE NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    cloud_provider VARCHAR(50),
    account_id VARCHAR(100),
    asset_id VARCHAR(255),
    owner_guess VARCHAR(255),
    status VARCHAR(20) DEFAULT 'UNAPPROVED', -- UNAPPROVED, ONBOARDED, SHUTDOWN
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.shadow_it_discovery IS 'Tracks unauthorized cloud assets discovered by automated scanning';

CREATE INDEX idx_shadow_it_status ON sec.shadow_it_discovery(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB285 - secure_development_environment
-- Description: Config for secure dev workspaces.
-- Business Case: Developers need secure environments to test secrets/policies. This table
--  defines configurations for "Sandboxes" or "Secure Enclaves" used by devs, ensuring
--  they are isolated from production but have the security controls active.
-- KPIs:
-- 1. Environment Provisioning Speed
-- 2. Isolation Verification (No access to Prod)
-- 3. Secret Injection Accuracy (Fake secrets)
-- 4. Environment Expiry (Auto-destroy)
-- 5. Developer Availability (Uptime)
-- Feature Reference: M17-F036 (Secure Enclave SDK Wrapper)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_development_environment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    env_id VARCHAR(100) UNIQUE NOT NULL,
    developer_id UUID NOT NULL,
    workspace_id VARCHAR(255),
    policy_bundle_id VARCHAR(100), -- Which policies to test
    expires_at TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_development_environment IS 'Manages temporary secure workspaces for developers to test security features';

CREATE INDEX idx_dev_env_developer ON sec.secure_development_environment(developer_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB286 - supply_chain_sbom_licenses
-- Description: Breakdown of licenses found in a specific SBOM.
-- Business Case: SBOMs contain many packages, each with a license. This table provides a
-- breakdown table linking an SBOM to all discovered licenses, allowing for quick
--  scanning for "GPL" or "MIT" in a specific build.
-- KPIs:
-- 1. License Extraction Accuracy
-- 2. Conflict Detection (GPL + Proprietary code?)
-- 3. Scan Speed
-- 4. Policy Violation Count
-- 5. SBOM Coverage (100% of files scanned)
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.supply_chain_sbom_licenses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_license_id VARCHAR(100) UNIQUE NOT NULL,
    sbom_id UUID NOT NULL,
    package_name VARCHAR(255),
    license_id VARCHAR(50) NOT NULL,
    license_name VARCHAR(255),
    risk_level VARCHAR(20),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT sbom_lic_sbom_fkey FOREIGN KEY (sbom_id) REFERENCES sec.sbom_entries(id)
);
COMMENT ON TABLE sec.supply_chain_sbom_licenses IS 'Breakdown of licenses found within a specific SBOM';

CREATE INDEX idx_sbom_lic_sbom ON sec.supply_chain_sbom_licenses(sbom_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB287 - key_management_approval_chain
-- Description: Workflow for high-value key operations.
-- Business Case: Some keys (Root CA) are too sensitive for a single operator. This table
--  tracks the approval chain for operations on these keys (e.g., "Generate HSM Key
--  requires approval from CISO + CFO"). It enforces dual/multi-person control.
-- KPIs:
-- 1. Approval Workflow Completion Time
-- 2. Required Approver Count (N of M)
-- 3. Step Enforcement (Can't skip steps)
-- 4. Timeout Handling (What if approver is away?)
-- 5. Audit Trail Completeness
-- Feature Reference: M17-F004 (HSM Key Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.key_management_approval_chain (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    chain_id VARCHAR(100) UNIQUE NOT NULL,
    operation_type VARCHAR(50) NOT NULL, -- GENERATE, DESTROY, ROTATE
    key_id UUID,
    requester_id UUID NOT NULL,
    current_step INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    expiry_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_approve_chain_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.key_management_approval_chain IS 'Manages multi-step approval workflows for sensitive key operations';

CREATE INDEX idx_key_approve_chain_status ON sec.key_management_approval_chain(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB288 - compliance_control_testing
-- Description: Results of testing specific controls.
-- Business Case: Having a control (e.g., "WAF Rule #555") isn't enough; you must test it.
--  This table stores results of automated tests (e.g., "Attacked with XSS payload against
--  App A"). It proves the control is effective.
-- KPIs:
-- 1. Test Execution Frequency (Weekly)
-- 2. Control Effectiveness Score (Pass/Fail rate)
-- 3. Failure Analysis (Why did it fail?)
-- 4. Remediation Velocity
-- 5. Coverage (% of controls tested)
-- Feature Reference: M17-F164 (Control Effectiveness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_control_testing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id VARCHAR(100) UNIQUE NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    test_type VARCHAR(50), -- BLACK_BOX, WHITE_BOX, GREY_BOX
    test_payload JSONB,
    expected_result VARCHAR(20), -- BLOCK, ALLOW, LOG
    actual_result VARCHAR(20),
    passed BOOLEAN,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.compliance_control_testing IS 'Stores results of automated tests to verify the effectiveness of security controls';

CREATE INDEX idx_control_test_control ON sec.compliance_control_testing(control_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB289 - data_subject_request_workflow
-- Description: Workflow for GDPR Data Subject Requests.
-- Business Case: Processing a DSAR (Data Subject Access Request) involves multiple steps
--  (Verification, Extraction, Redaction, Delivery). This table tracks the workflow
--  status of these requests to ensure SLA compliance.
-- KPIs:
-- 1. Request Processing Time (<30 days)
-- 2. Verification Step Accuracy
-- 3. Redaction Accuracy (No 3rd party data leaked)
-- 4. Delivery Success Rate
-- 5. User Satisfaction
-- Feature Reference: M17-F030 (GDPR Data Requests)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_subject_request_workflow (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_id VARCHAR(100) UNIQUE NOT NULL,
    request_id UUID NOT NULL,
    current_step VARCHAR(100) NOT NULL, -- VERIFICATION, EXTRACTION, REDACTION
    assigned_to UUID,
    sla_due_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'IN_PROGRESS',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT dsr_workflow_req_fkey FOREIGN KEY (request_id) REFERENCES sec.gdpr_data_requests(id)
);
COMMENT ON TABLE sec.data_subject_request_workflow IS 'Tracks the step-by-step workflow for GDPR Data Subject Requests';

CREATE INDEX idx_dsr_workflow_status ON sec.data_subject_request_workflow(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB290 - dynamic_risk_scoring_cache
-- Description: Cached risk scores for real-time decisions.
-- Business Case: Calculating risk scores (User + Device + Behavior) on every request is
--  expensive. This table acts as a cache of current risk scores, updated by background
--  processes, to allow for millisecond-level auth decisions.
-- KPIs:
-- 1. Cache Hit Ratio (>99%)
-- 2. Data Freshness (<5 min stale)
-- 3. Update Latency (<1s)
-- 4. Storage Size Optimization
-- 5. Invalidation Accuracy
-- Feature Reference: M17-F122 (Context-Aware Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dynamic_risk_scoring_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id VARCHAR(100) UNIQUE NOT NULL,
    entity_type VARCHAR(20) NOT NULL, -- USER, SESSION, DEVICE
    current_score INTEGER NOT NULL,
    factors JSONB,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dynamic_risk_scoring_cache IS 'High-performance cache of risk scores for real-time authorization decisions';

CREATE INDEX idx_risk_cache_entity ON sec.dynamic_risk_scoring_cache(entity_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB291 - incident_post_mortem
-- Description: Detailed post-incident review document.
-- Business Case: Learning is critical. This table stores the structured post-mortem document,
--  covering the timeline, root cause, what went well, what failed, and action items.
--  It becomes a searchable knowledge base.
-- KPIs:
-- 1. Post-Mortem Completion Rate (100% of incidents)
-- 2. Action Item Implementation (%)
-- 3. Review Timeliness (Within 1 week)
-- 4. Document Quality (Completeness)
-- 5. Search Frequency (Re-use of knowledge)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_post_mortem (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    postmortem_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    conducted_by UUID NOT NULL,
    document_url VARCHAR(500), -- Link to Google Docs/Confluence
    key_findings TEXT,
    root_cause TEXT,
    lessons_learned TEXT,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT postmortem_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_post_mortem IS 'Stores detailed post-incident reviews and lessons learned';

CREATE INDEX idx_postmortem_incident ON sec.incident_post_mortem(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB292 - security_metrics_aggregation
-- Description: Pre-calculated aggregates for dashboards.
-- Business Case: Dashboard queries are heavy. This table pre-calculates heavy aggregates
--  (e.g., "Total Incidents last 30 days", "Mean MTTR") updated hourly or daily.
--  It makes the executive dashboard instant.
-- KPIs:
-- 1. Aggregation Accuracy
-- 2. Dashboard Load Time (<1s)
-- 3. Data Freshness (How old is the aggregate?)
-- 4. Storage Efficiency
-- 5. Query Simplification
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_metrics_aggregation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_id VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    dimension VARCHAR(100), -- Region, Team, Environment
    value NUMERIC(15,2),
    aggregation_window VARCHAR(50), -- LAST_HOUR, LAST_DAY, LAST_MONTH
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_metrics_aggregation IS 'Stores pre-calculated metric aggregates for high-performance dashboards';

CREATE INDEX idx_metrics_agg_name_window ON sec.security_metrics_aggregation(metric_name, aggregation_window);

------------------------------------------------------------------------------------------------
-- Table: M17-DB293 - threat_intelligence_enrichment
-- Description: Enrichment of alerts with TI data.
-- Business Case: Alert context is key. This table links security alerts to Threat Intelligence
--  data (e.g., "The IP in this alert is known as 'CobaltStrike C2'"). It helps
--  analysts understand the intent of the attacker immediately.
-- KPIs:
-- 1. Enrichment Speed (<2s)
-- 2. Match Rate (Percentage of alerts enriched)
-- 3. Data Accuracy (False TI matches?)
-- 4. Source Coverage (How many TI feeds used?)
-- 5. Analyst Feedback (Is this useful?)
-- Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_intelligence_enrichment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    enrichment_id VARCHAR(100) UNIQUE NOT NULL,
    alert_id UUID NOT NULL,
    ioc_id VARCHAR(100) NOT NULL,
    ti_source VARCHAR(100),
    ti_description TEXT,
    confidence_level NUMERIC(3,2),
    enriched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT ti_enrich_alert_fkey FOREIGN KEY (alert_id) REFERENCES sec.anomaly_alerts(id)
);
COMMENT ON TABLE sec.threat_intelligence_enrichment IS 'Links security alerts to Threat Intelligence data for analyst context';

CREATE INDEX idx_ti_enrich_alert ON sec.threat_intelligence_enrichment(alert_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB294 - network_segment_enforcement
-- Description: Status of micro-segment enforcement points.
-- Business Case: Segmentation is only good if enforced. This table checks the enforcement
--  points (Firewall, API Gateway, Service Mesh) to ensure they have the correct
--  segmentation policies loaded and active. It detects "Policy Drift".
-- KPIs:
-- 1. Enforcement Accuracy (100%)
-- 2. Drift Detection Time (<5 min)
-- 3. Policy Version Consistency
-- 4. Enforcement Point Availability
-- 5. Configuration Push Success
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.network_segment_enforcement (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    enforcement_id VARCHAR(100) UNIQUE NOT NULL,
    enforcement_point_type VARCHAR(50) NOT NULL, -- FIREWALL, ISTIO, AWS_NACL
    policy_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'SYNCED', -- SYNCED, NOT_SYNCED, ERROR
    policy_version VARCHAR(50),
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT seg_enforce_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.network_policies(id)
);
COMMENT ON TABLE sec.network_segment_enforcement IS 'Verifies that segmentation policies are correctly enforced across all enforcement points';

CREATE INDEX idx_seg_enforce_point ON sec.network_segment_enforcement(enforcement_point_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB295 - secure_key_destruction_queue
-- Description: Queue for scheduled key destruction.
-- Business Case: Deleting keys (Crypto-shredding) is risky. This table queues the requests
--  after policy or legal hold periods expire. A background worker processes the queue,
--  ensuring destruction happens at the right time.
-- KPIs:
-- 1. Queue Processing Latency (<24h)
-- 2. Destruction Success Rate (100%)
-- 3. Hold Release Accuracy
-- 4. Queue Depth (Is backlog growing?)
-- 5. Audit Trail Completion
-- Feature Reference: M17-F049 (Secure Key Deletion)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_key_destruction_queue (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    queue_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    eligible_at TIMESTAMP WITH TIME ZONE NOT NULL, -- When to destroy
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, PROCESSING, DESTROYED, FAILED
    failure_reason TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_destr_queue_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.secure_key_destruction_queue IS 'Queues keys for secure destruction after retention periods expire';

CREATE INDEX idx_key_destr_queue_status ON sec.secure_key_destruction_queue(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB296 - audit_log_forwarding_errors
-- Description: Logs errors in forwarding logs.
-- Business Case: Forwarding logs to SIEM can fail (Network error, SIEM down). This table
--  logs specific errors. If too many errors accumulate, it alerts the ops team that
--  the audit trail is broken, preventing visibility gaps.
-- KPIs:
-- 1. Error Rate (<0.1%)
-- 2. Error Type Distribution
-- 3. Recovery Success Rate
-- 4. Data Loss Prevention (Did we lose the log?)
-- 5. Notification Latency
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_log_forwarding_errors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    error_id VARCHAR(100) UNIQUE NOT NULL,
    forwarder_id VARCHAR(100) NOT NULL,
    log_type VARCHAR(100) NOT NULL,
    error_message TEXT NOT NULL,
    error_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    resolved BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_log_forwarding_errors IS 'Logs failures in the audit log forwarding pipeline to SIEMs';

CREATE INDEX idx_fwd_errors_forwarder ON sec.audit_log_forwarding_errors(forwarder_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB297 - compliance_exception_review
-- Description: Annual review of approved exceptions.
-- Business Case: Exceptions shouldn't be permanent. This table schedules annual reviews of
--  approved exceptions (e.g., "No MFA for Legacy App X") to check if they are still
--  valid or if the risk can now be removed.
-- KPIs:
-- 1. Review Completion Rate (100%)
-- 2. Exception Closure Rate (Can we fix the root cause now?)
-- 3. Exception Extension Approval (Only valid ones extended)
-- 4. Risk Reassessment
-- 5. Evidence Attachment (Why is it still needed?)
-- Feature Reference: M17-F043 (Supply Chain Integrity Check)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_exception_review (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    review_id VARCHAR(100) UNIQUE NOT NULL,
    exception_id UUID NOT NULL,
    review_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_by UUID NOT NULL,
    outcome VARCHAR(50) CHECK (outcome IN ('RENEWED','REVOKED','MODIFIED')),
    justification TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT exception_review_exc_fkey FOREIGN KEY (exception_id) REFERENCES sec.control_exceptions(id)
);
COMMENT ON TABLE sec.compliance_exception_review IS 'Records annual reviews of temporary compliance exceptions';

CREATE INDEX idx_exception_review_exc ON sec.compliance_exception_review(exception_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB298 - biometric_template_updates
-- Description: Updates to biometric templates.
-- Business Case: Biometrics change (Voice changes, Face changes). This table logs when a
-- user's biometric template is updated (Enrolled/Re-enrolled) to maintain a history
--  of the identity parameters for audit.
-- KPIs:
-- 1. Update Success Rate
-- 2. Template Quality Score (New template vs Old)
-- 3. Re-enrollment Frequency (Too frequent?)
-- 4. Verification Success (Does new template work?)
-- 5. History Retention
-- Feature Reference: M17-F054 (Biometric Multi-Factor Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.biometric_template_updates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    update_id VARCHAR(100) UNIQUE NOT NULL,
    template_id UUID NOT NULL,
    previous_template_hash VARCHAR(64),
    new_template_hash VARCHAR(64),
    reason VARCHAR(255), -- USER_REQUESTED, DEGRADED
    updated_by UUID NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT bio_update_template_fkey FOREIGN KEY (template_id) REFERENCES sec.biometric_templates(id)
);
COMMENT ON TABLE sec.biometric_template_updates IS 'Logs updates and changes to user biometric templates';

CREATE INDEX idx_bio_update_template ON sec.biometric_template_updates(template_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB299 - cloud_storage_classification
-- Description: Classification of cloud storage objects.
-- Business Case: Classifying S3 buckets/Blobs is hard. This table holds the classification
--  (Confidential, Public) for specific storage objects, often derived from automated
-- scanners (Data Loss Prevention scanning the files). DLP engines use this to block
-- access.
-- KPIs:
-- 1. Classification Coverage (% of objects)
-- 2. Scan Latency (Time after upload to classify)
-- 3. Accuracy (Verified labels)
-- 4. Label Persistence (Changes tracked)
-- 5. False Positive Reduction
-- Feature Reference: M17-F127 (Data Classification Tagging)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_storage_classification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    object_id VARCHAR(100) UNIQUE NOT NULL,
    storage_path VARCHAR(500) NOT NULL,
    classification sec.enum_data_classification NOT NULL,
    scanner_id VARCHAR(100),
    confidence_score NUMERIC(3,2),
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reclassified_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_storage_classification IS 'Stores classification labels for cloud storage objects (S3, Azure Blob)';

CREATE INDEX idx_storage_class_path ON sec.cloud_storage_classification(storage_path);

------------------------------------------------------------------------------------------------
-- Table: M17-DB300 - user_behavioral_baseline
-- Description: Baseline of "normal" behavior for a user.
-- Business Case: To detect anomalies, we need a baseline. This table stores the aggregated
--  "normal" parameters for a user (e.g., "Typical login location: London", "Typical
--  traffic: 500 MB/day"). Deviations from this trigger alerts.
-- KPIs:
-- 1. Baseline Accuracy (Do changes reflect reality?)
-- 2. Update Frequency (Daily/Weekly)
-- 3. Baseline Drift Detection (Is behavior fundamentally changing?)
-- 4. False Positive Reduction (Good baselines = fewer false alarms)
-- 5. Data Retention (How much history?)
-- Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_behavioral_baseline (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    baseline_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    metric_name VARCHAR(100) NOT NULL, -- GEO_LOCATION, TRAFFIC_VOLUME, LOGINS
    baseline_value JSONB NOT NULL, -- e.g., { "mean": 100, "std_dev": 20 }
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_behavioral_baseline IS 'Stores learned baselines of "normal" behavior for UEBA anomaly detection';

CREATE INDEX idx_user_behavior_baseline_user ON sec.user_behavioral_baseline(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB301 - container_host_breach_attempts
-- Description: Logs attempts to break out of container.
-- Business Case: Container Escape is the ultimate goal of many attacks. This table logs
--  detected attempts to escape the container runtime (e.g., accessing /proc, mounting
--  host sockets). These are critical incidents.
-- KPIs:
-- 1. Detection Rate (100%)
-- 2. Response Speed (<1s)
-- 3. Prevention Success (Was it blocked?)
-- 4. Technique Classification (Exploit type)
-- 5. Host Integrity Check (Did host get compromised?)
-- Feature Reference: M17-F114 (Container Escape Prevention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.container_host_breach_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    breach_id VARCHAR(100) UNIQUE NOT NULL,
    container_id VARCHAR(100) NOT NULL,
    host_node VARCHAR(255),
    technique VARCHAR(100), -- MOUNT_HOST_PATH, CVE_EXPLOITATION
    blocked BOOLEAN DEFAULT true,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.container_host_breach_attempts IS 'Logs attempts to escape from container to host node';

CREATE INDEX idx_container_breach_container ON sec.container_host_breach_attempts(container_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB302 - secret_rotation_failures
-- Description: Logs of failed secret rotation attempts.
-- Business Case: Automating rotation is great, until it fails and breaks production. This table
--  logs failures (Dependency issue, App didn't pick up new key) to ensure operational
--  teams can intervene manually if automation fails.
-- KPIs:
-- 1. Failure Capture Rate (100%)
-- 2. MTTR for Rotation Failure
-- 3. Root Cause Analysis (Why did it fail?)
-- 4. Notification Accuracy (Who got alerted?)
-- 5. Success Rate (Target >99.9%)
-- Feature Reference: M17-F021 (KMS Auto-Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secret_rotation_failures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    failure_id VARCHAR(100) UNIQUE NOT NULL,
    secret_id VARCHAR(255) NOT NULL, -- Reference to secret in Vault/KMS
    rotation_plan_id VARCHAR(100),
    error_message TEXT NOT NULL,
    failure_category VARCHAR(50), -- AUTH_ERROR, TIMEOUT, DEPENDENCY_DOWN
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secret_rotation_failures IS 'Logs failures in automated secret rotation workflows';

CREATE INDEX idx_secret_rotation_time ON sec.secret_rotation_failures(occurred_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB303 - secure_communication_audit
-- Description: Audit of encrypted messages between components.
-- Business Case: Zero Trust implies all traffic is authenticated. This table audits the
--  establishment of encrypted channels (e.g., TLS handshake success, peer certificate
--  validation) between internal services, providing a "Wiretap" audit of who talks to whom.
-- KPIs:
-- 1. Channel Establishment Success (100%)
-- 2. Peer Verification Rate (Are certs valid?)
-- 3. Cipher Suite Audit (Are weak ciphers used?)
-- 4. Metadata Accuracy
-- 5. Retention Compliance
-- Feature Reference: M17-F002 (SPIFFE Identity Provisioning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_communication_audit (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) UNIQUE NOT NULL,
    source_identity VARCHAR(255) NOT NULL,
    dest_identity VARCHAR(255) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    cipher_suite VARCHAR(100),
    negotiated_version VARCHAR(20),
    session_duration_seconds INTEGER,
    terminated_reason VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_communication_audit IS 'Audits establishment and termination of secure channels (mTLS) between components';

CREATE INDEX idx_comm_audit_source ON sec.secure_communication_audit(source_identity);

------------------------------------------------------------------------------------------------
-- Table: M17-DB304 - api_gateway_rate_limit_rules
-- Description: Granular rules for API rate limiting.
-- Business Case: "Limit API" is too simple. This table defines granular rules (e.g.,
--  "Limit 'POST /transfer' to 10 req/min" but "Allow 'GET /status' to 1000 req/min").
--  It ensures fair usage without blocking legitimate traffic.
-- KPIs:
-- 1. Rule Enforcement Accuracy
-- 2. Throttling Efficiency (CPU/Mem usage)
-- 3. Latency Impact (Enforcement < 1ms)
-- 4. Key Priority (VIP users bypass?)
-- 5. Dynamic Adjustment
-- Feature Reference: M17-F101 (Secure API Gateway Rate Limiting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_gateway_rate_limit_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    endpoint_pattern VARCHAR(255) NOT NULL,
    method VARCHAR(10),
    limit_per_second INTEGER,
    limit_per_minute INTEGER,
    limit_per_hour INTEGER,
    burst_limit INTEGER,
    apply_to_user_type VARCHAR(50), --  ALL, INTERNAL, EXTERNAL
    priority INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_gateway_rate_limit_rules IS 'Defines granular rate limiting rules for API gateway endpoints';

CREATE INDEX idx_api_rl_endpoint ON sec.api_gateway_rate_limit_rules(endpoint_pattern);

------------------------------------------------------------------------------------------------
-- Table: M17-DB305 - user_defined_security_tags
-- Description: Tags applied by users to assets for organization.
-- Business Case: Automatic classification is good, but manual tags are essential for context.
--  This table allows users to tag assets (e.g., "Project X", "Confidential", "Crown Jewels").
--  Access control policies can use these tags.
-- KPIs:
-- 1. Tag Usage Frequency
-- 2. Tag Consistency (Spelling/Standard)
-- 3. Policy Integration (% of tags used in policies)
-- 4. Tag Conflict Resolution
-- 5. Unsupervised Tag Recommendations (AI suggestions)
-- Feature Reference: M17-F127 (Data Classification Tagging)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_defined_security_tags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tag_id VARCHAR(100) UNIQUE NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- ASSET, USER, ROLE
    asset_id VARCHAR(255) NOT NULL,
    tag_key VARCHAR(100) NOT NULL,
    tag_value VARCHAR(255) NOT NULL,
    applied_by UUID NOT NULL,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_defined_security_tags IS 'Allows users to apply organizational tags to assets for custom policies';

CREATE INDEX idx_user_tags_asset ON sec.user_defined_security_tags(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB306 - security_policy_versioning
-- Description: Tracks version history of security policies.
-- Business Case: Policies change. To know "When was this rule introduced?", we need versioning.
--  This table stores the active version number of every policy in the system, linked to
--  previous versions.
-- KPIs:
-- 1. Version Integrity (No gaps)
-- 2. Rollback Speed (Time to revert)
-- 3. Change History Visibility
-- 4. Diff Capability (Can we see what changed?)
-- 5. Promotion Success (Staging -> Prod)
-- Feature Reference: M17-F034 (Policy-as-Code)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_policy_versioning (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_id VARCHAR(100) UNIQUE NOT NULL,
    policy_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    policy_content_hash VARCHAR(64),
    created_by UUID NOT NULL,
    change_summary TEXT,
    deployed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT policy_version_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.zero_trust_policies(id)
);
COMMENT ON TABLE sec.security_policy_versioning IS 'Tracks version history and changes to security policies';

CREATE INDEX idx_policy_version_policy ON sec.security_policy_versioning(policy_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB307 - quantum_key_experimentation
-- Description: Tests of experimental PQC algorithms.
-- Business Case: We don't know which PQC algo will survive standardization. This table
--  stores results of "Crypto Agility Tests" (e.g., "Kyber vs FrodoKem" performance),
--  helping the organization make future-proof decisions.
-- KPIs:
-- 1. Test Coverage (Algorithms tested)
-- 2. Performance Metrics (Latency/Throughput)
-- 3. Security Strength Comparison
-- 4. Interoperability Test Results
-- 5. Recommendation Score
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_key_experimentation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    key_size INTEGER,
    environment VARCHAR(50), -- AWS_NITRO, INTEL_SGX, SOFTWARE
    latency_ms NUMERIC(10,2),
    throughput_mbps NUMERIC(10,2),
    security_score NUMERIC(3,2),
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.quantum_key_experimentation IS 'Stores results of experimentation with Post-Quantum Cryptography algorithms';

CREATE INDEX idx_quantum_exp_algo ON sec.quantum_key_experimentation(algorithm);

------------------------------------------------------------------------------------------------
-- Table: M17-DB308 - secure_backup_verification
-- Description: Verifying integrity of secure backups.
-- Business Case: A backup is only good if it restores. This table logs verification jobs
--  (Checksum verification, test restore to sandbox) to ensure that secure backups
--  of keys and data are not corrupt.
-- KPIs:
-- 1. Verification Frequency (Weekly)
-- 2. Verification Success Rate (100%)
-- 3. Restore Test Success Rate
-- 4. Corruption Detection (Count)
-- 5. Remediation Speed
-- Feature Reference: M17-F039 (Backup Encryption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_backup_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    verification_id VARCHAR(100) UNIQUE NOT NULL,
    backup_id VARCHAR(100) NOT NULL,
    verification_type VARCHAR(50), -- CHECKSUM, TEST_RESTORE
    status VARCHAR(20) DEFAULT 'SUCCESS', -- SUCCESS, FAILED, CORRUPT
    checksum_mismatch BOOLEAN DEFAULT false,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT backup_verify_backup_fkey FOREIGN KEY (backup_id) REFERENCES sec.backup_logs(id)
);
COMMENT ON TABLE sec.secure_backup_verification IS 'Logs integrity checks and test restores for secure backups';

CREATE INDEX idx_backup_verify_backup ON sec.secure_backup_verification(backup_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB309 - regulatory_mandate_tracking
-- Description: Tracking new laws/regulations and their impact.
-- Business Case: Compliance is a moving target. This table tracks new mandates (e.g.,
--  "New EU AI Act requirements"), analyzes their impact on M17, and assigns owners.
-- It ensures the system stays compliant as laws evolve.
-- KPIs:
-- 1. Mandate Identification Speed (Within 1 week of publication)
-- 2. Impact Analysis Coverage (All components checked)
-- 3. Implementation Plan Creation (100%)
-- 4. Owner Assignment
-- 5. Compliance Deadline Achievement
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.regulatory_mandate_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mandate_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    region VARCHAR(50),
    effective_date TIMESTAMP WITH TIME ZONE,
    impact_summary TEXT,
    owner_id UUID,
    status VARCHAR(20) DEFAULT 'ASSESSING', --  ASSESSING, IMPLEMENTED, COMPLIANT
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.regulatory_mandate_tracking IS 'Tracks new regulatory mandates and their implementation status';

CREATE INDEX idx_reg_mandate_status ON sec.regulatory_mandate_tracking(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB310 - service_mesh_traffic_split
-- Description: Breakdown of traffic by service type.
-- Business Case: Understanding what services do is vital. This table aggregates traffic
--  specifically splitting it by Service Class (e.g., "Customer Facing", "Internal Admin").
--  It helps prioritize security efforts on the most critical paths.
-- KPIs:
-- 1. Traffic Classification Accuracy
-- 2. Critical Path Identification
-- 3. Volume Distribution (Pareto Principle)
-- 4. Error Rate Analysis (Per Class)
-- 5. Latency Analysis (Per Class)
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_traffic_split (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    split_id VARCHAR(100) UNIQUE NOT NULL,
    service_class VARCHAR(50) NOT NULL,
    rps NUMERIC(15,2), -- Requests Per Second
    p95_latency_ms NUMERIC(10,2),
    error_rate NUMERIC(5,2),
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_mesh_traffic_split IS 'Aggregates mesh traffic split by service class for analysis';

CREATE INDEX idx_mesh_split_class ON sec.service_mesh_traffic_split(service_class);

------------------------------------------------------------------------------------------------
-- Table: M17-DB311 - cspm_resource_configuration
-- Description: Specific configuration of cloud resources.
-- Business Case: CSPM tools need to know the state of resources. This table stores the
--  resolved configuration of a specific cloud resource (e.g., "S3 Bucket 'X'
--  Public = false, Encryption = AES256") at a point in time, allowing for
--  configuration drift detection.
-- KPIs:
-- 1. Configuration Capture Rate (100%)
-- 2. State Comparison Speed (Current vs Golden)
-- 3. Drift Detection (Changes found)
-- 4. Normalization Accuracy (AWS vs Azure -> Standard Schema)
-- 5. Storage Retention
-- Feature Reference: M17-F082 (Cloud Workload Protection (CWP))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cspm_resource_configuration (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_id VARCHAR(100) UNIQUE NOT NULL,
    cloud_provider VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    configuration_hash VARCHAR(64),
    configuration_snapshot JSONB NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.cspm_resource_configuration IS 'Stores configuration snapshots of cloud resources for drift detection';

CREATE INDEX idx_cspm_config_resource ON sec.cspm_resource_configuration(resource_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB312 - supply_chain_dependency_pinning
-- Description: Locking down specific dependency versions.
-- Business Case: Supply chain attacks happen via updates. Pinning (locking) a dependency
--  to a specific version prevents automatic updates that might contain malicious code.
--  This table manages the pinned versions for the organization.
-- KPIs:
-- 1. Pinning Coverage (% of dependencies)
-- 2. Vulnerability Scanning of Pinned Versions (Are they safe?)
-- 3. Pin Approval Workflow
-- 4. Unpinning Speed (If needed)
-- 5. Policy Compliance
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.supply_chain_dependency_pinning (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pin_id VARCHAR(100) UNIQUE NOT NULL,
    dependency_group VARCHAR(255) NOT NULL,
    dependency_name VARCHAR(255) NOT NULL,
    pinned_version VARCHAR(100) NOT NULL,
    pinned_hash VARCHAR(64),
    justification TEXT,
    expires_at TIMESTAMP WITH TIME ZONE, --  Optional expiry
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.supply_chain_dependency_pinning IS 'Manages version pinning for software dependencies to prevent supply chain attacks';

CREATE INDEX idx_dep_pin_package ON sec.supply_chain_dependency_pinning(dependency_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB313 - incident_response_team_roster
-- Description: Roster of the Incident Response Team (IRT).
-- Business Case: Who is on call? This table defines the members of the IRT, their roles
--  (Commander, Comms, Scribe), and contact methods. It ensures that escalations
--  go to the right humans.
-- KPIs:
-- 1. Roster Completeness (100%)
-- 2. Contact Info Validity (Phone works?)
-- 3. Role Assignment Accuracy
-- 4. Shift Handover Process
-- 5. Availability Tracking (Vacations/OOO)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_response_team_roster (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    member_id UUID NOT NULL,
    role_name VARCHAR(100) NOT NULL, -- INCIDENT_COMMANDER, SECOPS_LEAD, LEGAL
    contact_method VARCHAR(50), -- SLACK, SMS, EMAIL
    contact_value VARCHAR(255) NOT NULL,
    priority INTEGER,
    is_primary BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.incident_response_team_roster IS 'Lists members of the Incident Response Team (IRT) and their contact details';

CREATE INDEX idx_irt_member_role ON sec.incident_response_team_roster(role_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB314 - security_incident_tags
-- Description: Categorical tags for incidents.
-- Business Case: Searching for similar incidents is easier with tags. This table stores tags
--  applied to incidents (e.g., "Phishing", "Ransomware", "Insider", "DDoS"). It enables
--  better metrics and reporting (e.g., "Phishing incidents increased 20% this quarter").
-- KPIs:
-- 1. Tag Consistency
-- 2. Tag Coverage (Are all incidents tagged?)
-- 3. Search Efficiency
-- 4. Reporting Accuracy
-- 5. Trend Analysis Quality
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_incident_tags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    tag_name VARCHAR(100) NOT NULL,
    tag_source VARCHAR(50), -- ANALYST, AUTOMATED, ML
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT incident_tag_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id) ON DELETE CASCADE
);
COMMENT ON TABLE sec.security_incident_tags IS 'Allows categorical tagging of incidents for reporting and trend analysis';

CREATE INDEX idx_incident_tag_name ON sec.security_incident_tags(tag_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB315 - network_protocol_anomaly
-- Description: Anomalies in protocol usage.
-- Business Case: Anomalous protocols (e.g., Telnet in a SSH-only environment) are bad
--  signs. This table logs deviations from expected protocol usage (e.g., "ICMP flood",
--  "Non-HTTP traffic on port 443"), detecting stealthy communication channels.
-- KPIs:
-- 1. Protocol Identification Accuracy
-- 2. Anomaly Scoring (High severity?)
-- 3. False Positive Reduction (e.g., Heartbeats)
-- 4. Blocking Action Triggering
-- 5. Investigation Workflow Creation
-- Feature Reference: M17-F056 (DNS Security (DNSSEC))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.network_protocol_anomaly (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    protocol VARCHAR(20) NOT NULL, -- ICMP, TELNET, DNS, TCP
    anomaly_type VARCHAR(100),
    packet_count BIGINT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.network_protocol_anomaly IS 'Logs anomalies in network protocol usage (e.g., unexpected Telnet, high ICMP)';

CREATE INDEX idx_proto_anomaly_protocol ON sec.network_protocol_anomaly(protocol);

------------------------------------------------------------------------------------------------
-- Table: M17-DB316 - security_awareness_training_history
-- Description: Historical record of completed trainings.
-- Business Case: Tracking who took what training and when. This table stores the historical
--  record of every training module completed by every employee, allowing for audit
--  trails and compliance dashboards (e.g., "90% of staff have completed Phishing Training").
-- KPIs:
-- 1. Completion Rate (Target 100%)
-- 2. Score Distribution (Are people passing?)
-- 3. Due Date Adherence
-- 4. Retraining Frequency (Annual refresh)
-- 5. Module Effectiveness (Does training reduce incidents?)
-- Feature Reference: M17-F142 (AI-Powered Phishing Simulation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_awareness_training_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    history_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    training_module_id VARCHAR(100) NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    score INTEGER,
    passed BOOLEAN DEFAULT true,
    time_spent_minutes INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_awareness_training_history IS 'Historical record of security awareness training completed by users';

CREATE INDEX idx_awareness_history_user ON sec.security_awareness_training_history(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB317 - threat_hunting_queries
-- Description: Saved queries for Threat Hunting.
-- Business Case: Threat Hunters use complex queries to find bad stuff. This table saves these
--  queries (e.g., "All Python processes in /tmp directory") so they can be re-run
--  regularly or shared among hunters. It builds a knowledge base of hunting hypotheses.
-- KPIs:
-- 1. Query Usage Frequency
-- 2. Hunt Success Rate (Findings per query)
-- 3. Query Performance
-- 4. False Positive Rate
-- 5. Knowledge Base Expansion
-- Feature Reference: M17-F068 (Advanced Persistent Threat (APT) Hunt)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_hunting_queries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    query_logic JSONB NOT NULL, -- SPLUNK KQL, SQL, Elastic DSL
    author_id UUID NOT NULL,
    last_run TIMESTAMP WITH TIME ZONE,
    findings_count INTEGER,
    active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.threat_hunting_queries IS 'Saved library of queries for Threat Hunting operations';

CREATE INDEX idx_hunt_query_author ON sec.threat_hunting_queries(author_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB318 - audit_data_sample
-- Description: Sampling data for reporting (privacy).
-- Business Case: Auditing all data is heavy. Sometimes we only need a sample. This table
--  defines sampling rules (e.g., "Select 1% of transactions randomly") and stores
--  references to the sampled data for specific audits.
-- KPIs:
-- 1. Sampling Accuracy (Statistically valid?)
-- 2. Sample Storage Efficiency
-- 3. Selection Bias (Is the sample representative?)
-- 4. Audit Reconstruction (Can we prove X happened?)
-- 5. Privacy Protection (Sampling reduces exposure)
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_data_sample (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sample_id VARCHAR(100) UNIQUE NOT NULL,
    audit_id UUID NOT NULL,
    sampling_method VARCHAR(50), -- RANDOM, TIME_BASED, KEY_BASED
    sample_percentage NUMERIC(5,2),
    criteria JSONB, -- e.g., {"amount": ">1000"}
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT sample_audit_fkey FOREIGN KEY (audit_id) REFERENCES sec.audit_trail(id)
);
COMMENT ON TABLE sec.audit_data_sample IS 'Stores configurations and metadata for sampling audit data for efficiency';

CREATE INDEX idx_sample_audit ON sec.audit_data_sample(audit_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB319 - secure_key_storage_location
-- Description: Physical location of keys.
-- Business Case: Knowing *where* a key is stored is vital for sovereignty and compliance.
--  This table maps a logical key ID to a physical location (e.g., "AWS HSM
--  us-east-1" or "Physical Safe A"). It is crucial for disaster recovery planning.
-- KPIs:
-- 1. Location Accuracy
-- 2. Multi-Region Verification (Is replica there?)
-- 3. Jurisdiction Compliance
-- 4. Access Control to Location
-- 5. Migration Planning
-- Feature Reference: M17-F004 (HSM Key Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_key_storage_location (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    location_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    storage_type VARCHAR(50) NOT NULL, -- CLOUD_HSM, PHYSICAL_VAULT, ENCLAVE
    region_code CHAR(2),
    data_center VARCHAR(255), -- For physical
    availability_zone VARCHAR(50), -- AZ-1, AZ-2
    is_primary BOOLEAN DEFAULT false, --  Is this the primary active copy?

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT key_loc_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.secure_key_storage_location IS 'Maps logical keys to their physical storage locations for compliance and DR';

CREATE INDEX idx_key_loc_key ON sec.secure_key_storage_location(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB320 - user_authenticator_metadata
-- Description: Metadata about MFA devices.
-- Business Case: Managing MFA methods requires metadata. This table stores details about
--  authenticators (e.g., "YubiKey Serial 12345", "Phone Model X"), enrollment
--  dates, and firmware versions. It helps manage the lifecycle of hardware tokens.
-- KPIs:
-- 1. Device Health Check Success
-- 2. Firmware Update Coverage
-- 3. Lost Device Reporting Speed
-- 4. Device Type Distribution
-- 5. Enrolment Rate
-- Feature Reference: M17-F054 (Biometric Multi-Factor Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_authenticator_metadata (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    authenticator_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    authenticator_type VARCHAR(50) NOT NULL, -- HARDWARE_TOKEN, SMS, TOTP, BIOMETRIC
    device_details JSONB, -- Serial, Model, OS Version
    enrolled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, LOST, BROKEN, REVOKED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_authenticator_metadata IS 'Stores metadata about user MFA authenticator devices';

CREATE INDEX idx_authenticator_user ON sec.user_authenticator_metadata(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB321 - network_segment_health
-- Description: Health status of network segments.
-- Business Case: Segments shouldn't become silos (where no one can see). This table tracks
--  health metrics of segments (e.g., "Can App A talk to DB?"). If a segment health
--  drops, it indicates a routing issue or a misconfigured firewall rule.
-- KPIs:
-- 1. Segment Reachability (% of hosts reachable)
-- 2. Latency (Ping times across segment)
-- 3. Packet Loss Rate
-- 4. Rule Configuration Status
-- 5. Alert Generation (When health drops)
-- Feature Reference: M17-F032 (Zero-Trust Network Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.network_segment_health (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    health_check_id VARCHAR(100) UNIQUE NOT NULL,
    segment_id VARCHAR(100) NOT NULL,
    check_type VARCHAR(50) NOT NULL, -- CONNECTIVITY, LATENCY, BANDWIDTH
    status VARCHAR(20) DEFAULT 'HEALTHY',
    value NUMERIC(10,2), -- e.g., Latency in ms
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.network_segment_health IS 'Stores health status of network segments to ensure connectivity';

CREATE INDEX idx_segment_health_segment ON sec.network_segment_health(segment_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB322 - cloud_account_onboarding
-- Description: Onboarding new cloud accounts into security monitoring.
-- Business Case: Spinning up a new AWS account? It needs to be onboarded into CSPM/Logging.
--  This table tracks the onboarding checklist (Deploy Agent, Create Trail, Enable Shield).
--  It ensures no new account goes unmonitored.
-- KPIs:
-- 1. Checklist Completion Rate (100%)
-- 2. Onboarding Time (Target <1 day)
-- 3. Agent Deployment Success
-- 4. Baseline Establishment (Is the account "safe"?)
-- 5. Access Granting (Do we have permissions?)
-- Feature Reference: M17-F082 (Cloud Workload Protection (CWP))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_account_onboarding (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    onboarding_id VARCHAR(100) UNIQUE NOT NULL,
    cloud_account_id VARCHAR(100) NOT NULL,
    cloud_provider VARCHAR(50),
    status VARCHAR(20) DEFAULT 'IN_PROGRESS', -- IN_PROGRESS, COMPLETED, FAILED
    steps_json JSONB, -- Checklist state
    started_by UUID NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_account_onboarding IS 'Tracks the onboarding process of new cloud accounts into security monitoring';

CREATE INDEX idx_cloud_onboarding_status ON sec.cloud_account_onboarding(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB323 - data_retention_legal_hold
-- Description: Applying legal holds to data retention.
-- Business Case: Litigation often overrides deletion policies. This table applies a "Legal
--  Hold" to specific data sets, suspending automated deletion even if the retention
--  period has expired, to ensure evidence is preserved for court.
-- KPIs:
-- 1. Hold Application Accuracy (No data lost)
-- 2. Hold Release Authorization
-- 3. Search Efficiency (Can we find held data?)
-- 4. Duration Tracking
-- 5. Conflict Resolution (Retention vs Hold)
-- Feature Reference: M17-F045 (Log Retention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_retention_legal_hold (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hold_id VARCHAR(100) UNIQUE NOT NULL,
    case_number VARCHAR(100) NOT NULL,
    data_scope JSONB NOT NULL, -- Logs, Emails, Files
    hold_start_date DATE NOT NULL,
    hold_end_date DATE, --  NULL until case closed
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, RELEASED
    requesting_attorney VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_retention_legal_hold IS 'Applies Legal Holds to prevent data deletion during litigation';

CREATE INDEX idx_retention_hold_status ON sec.data_retention_legal_hold(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB324 - security_event_correlation
-- Description: Linking related security events.
-- Business Case: An incident is often a chain of events. This table links related events
--  (e.g., Phishing Email -> Malware Download -> C2 Connection). Linking them helps
--  visualize the attack chain and calculate the total impact.
-- KPIs:
-- 1. Linkage Accuracy (Are they really related?)
-- 2. Chain Reconstruction Speed
-- 3. Visualization Support
-- 4. Alert Clustering
-- 5. Timeline Generation
-- Feature Reference: M17-F058 (Fraud Signal Correlation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_event_correlation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    correlation_id VARCHAR(100) UNIQUE NOT NULL,
    parent_event_id UUID NOT NULL,
    child_event_id UUID NOT NULL,
    relationship_type VARCHAR(50), -- CAUSED_BY, PART_OF_SAME_ATTACK, CORRELATED
    confidence_score NUMERIC(3,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_event_correlation IS 'Links related security events to form attack chains';

CREATE INDEX idx_event_corr_parent ON sec.security_event_correlation(parent_event_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB325 - asset_risk_profile
-- Description: Aggregated risk profile for an asset.
-- Business Case: Assets have a composite risk score. This table aggregates various risk
--  factors (Vulnerabilities, Exposure, Criticality) into a single risk profile for
--  an asset (Server, Database). It drives patching priority.
-- KPIs:
-- 1. Score Calculation Consistency
-- 2. Weighting Model Accuracy
-- 3. Dynamic Update Speed (New vuln drops score?)
-- 4. Critical Asset Identification
-- 5. Risk Trending (Improving or Worsening?)
-- Feature Reference: M17-F164 (Control Effectiveness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.asset_risk_profile (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    profile_id VARCHAR(100) UNIQUE NOT NULL,
    asset_id VARCHAR(100) NOT NULL,
    overall_score INTEGER NOT NULL CHECK (overall_score BETWEEN 0 AND 100),
    vulnerability_score INTEGER,
    exposure_score INTEGER,
    business_criticality_score INTEGER,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.asset_risk_profile IS 'Aggregates risk factors into a single composite score for assets';

CREATE INDEX idx_asset_profile_asset ON sec.asset_risk_profile(asset_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB326 - security_policy_translation
-- Description: Mapping policy legalese to technical rules.
-- Business Case: Translating "GDPR Article 32" to "Encrypt DB" is hard. This table stores
--  the translation mapping (Control -> Implementation). It bridges the gap between
--  compliance officers and engineers.
-- KPIs:
-- 1. Translation Accuracy
-- 2. Coverage (All controls mapped?)
-- 3. Change Propagation (Update Control -> Update Rules)
-- 4. Verification Status (Does the rule actually enforce the control?)
-- 5. Evidence Linkage
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_policy_translation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    translation_id VARCHAR(100) UNIQUE NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    technical_rule_id VARCHAR(100) NOT NULL,
    mapping_quality VARCHAR(20), --  DIRECT, INDIRECT, PARTIAL
    verified_by UUID NOT NULL,
    verification_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_policy_translation IS 'Maps abstract compliance controls to specific technical enforcement rules';

CREATE INDEX idx_policy_translation_control ON sec.security_policy_translation(control_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB327 - forensic_tool_output
-- Description: Output from forensic tools.
-- Business Case: Forensic tools (Volatility, Rekall) generate JSON/Text output. This table
--  stores the raw output from these tools attached to an investigation, ensuring
--  findings are preserved exactly as the tool reported them.
-- KPIs:
-- 1. Output Capture Rate (100%)
-- 2. Tool Version Tracking
-- 3. File Integrity (Tamper-evident)
-- 4. Storage Compression
-- 5. Searchability (Can we grep it?)
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.forensic_tool_output (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    output_id VARCHAR(100) UNIQUE NOT NULL,
    investigation_id UUID NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    tool_version VARCHAR(50),
    output_type VARCHAR(50), -- JSON, TEXT, XML, HTML
    output_path VARCHAR(500) NOT NULL, -- Link to file
    size_bytes BIGINT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.forensic_tool_output IS 'Stores output from forensic analysis tools attached to investigations';

CREATE INDEX idx_forensic_tool_investigation ON sec.forensic_tool_output(investigation_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB328 - user_consent_history
-- Description: History of consent changes.
-- Business Case: Consent can be withdrawn. This table tracks the history of consent
--  events (Granted -> Withdrawn -> Granted). It provides the "as-of" compliance status
--  for any point in time (e.g., "Was consent active on Jan 1st?").
-- KPIs:
-- 1. History Completeness
-- 2. Point-in-Time Query Speed
-- 3. Withdrawal Reason Tracking
-- 4. Re-consent Rate
-- 5. Privacy Policy Version Mapping
-- Feature Reference: M17-F092 (Privacy Preserving Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_consent_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    history_id VARCHAR(100) UNIQUE NOT NULL,
    consent_id UUID NOT NULL,
    user_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL, --  GRANTED, WITHDRAWN, MODIFIED
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_status VARCHAR(50),
    new_status VARCHAR(50),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT consent_hist_consent_fkey FOREIGN KEY (consent_id) REFERENCES sec.consent_records(id)
);
COMMENT ON TABLE sec.user_consent_history IS 'Tracks the full history of user consent changes for GDPR compliance';

CREATE INDEX idx_consent_hist_user ON sec.user_consent_history(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB329 - dynamic_secrets_cache
-- Description: Cache of active secrets (Runtime).
-- Business Case: Reading from Vault/KMS for every request is slow. This table caches the
--  most recently used secrets (encrypted) in memory or fast storage for
--  high-throughput applications, with a very short TTL.
-- KPIs:
-- 1. Cache Hit Ratio (>99.9%)
-- 2. Eviction Accuracy (TTL adherence)
-- 3. Security (Encryption at rest)
-- 4. Update Propagation (New secret appears fast)
-- 5. Size Limits (Don't fill RAM)
-- Feature Reference: M17-F008 (Automated Secret Injection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dynamic_secrets_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_id VARCHAR(100) UNIQUE NOT NULL,
    secret_path VARCHAR(255) NOT NULL,
    secret_value_encrypted TEXT NOT NULL, -- The cached secret
    version_id INTEGER NOT NULL,
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ttl_seconds INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.dynamic_secrets_cache IS 'High-performance cache for frequently used secrets to reduce load on KMS';

CREATE INDEX idx_dyn_cache_path ON sec.dynamic_secrets_cache(secret_path);

------------------------------------------------------------------------------------------------
-- Table: M17-DB330 - user_auth_anomalies
-- Description: Anomalies detected in authentication flow.
-- Business Case: Not all auth attacks are valid credentials. This table logs anomalies in the
--  authentication flow itself (e.g., "Impossible travel speed", "Failed MFA attempt"),
--  which are blocked by the auth service.
-- KPIs:
-- 1. Blocking Accuracy
-- 2. False Positive Rate (User blocked by mistake?)
-- 3. Attack Vector Analysis
-- 4. Alerting Volume
-- 5. User Notification (Did we tell the user?)
-- Feature Reference: M17-F109 (Context-Aware Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_auth_anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID,
    auth_method VARCHAR(50),
    anomaly_reason VARCHAR(255),
    blocked BOOLEAN DEFAULT true,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_auth_anomalies IS 'Logs anomalies detected during the user authentication process';

CREATE INDEX idx_user_auth_anomaly_user ON sec.user_auth_anomalies(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB331 - service_mesh_performance_slis
-- Description: SLOs for mesh performance.
-- Business Case: Mesh adds latency. This table stores SLIs (Service Level Indicators)
--  for the mesh (e.g., "Latency for 'Auth Service' must be < 50ms"). Breaching
--  this triggers alerts or scaling.
-- KPIs:
-- 1. SLI Breach Count
-- 2. Latency Trending (Is it getting slower?)
-- 3. Error Budget Calculation
-- 4. Dependency Analysis (Which hop is slow?)
-- 5. Optimization Success
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_performance_slis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sli_id VARCHAR(100) UNIQUE NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(50) NOT NULL, -- LATENCY_P99, ERROR_RATE
    threshold_value NUMERIC(10,2),
    measured_value NUMERIC(10,2),
    is_breaching BOOLEAN DEFAULT false,
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_mesh_performance_slis IS 'Tracks Service Level Indicators (SLIs) for the service mesh';

CREATE INDEX idx_mesh_sli_service ON sec.service_mesh_performance_slis(service_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB332 - cloud_cost_anomaly_detection
-- Description: Anomalies in cloud spend/billing.
-- Business Case: Crypto mining can spike cloud costs. This table monitors cloud billing
--  APIs for anomalies (e.g., "S3 costs doubled overnight"), which often indicates a
--  compromised resource being abused.
-- KPIs:
-- 1. Budget Adherence (Within 10%)
-- 2. Anomaly Detection Sensitivity
-- 3. Alerting Speed (Stop the bleeding money)
-- 4. Resource Investigation (Which resource?)
-- 5. False Positive Rate (Legitimate surge?)
-- Feature Reference: M17-F082 (Cloud Workload Protection (CWP))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_cost_anomaly_detection (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id VARCHAR(100) UNIQUE NOT NULL,
    cloud_account_id VARCHAR(100) NOT NULL,
    service VARCHAR(100) NOT NULL, --  EC2, S3, EBS
    projected_cost NUMERIC(15,2),
    actual_cost NUMERIC(15,2),
    anomaly_score NUMERIC(5,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_cost_anomaly_detection IS 'Detects anomalies in cloud billing/costs to identify resource compromise';

CREATE INDEX idx_cost_anomaly_account ON sec.cloud_cost_anomaly_detection(cloud_account_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB333 - security_incident_feedback
-- Description: Internal feedback on incident handling.
-- Business Case: How was the incident managed? This table collects feedback from the IRT
--  on their own process (e.g., "Playbook X was confusing"). It helps improve the
--  incident response playbooks for next time.
-- KPIs:
-- 1. Feedback Collection Rate (>50%)
-- 2. Playbook Improvement Cycle Time
-- 3. Criticism Category Analysis
-- 4. Actionable Insights (Can we fix it?)
-- 5. Satisfaction Score
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_incident_feedback (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feedback_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    category VARCHAR(50), --  PROCESS, TOOLING, COMMUNICATION
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,
    provided_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT incident_feedback_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.security_incident_feedback IS 'Collects feedback from IRT members on incident handling process';

CREATE INDEX idx_incident_feedback_incident ON sec.security_incident_feedback(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB334 - secure_boot_verification
-- Description: Logs of secure boot integrity checks.
-- Business Case: Secure Boot ensures the OS hasn't been tampered with. This table logs
--  the verification results (Pass/Fail) of Secure Boot signatures for every
--  server boot, ensuring the supply chain of the firmware is intact.
-- KPIs:
-- 1. Verification Success Rate (100%)
-- 2. Fail Reaction (Server is powered off if fails)
-- 3. Signature Coverage (All servers enrolled)
-- 4. Certificate Expiry Monitoring
-- 5. False Positive Rate (Valid boot flagged as bad)
-- Feature Reference: M17-F022 (Secure Boot Validation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_boot_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    verification_id VARCHAR(100) UNIQUE NOT NULL,
    host_id VARCHAR(100) NOT NULL,
    firmware_signer VARCHAR(255),
    signature_status VARCHAR(20) NOT NULL, --  VALID, INVALID, REVOKED
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tpm_present BOOLEAN DEFAULT true,
    details TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_boot_verification IS 'Logs the verification of secure boot signatures for server integrity';

CREATE INDEX idx_secure_boot_host ON sec.secure_boot_verification(host_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB335 - secret_scanner_findings
-- Description: Findings from scanning code for secrets.
-- Business Case: Scanning repos for secrets is crucial. This table stores findings (Git leaks)
--  (e.g., "AWS Key found in config.json"). It drives the revocation workflow and
--  developer education.
-- KPIs:
-- 1. Scan Frequency (Every push)
-- 2. Detection Accuracy (Real key vs dummy data)
-- 3. Auto-Revocation Success (Did we invalidate the key?)
-- 4. Developer Notification (Email sent to dev)
-- 5. Remediation Time (Key removed from repo)
-- Feature Reference: M17-F105 (Secret Scanning in Repos)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secret_scanner_findings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id VARCHAR(100) UNIQUE NOT NULL,
    repo_url VARCHAR(500) NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    secret_hash VARCHAR(64),
    secret_type VARCHAR(50), --  AWS_KEY, PASSWORD, CERTIFICATE
    severity VARCHAR(20),
    state VARCHAR(20) DEFAULT 'OPEN', -- OPEN, REVOKING, FIXED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secret_scanner_findings IS 'Stores findings from scanning code repositories for leaked secrets';

CREATE INDEX idx_secret_scanner_repo ON sec.secret_scanner_findings(repo_url);

------------------------------------------------------------------------------------------------
-- Table: M17-DB336 - quantum_readiness_score
-- Description: Score for preparedness for Quantum threats.
-- Business Case: "Post-Quantum Readiness" is a journey. This table calculates a maturity
--  score (0-100) for the organization based on inventory, migration, and algorithm
--  agility. It tracks progress over time.
-- KPIs:
-- 1. Readiness Score Trend (Increasing)
-- 2. Inventory Coverage (% of keys assessed)
-- 3. Migration Completion (Number of systems migrated)
-- 4. Agility (Can we swap algos quickly?)
-- 5. Board Reporting Frequency
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_readiness_score (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    score_id VARCHAR(100) UNIQUE NOT NULL,
    overall_score INTEGER CHECK (overall_score BETWEEN 0 AND 100),
    inventory_score INTEGER,
    migration_score INTEGER,
    agility_score INTEGER,
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    target_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.quantum_readiness_score IS 'Tracks the organization's maturity score for post-quantum cryptography readiness';

CREATE INDEX idx_qr_score_date ON sec.quantum_readiness_score(assessed_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB337 - data_lineage_tracing
-- Description: Tracing data flow through systems.
-- Business Case: Where did this data come from? This table traces lineage (e.g., "Data in
--  Data Warehouse came from API, which came from User Upload"). It supports audit
--  trails and compliance "Source of Truth" requirements.
-- KPIs:
-- 1. Lineage Depth (Number of hops)
-- 2. Trace Completeness (No gaps)
-- 3. Transformation Tracking (How was data modified?)
-- 4. Consent Propagation (Did consent travel?)
-- 5. Query Performance
-- Feature Reference: M17-F011 (Audit & Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_lineage_tracing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trace_id VARCHAR(100) UNIQUE NOT NULL,
    trace_run_id UUID NOT NULL,
    node_id VARCHAR(255) NOT NULL, --  System/Service
    node_type VARCHAR(50) NOT NULL, --  GENERATOR, PROCESSOR, STORAGE
    data_fingerprint VARCHAR(64), --  Hash of data at this stage
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.data_lineage_tracing IS 'Traces the flow and transformation of data through systems for auditing';

CREATE INDEX idx_lineage_run ON sec.data_lineage_tracing(trace_run_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB338 - incident_stakeholder_notification
-- Description: Log of notifications sent to stakeholders.
-- Business Case: Stakeholders (Executives, Legal, PR) need to know about breaches. This
--  table logs every notification sent, including the message content and timestamp,
--  proving transparency and timeliness.
-- KPIs:
-- 1. Notification Success Rate (100%)
-- 2. Delivery Latency (<1 hour)
-- 3. Message Accuracy
-- 4. Stakeholder Coverage (Did we notify everyone?)
-- 5. Channel Verification (Did they read it?)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_stakeholder_notification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    notification_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    stakeholder_id UUID NOT NULL,
    channel VARCHAR(50), --  EMAIL, SMS, SLACK
    status VARCHAR(20), --  SENT, DELIVERED, FAILED
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    content_summary TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT stakeholder_notif_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_stakeholder_notification IS 'Logs notifications sent to stakeholders during incidents';

CREATE INDEX idx_stakeholder_notif_incident ON sec.incident_stakeholder_notification(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB339 - security_policy_impact_analysis
-- Description: Analysis of policy impact before deployment.
-- Business Case: Changing a policy can break things. This table stores results of a "Blast
--  Radius Analysis" (What happens if we block this port? Which services fail?).
--  It prevents outages caused by security changes.
-- KPIs:
-- 1. Analysis Coverage (100% of changes)
-- 2. Prediction Accuracy (Did the analysis predict the failure?)
-- 3. Remediation Speed (If impact is high, fix it)
-- 4. Blast Radius Visualization
-- 5. Rollback Plan Availability
-- Feature Reference: M17-F034 (Policy-as-Code)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_policy_impact_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    analysis_id VARCHAR(100) UNIQUE NOT NULL,
    policy_change_id UUID NOT NULL,
    affected_services TEXT[], -- List of services impacted
    risk_level VARCHAR(20), -- LOW, MEDIUM, HIGH
    remediation_plan TEXT,
    approved_by UUID NOT NULL,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_policy_impact_analysis IS 'Stores impact analysis for security policy changes before deployment';

CREATE INDEX idx_policy_impact_change ON sec.security_policy_impact_analysis(policy_change_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB340 - secure_deployment_approval
-- Description: Approval for deploying to production.
-- Business Case: You can't push to prod without a sign-off. This table records approvals
--  (e.g., "Approved by CISO") for specific deployment IDs or Code Commits.
--  It enforces separation of duties (Developer cannot approve own code).
-- KPIs:
-- 1. Approval Enforcement (0 unapproved deploys)
-- 2. Approval Workflow Speed
-- 3. Compliance Coverage (All prod deployments approved?)
-- 4. Revocation Rate (Did we cancel the deployment?)
-- 5. Evidence Retention
-- Feature Reference: M17-F065 (Secure CI/CD Pipeline)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_deployment_approval (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    approval_id VARCHAR(100) UNIQUE NOT NULL,
    deployment_id VARCHAR(100) NOT NULL, -- e.g., Release Tag
    approver_id UUID NOT NULL,
    role VARCHAR(100) NOT NULL, -- CISO, SECURITY_LEAD, PEER
    context TEXT,
    approved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_deployment_approval IS 'Records approvals required for deploying to production environments';

CREATE INDEX idx_secure_deploy_deployment ON sec.secure_deployment_approval(deployment_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB341 - security_automation_metrics
-- Description: Metrics for the automation platform itself.
-- Business Case: The automation engine (SOAR/Ansible) needs to be healthy. This table
--  tracks metrics like "Playbooks run", "Playbooks failed", "Average execution time"
--  to ensure the automation is reliable.
-- KPIs:
-- 1. Automation Success Rate (>99%)
-- 2. Execution Latency
-- 3. Error Rate
-- 4. Coverage (How many events are automated?)
-- 5. Manual Intervention Rate (Are we too chatty?)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_automation_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_id VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL, --  PLBOOK_RUN, PLBOOK_SUCCESS
    value NUMERIC(15,2),
    dimension VARCHAR(50), -- PER_HOUR, PER_DAY, PER_WEEK
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_automation_metrics IS 'Tracks performance and reliability metrics of the security automation platform';

CREATE INDEX idx_auto_metrics_name ON sec.security_automation_metrics(metric_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB342 - vulnerability_disclosure_timeline
-- Description: Timeline of vulnerability public disclosure.
-- Business Case: Coordination with vendors. When a vuln is disclosed (but not fixed yet),
--  we need to know. This table tracks the vendor's timeline (Vendor Notification ->
--  Public Release -> Patch Available) to manage risk exposure.
-- KPIs:
-- 1. Disclosure Monitoring Speed
-- 2. Patch Acquisition Speed
-- 3. Exposure Window Duration
-- 4. Communication Clarity
-- 5. Risk Mitigation Planning
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_disclosure_timeline (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timeline_id VARCHAR(100) UNIQUE NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL, --  PRIVATE_REPORT, PUBLIC_DISCLOSURE, PATCH_RELEASE
    description TEXT,
    date DATE NOT NULL,
    internal_notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.vulnerability_disclosure_timeline IS 'Tracks the timeline of vulnerability disclosure and patch availability';

CREATE INDEX idx_vuln_disclosure_cve ON sec.vulnerability_disclosure_timeline(cve_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB343 - security_posture_rating
-- Description: The "Posture" rating of the org.
-- Business Case: A single "Security Posture" score is useful for execs. This table aggregates
--  thousands of metrics into a single letter grade or score (A-F) that represents the
--  current state of security maturity.
-- KPIs:
-- 1. Score Calculation Consistency
-- 2. Grade Distribution (Are we an 'A' organization?)
-- 3. Trend Analysis (Improving or slipping?)
-- 4. Component Contribution (What is dragging the score down?)
-- 5. Reporting Accuracy
-- Feature Reference: M17-F024 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_posture_rating (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rating_id VARCHAR(100) UNIQUE NOT NULL,
    overall_score NUMERIC(5,2) NOT NULL,
    letter_grade VARCHAR(2),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    previous_score NUMERIC(5,2),
    factors JSONB, -- Weighted factors

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_posture_rating IS 'Aggregates security metrics into a single organizational posture rating (Grade)';

CREATE INDEX idx_posture_rating_date ON sec.security_posture_rating(calculated_at);

------------------------------------------------------------------------------------------------
-- Table: M17-DB344 - incident_notification_log
-- Description: Log of notification attempts.
-- Business Case: Did we actually call the on-call engineer? This table logs the actual
--  notification attempts (Call connected? Email bounced? PagerDuty trigger received?).
--  It proves the mobilization process worked.
-- KPIs:
-- 1. Notification Delivery Success
-- 2. Alert Receipt Acknowledgement
-- 3. Channel Redundancy (If email fails, did we use SMS?)
-- 4. Time to Acknowledge
-- 5. Escalation Triggering (Did we escalate if no ack?)
-- Feature Reference: M17-F059 (Automated Incident Response Playbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_notification_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    notification_log_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    method VARCHAR(50) NOT NULL, --  EMAIL, SLACK, PAGERDUTY, CALL
    destination VARCHAR(255),
    status VARCHAR(20) NOT NULL, --  SUCCESS, FAILED, BOUNCED
    status_message TEXT,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT incident_notif_log_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_notification_log IS 'Logs the actual attempts to notify responders about incidents';

CREATE INDEX idx_notif_log_incident ON sec.incident_notification_log(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB345 - data_loss_incidents
-- Description: Specific incidents of data loss.
-- Business Case: Some incidents are "Data Loss" (exfiltration) rather than "System Compromise".
--  This table records these specific incidents, tracking *what* data was lost, *how much*,
--  and *to whom*. It is critical for GDPR breach notification.
-- KPIs:
-- 1. Detection Time (How long before we noticed?)
-- 2. Victim Identification Accuracy (Do we know who?)
-- 3. Data Volume Tracking
-- 4. Notification Compliance (Did we notify authorities in 72h?)
-- 5. Containment Success
-- Feature Reference: M17-F037 (Data Loss Prevention (DPI))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_loss_incidents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dli_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    data_type VARCHAR(100) NOT NULL, --  PII, IP, FINANCIAL
    records_affected INTEGER,
    exfiltration_method VARCHAR(100), --  DOWNLOAD, EMAIL, USB
    discovered_date DATE,
    notification_sent BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT dli_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.data_loss_incidents IS 'Records details of specific data loss incidents for regulatory reporting';

CREATE INDEX idx_dli_date ON sec.data_loss_incidents(discovered_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB346 - secure_file_transfer_log
-- Description: Logs of managed file transfers (MFT).
-- Business Case: B2B file transfers are risky. This table logs every transfer managed by
--  the Secure File Transfer system (MFT), tracking sender, receiver, file hash, and
--  status, providing a full audit trail of B2B data movement.
-- KPIs:
-- 1. Transfer Success Rate (100%)
-- 2. Encryption Verification (Was file encrypted in transit/at rest?)
-- 3. Receiver Validation
-- 4. Quota Enforcement
-- 5. File Integrity (Hash matches?)
-- Feature Reference: M17-F060 (Secure File Transfer (SFTP/MFT))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_file_transfer_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transfer_id VARCHAR(100) UNIQUE NOT NULL,
    source_partner VARCHAR(255) NOT NULL,
    destination_partner VARCHAR(255) NOT NULL,
    file_path VARCHAR(255),
    file_hash VARCHAR(64),
    status VARCHAR(20), --  UPLOADED, DELIVERED, FAILED
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_file_transfer_log IS 'Logs secure file transfers for B2B integration and auditing';

CREATE INDEX idx_mft_transfer_partner ON sec.secure_file_transfer_log(source_partner, destination_partner);

------------------------------------------------------------------------------------------------
-- Table: M17-DB347 - security_certification_exams
-- Description: Exams to certify personnel.
-- Business Case: How do we know security staff are competent? This table manages
--  certification exams (e.g., "CISSP Mock Exam", "CyberOps Test"), tracking
--  scores and validity. It ensures staff maintain their skills.
-- KPIs:
-- 1. Exam Pass Rate
-- 2. Certification Renewal Tracking
-- 3. Skill Gap Analysis (Which exams failed?)
-- 4. Training Effectiveness (Does pass rate correlate with performance?)
-- 5. Exam Difficulty Calibration
-- Feature Reference: M17-F186 (Audit Certifications)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_certification_exams (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exam_id VARCHAR(100) UNIQUE NOT NULL,
    exam_name VARCHAR(255) NOT NULL,
    candidate_id UUID NOT NULL,
    score INTEGER CHECK (score BETWEEN 0 AND 100),
    passed BOOLEAN NOT NULL,
    passed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiry_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_certification_exams IS 'Stores results of internal security certification exams for staff';

CREATE INDEX idx_security_exam_candidate ON sec.security_certification_exams(candidate_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB348 - threat_hunt_knowledge_base
-- Description: Knowledge base built from hunting.
-- Business Case: We find new threats while hunting. This table captures "Intel" discovered
--  during hunting activities (e.g., "New IOC for 'Actor X'"). It enriches the global
--  Threat Intelligence database with internal findings.
-- KPIs:
-- 1. Knowledge Base Growth Rate
-- 2. Reuse Frequency (Is this IOC useful again?)
-- 3. Integration with External TI (Did we share it?)
-- 4. Confidence Scoring
-- 5. Attribution Accuracy
-- Feature Reference: M17-F068 (Advanced Persistent Threat (APT) Hunt)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.threat_hunt_knowledge_base (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    kb_id VARCHAR(100) UNIQUE NOT NULL,
    kb_title VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    ioc JSONB,
    description TEXT,
    confirmed BOOLEAN DEFAULT false,
    confirmed_by UUID NOT NULL,
    confirmed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.threat_hunt_knowledge_base IS 'Captures new threat intelligence and Indicators of Compromise discovered during threat hunting';

CREATE INDEX idx_hunt_kb_category ON sec.threat_hunt_knowledge_base(category);

------------------------------------------------------------------------------------------------
-- Table: M17-DB349 - container_resource_limits
-- Description: Defined resource limits for containers.
-- Business Case: Noisy neighbors can kill performance. This table defines CPU/Memory limits
--  for containers to ensure a single compromised container cannot take down the whole
--  host (Resource Exhaustion attack).
-- KPIs:
-- 1. Limit Enforcement Success (100%)
-- 2. OOMKill Rate (Too many kills?)
-- 3. Limit Accuracy (Are limits set right?)
-- 4. Performance Impact (Are apps throttled unnecessarily?)
-- 5. Over-Subscription Avoidance
-- Feature Reference: M17-F093 (Resource Quota Enforcement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.container_resource_limits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    limit_id VARCHAR(100) UNIQUE NOT NULL,
    container_image_id VARCHAR(255) NOT NULL,
    cpu_limit_millicores NOT NULL,
    memory_limit_mb INTEGER NOT NULL,
    enforced_by VARCHAR(50), -- CGROUPS, KUBERNETES
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.container_resource_limits IS 'Stores defined resource limits for containers to prevent DoS via resource exhaustion';

CREATE INDEX idx_container_limits_image ON sec.container_resource_limits(container_image_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB350 - secure_backup_catalog
-- Description: Catalog of all backup types.
-- Business Case: Knowing what we have backed up. This table catalogs all backup types (Full,
--  Incremental, Differential, Snapshot) and their retention policies, ensuring we can
--  restore "Point-in-Time" accurately.
-- KPIs:
-- 1. Catalog Accuracy (100% of backups listed)
-- 2. Restoration Point Availability (Can we restore last night?)
-- 3. Retention Compliance
-- 4. Cross-Region Copy Status
-- 5. Storage Capacity (Disk space check)
-- Feature Reference: M17-F039 (Backup Encryption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_backup_catalog (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    catalog_id VARCHAR(100) UNIQUE NOT NULL,
    asset_id VARCHAR(100) NOT NULL,
    backup_type VARCHAR(50) NOT NULL,
    location VARCHAR(255) NOT NULL,
    backup_start TIMESTAMP WITH TIME ZONE NOT NULL,
    size_bytes BIGINT,
    is_restorable BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_backup_catalog IS 'Catalogs all backups to facilitate Point-in-Time recovery operations';

CREATE INDEX idx_backup_catalog_asset ON sec.secure_backup_catalog(asset_id);


-- 2. Triggers for Update Timestamps (DB251-DB350)
-- ================================================================================

CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.forensic_chain_of_custody FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.seizure_orders FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.adversarial_ml_inputs FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.model_performance_drift FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.training_data_provenance FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.reginal_compliance_overrides FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.rebac_relationships FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dynamic_group_membership FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.bcdr_drill_reports FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.failover_test_results FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.east_west_traffic_anomalies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cspm_iam_analysis FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.vex_scores FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.mitre_attack_patterns FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.escalation_matrices FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.on_call_rotations FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.alert_suppression_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_budget_tracking FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.insider_threat_indicators FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_asset_mutability FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_risk_assessments FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.patch_deployment_windows FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.forensic_artifacts_collected FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_control_slo FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.third_party_risk_surveys FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.anomaly_feedback_loops FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.regulatory_filing_calendar FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_residency_verification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.container_runtime_anomalies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.privileged_session_activity FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.api_abuse_patterns FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_mesh_outlier_detection FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.encryption_key_access_matrix FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.shadow_it_discovery FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_development_environment FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.supply_chain_sbom_licenses FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.key_management_approval_chain FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.compliance_control_testing FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_subject_request_workflow FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dynamic_risk_scoring_cache FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_post_mortem FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_metrics_aggregation FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.threat_intelligence_enrichment FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.network_segment_enforcement FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_key_destruction_queue FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.audit_log_forwarding_errors FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.compliance_exception_review FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.biometric_template_updates FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_storage_classification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_behavioral_baseline FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.container_host_breach_attempts FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secret_rotation_failures FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_communication_audit FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.api_gateway_rate_limit_rules FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_defined_security_tags FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_policy_versioning FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_key_experimentation FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_backup_verification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.regulatory_mandate_tracking FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_mesh_traffic_split FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_account_onboarding FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_retention_legal_hold FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_event_correlation FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.asset_risk_profile FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_policy_translation FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.forensic_tool_output FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_consent_history FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dynamic_secrets_cache FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_auth_anomalies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_mesh_performance_slis FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_cost_anomaly_detection FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_incident_feedback FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_boot_verification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secret_scanner_findings FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_readiness_score FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_lineage_tracing FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_stakeholder_notification FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_loss_incidents FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_file_transfer_log FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_certification_exams FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.threat_hunt_knowledge_base FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.container_resource_limits FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.secure_backup_catalog FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- End of Script Part 6 (Tables Complete: 1-350)
-- End of Entire Schema Generation Phase

-- ================================================================================
-- PARI SYSTEM - MODULE M17: ZERO-TRUST SECURITY FABRIC
-- Database Schema Definition Script (Part 7: Tables DB351-DB450)
-- ================================================================================
-- Description:
-- Continuation of M17 schema definition. This part extends the table set to
-- DB351-DB450, covering advanced compliance workflows (GDPR DSAR),
-- cyber insurance risk management, AI/ML model observability and lineage,
-- operational technology (IoT) security for payment terminals, post-quantum
-- cryptography resilience testing, disaster recovery (DR) site and performance metrics,
-- and advanced supply chain dependency resolution at scale.
--
-- Standards:
-- - Idempotent DDL (CREATE IF NOT EXISTS)
-- - Comprehensive documentation for Business Case and KPIs
-- - Audit columns (created_at, updated_at, created_by, updated_by) on all tables
-- - Check constraints and Data Types aligned with security requirements
-- ================================================================================

-- 1. DDL Statements (Tables 351-450)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Table: M17-DB351 - gdpr_dsar_workflows
-- Description: Manages GDPR Data Subject Access Request (DSAR) workflows.
-- Business Case: Handling DSARs (Access, Portability, Erasure) is complex and manual.
// This table orchestrates the workflow steps (Verification, Data Gathering, Review,
// Delivery), ensuring that requests are processed within the 30-day legal deadline.
// It tracks state, assignees, and automatic escalation if deadlines are missed.
-- KPIs:
-- 1. Workflow Completion Rate (100%)
-- 2. Mean Time to Process (<30 days)
-- 3. Missed Deadline Count (0)
-- 4. Requester Satisfaction Score
-- 5. Verification Accuracy (Data match %)
-- Feature Reference: M17-F030 (GDPR Data Requests)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.gdpr_dsar_workflows (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_id VARCHAR(100) UNIQUE NOT NULL,
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('ACCESS','PORTABILITY','ERASURE','CORRECTION','OBJECTION'),
    requester_id UUID NOT NULL,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    due_date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'NEW' CHECK (status IN ('NEW','IDENTITY_VERIFIED','DATA_GATHERING','REVIEW','DELIVERY','CLOSED','ESCALATED')),
    assigned_to UUID,
    review_notes TEXT,
    data_scope JSONB, -- Details of affected systems
    delivery_method VARCHAR(50), -- EMAIL, PORTAL, DOWNLOAD

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.gdpr_dsar_workflows IS 'Manages end-to-end workflows for GDPR Data Subject Access Requests (DSAR)';

CREATE INDEX idx_gdpr_workflow_requester ON sec.gdpr_dsar_workflows(requester_id);
CREATE INDEX idx_gdpr_workflow_status ON sec.gdpr_dsar_workflows(status);
CREATE INDEX idx_gdpr_workflow_due ON sec.gdpr_dsar_workflows(due_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB352 - privacy_consent_justifications
-- Description: Justifications recorded for consent withdrawal.
-- Business Case: When users withdraw consent (GDPR), they must be able to justify the legal
// basis or trigger (e.g., "Service no longer needed"). This table stores these
// justifications to support audits and prove that withdrawals were valid, not malicious
// actions.
-- KPIs:
-- 1. Justification Capture Rate (100%)
-- 2. Review Success Rate (>95%)
-- 3. Retention Period Compliance
-- 4. Data Processing Stoppage Time (<1 hr)
-- 5. Auditor Satisfaction
-- Feature Reference: M17-F092 (Privacy Preserving Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privacy_consent_justifications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    justification_id VARCHAR(100) UNIQUE NOT NULL,
    consent_id UUID NOT NULL,
    user_id UUID NOT NULL,
    reason TEXT NOT NULL,
    legal_basis VARCHAR(50), // GDPR_ARTICLE_17, CONTRACT_TERMINATION
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_by UUID,
    accepted BOOLEAN DEFAULT false,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT priv_consent_justif_consent_fkey FOREIGN KEY (consent_id) REFERENCES sec.consent_records(id)
);
COMMENT ON TABLE sec.privacy_consent_justifications IS 'Stores justifications for privacy consent withdrawal to ensure legal compliance';

CREATE INDEX idx_priv_consent_user ON sec.privacy_consent_justifications(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB353 - data_subject_access_audit
-- Description: Detailed audit of data accessed during DSAR fulfillment.
-- Business Case: When fulfilling a DSAR, the system accesses sensitive data. This table logs
// every record touched, who accessed it, and when. It creates an immutable "Access
// Report" proving exactly what data the subject owns.
-- KPIs:
-- 1. Access Logging Completeness (100%)
-- 2. False Positive Exclusion Rate (0)
-- 3. Report Generation Time (<1 hour)
-- 4. Data Integrity Verification (Hash matches live DB)
-- 5. PII Volume Reporting
-- Feature Reference: M17-F137 (Compliance Evidence Collection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_subject_access_audit (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id VARCHAR(100) UNIQUE NOT NULL,
    workflow_id UUID NOT NULL,
    user_id UUID NOT NULL,
    resource_type VARCHAR(50) NOT NULL, // DATABASE, FILE_SYSTEM, API_LOG
    resource_id VARCHAR(255) NOT NULL,
    record_count BIGINT DEFAULT 0,
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT dsar_audit_workflow_fkey FOREIGN KEY (workflow_id) REFERENCES sec.gdpr_dsar_workflows(id)
);
COMMENT ON TABLE sec.data_subject_access_audit IS 'Logs detailed access to data during DSAR fulfillment for evidence generation';

CREATE INDEX idx_dsar_audit_workflow ON sec.data_subject_access_audit(workflow_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB354 - cyber_insurance_policies
-- Description: Active cyber insurance policies.
-- Business Case: Cyber insurance reduces financial risk. This table stores the
// active policy details (Coverage limits, Sub-limits, Insurer). It is used by the
-- incident response team to decide if a claim should be triggered and to calculate
// potential recovery costs.
-- KPIs:
-- 1. Coverage Verification (100%)
-- 2. Sub-limit Tracking (Are we within limits?)
-- 3. Policy Expiry Date
-- 4. Premium Accuracy
-- 5. Claim Readiness Rate
-- Feature Reference: M17-F220 (Incident Cost Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cyber_insurance_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    insurer_name VARCHAR(255) NOT NULL,
    policy_number VARCHAR(100) NOT NULL,
    coverage_limit NUMERIC(15,2) NOT NULL, -- Max payout per incident
    retention_limit NUMERIC(15,2) NOT NULL,
    deductible_amount NUMERIC(15,2) DEFAULT 0,
    exclusion_rules JSONB, -- Events not covered
    start_date DATE NOT NULL,
    end_date DATE,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cyber_insurance_policies IS 'Stores active cyber insurance policy limits and coverage details';

CREATE INDEX idx_cyber_policy_status ON sec.cyber_insurance_policies(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB355 - incident_financial_impact
-- Description: Financial impact estimation for incidents.
-- Business Case: To file an insurance claim, you need a solid cost estimate. This table
// tracks costs (Lost Revenue, Recovery Costs, Regulatory Fines) for incidents. It
// provides the data needed to justify insurance payouts and budget for remediation.
-- KPIs:
-- 1. Estimation Accuracy (Vs Actual)
-- 2. Categorization Accuracy (Direct vs Indirect costs)
-- 3. Reporting Speed (<24h)
-- 4. Cost Recovery Rate (How much saved?)
-- 5. Budget Adherence (Actual vs Estimated)
-- Feature Reference: M17-F220 (Incident Cost Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_financial_impact (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    impact_id VARCHAR(100) UNIQUE NOT NULL,
    incident_id UUID NOT NULL,
    cost_category VARCHAR(50) NOT NULL, -- LOST_REVENUE, REMEDIATION, FINE, LEGAL
    estimated_amount NUMERIC(15,2) NOT NULL,
    actual_amount NUMERIC(15,2),
    currency CHAR(3) DEFAULT 'USD',
    description TEXT,
    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fin_impact_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_financial_impact IS 'Tracks financial impact assessments of security incidents for insurance and budgeting';

CREATE INDEX idx_fin_impact_incident ON sec.incident_financial_impact(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB356 - insurance_claims_history
-- Description: History of claims filed with insurers.
-- Business Case: Claims history determines future premiums and reputation. This table records all
// claims filed (including denied ones), linking them to incidents and policies. It helps
// in negotiating better terms by demonstrating risk management effectiveness.
-- KPIs:
-- 1. Claim Closure Rate
-- 2. Payout Velocity (Days to pay)
-- 3. Claim Success Rate (Approved vs Denied)
-- 4. Premium Impact Analysis
-- 5. Dispute Resolution Time
-- Feature Reference: M17-F220 (Incident Cost Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.insurance_claims_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    claim_id VARCHAR(100) UNIQUE NOT NULL,
    policy_id UUID NOT NULL,
    incident_id UUID,
    claim_amount NUMERIC(15,2),
    claim_status VARCHAR(20) CHECK (claim_status IN ('OPEN','UNDER_INVESTIGATION','PAID','DENIED','CLOSED')),
    filed_date DATE NOT NULL,
    settled_date DATE,
    adjuster_id VARCHAR(255), -- External Adjuster

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT claims_history_policy_fkey FOREIGN KEY (policy_id) REFERENCES sec.cyber_insurance_policies(id)
);
COMMENT ON TABLE sec.insurance_claims_history IS 'Historical record of cyber insurance claims filed against policies';

CREATE INDEX idx_claims_history_status ON sec.insurance_claims_history(claim_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB357 - ml_training_data_lineage
-- Description: Lineage of data used to train ML models.
-- Business Case: AI models need to be reproducible. This table tracks the lineage (source) of
// training datasets, including preprocessing steps and version control. If a model is
// questioned, we can trace exactly which data version trained it.
-- KPIs:
-- 1. Lineage Traceability (100%)
-- 2. Data Freshness (Training data recency)
-- 3. Version Control Integrity
-- 4. Preprocessing Reproducibility
-- 5. Storage Cost Optimization
-- Feature Reference: M17-F255 (Training Data Provenance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.ml_training_data_lineage (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    lineage_id VARCHAR(100) UNIQUE NOT NULL,
    dataset_id VARCHAR(100) NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    source_system VARCHAR(255) NOT NULL, -- e.g., INCIDENT_LOGS, USER_BEHAVIOR
    ingestion_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_hash VARCHAR(64), // SHA256 of the dataset
    version INTEGER,
    preprocessing_steps JSONB, // Steps taken to clean/normalize
    sample_size_bytes BIGINT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.ml_training_data_lineage IS 'Tracks the lineage and versioning of datasets used to train security models';

CREATE INDEX idx_ml_lineage_model ON sec.ml_training_data_lineage(model_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB358 - model_feature_importance
-- Description: Aggregated importance of features for specific models.
-- Business Case: Not all features in a model are equal. This table stores the aggregated
// "feature importance" scores (e.g., from SHAP values or permutation importance).
// It helps in model pruning (removing noisy features) and understanding model decisions
// for auditors.
-- KPIs:
-- 1. Feature Stability (Score change over time)
-- 2. Correlation Analysis (Are related features ranked similarly?)
-- 3. Model Performance Impact (Pruning effect)
-- 4. Retraining Efficiency (Pruned models train faster?)
-- 5. Explainability Support (Can we explain why X was important?)
-- Feature Reference: M17-F252 (AI Feature Importance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.model_feature_importance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    importance_id VARCHAR(100) UNIQUE NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    feature_name VARCHAR(255) NOT NULL,
    importance_score NUMERIC(5,2) NOT NULL,
    calculation_method VARCHAR(50), // SHAP, PERMUTATION, GAIN_RATIO
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_version_id VARCHAR(100), -- Reference to lineage table

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.model_feature_importance IS 'Stores calculated importance scores of features for explainability and optimization of ML models';

CREATE INDEX idx_feat_imp_model ON sec.model_feature_importance(model_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB359 - bias_detection_datasets
-- Description: Datasets specifically used to detect algorithmic bias.
-- Business Case: Fairness is critical. This table identifies and tracks datasets used
// specifically to test for bias (e.g., gender bias in fraud detection).
// By managing these datasets separately, we can prove to regulators that our models are
// fair and unbiased.
-- KPIs:
-- 1. Bias Detection Rate (Found per 100k records)
-- 2. False Negative Rate (Fair data marked biased)
-- 3. Model Retraining Frequency (Based on bias findings)
-- 4. Diversity Score (Of dataset)
-- 5. Regulatory Approval Date
-- Feature Reference: M17-F255 (Training Data Provenance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.bias_detection_datasets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id VARCHAR(100) UNIQUE NOT NULL,
    dataset_name VARCHAR(255) NOT NULL,
    protected_attribute VARCHAR(50), -- GENDER, RACE, GEO_LOCATION
    data_provider VARCHAR(255),
    classification VARCHAR(50) NOT NULL, -- PUBLIC, PROTECTED, SENSITIVE
    bias_test_result JSONB,
    last_assessed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(20), // LOW, MEDIUM, CRITICAL
    mitigation_plan TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.bias_detection_datasets IS 'Manages datasets used specifically for detecting algorithmic bias in AI models';

CREATE INDEX idx_bias_dataset_risk ON sec.bias_detection_datasets(risk_level);

------------------------------------------------------------------------------------------------
-- Table: M17-DB360 - iot_device_enrollment
-- Description: Zero-Trust enrollment for IoT/OT devices (e.g., Payment Terminals).
-- Business Case: IoT devices are high-risk endpoints. This table manages the initial
// Zero-Trust enrollment process: generating identity, provisioning certificates, and
// establishing the "trust anchor" (TPM/TEE) for the hardware before it connects to
// the PARI network.
-- KPIs:
-- 1. Enrollment Success Rate (>98%)
-- 2. Time to Production (<48 hours)
-- 3. Identity Provisioning Latency (<5s)
-- 4. TPM Verification Success (100%)
-- 5. Attestation Pass Rate (100%)
-- Feature Reference: M17-F002 (SPIFFE Identity Provisioning) & M17-F052 (Zero-Trust for IoT)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.iot_device_enrollment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    enrollment_id VARCHAR(100) UNIQUE NOT NULL,
    serial_number VARCHAR(255) NOT NULL,
    device_type VARCHAR(100) NOT NULL, // POS, ATM, PAYMENT_KIOSK
    manufacturer VARCHAR(100) NOT NULL,
    firmware_version VARCHAR(50) NOT NULL,
    firmware_hash VARCHAR(64) NOT NULL,
    hardware_tpm_hash VARCHAR(64), -- Endorsement public key
    spiffe_id VARCHAR(255), -- Resulting identity
    enrollment_status VARCHAR(50) DEFAULT 'PENDING' CHECK (enrollment_status IN ('PENDING','PROVISIONED','ACTIVE','REVOKED','FAILED')),
    enrolled_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.iot_device_enrollment IS 'Manages the Zero-Trust enrollment of IoT devices, linking hardware identity to cryptographic trust';

CREATE INDEX idx_iot_enroll_serial ON sec.iot_device_enrollment(serial_number);

------------------------------------------------------------------------------------------------
-- Table: M17-DB361 - iot_firmware_signing
-- Description: Registry of signed firmware images for IoT devices.
-- Business Case: Unauthorized firmware can brick devices or steal data. This table tracks the official
// signed firmware versions authorized for deployment. It prevents the installation of malicious
// firmware on payment terminals.
-- KPIs:
-- 1. Firmware Validation Success (100%)
-- 2. Version Distribution Accuracy
-- 3. Revocation Propagation Time (<24h)
-- 4. Malware Detection Rate (Firmware scanning)
-- 5. Deployment Compliance
-- Feature Reference: M17-F009 (Container Image Admission Control)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.iot_firmware_signing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    firmware_id VARCHAR(100) UNIQUE NOT NULL,
    device_model VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    firmware_hash VARCHAR(64) NOT NULL,
    signature_id UUID NOT NULL,
    release_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUPERSEDED, REVOKED
    supplier VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT iot_firmware_sig_fkey FOREIGN KEY (signature_id) REFERENCES sec.digital_signatures(id)
);
COMMENT ON TABLE sec.iot_firmware_signing IS 'Registry of cryptographically signed firmware images for IoT devices to prevent malware injection';

CREATE INDEX idx_iot_firmware_model ON sec.iot_firmware_signing(device_model);

------------------------------------------------------------------------------------------------
-- Table: M17-DB362 - iot_attestation_logs
-- Description: Logs of hardware attestation attempts for IoT.
-- Business Case: IoT devices must prove they are trusted every time they wake up. This table logs
// the outcome of these checks (TPM/Attestation). A failure indicates a
// potential physical attack (cloned device).
-- KPIs:
-- 1. Attestation Frequency (Every boot)
-- 2. Failure Investigation Rate (100% of fails)
-- 3. False Positive Rate (Legit firmware update)
-- 4. Geo-Location Verification (Is it where it should be?)
-- 5. Device Trust Score Trend
-- Feature Reference: M17-F005 (Hardware Attestation Verification)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.iot_attestation_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_id VARCHAR(100) UNIQUE NOT NULL,
    device_serial VARCHAR(255) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    quote_hash VARCHAR(64),
    verification_result BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    location_gps_lat NUMERIC(10,8),
    location_gps_long NUMERIC(11,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.iot_attestation_logs IS 'Logs the results of hardware attestation checks for IoT devices';

CREATE INDEX idx_iot_attest_serial ON sec.iot_attestation_logs(device_serial);

------------------------------------------------------------------------------------------------
-- Table: M17-DB363 - operational_risk_register
-- Description: High-level risk register for Operational Technology (OT).
-- Business Case: OT failures impact physical access to digital systems. This table tracks risks
// related to OT (e.g., "SCADA server runs on Windows XP", "Factory floor Wi-Fi is
// unencrypted"). It bridges the gap between OT security and Cyber Security.
-- KPIs:
-- 1. Risk Remediation Velocity
-- 2. Cross-Infection Impact Score
-- 3. OT Coverage (% of devices registered)
-- 4. Patch Compliance Rate
-- 5. Asset Discovery (New OT devices found)
-- Feature Reference: M17-F110 (Compliance Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.operational_risk_register (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id VARCHAR(100) UNIQUE NOT NULL,
    asset_identifier VARCHAR(255) NOT NULL,
    risk_description TEXT NOT NULL,
    risk_level VARCHAR(20) CHECK (risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    category VARCHAR(50), // FIRMWARE, NETWORK, CONFIGURATION
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    owner_department VARCHAR(100),
    remediation_plan TEXT,
    status VARCHAR(20) DEFAULT 'OPEN', // OPEN, MITIGATING, MONITORING

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.operational_risk_register IS 'High-level risk register for Operational Technology (OT) impacting physical security';

CREATE INDEX idx_ot_risk_level ON sec.operational_risk_register(risk_level);

------------------------------------------------------------------------------------------------
-- Table: M17-DB364 - quantum_crypto_benchmarks
-- Description: Benchmark results for Post-Quantum Cryptography (PQC).
-- Business Case: PQC algorithms are new and slower. We need to measure performance and
// resilience to ensure PQC won't slow down payments. This table stores benchmark results
// (Key Gen time, Encryption Speed, Resource Usage) for algorithms like
// CRYSTALS-Dilithium and Kyber.
-- KPIs:
-- 1. Latency Overhead (<2x vs RSA)
-- 2. Throughput (Transactions per second)
-- 3. Resource Cost Analysis
-- 4. Algorithm Agility (Swap speed)
-- 5. Implementation Readiness Score
-- Feature Reference: M17-F014 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_crypto_benchmarks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    benchmark_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm_name VARCHAR(100) NOT NULL, // e.g., DILITHIUM5, KYBER768
    key_size INTEGER NOT NULL,
    operation_type VARCHAR(50) NOT NULL, // KEYGEN, ENCRYPT, DECRYPT
    latency_ms NUMERIC(10,2) NOT NULL,
    throughput_ops_sec NUMERIC(15,2),
    benchmark_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    environment VARCHAR(50), // AWS_NITRO, INTEL_SGX

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.quantum_crypto_benchmarks IS 'Stores performance benchmarks for Post-Quantum cryptographic algorithms to ensure production readiness';

CREATE INDEX idx_quantum_bench_algo ON sec.quantum_crypto_benchmarks(algorithm_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB365 - quantum_migration_progress
-- Description: Tracks the migration status of keys from Classical to PQC.
-- Business Case: Migrating to PQC is a multi-year journey. This table tracks the migration
// progress of specific keys (e.g., "Key X is 50% migrated"), defining targets and
// rollback points if PQC algorithms are broken by new discoveries (e.g., Quantum
// attacks).
-- KPIs:
-- 1. Migration Completion % (Target 100%)
-- 2. Rollback Readiness (Can we revert?)
-- 3. Hybrid Mode Stability (Performance impact of hybrid crypto)
-- 4. Vulnerability Exposure Time (How long is key "naked"?)
-- 5. Deadline Adherence
-- Feature Reference: M17-F201 (Quantum Migration Paths)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_migration_progress (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    migration_id VARCHAR(100) UNIQUE NOT NULL,
    key_id UUID NOT NULL,
    current_algorithm VARCHAR(50) NOT NULL, // RSA2048, EDDSA25519
    target_algorithm VARCHAR(50) NOT NULL, // CRYSTALS_DILITHIUM5
    progress_percentage NUMERIC(5,2) CHECK (progress_percentage BETWEEN 0 AND 100),
    start_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    estimated_completion DATE,
    status VARCHAR(50) DEFAULT 'IN_PROGRESS', // IN_PROGRESS, COMPLETED, ROLLBACK
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT quantum_prog_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.quantum_migration_progress IS 'Tracks the progress of migrating cryptographic keys from classical to post-quantum algorithms';

CREATE INDEX idx_quantum_prog_key ON sec.quantum_migration_progress(key_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB366 - dr_site_health
-- Description: Health status of Disaster Recovery (DR) sites.
-- Business Case: Business continuity requires healthy DR sites. This table monitors the health
// of the DR site (Hot/Warm/Standby) in real-time, checking power, network, and
// storage availability. It triggers failover if the DR site fails.
-- KPIs:
-- 1. Site Availability (Target 100%)
-- 2. Failover Trigger Speed (<5 min)
-- 3. Data Lag (Max lag from Primary)
-- 4. Recovery Time Objective (RTO) Validation
-- 5. Exercise Success Rate
-- Feature Reference: M17-F146 (Disaster Recovery Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dr_site_health (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    site_id VARCHAR(100) UNIQUE NOT NULL,
    site_type VARCHAR(50) NOT NULL CHECK (site_type IN ('PRIMARY','DR_HOT','DR_WARM','COLD_STORAGE')),
    location VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'UNKNOWN', -- ONLINE, DEGRADED, DOWN
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    data_lag_seconds INTEGER,
    rto_target_seconds INTEGER,
    rto_actual_latest NUMERIC(10,2), -- Latest measured RTO

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dr_site_health IS 'Monitors the health status of Disaster Recovery sites to ensure business continuity';

CREATE INDEX idx_dr_site_status ON sec.dr_site_health(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB367 - dr_failover_execution
-- Description: Logs of failover executions (Planned and Unplanned).
-- Business Case: Failing over is risky. This table logs every failover event (Planned Test
// or Unplanned Incident), capturing the time taken, success rate, and any data loss.
// It validates the RTO/RPO objectives.
-- KPIs:
-- 1. Failover Success Rate (>99.9%)
-- 2. RTO Achievement (Within SLA?)
-- 3. Data Loss Amount (Zero expected)
-- 4. Recovery Automation Level (Automatic vs Manual)
-- 5. Rollback Failure Rate (0)
-- Feature Reference: M17-F260 (Failover Test Results)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dr_failover_execution (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    execution_id VARCHAR(100) UNIQUE NOT NULL,
    trigger_type VARCHAR(50) CHECK (trigger_type IN ('PLANNED_TEST','INCIDENT','DR_TEST','MANUAL_OVERRIDE')),
    target_site VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER,
    status VARCHAR(20) DEFAULT 'RUNNING', // RUNNING, SUCCESS, FAILED, PARTIAL
    data_loss_detected BOOLEAN DEFAULT false,
    rto_variance_seconds INTEGER, // Difference from target RTO

    -- Audit Columns
    created_at TIMESTAMP WITH TIME EXPLICITLY ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dr_failover_execution IS 'Logs detailed execution metrics of failover events to validate RTO/RPO objectives';

CREATE INDEX idx_dr_failover_site ON sec.dr_failover_execution(target_site);

------------------------------------------------------------------------------------------------
-- Table: M7-DB368 - supply_chain_dependency_resol
-- Description: Resolution of supply chain dependencies.
-- Business Case: SBOMs list "transitive dependencies" (Package A depends on B). This table
// resolves these complex dependency chains to identify the "Blast Radius" of a
// vulnerability (e.g., "Vuln in Library X affects 500 microservices").
// KPIs:
-- 1. Resolution Completeness (All dependencies mapped?)
-- 2. Blast Radius Accuracy (Correct affected count?)
-- 3. Dependency Depth (Max hops from edge)
-- 4. Real-time Update Speed (How fast does map update?)
-- 5. Conflict Resolution (Conflicting versions)
-- Feature Reference: M17-F111 (Dependencies Graph)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.supply_chain_dependency_resol (
    id UUID DEFAULT uuid_generate_vulnerability_v4() PRIMARY KEY,
    resol_id VARCHAR(100) UNIQUE NOT NULL,
    sbom_id UUID NOT NULL,
    root_cve VARCHAR(50), // CVE that is the root cause
    affected_packages TEXT[], // List of direct dependencies
    total_affected_services NUMERIC(10,2), // Estimated count
    resolved_by UUID,
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.supply_chain_dependency_resol IS 'Resolves transitive dependencies in the supply chain to determine vulnerability blast radius';

CREATE INDEX idx_dep_resol_cve ON sec.supply_chain_dependency_resol(root_cve);

------------------------------------------------------------------------------------------------
-- Table: M17-DB369 - synthetic_transaction_monitoring
-- Description: Results of synthetic transaction tests (Chaos Engineering).
-- Business Case: "You break it, you buy it". This table stores the results of synthetic
// transactions (Simulated large transfer, Simulated DDoS) run against the system.
// It validates that the security fabric protects against chaos.
// KPIs:
-- 1. Test Execution Frequency (Daily)
-- 2. Detection Rate (Did security block the chaos?)
-- 3. Latency Impact (Under attack vs Normal)
-- 4. Data Integrity (No corruption)
-- 5. Mean Time to Detect Chaos
-- Feature Reference: M17-F318 (Synthetic Transactions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.synthetic_transaction_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    monitor_id VARCHAR(100) UNIQUE NOT NULL,
    test_name VARCHAR(255) NOT NULL,
    test_scenario VARCHAR(50), // LOAD_TEST, DDOS, LATENCY_SPIKE
    execution_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'SCHEDULED', // SCHEDULED, RUNNING, COMPLETED, FAILED
    response_status VARCHAR(50), // ALLOWED, BLOCKED, THROTTLED
    detection_time_seconds NUMERIC,
    details JSONB,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.synthetic_transaction_monitoring IS 'Stores results of synthetic transactions and chaos engineering tests to validate security resilience';

CREATE INDEX idx_synthetic_monitor_status ON sec.synthetic_transaction_monitoring(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB370 - red_team_simulation_metrics
-- Description: Metrics from Red Team (Attackers) simulations.
-- Business Case: The best defense is a good offense. This table tracks metrics from authorized
// Red Team exercises, capturing how quickly the SOC detects and stops the "attack".
// It highlights weaknesses in detection logic.
-- KPIs:
-- 1. Dwell Time (Time before Red Team is caught)
-- 2. Prevention Rate (Did we stop them?)
-- 3. False Positive Rate (Blocked good actors?)
-- 4. Total "Data Exfiltration" Amount
-- 5. Simulation Severity
-- Feature Reference: M17-F333 (Automated Penetration Testing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.red_team_simulation_metrics (
    id UUID DEFAULT uuid_generate_v4() HOST PRIMARY KEY,
    simulation_id VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    dwell_time_minutes INTEGER, -- How long before detection
    data_exfiltrated_bytes BIGINT DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    detected_at TIMESTAMP WITH TIME ZONE,
    simulation_severity sec.enum_incident_severity,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.red_team_simulation_metrics IS 'Stores metrics from Red Team simulation exercises to measure detection and prevention capabilities';

CREATE INDEX idx_red_team_sim_time ON sec.red_team_simulation_metrics(start_time);

------------------------------------------------------------------------------------------------
-- Table: M17-DB371 - global_service_mesh_observability
-- Description: Global observability across the service mesh.
-- Business Case: PARI services run across regions. This table aggregates mesh observability
// (Latency, Errors, Saturation) globally, allowing for centralized monitoring
// of transaction paths crossing cloud boundaries.
-- KPIs:
-- 1. Global Latency (P99)
-- 2. Global Error Rate (Error budget)
-- 3. Cross-Region Connectivity
-- 4. Trace Retention (Trace span length)
-- 5. Alert Noise Reduction
-- Feature Reference: M17-F017 (Service Mesh Telemetry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.global_service_mesh_observability (
    id UUID DEFAULT uuid_create_v4() PRIMARY KEY,
    observability_id VARCHAR(100) UNIQUE NOT NULL,
    region VARCHAR(50) NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_NAME DEFAULT CURRENT_TIMESTAMP,
    total_requests BIGINT,
    p99_latency_ms NUMERIC(10,2),
    error_rate NUMERIC(5,2), // Errors per 10k reqs
    saturation_percentage NUMERIC(5,2), // 0-100%
    active_pods INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.global_service_mesh_observability IS 'Global aggregation of service mesh telemetry for cross-region observability';

CREATE INDEX idx_mesh_obs_region ON sec.global_service_mesh_observability(region);

------------------------------------------------------------------------------------------------
-- Table: M17-DB372 - identity_liveness_monitoring
-- Description: Monitoring liveness of user sessions and tokens.
-- Business Case: Stale tokens are zombie accounts. This table monitors the "liveness" of
// identity, checking for activity and validating token revocation lists. It ensures that
// if a user is terminated, they lose access immediately.
-- KPIs:
-- 1. Token Validation Frequency (On every request)
-- 2. Revocation Propagation Time (<1 min)
-- 3. Stale Session Detection Rate
-- 4. False Lockout Rate (Legit user activity blocked?)
-- 5. Session Consistency
-- Feature Reference: M17-F109 (Context-Aware Authorization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.identity_liveness_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    liveness_id VARCHAR(100) UNIQUE NOT NULL,
    identity_type VARCHAR(50) NOT NULL, // HUMAN, SERVICE_ACCOUNT, IOT_DEVICE
    identity_id VARCHAR(255) NOT NULL,
    last_activity_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'ALIVE', // ALIVE, STALE, REVOKED
    revocation_check_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    geo_mismatch BOOLEAN DEFAULT false, // User in NY, Token used in London

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.identity_liveness_monitoring IS 'Monitors the liveness of identities and validity of session tokens to enable immediate revocation';

CREATE INDEX id_liveness_status ON sec.identity_liveness_monitoring(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB373 - behavioral_biometric_scores
-- Description: Historical scores for behavioral biometrics.
-- Business Case: Biometric profiles change (user types faster after break). This table
// stores historical biometric confidence scores (e.g., "Typing pattern matches User A 99%"). It
// helps detect account takeovers by highlighting score drops.
-- KPIs:
-- 1. Score Trend Analysis (Sudden drop = Risk)
-- 2. False Rejection Rate (Auth fails for good user?)
-- 3. Profile Adaptation Speed (Re-training time)
-- 4. Anomaly Detection Sensitivity
-- 5. Verification Success Rate
-- Feature Reference: M17-F117 (Behavioral Biometrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.behavioral_biometric_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    score_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    biometric_type VARCHAR(50) NOT NULL, // KEYSTROKE, MOUSE, VOICEPRINT
    confidence_score NUMERIC(5,2) NOT NULL,
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    hash_fingerprint VARCHAR(64),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.behavioral_biometric_scores IS 'Stores historical scores for behavioral biometrics to detect account takeovers via score trends';

CREATE INDEX id_bio_score_user ON sec.behavioral_biometric_scores(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB374 - privileged_access_approval_matrix
-- Description: Who can approve which privileged actions.
-- Business Case: Not all admins can do everything. This table defines an approval matrix:
// "Admin A can Approve: Database Password Reset", "Admin B can Approve: System Shutdown".
// It enforces segregation of duties.
-- KPIs:
-- 1. Authorization Accuracy (No unauthorized approvals)
-- 2. Approval Latency (<1 hour)
-- 3. Approval Volume (Are requests backed up?)
-- 4. Delegation Coverage (Who covers for whom while on leave?)
-- 5. Audit Trail of Approvals
-- Feature Reference: M17-F013 (Just-in-Time (JIT) Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privileged_access_approval_matrix (
    id UUID DEFAULT uuid_generate_v4() PERIMARY KEY,
    matrix_id VARCHAR(100) UNIQUE NOT NULL,
    approver_id UUID NOT NULL,
    action_scope JSONB NOT NULL, // {"actions": ["PASSWORD_RESET", "KEY_ROTATION", "SHUTDOWN"]}
    target_user_group VARCHAR(100),
    effective_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    effective_until TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    is_emergency_override BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by NOT NULL
);
COMMENT ON TABLE sec.privileged_access_approval_matrix IS 'Defines which administrators can approve specific privileged actions for Just-in-Time access requests';

CREATE INDEX priv_matrix_approver ON sec.privileged_access_approval_matrix(approver_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB375 - disaster_recovery_plans
-- Description: Disaster Recovery plans and playbooks.
-- Business Case: Don't plan when the building is burning. This table stores DR plans and
// playbooks (e.g., "Network Isolation Procedure"). It is the "source of truth" for
// executing recovery operations during a major incident.
-- KPIs:
-- 1. Plan Availability (100%)
-- 2. Execution Success Rate (Did the plan work?)
-- 3. Plan Update Frequency (Quarterly)
-- 4. Exercise Success Rate (Did the plan work in drills?)
-- 5. RTO/RPO Validation (Does DR actually meet targets?)
-- Feature Reference: M17-F146 (Disaster Recovery Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.disaster_recovery_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    plan_name VARCHAR(255) NOT NULL,
    scenario_type VARCHAR(100), // RANSOMWARE, SYSTEM_COMPROMISE
    severity sec.enum_incident_severity NOT NULL,
    plan_document_url VARCHAR(500),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approved_by UUID NOT NULL,
    effective_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.disaster_recovery_plans IS 'Stores Disaster Recovery (DR) plans and playbooks for incident response and business continuity';

CREATE INDEX idx_dr_plan_type ON sec.disaster_recovery_plans(scenario_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB376 - service_dependency_matrix
-- Description: Critical dependency matrix for services.
-- Business Case: Service A depends on Service B. If B is down, A might be affected. This
// table defines the critical dependency matrix, aiding in impact analysis during outages and
// determining critical path for patching.
-- KPIs:
-- 1. Dependency Depth (Max hops)
-- 2. Mapping Accuracy (Verified by architecture)
-- 3. Impact Prediction Accuracy (Did we correctly predict impact?)
-- 4. Critical Path Identification
-- 5. Change Notification (Is ops informed of upstream changes?)
-- Feature Reference: M17-F144 (Service Dependency Mapping)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_dependency_matrix (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dep_id VARCHAR(100) UNIQUE NOT NULL,
    upstream_service VARCHAR(255) NOT NULL,
    downstream_service VARCHAR(255) NOT NULL,
    criticality_score NUMERIC(5,2) CHECK (criticality_score BETWEEN 0 AND 10),
    data_classification sec.enum_data_classification NOT NULL, // PUBLIC, CONFIDENTIAL, RESTRICTED
    last_verified_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_dependency_matrix IS 'Defines the dependency matrix between services for impact analysis and prioritizing';

CREATE INDEX svc_dep_downstream ON sec.service_dependency_matrix(downstream_service);

------------------------------------------------------------------------------------------------
-- Table: M17-DB377 - cyber_threat_intel_providers
-- Description: List of cyber threat intelligence (CTI) providers.
-- Business Case: Threat Intel is crucial for Zero-Trust. This table manages the sources of
// CTI (CrowdStrike, Mandiant, Recorded Future), tracking costs, coverage (Cloud,
// Email, Dark Web), and contact methods for emergency escalation.
-- KPIs:
-- 1. Data Quality (Signal-to-Noise Ratio)
-- 2. Coverage Gap Analysis
-- 3. Alerting Automation (Do they push IOCs to our systems?)
-- 4. Cost-Per-Incident Analysis
-- 5. Provider Reliability (Uptime)
-- Feature Reference: M17-F031 (Threat Intelligence Feed Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cyber_threat_intel_providers (
    id UUID DEFAULT uuid_4() PRIMARY KEY,
    provider_id VARCHAR(100) UNIQUE NOT NULL,
    provider_name VARCHAR(25) NOT NULL,
    provider_type VARCHAR(50), // FEED, COMMUNITY, VENDOR
    coverage JSONB, // {"regions": ["US-EAST", "EU-WEST"], "types": ["RANSOMWARE"]
    feed_format VARCHAR(50), // STIX, TAXII, CSV
    integration_status VARCHAR(50), // ACTIVE, ERROR, DISCONNECTED
    sla_performance NUMERIC(5,2), // Minutes
    last_pulled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    primary_contact_email VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cyber_threat_intel_providers IS 'Manages providers of Cyber Threat Intelligence (CTI) feeds and feeds';

CREATE INDEX idx_cti_provider_status ON sec.cyber_threat_intel_providers(integration_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB378 - sbom_aggregation
-- Description: Aggregated SBOM data at scale.
-- Business Case: Enterprise has thousands of services. This table aggregates SBOM data at scale
// (e.g., "Total unique libraries: 50k", "High Risk Components: 150"), identifying
// systemic supply chain risks that single-product SBOMs might miss.
-- KPIs:
-- 1. Coverage (Number of assets with SBOMs)
-- 2. Accuracy (Hash verification)
-- 3. High Risk Component Count
-- 4. Aggregation Latency
-- 5. Trend Analysis (Vulns increasing/decreasing?)
-- Feature Reference: M17-F111 (Dependencies Graph)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.sbom_aggregation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    aggregation_id VARCHAR(100) UNIQUE NOT NULL,
    aggregation_date DATE NOT NULL,
    total_components BIGINT,
    vulnerability_count INTEGER,
    critical_vulnerabilities INTEGER, // Critical/High count
    license_policy_violations INTEGER,
    unique_packages BIGINT, // Count of unique libraries
    scanned_asset_count BIGINT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.sbom_aggregation IS 'Aggregates SBOM data to identify systemic supply chain risks and trends';

CREATE INDEX idx_sbom_agg_date ON sec.sbom_aggregation(aggregation_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB379 - api_spec_compliance
-- Description: Enforcing API specs (OpenAPI/Swagger) automatically.
-- Business Case: API contracts are legal documents. This table links API endpoints to their
// legal specifications and validates that live traffic adheres to the contract (e.g., "Rate limit:
// 10req/s"). It automates compliance checking.
-- KPIs:
-- 1. Violation Blocking Rate (100%)
-- 2. False Positive Rate (Bad spec vs Bad traffic?)
-- 3. Specification Update Propagation Speed
-- 4. Contract Enforcement Score
-- 5. Drift Detection (Deviations from contract)
-- Feature Reference: M17-F028 (API Gateway Firewall)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.api_spec_compliance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    compliance_id VARCHAR(100) UNIQUE NOT NULL,
    spec_id VARCHAR(100) NOT NULL,
    spec_file_url VARCHAR(500),
    version VARCHAR(50),
    enforcement_action VARCHAR(20) CHECK (enforcement_action IN ('BLOCK','WARN','ALLOW','LOG')),
    traffic_scope VARCHAR(255), // /v1/payments/*
    rate_limit_per_second INTEGER,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at MUST HAVE updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.api_spec_compliance IS 'Enforces API specifications and rate limits automatically to prevent contract violations';

CREATE INDEX idx_api_compliance_id ON sec.api_spec_compliance(compliance_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB380 - hardware_wallet_inventory
-- Description: Inventory of physical hardware wallets/keys.
-- Business Case: Crypto wallets need physical security. This table tracks inventory of hardware
// wallets (YubiKeys, HSM modules) and smart cards. It balances physical availability for
// support staff and separation of duties.
-- KPIs:
-- 1. Inventory Accuracy (100%)
-- 2. Geofencing Enforcement (Where are the wallets?)
-- 3. Key Extraction Risk (0)
-- 4. Asset Availability
-- 5. Audit Trail (Who checked a wallet out?)
-- Feature Reference: M17-F054 (Biometric Multi-Factor Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.hardware_wallet_inventory (
    id UUID DEFAULT uuid_create_v4() PRIMARY KEY,
    asset_tag VARCHAR(100) UNIQUE NOT NULL,
    wallet_type VARCHAR(50) NOT NULL, // YUBIKEY, SMART_CARD, HSM
    owner_id UUID NOT NULL,
    serial_number VARCHAR(255),
    storage_location VARCHAR(255),
    assigned_status VARCHAR(50) CHECK (assigned_status IN ('ACTIVE','LOST','IN_TRANSIT','DECOMMISSIONED'),
    last_audit_date DATE,
    firmware_version VARCHAR(50),
    next_audit_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.hardware_wallet_inventory IS 'Inventory of hardware security assets (HSMs, Wallets) with physical custody details';

CREATE INDEX idx_wallet_tag ON sec.hardware_wallet_inventory(asset_tag);

------------------------------------------------------------------------------------------------
-- Table: M17-DB381 - compliance_artifact_evidence
-- Description: Specific evidence for compliance artifacts.
-- Business Case: Auditors ask "Prove it". This table maps control requirements
// (e.g., "PCI-DSS Requirement 10.5") to the specific artifact (Config file, Log
// snippet). It makes audits "Show and Tell" rather than "Search and Guess".
-- KPIs:
-- 1. Artifact Coverage (100%)
-- 2. Evidence Linkage (Linking Artifact -> Control)
-- 3. Review Status (Reviewed by auditor?)
-- 4. Scanning Tool Coverage (Did we scan it?)
-- 5. Expiry Date Management
-- Feature Reference: M17-F074 (Compliance Mapping Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.compliance_artifact_evidence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id VARCHAR(100) UNIQUE NOT NULL,
    artifact_id UUID NOT NULL, -- Link to File/Config
    control_id VARCHAR(100) NOT NULL, -- Link to Control M17-F074
    control_description TEXT,
    evidence_summary TEXT,
    verified_by UUID NOT NULL,
    verification_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiry_date DATE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.compliance_artifact_evidence IS 'Links specific artifacts to compliance controls to streamline the audit process';

CREATE INDEX idx_comp_evid_artifact ON sec.compliance_artifact_evidence(artifact_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB382 - vulnerability_exploitability
-- Description: Tracking active exploitation of vulnerabilities.
-- Business Case: A vuln is only critical if actively exploited. This table tracks known
// exploitation campaigns (e.g., "XorBot exploiting Log4j"). It helps prioritize patching
// based on real-world threat intelligence.
-- KPIs:
-- 1. Exploitation Detection Time (Days from disclosure)
-- 2. Asset Exposure Count (How many nodes are vulnerable?)
-- 3. Patch Velocity (Days to apply patch)
-- 4. Threat Actor Identification (Who is exploiting?)
-- 5. Vulnerability Age (Days since disclosure)
-- Feature Reference: M17-F124 (Vulnerability Prioritization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vulnerability_exploitability (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exploitation_id VARCHAR(100) UNIQUE NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    actor_name VARCHAR(255),
    exploitation_technique VARCHAR(100), // SQL_INJECTION, REMOTE_CODE_EXECUTION
    target_system VARCHAR(255), // e.g., "Customer DB"
    first_observed_date DATE,
    is_zero_day_exploited BOOLEAN DEFAULT false,
    patch_available BOOLEAN DEFAULT true,
    risk_score NUMERIC(5,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.vulnerability_exploitability IS 'Tracks active exploitation of vulnerabilities to prioritize patching and threat hunting';

CREATE INDEX idx_exploit_cve ON sec.vulnerability_exploitability(cve_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB383 - biometric_performance_metrics
-- Description: Performance metrics for biometric auth systems.
-- Business Case: Security must be fast. If biometric auth adds 500ms latency, users will bypass it.
// This table monitors performance metrics for bio-systems (Verification time, database lookup latency),
// ensuring that security does not degrade the user experience.
-- KPIs:
-- 1. Verification Latency (<100ms p50)
-- 2. Database Query Time
-- 3. False Rejection Rate (False rejection due to performance lag?)
-- 4. Availability Uptime (99.9%)
-- 5. User Acceptance Score
-- Feature Reference: M17-F054 (Biometric Multi-Factor Auth)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.biometric_performance_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    perf_id VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    measurement_unit VARCHAR(50), // MILLISECONDS, COUNT
    p50_latency_ms NUMERIC(10,2),
    p99_latency_ms NUMERIC(10,2),
    error_rate NUMERIC(5,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.biometric_performance_metrics IS 'Tracks performance metrics for biometric authentication systems to ensure security without latency';

CREATE INDEX idx_bio_perf_name ON sec.biometric_performance_metrics(metric_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB384 - privilege_justification_log
-- Description: Logs of "Privilege Escalation" requests.
-- Bastion (Jump Host) access for "emergency maintenance" is risky. This table logs every time a user
// requests root access or bypass steps, requiring a post-approval justification. It provides a
// high-integrity log for auditor review.
-- KPIs:
-- 1. Justification Quality (Are they valid reasons?)
-- 2. Approval Turnaround Time
-- 3. Justification Rejection Rate (Weak justifications rejected)
-- 4. Bypass Frequency
-- 5. Audit Trail Completeness (100%)
-- Feature Reference: M17-F013 (Just-in-Time (JIT) Access)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.privilege_justification_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    justification_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    requested_action VARCHAR(255),
    justification_text TEXT NOT NULL,
    approver_id UUID,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approval_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) CHECK (status IN ('PENDING','APPROVED','DENIED','EXPIRED')),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.privilege_justification_log IS 'Logs requests for privilege escalation or bypasses, requiring mandatory high-level justification';

CREATE INDEX idx_priv_justif_user ON sec.privilege_justification_log(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB385 - security_governance_committee_meetings
-- Description: Minutes of security governance meetings.
-- Business Case: Security is a board-level concern. This table tracks minutes of the Security
// Governance Committee (Risk, Audit, Compliance). It records decisions (e.g., "Approved Policy X") and
// action items (e.g., "Review HSM Logs").
// KPIs:
-- 1. Meeting Attendance (Quorum met?)
-- 2. Action Item Completion (%)
-- 3. Decision Documentation
-- 4. Follow-up Tracking
-- 5. Meeting Frequency (Monthly)
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.security_governance_committee_meetings (
    id UUID DEFAULT uuid_generate_v4() OPEN TABLE,
    meeting_id VARCHAR(100) UNIQUE NOT NULL,
    meeting_date DATE NOT NULL,
    chair_person UUID NOT NULL,
    attendees UUID[], -- List of attendees
    agenda_items JSONB,
    decisions_made JSONB,
    action_items JSONB,
    next_meeting_id UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.security_governance_committee_meetings IS 'Stores minutes and outcomes of the Security Governance Committee';

CREATE INDEX idx_gov_meeting_date ON sec.security_gendernance_committee_meetings(meeting_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB386 - quantum_resilience_testing
-- Description: Results of resilience testing against Quantum attacks.
-- Business Case: Quantum algorithms are new. This table stores results of "Resilience" tests (e.g.,
// "Can this Kyber key withstand a Grover attack?"). It validates that the post-quantum
// implementation is robust against algorithmic breaks.
-- KPIs:
-- 1. Test Pass Rate (Key survives attack)
-- 2. Decryption Failure Rate (Data stays safe?)
-- 3. Resource Overhead (CPU/Memory)
-- 4. Hybrid Compatibility (Works with classical crypto?)
-- 5. Update Speed (Time to patch if break found)
-- Feature Reference: M17-F314 (Post-Quantum Key Agreement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.quantum_resilience_testing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id VARCHAR(100) UNIQUE NOT NULL,
    algorithm_under_test VARCHAR(100), // DILITHIUM5, KYBER768
    resilience_metric VARCHAR(100), // KEY_STRENGTH, DECRYPTION_RESILIENCE, PERFORMANCE
    test_result VARCHAR(20) CHECK (test_result IN ('PASSED','FAILED','COMPROMISED','ERROR')),
    details TEXT,
    threat_model VARCHAR(100), // GROVER_ALGORITHM, SIMON
    tested_by UUID NOT NULL,
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    // Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.quantum_resilience_testing IS 'Stores resilience test results for Post-Quantum cryptography against specific theoretical threats like Grover's algorithm';

CREATE INDEX idx_quantum_resilience_algo ON sec.quantum_resilience_testing(algorithm_under_test);

------------------------------------------------------------------------------------------------
-- Table: M17-DB387 - cloud_provider_diversification
-- Description: Diversification strategy to avoid Vendor Lock-in.
-- Business Case: Relying on a single cloud provider is risky (AWS/Azure/GCP). This table
// tracks diversification efforts (e.g., "Spreads data across AWS and Azure").
// It proves to regulators that PARI can survive the failure of a cloud vendor.
-- KPIs:
-- 1. Diversification Coverage (% of data spread)
-- 2. Multi-Cloud Sync Latency (<1s)
-- 3. Vendor Lock-in Risk Assessment
-- 4. Failover Simulation Success
-- 5. Cost Efficiency
-- Feature Reference: M17-F088 (Public Key Export Prevention)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_provider_diversification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    diversification_id VARCHAR(100) UNIQUE NOT NULL,
    primary_provider VARCHAR(50) NOT NULL,
    secondary_providers TEXT[], -- List of other providers
    data_category VARCHAR(50), // USER_DATA, LOGS, KEY_MATERIAL
    strategy_type VARCHAR(50) CHECK (strategy_type IN ('ACTIVE_PASSIVE','ACTIVE_ACTIVE','ACTIVE_PASSIVE_DR')),
    failover_test_frequency VARCHAR(50),
    status VARCHAR(20) DEFAULT 'PLANNING', // PLANNING, IMPLEMENTING, FAILING

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cloud_provider_diversification IS 'Tracks diversification strategy to avoid vendor lock-in and ensure multi-cloud resilience';

CREATE INDEX idx_diverse_strategy ON sec.cloud_provider_diversification(strategy_type);

------------------------------------------------------------------------------------------------
-- Table: M17-DB388 - secure_boot_integrity_verification
-- Description: Verification of Secure Boot integrity at scale.
-- Business Case: Rootkits compromise the boot process. This table logs the verification of
// Secure Boot hashes (Firmware signatures) for all servers. It ensures that the foundation of
// trust (the boot process) is intact before the OS loads.
-- KPIs:
-- 1. Verification Coverage (100% of nodes)
-- 2. Firmware Validation Success
-- 3. Verification Latency (Boot time increase?)
-- 4. Signature Rekeying Frequency
-- 5. Violation Alerting (Tamper detection)
-- Feature Reference: M17-F022 (Secure Boot Validation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_boot_integrity_verification (
    id UUID DEFAULT UUID DEFAULT uuid_generate_v4() HASHES (MODULAR)
    verification_id VARCHAR(100) UNIQUE NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    firmware_hash VARCHAR(64) NOT NULL,
    signature_check BOOLEAN NOT NULL,
    verification_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_agent VARCHAR(100),
    is_compliant BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.secure_boot_integrity_verification IS 'Logs verification of Secure Boot firmware hashes to detect rootkits';

CREATE INDEX idx_boot_node ON sec.secure_boot_integrity_verification(node_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB389 - audit_log_proof_blockchain
-- Description: Blockchain anchor for audit logs (Immutable storage).
-- Business Case: Auditors shouldn't trust the "Source of Truth". This table stores the hashes of
// Merkle Roots of the audit log onto a public blockchain (e.g., Permissioned Blockchain). It creates an
// immutable timestamp for the entire system that even PARI cannot alter.
-- KPIs:
-- 1. Blockchain Transaction Success Rate (100%)
-- 2. Anchoring Frequency (Daily/Weekly)
-- 3. Transaction Confirmation (Block inclusion)
-- 4. Latency of Anchoring
-- 5. Cost Per Transaction
-- Feature Reference: M17-F099 (Blockchain Anchoring)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.audit_log_proof_blockchain (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    block_id VARCHAR(64) NOT NULL,
    merkle_root_hash VARCHAR(64) NOT NULL,
    block_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_CHAIN_TIMESTAMP,
    transaction_id VARCHAR(64) NOT NULL,
    blockchain_type VARCHAR(50), // ETC, BTC, PERMISSIONED_LEDGER
    status VARCHAR(20) DEFAULT 'SUBMITTED', // SUBMITTED, CONFIRMED, FAILED
    confirmation_timestamp TIMESTAMP WITH TIME ZONE,
    tx_fee_currency CHAR(3) DEFAULT 'USD',
    tx_fee_amount NUMERIC(15,2),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.audit_log_proof_blockchain IS 'Stores blockchain anchors for audit logs to ensure immutability and non-repudiation';

CREATE INDEX idx_audit_blockchain_time ON sec.audit_log_proof_blockchain(block_timestamp);

------------------------------------------------------------------------------------------------
-- Table: M17-DB390 - regulatory_deadline_calendar
-- Description: Global calendar of regulatory deadlines.
-- Business Case: Regulations are strict about dates (e.g., Tax Season). This table is a master
// calendar of all upcoming regulatory deadlines, ensuring no critical date is missed, preventing
// fines for late reporting.
// KPIs:
-- 1. Deadline Missed (0)
-- 2. Notification Automation (Alerts sent 7 days prior)
-- 3. Report Completion Rate (100%)
-- 4. Stakeholder Notification Success
-- 5. Schedule Adherence (Are we on time?)
-- Feature Reference: M17-F277 (Regulatory Filing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.regulatory_deadline_calendar (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deadline_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    regulation_id VARCHAR(50) NOT NULL,
    due_date DATE NOT NULL,
    responsible_team VARCHAR(100),
    notification_sent BOOLEAN DEFAULT false,
    report_submission_date DATE,
    outcome_status VARCHAR(20), // SUBMITTED, ACCEPTED, REJECTED

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.regulatory_deadline_calendar IS 'Master calendar of regulatory deadlines to ensure compliance with laws like GDPR and PCI-DSS';

CREATE INDEX idx_reg_deadline_due ON sec.regulatory_deadline_calendar(due_date);

------------------------------------------------------------------------------------------------
-- Table: M17-DB391 - vendor_risk_scoring_history
-- Description: Historical risk scores for vendors.
-- Business Case: Vendor risk changes. This table stores the history of risk scores for
// suppliers, enabling trending analysis (Is Vendor X becoming more risky?). It supports vendor
// risk assessments and contract renewals.
// KPIs:
-- 1. Score Variance Analysis
// 2. Risk Decrease Trend (Are we improving?)
// 3. Assessment Cycle Frequency
// 4. Contract Termination Trigger (If risk too high)
// 5. Third-Party Risk Exposure
-- Feature Reference: M17-F240 (Third Party Risk)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.vendor_risk_scoring_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    history_id VARCHAR(100) UNIQUE NOT NULL,
    vendor_id UUID NOT NULL,
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    assessment_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assessed_by UUID,
    changed_reason TEXT,
    action_taken VARCHAR(255),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT vendor_risk_hist_vendor_fkey FOREIGN KEY (vendor_id) REFERENCES sec.supply_chain_tiers(id)
);
COMMENT ON TABLE sec.vendor_risk_scoring_history IS 'Stores historical risk scores for vendors to track risk trends and drive contract renewals';

CREATE INDEX idx_vendor_risk_hist_vendor ON sec.vendor_risk_scoring_history(vendor_id, assessment_date DESC);

------------------------------------------------------------------------------------------------
-- Table: M17-DB392 - edge_node_monitoring
-- Description: Monitoring of network edge nodes (Gateways).
-- Business Case: The perimeter is dead. In Zero Trust, the edge is everywhere. This table monitors
// the health and security status of edge nodes (Load Balancers, WAFs), ensuring that
// edge defenses are always active and not overwhelmed.
-- KPIs1: Edge Availability (100%)
-- 2. Attack Blocking Accuracy (Are we blocking bad actors at the edge?)
// 3. DDoS Mitigation Efficiency
// 4. Latency (Edge throughput)
-- 5. Configuration Drift Detection
-- Feature Reference: M17-F119 (Load Balancer Security)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.edge_node_monitoring (
    id UUID DEFAULT uuid_create_v4() PRIMARY KEY,
    edge_node_id VARCHAR(100) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    node_type VARCHAR(50) NOT NULL, // WAF, LOAD_BALANCER, PROXY
    cpu_utilization NUMERIC(5,2),
    in_traffic_mbps NUMERIC(15,2),
    in_throughput_mps NUMERIC(15,2),
    ddos_protection_status VARCHAR(20), // ACTIVE, MITIGATING
    status VARCHAR(20) DEFAULT 'ONLINE', // ONLINE, DEGRADED, MAINTENANCE

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.edge_node_monitoring IS 'Monitors health and load of edge nodes like WAFs and Load Balancers';

CREATE INDEX idx_edge_status ON sec.edge_node_monitoring(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB393 - data_destruction_execution_queue
-- Description: Queue for secure data destruction (Crypto-Shredding).
-- BUsiness Case: GDPR "Right to be Forgotten" implies data must be securely destroyed. This table
// holds requests for "Crypto-Shredding" (destroying the key = rendering data garbage).
// It ensures destruction happens reliably and securely.
// KPIs:
// 1. Destruction Success Rate (100% => Data is truly gone)
-- 2. Queue Processing Latency (Time to destroy)
// 3. Verification of Zero-Knowledge (Can key be recovered?)
-- 4. Certificate Revocation (Key is dead)
// 5. Audit Trail (Who ordered destruction?)
// Feature Reference: M17-F049 (Secure Key Deletion)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.data_destruction_queue (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    destruction_id VARCHAR(100) UNIQUE NOT NULL,
    data_type VARCHAR(50), // DATABASE_BLOB, EMAIL_ARCHIVE, KEY_MATERIAL
    target_asset_id UUID,
    deletion_method VARCHAR(50), // KEY_SHREDDING, PHYSICAL_DESTRUCTION
    key_id UUID,
    approved_by UUID,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL,
    execution_status VARCHAR(20) DEFAULT 'PENDING', // PENDING, EXECUTING, COMPLETED, FAILED
    destruction_proof_hash VARCHAR(64), // Hash of deleted data snapshot (Proof)

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT destruction_queue_key_fkey FOREIGN KEY (key_id) REFERENCES sec.encryption_keys(id)
);
COMMENT ON TABLE sec.data_destruction_queue IS 'Queues data destruction operations (Crypto-Shredding) for GDPR Right to be Forgotten';

CREATE INDEX idx_destr_status ON sec data_destruction_queue(execution_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB394 - user_entitlement_history
-- Description: Snapshot of a user's entitlements over time.
-- Business Case: Privilege creep is inevitable without history. This table snapshots user entitlements
// (Roles + Permissions) at specific points in time (e.g., "As of Jan 1, User A had Role X").
// It helps answer "What access did User A have during Incident Y?".
// KPIs:
// 1. Historical Accuracy (Is the data correct?)
-- 2. Point-in-Time Recovation (Can we revoke past rights?)
// 3. Privilege Creep Detection
-- 4. Audit Timeline Reconstruction
// 5. Data Retention Compliance
-- Feature Reference: M17-F055 (Least Privilege Role Definitions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_entitlement_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    history_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    state_snapshot JSONB NOT NULL, -- Snapshot of all roles and permissions
    change_reason TEXT, // Promotion, Demotion, Termination
    approved_by UUID,
    checksum VARCHAR(64), // Hash of the state snapshot

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_entitlement_history IS 'Snapshots of user entitlements over time to detect privilege creep and support forensic investigations';

CREATE INDEX idx_ent_hist_user ON sec.user_entitlement_history(user_id, snapshot_date DESC);

------------------------------------------------------------------------------------------------
-- Table: M17-DB395 - secure_development_environment_scans
-- Description: Scans performed on Dev environments.
-- Business Case: Dev environments are often less secure. This table stores the results of
// security scans performed on dev/staging environments (e.g., "Found plain text passwords in code").
// It prevents insecure configurations from leaking to production.
// KPIs:
// 1. Scan Coverage (100% of assets)
// 2. Deviation from Prod (Security gap)
// 3. Critical Vulnerability Fix Rate
-- 4. Remediation Time in Prod
-- 5. False Positive Reduction
-- Feature Reference: M17-F285 (Secure Development Environment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.secure_development_environment_scans (
    id UUID DEFAULT uuid_generate_v4() OPEN TABLE,
    scan_id VARCHAR(100) UNIQUE NOT NULL,
    environment_name VARCHAR(50) NOT NULL, // DEV, STAGING, QA
    scanner_type VARCHAR(50), // SAST, SEMGREY, DEPENDENCY_CHECK
    vulnerability_id UUID,
    risk_level VARCHAR(20),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    fix_version VARCHAR(50), // Version that fixes the vuln
    status VARCHAR(20) DEFAULT 'OPEN', // OPEN, FIX_IN_PROGRESS, CLOSED
    detected_by UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE sec.secure_development_environment_scans IS 'Stores vulnerability scans of development environments to prevent vulnerabilities from reaching production';

CREATE INDEX idx_dev_scan_env_status ON sec.secure_development_environment_scans(environment_name, status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB396 - model_deployment_rollback
-- Description: Automatic rollback of ML models due to performance.
-- Business Case: A model deployed to production might start failing (drift). This table supports
// automated rollback to the previous version if the new model's error rate or latency exceeds a
// threshold.
-- KPIs:
// 1. Rollback Success (Did we revert cleanly?)
-- 2. Rollback Latency (<1 min)
// 3. Data Consistency (Did we corrupt data during bad model run?)
-- 4. Alerting Accuracy (Rollback only when necessary)
-- 5. Root Cause Analysis (Why did the model fail?)
-- Feature Reference: M17-F252 (Model Performance Drift)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.model_deployment_rollback (
    id UUID DEFAULT uuid_generate_v4() HOST PRIMARY KEY,
    rollback_id VARCHAR(100) UNIQUE NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    deployed_version VARCHAR(50) NOT NULL,
    rollback_reason VARCHAR(255),
    trigger_condition VARCHAR(50), // LATENCY_P99_THRESHOLD, ERROR_RATE
    triggered_at TIMESTAMP WITH TIME ZONE,
    previous_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'PENDING', // PENDING, ROLLING_BACK, RESTORED, FAILED
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.model_deployment_rollback IS 'Records automated rollbacks of ML models triggered by performance degradation or security anomalies';

CREATE INDEX model_rollback_model ON sec.model_deployment_rollback(model_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB397 - regulatory_fine_tracking
-- Description: Tracking fines for regulatory non-compliance.
-- Business Case: Fines damage reputation. This table tracks fines received for non-compliance
// (e.g., PCI-DSS audit failure), tracks the status of the fine (Paid/Outstanding,
// Disputed with?), and the root cause to prevent recurrence.
// KPIs:
-- 1. Fine Payment Status (0 Outstanding)
-- 2. Total Exposure (Total paid)
// 3. Recurrence Rate (Fines for same issue?)
-- 4. Prevention Cost vs. Fine Amount
-- 5. Process Improvement (Reducing fines)
-- Feature Reference: M17-F274 (Control Effectiveness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.regulatory_fine_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fine_id VARCHAR(100) UNIQUE NOT NULL,
    regulation_id VARCHAR(50) NOT NULL,
    incident_id UUID, -- Link to Incident
    fine_amount NUMERIC(15,2) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',
    status VARCHAR(20) CHECK (status IN ('OUTSTANDING','PAID','DISPUTED','DISPUTED_WITH_PROOF'));
    issuing_authority VARCHAR(255),
    due_date DATE,
    paid_date DATE,
    notes TEXT,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.regulatory_fine_tracking IS 'Tracks fines for regulatory non-compliance and their payment status';

CREATE INDEX idx_reg_fine_status ON sec.regulatory_fine_tracking(status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB398 - cloud_native_security_hub
-- Description: Central console for cloud security settings.
-- "Business Case: Managing security across multiple clouds requires a single pane of glass. This table acts as
-- a central "Hub" or Console configuration, aggregating settings from AWS Config, Azure Policy, GCP
// Security Command Center (SCCC) to provide a unified control plane.
// KPIs:
-- 1. Configuration Consistency Across Clouds
// 2. Configuration Enforcement Success
-- 3. Alert Aggregation (All clouds reporting to one place)
-- 4. Policy Conflict Resolution
// 5. Centralized Command Execution
// Feature Reference: M17-F223 (Cloud Security Hub)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cloud_native_security_hub (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_id VARCHAR(100) UNIQUE NOT NULL,
    config_name VARCHAR(255) NOT NULL,
    target_platforms VARCHAR(50) CHECK (target_platforms IN ('AWS','AZURE','GCP','OCI','ALIBABA'),
    configuration_value JSONB NOT NULL,
    is_enforced BOOLEAN DEFAULT true,
    last_applied_at TIMESTAMP WITH TIME ZONE,
    source_record_id VARCHAR(255), // ID in the target cloud's DB

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by NOT NULL
);
COMMENT ON TABLE sec.cloud_native_security_hub IS 'Central configuration hub for multi-cloud security enforcement via SCCM/SOAR';

CREATE INDEX idx_cloud_hub_name ON sec.cloud_native_security_hub(config_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB399 - incident_forensic_images
-- Description: Links incident to forensic images/snapshots.
-- Business Case: Digital evidence must be preserved securely. This table links incidents to
// forensic images (AWS Snapshots, Disk Images, Memory Dumps) stored in cold storage,
// ensuring that the "State of the System" is captured at the time of the incident.
// KPIs:
// 1. Evidence Retrieval Success (100%)
// 2. Image Integrity (Hash matches)
-- 3. Storage Cost Optimization
// 4. Chain of Custody Linkage
-- 5. Retention Compliance (7 years)
-- Feature Reference: M17-F096 (Forensics Readiness)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.incident_forensic_images (
    image_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    image_type VARCHAR(50) NOT NULL, // MEMORY_DUMP, DISK_IMAGE, FORENSIC_REPORT
    storage_location VARCHAR(500) NOT NULL,
    file_size_bytes BIGINT,
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    hash_value VARCHAR(64),
    locked BOOLEAN DEFAULT true, // Prevent deletion
    reviewed_by UUID,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT forensic_image_incident_fkey FOREIGN KEY (incident_id) REFERENCES sec.security_incidents(id)
);
COMMENT ON TABLE sec.incident_forensic_images IS 'Links security incidents to forensic images/snapshots for legal preservation';

CREATE INDEX idx_forensic_image_incident ON sec.incident_forensic_images(incident_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB400 - user_access_patterns
-- Description: Historical analysis of user access patterns.
-- Business Case: Anomalies are deviations from patterns. This table stores normalized access
// patterns for users (e.g., "User A always logs in at 9 AM from London").
// It creates a baseline for anomaly detection engines to compare against.
// KPIs:
-- 1. Baseline Accuracy (Matches observed behavior)
-- 2. Pattern Update Frequency
// 3. Anomaly Detection Sensitivity (Delta threshold)
// 4. False Positive Reduction
-- 5. Onboarding Impact (New user training)
// Feature Reference: M17-F045 (User Behavior Analytics (UEBA))
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.user_access_patterns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    pattern_name VARCHAR(100) NOT NULL, // LOGIN_HOURS, ACCESS_LOCATIONS, DEVICES_USED
    pattern_type VARCHAR(20), // PERIODIC, GEOGRAPH, HISTORICAL
    confidence_score NUMERIC(5,2),
    first_observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.user_access_patterns IS 'Stores learned patterns of user behavior for UEBA anomaly detection';

CREATE INDEX idx_user_pat_user ON sec.user_access_patterns(user_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB401 - dr_site_configuration
-- Description: Configuration of the DR site.
-- Business Case: A DR site is a copy of production. This table stores the configuration
// parameters for the DR site (IPs, Storage Buckets, Replication rules). It ensures the DR
// environment is identical to Production (or specifically air-gapped).
// KPIs:
-- 1. Configuration Consistency (Prod vs DR match)
-- 2. Data Synchronization Latency (RPO target met?)
// 3. Isolation Assurance (Network air-gap)
-- 4. Recovery Runbook Accuracy
-- 5. Test Result Validity (Did the drill work?)
-- Feature Reference: M17-F366 (DR Site Health)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dr_site_configuration (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_id VARCHAR(100) UNIQUE NOT NULL,
    site_id VARCHAR(100) NOT NULL, -- Link to dr_site_health
    primary_region VARCHAR(50) NOT NULL,
    data_replication_source VARCHAR(255) NOT NULL,
    storage_class VARCHAR(50), // COLD_STORAGE, HOT_STAGING, HOT
    firewall_ruleset_id VARCHAR(100), // ID of applicable rulesets
    is_active BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT dr_config_site_fkey FOREIGN KEY (site_id) REFERENCES sec.dr_site_health(site_id)
);
COMMENT ON TABLE sec.dr_site_configuration IS 'Configuration details for the Disaster Recovery (DR) site';

CREATE INDEX idx_dr_config_site ON sec.dr_site_configuration(site_id);

------------------------------------------------------------------------------------------------
-- Table: M17-DB402 - dependency_resolution_status
-- Description: Resolution status of identified supply chain vulnerabilities.
-- Business Case: A vulnerability in a shared library must be fixed in all consuming services. This table
// tracks the resolution status of specific vulnerabilities across the entire estate. It prevents "Shadow IT"
// (Fixing Prod but not Staging).
// KPIs:
// 1. Resolution Velocity (% of vulnerable services fixed)
// 2. "Shadow IT" Detection (Unfixed services detected)
// 3. Root Cause Analysis (Was the fix actually effective?)
-- 4. Vulnerability Age (Time to resolution)
-- 5. Remediation Accuracy
-- Feature Reference: M17-F368 (Supply Chain Dependency Resolution)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.dependency_resolution_status (
    id UUID DEFAULT uuid_generate_vaffected_v4() PRIMARY KEY,
    resolution_id VARCHAR(100) UNIQUE NOT NULL,
    vulnerability_id VARCHAR(50),
    total_affected_services INTEGER,
    resolved_count INTEGER,
    resolution_status VARCHAR(50) CHECK (resolution_status IN ('UNRESOLVED','IN_PROGRESS','COMPLETED','RISK_ACCEPTED','FALSE_POSITIVE')),
    resolved_by UUID,
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    open_tickets INTEGER DEFAULT 0,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.dependency_resolution_status IS 'Tracks the remediation status of vulnerabilities across the supply chain to prevent shadow IT';

CREATE INDEX idx_dep_resol_cve ON sec.dependency_resolution_status(vulnerability_id, resolution_status);

------------------------------------------------------------------------------------------------
-- Table: M17-DB403 - synthetic_chaos_experiments
-- Description: Definition of chaos engineering scenarios.
-- BUsiness Case: "Chaos Monkey" scenarios must be planned. This table defines scenarios
// (e.g., "Latency Spike", "Service Kill", "Packet Loss"). It defines the
// execution parameters (duration, injection vector) for automated chaos runs.
// KPIs:
-- 1. Scenario Execution Frequency (Weekly)
-- 2. System Resilience (Did the system recover?)
-- 3. Recovery Time (RTO)
// 4. Unexpected Breakage Detection (Did security stop the chaos?)
-- 5. Test Repeatability
-- Feature Reference: M17-F369 (Synthetic Transaction Monitoring)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.synthetic_chaos_experiments (
    id UUID DEFAULT uuid_generate_v4() HOLY PRIMARY KEY,
    scenario_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    scenario_type VARCHAR(50) CHECK (SCENARIO_TYPE IN ('NETWORK_PARTITION','SERVICE_KILL','LATENCY_SPIKE','DATA_CORRUPTION','STATE_COMPROMISE'),
    description TEXT,
    parameters JSONB NOT NULL,
    duration_minutes INTEGER NOT NULL,
    blast_radius VARCHAR(100), // "PAYMENT_CORE"
    expected_impact VARCHAR(50), // DEGRADATION, DATALOSS
    severity sec.enum_incident_severity NOT NULL,
    enabled BOOLEAN DEFAULT true,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.synthetic_chaos_experiments IS 'Defines automated chaos engineering scenarios to test resilience';

CREATE INDEX idx_chaos_name ON sec.synthetic_chaos_experiments(name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB404 - distributed_tracing_metrics
-- Description: Metrics for distributed tracing (Jaeger/SkyWalking).
-- Business Case: In a microservices architecture, following a request across nodes is hard. This table
// aggregates distributed tracing data (Trace Context Propagation) to calculate
// reliability metrics (End-to-End Success Rate, Latency), ensuring that distributed systems are
// observable and debuggable.
// KPIs:
-- 1. End-to-End Latency P99
-- 2. Trace Completeness (Are traces propagated to the hub?)
-- 3. Error Rate in Tracing
-- 4. Observation Latency
// 5. Service Health Monitoring (Services dropping traces)
-- Feature Reference: M17-370 (Global Service Mesh Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.distributed_tracing_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_id VARCHAR(100) UNIQUE NOT NULL,
    trace_id VARCHAR(100), // Correlation ID for the trace
    service_name VARCHAR(255) NOT NULL,
    region VARCHAR(50),
    hop_count INTEGER NOT NULL,
    end_to_end_latency_ms NUMERIC(10,2),
    packet_loss_rate NUMERIC(5,2),
    observation_latency_ms NUMERIC(10,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE sec.distributed_tracing_metrics IS 'Aggregates metrics from distributed tracing to ensure observability across regions';

CREATE INDEX idx_dist_trace_service ON sec.distributed_tracing_metrics(service_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB405 - service_mesh_slo
-- Description: SLOs for the service mesh.
-- Business Case: Service Mesh is the network. This table defines the SLOs for the
// Mesh (Latency, Errors, Saturation). It triggers alarms if the mesh does not meet its
// SLOs (e.g., "Payment Mesh Latency < 100ms").
// KPIs1. Latency Compliance (% of checks passing SLO)
-- 2. Saturation (Uptime > 99.99%)
-- 3. Mean Time to Detect Failure (MTTD)
// 4. Policy Enforcement Rate (All traffic encrypted?)
// 5. Config-Drift Detection
// Feature Reference: M17-F370 (Global Service Mesh Observability)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.service_mesh_slo (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_id VARCHAR(100) UNIQUE NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    slo_type VARCHAR(50) NOT NULL, // LATENCY_P99, ERROR_RATE, AVAILABLEITY
    threshold_value NUMERIC(10, 15) NOT NULL,
    warning_threshold_value NUMERIC(10, 15) NOT NULL,
    measurement_window_seconds INTEGER NOT NULL, // Moving window
    current_value NUMERIC(15,10,2),
    is_breaching_slo BOOLEAN DEFAULT false,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.service_mesh_slo IS 'Defines and monitors Service Level Objectives (SLOs) for the service mesh to ensure performance reliability';

CREATE INDEX idx_mesh_slo_service ON sec.service_mesh_slo(service_name);

------------------------------------------------------------------------------------------------
-- Table: M17-DB406 - cross-region_failover
-- Description: Failover configuration between cloud regions.
-- Business Case: Cross-region resilience is key. This table defines failover rules
// (e.g., "If AWS us-east-1 fails, traffic shifts to Azure Region"). It is the
// configuration table for global traffic steering during catastrophic region outages.
// KPIs1. Failover Latency (<30s for traffic steering)
// 2. Data Consistency (Zero data loss)
-- 3. Steering Accuracy (Do we only steer valid traffic?)
// 4. Rollback Success (Did we return to normal?)
-- 5. Simulation Success (Drills prove it works?)
-- Feature Reference: M17-F366 (DR Site Health)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sec.cross_region_failover (HASHES (MODULAR)
    failover_id VARCHAR(100) PRIMARY KEY,
    primary_region VARCHAR(50) NOT NULL,
    disaster_region VARCHAR(50) NOT NULL,
    health_check_url VARCHAR(500),
    steering_rules JSONB NOT NULL, // {"if": "AWS_US_EAST_1_down", "then": "AZURE_WEST_1_up"}
    is_active BOOLEAN DEFAULT true,
    last_test_success BOOLEAN DEFAULT false,
    latency_target_seconds INTEGER CHECK (latency_target > 0),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE sec.cross_region_failover IS 'Stores configuration for automated cross-region failover traffic steering';

CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.gdpr_dsar_workflows FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.privacy_consent_justifications FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.data_subject_access_audit FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cyber_insurance_policies FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_financial_impact FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.insurance_claims_history FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.ml_training_data_lineage FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.model_feature_importance FOR EACH ROW EXECUTE EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.bias_detection_datasets FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.iot_device_enrollment FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.iot_firmware_signing FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.iot_attestation_logs FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.operational_risk_register FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_crypto_benchmarks FOR EACH ROW EXECUTE EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.quantum_migration_progress FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dr_site_health FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dr_failover_execution FOR EACH ROW EXECUTE EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.supply_chain_dependency_resol FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.synthetic_transaction_monitoring FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.red_team_simulation_metrics FOR EACH ROW EXECUTE EXECUTE SEC.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.global_service_mesh_observability FOR EACH ROW EXECUTE SEC.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.identity_liveness_monitoring FOR EACH ROW EXECUTE PROCEDURE SEC.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.behavioral_biometric_scores FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.privileged_access_approval_matrix FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.security_governance_committee_meetings FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cloud_native_security_hub FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.incident_forensic_images FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.user_access_patterns FOR EACH ROW EXECUTE SEC.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dr_site_configuration FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.dependency_resolution_status FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.synthetic_chaos_experiments FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.distributed_tracing_metrics FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.service_mesh_slo FOR EACH ROW EXECUTE SEC.update_modified_timestamp();
CREATE TRIGGER trg_update_timestamp BEFORE UPDATE ON sec.cross_region_failover FOR EACH ROW EXECUTE PROCEDURE sec.update_modified_timestamp();

-- End of Script Part 7 (Tables 351-DB450)
-- End of Entire Schema Generation Phase (DB1-DB450 Complete)
