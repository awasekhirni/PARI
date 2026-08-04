-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition
-- Scope: First 50 Database Objects (DB001 - DB050) + Prerequisites (Enums)
-- ================================================================================

-- 1. Schema Creation
-- ================================================================================
CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA iam IS 'Identity and Access Management (IAM) module for the PARI platform, handling RBAC, ABAC, RLS, and audit logging.';

-- 2. Extensions
-- ================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides functions to generate universally unique identifiers (UUIDs).';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Provides cryptographic functions for hashing, encryption, and securing data at rest.';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows B-tree equivalent indexing using GIN, useful for indexing composite types and JSONB.';

CREATE EXTENSION IF NOT EXISTS "postgis";
COMMENT ON EXTENSION "postgis" IS 'Adds support for geographic objects, allowing location queries and geometric operations.';

-- 2.a List of Database Objects (First Batch)
-- Types: Enums (EN001-EN010), Tables (DB001-DB050)
-- Note: Enums are defined first as they are dependencies for the following tables.

-- 3. Enums
-- ================================================================================

-- Enum: EN001
-- Description: Defines the actions a subject can perform on a resource.
-- Purpose: Granular permission control.
CREATE TYPE iam.enum_access_action AS ENUM ('READ', 'WRITE', 'DELETE', 'EXECUTE', 'APPROVE', 'AUDIT');
COMMENT ON TYPE iam.enum_access_action IS 'Enumeration of valid access actions for permission checks.';

-- Enum: EN002
-- Description: The outcome of a policy evaluation.
-- Purpose: To store audit decisions clearly.
CREATE TYPE iam.enum_decision AS ENUM ('ALLOW', 'DENY', 'ABSTAIN');
COMMENT ON TYPE iam.enum_decision IS 'Decision result returned by the Policy Decision Point (PDP).';

-- Enum: EN003
-- Description: General lifecycle status for users, roles, or policies.
-- Purpose: Standardizing status fields across the system.
CREATE TYPE iam.enum_status AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'PENDING_ACTIVATION', 'LOCKED');
COMMENT ON TYPE iam.enum_status IS 'General status enumeration for IAM entities.';

-- Enum: EN004
-- Description: State of an active user session.
-- Purpose: Managing session lifecycle and security (e.g., revocation).
CREATE TYPE iam.enum_session_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED', 'TERMINATED');
COMMENT ON TYPE iam.enum_session_status IS 'Current validity state of a user session.';

-- Enum: EN005
-- Description: Supported Multi-Factor Authentication mechanisms.
-- Purpose: Enabling flexible security step-up challenges.
CREATE TYPE iam.enum_mfa_method AS ENUM ('TOTP', 'FIDO2', 'SMS', 'EMAIL', 'PUSH', 'BACKUP_CODE');
COMMENT ON TYPE iam.enum_mfa_method IS 'Available second-factor authentication methods.';

-- Enum: EN006
-- Description: Severity levels for log entries.
-- Purpose: Filtering alerts and monitoring system health.
CREATE TYPE iam.enum_log_level AS ENUM ('INFO', 'WARN', 'ERROR', 'CRITICAL', 'DEBUG');
COMMENT ON TYPE iam.enum_log_level IS 'Severity levels for audit and system logs.';

-- Enum: EN007
-- Description: Categorization of risk scores.
-- Purpose: Triggering automated responses based on risk thresholds.
CREATE TYPE iam.enum_risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
COMMENT ON TYPE iam.enum_risk_level IS 'Qualitative representation of calculated risk scores.';

-- Enum: EN008
-- Description: Categorization of roles.
-- Purpose: Distinguishing between system-managed and user-defined roles.
CREATE TYPE iam.enum_role_type AS ENUM ('SYSTEM', 'CUSTOM', 'DYNAMIC', 'RESTRICTED');
COMMENT ON TYPE iam.enum_role_type IS 'Type classification for security roles.';

-- Enum: EN009
-- Description: States in the Just-In-Time access workflow.
-- Purpose: Tracking approval requests.
CREATE TYPE iam.enum_jit_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED');
COMMENT ON TYPE iam.enum_jit_status IS 'Status tracking for temporary privilege elevation requests.';

-- Enum: EN010
-- Description: Data types for dynamic ABAC attributes.
-- Purpose: Ensuring type safety in policy evaluation.
CREATE TYPE iam.enum_attr_type AS ENUM ('STRING', 'INTEGER', 'FLOAT', 'BOOLEAN', 'JSON', 'DATE', 'IP');
COMMENT ON TYPE iam.enum_attr_type IS 'Supported data types for user and resource attributes in ABAC.';

-- Trigger Function for Auditing (Created once, used everywhere)
CREATE OR REPLACE FUNCTION iam.update_modified_column()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.updated_by = CURRENT_USER; -- Or session user logic
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;
COMMENT ON FUNCTION iam.update_modified_column() IS 'Generic trigger function to automatically update the updated_at and updated_by columns.';

-- 4. DDL Statements (Tables DB001 - DB050)
-- ================================================================================

-- DB001: iam.users
-- Description: Core identity store for all system actors.
-- Business Case: The `users` table is the cornerstone of the IAM module. It stores the fundamental identity records for all human and non-human actors interacting with the PARI platform. By centralizing identity data here, we ensure a single source of truth for authentication and authorization. This table supports the principle of least privilege by linking users to roles and attributes, enabling granular access control. It is designed to handle high concurrency for login processes and integrates deeply with the audit system to track lifecycle events like creation, suspension, and deletion. The inclusion of status fields allows for immediate account lockdowns in case of detected anomalies, which is critical for the Zero Trust architecture mandated by the PARI system.
-- KPIs: User creation latency, Authentication success rate, Account lockout frequency.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS iam.users (
    user_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255), -- Nullable if using external IdP
    status iam.enum_status NOT NULL DEFAULT 'PENDING_ACTIVATION',
    is_super_user BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMP WITH TIME ZONE,

    -- Profile Information
    full_name VARCHAR(255),
    department VARCHAR(100),
    job_title VARCHAR(100),
    locale VARCHAR(10) DEFAULT 'en_US',

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE -- Soft delete support
);

COMMENT ON TABLE iam.users IS 'Core identity store for all system actors including humans and service accounts.';

-- DB002: iam.roles
-- Description: Definition of security roles.
-- Business Case: Roles provide the structural hierarchy necessary for RBAC. This table defines the "Job Functions" within the PARI ecosystem (e.g., Cashier, Auditor, Compliance Officer). By abstracting permissions into roles, we simplify administrative overhead—managing a few roles is far more efficient than managing permissions for thousands of individual users. The table supports role hierarchy (via DB006) and distinguishes between system-defined roles (which are immutable to prevent accidental deletion of critical access paths) and custom roles created by administrators. This structure is essential for maintaining the scalability of the access control system as the organization grows.
-- KPIs: Role assignment count, System role integrity checks, Role modification frequency.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS iam.roles (
    role_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    description TEXT,
    role_type iam.enum_role_type DEFAULT 'CUSTOM',
    is_system BOOLEAN DEFAULT FALSE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

COMMENT ON TABLE iam.roles IS 'Definitions of security roles used for RBAC grouping.';

-- DB003: iam.permissions
-- Description: Atomic permissions for resources/actions.
-- Business Case: Permissions are the atomic units of access control, defining exactly what can be done (e.g., `transaction:read`, `user:delete`). This table decouples the definition of capabilities from the roles that use them. By storing permissions centrally, the system supports dynamic policy evaluation and ensures that every action performed on the PARI platform is explicitly authorized. This granularity is required for the strict compliance environments (CMMI Level 5, GDPR) where the PARI platform operates, allowing auditors to trace specific rights to specific business needs.
-- KPIs: Total permission count, Permission usage frequency, Orphaned permission rate.
-- Feature Reference: F002
CREATE TABLE IF NOT EXISTS iam.permissions (
    perm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource VARCHAR(100) NOT NULL,
    action iam.enum_access_action NOT NULL,
    description TEXT,

    -- Constraint to ensure unique combination of resource and action
    CONSTRAINT uk_resource_action UNIQUE (resource, action),

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

COMMENT ON TABLE iam.permissions IS 'Atomic permissions defining specific actions on specific resources.';

-- DB004: iam.user_roles
-- Description: Mapping of users to roles.
-- Business Case: This junction table implements the many-to-many relationship between users and roles. It is the primary mechanism for granting access. By storing the `assigned_at` timestamp and `assigned_by` user ID, we maintain a complete provenance trail for every privilege granted. This is crucial for forensic investigations ("Who gave this user access?") and for implementing automated de-provisioning workflows (e.g., removing all roles upon employee termination). The table allows for a user to hold multiple roles simultaneously, supporting complex business scenarios where an individual might act in both a functional and administrative capacity.
-- KPIs: Assignment latency, Role assignment accuracy, Orphaned user-role count.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS iam.user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE, -- Supports temporary role grants

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.user_roles IS 'Mapping table assigning roles to users with audit trail.';

-- DB005: iam.role_permissions
-- Description: Granting permissions to roles.
-- Business Case: This table links roles to their constituent permissions. It defines the capabilities associated with a specific job function. By centralizing this mapping, the system can quickly determine the full permission set of a role during login or session validation. The audit columns here are critical for change management, ensuring that any escalation of privileges (adding a permission to a role) is logged with accountability. This table enables the principle of aggregation, where a user inherits all permissions attached to their assigned roles.
-- KPIs: Role permission count, Permission modification rate.
-- Feature Reference: F001
CREATE TABLE IF NOT EXISTS iam.role_permissions (
    role_id UUID NOT NULL,
    perm_id UUID NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID NOT NULL,

    PRIMARY KEY (role_id, perm_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_perm FOREIGN KEY (perm_id) REFERENCES iam.permissions(perm_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.role_permissions IS 'Mapping table granting permissions to roles.';

-- DB006: iam.role_hierarchy
-- Description: Nested role relationships.
-- Business Case: To reduce administrative overhead, this table defines a hierarchy where one role inherits permissions from another (e.g., a "Super-Admin" inherits all permissions of "Admin"). This transitive relationship allows for a clean, tree-like structure of privileges. Implementing this at the database level ensures that inheritance logic is consistent and performant. It prevents the need to manually duplicate permissions across multiple similar roles, reducing the risk of configuration errors (e.g., forgetting to assign a critical permission to a new sub-role).
-- KPIs: Hierarchy depth, Inheritance resolution time.
-- Feature Reference: F003
CREATE TABLE IF NOT EXISTS iam.role_hierarchy (
    parent_role_id UUID NOT NULL,
    child_role_id UUID NOT NULL,

    PRIMARY KEY (parent_role_id, child_role_id),
    CONSTRAINT fk_role_hierarchy_parent FOREIGN KEY (parent_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_role_hierarchy_child FOREIGN KEY (child_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT chk_no_self_reference CHECK (parent_role_id <> child_role_id)
);

COMMENT ON TABLE iam.role_hierarchy IS 'Defines inheritance relationships between roles (Parent -> Child).';

-- DB007: iam.user_attributes
-- Description: Dynamic ABAC attributes for users.
-- Business Case: In an ABAC model, static roles are not enough. This table stores dynamic attributes (e.g., `clearance_level`, `department`, `cost_center`, `manager_id`) that are evaluated at runtime to make access decisions. This supports context-aware policies such as "A user can only access data if their `department` matches the data's `owner_department`". The time-based validity (`valid_from`, `valid_to`) allows for temporary attribute changes, such as a short-term elevation in security clearance during a specific project, without permanently altering the user's core profile.
-- KPIs: Attribute sync latency, Query performance on attribute lookups.
-- Feature Reference: F004
CREATE TABLE IF NOT EXISTS iam.user_attributes (
    user_id UUID NOT NULL,
    attr_name VARCHAR(100) NOT NULL,
    attr_value JSONB NOT NULL, -- Flexible storage for different types
    attr_type iam.enum_attr_type NOT NULL DEFAULT 'STRING',
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_to TIMESTAMP WITH TIME ZONE,

    PRIMARY KEY (user_id, attr_name, valid_from),
    CONSTRAINT fk_user_attributes_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT chk_attr_time_range CHECK (valid_to IS NULL OR valid_from < valid_to)
);

COMMENT ON TABLE iam.user_attributes IS 'Dynamic ABAC attributes assigned to users with time-based validity.';

-- DB008: iam.sessions
-- Description: Active session tracking.
-- Business Case: This table maintains the state of all active user sessions. It is critical for security enforcement, allowing the system to revoke sessions immediately upon privilege loss, password change, or administrative lockdown. By tracking IP, User-Agent, and device fingerprint, the system can detect session hijacking attempts (e.g., impossible travel). The `expires_at` field ensures that sessions have a hard limit, enforcing the "Zero Standing Privilege" philosophy by forcing periodic re-authentication. High-performance access to this table is required for every API call to validate session validity.
-- KPIs: Session validation latency, Concurrent active sessions, Revocation propagation speed.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- Hash of the JWT or session token
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    status iam.enum_session_status DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT chk_session_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE iam.sessions IS 'Tracks active user sessions for security and revocation purposes.';

-- DB009: iam.access_logs
-- Description: Immutable audit log of access decisions.
-- Business Case: The `access_logs` table is the source of truth for all access events within the PARI ecosystem. It records every Allow/Deny decision made by the Policy Decision Point. This is mandatory for regulatory compliance (GDPR Article 30, SOX, PCI-DSS) and for forensic analysis following a security incident. The log includes the full context (`details_json`) of the request, allowing auditors to reconstruct the exact state of the system at the time of access. The table is designed as an append-only ledger, and ideally, data would be moved to cold storage after a retention period, but recent hot data remains here for real-time monitoring.
-- KPIs: Log ingestion rate, Query response time for audits, Data integrity verification.
-- Feature Reference: F015
CREATE TABLE IF NOT EXISTS iam.access_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    session_id UUID,
    resource VARCHAR(255) NOT NULL,
    action iam.enum_access_action NOT NULL,
    decision iam.enum_decision NOT NULL,
    policy_id UUID, -- Reference to the policy that made the decision
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    details_json JSONB, -- Stores dynamic context like attributes, env vars, etc.
    risk_score NUMERIC(5,2) CHECK (risk_score >= 0 AND risk_score <= 100),

    CONSTRAINT fk_access_logs_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_access_logs_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE SET NULL
);

COMMENT ON TABLE iam.access_logs IS 'Immutable audit trail of all authorization decisions and access attempts.';

-- DB010: iam.jit_requests
-- Description: Just-in-Time access requests.
-- Business Case: To minimize standing privileges, users request temporary access rights via this table. It formalizes the approval workflow, requiring a business justification (`justification`) and an explicit approval (`approved_by`). This workflow ensures that elevated privileges are only granted when necessary and for a defined duration (`expires_at`). By recording the requester, approver, and duration, the system creates a high-fidelity audit trail that satisfies CMMI Level 5 requirements for accountability. This table is central to the "Zero Trust" implementation, ensuring that admin accounts are not constantly powerful.
-- KPIs: Approval time, JIT elevation frequency, Justification quality (via NLP).
-- Feature Reference: F010
CREATE TABLE IF NOT EXISTS iam.jit_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    target_role_id UUID NOT NULL,
    justification TEXT NOT NULL,
    status iam.enum_jit_status DEFAULT 'PENDING',
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    rejection_reason TEXT,

    CONSTRAINT fk_jit_requests_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_jit_requests_role FOREIGN KEY (target_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_jit_requests_approver FOREIGN KEY (approved_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);

COMMENT ON TABLE iam.jit_requests IS 'Workflow table for requesting and approving temporary privilege elevation.';

-- DB011: iam.policies
-- Description: Central storage for ABAC policy rules.
-- Business Case: This table stores the logic that drives the ABAC engine. Policies define complex rules such as "Allow access IF user.role='Auditor' AND data.location='EU' AND time BETWEEN 09:00 AND 17:00". The `condition_json` column stores these rules in a structured format (e.g., CEL or JSON Logic) that the Policy Decision Point can evaluate. By centralizing policies, the system supports dynamic updates without code deployment, enabling compliance officers to react instantly to new regulations. The `priority` field ensures deterministic conflict resolution when multiple policies match a request.
-- KPIs: Policy evaluation latency, Policy modification frequency, Conflict rate.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS iam.policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    effect VARCHAR(20) NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    condition_json JSONB NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 0 CHECK (priority >= 0),
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit Columns
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);

COMMENT ON TABLE iam.policies IS 'Stores ABAC policy definitions for access control logic.';

-- DB012: iam.policy_conflicts
-- Description: Detected conflicts in policy logic.
-- Business Case: As the number of policies grows, conflicts (e.g., one policy says Allow, another says Deny with the same priority) are inevitable. This table automatically logs these detected conflicts so that administrators can resolve them before they impact production access. It serves as a health check for the access control system, highlighting areas where the rule set is ambiguous. Resolving these conflicts is critical for maintaining the deterministic behavior required by the security model.
-- KPIs: Conflict detection time, Time to resolution, Active conflict count.
-- Feature Reference: F023
CREATE TABLE IF NOT EXISTS iam.policy_conflicts (
    conflict_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_a_id UUID NOT NULL,
    policy_b_id UUID NOT NULL,
    description TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_policy_conflicts_a FOREIGN KEY (policy_a_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_policy_conflicts_b FOREIGN KEY (policy_b_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.policy_conflicts IS 'Logs detected conflicts between ABAC policies for resolution.';

-- DB013: iam.devices
-- Description: Registered devices for trust scoring.
-- Business Case: In a Zero Trust environment, the device is as important as the user. This table tracks known devices (fingerprinted via browser signature or mobile ID) and assigns a `trust_score`. A high trust score might lower friction (skip MFA), while a low score or new device triggers step-up authentication. Storing this history allows the system to detect anomalies like a sudden login from a device that hasn't been used in months, potentially indicating account takeover. This table is essential for contextual authentication.
-- KPIs: Trust score calculation accuracy, Device registration rate.
-- Feature Reference: F014
CREATE TABLE IF NOT EXISTS iam.devices (
    device_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    trust_score NUMERIC(3,2) DEFAULT 0.5 CHECK (trust_score >= 0 AND trust_score <= 1),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_devices_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT uk_device_fingerprint UNIQUE (fingerprint)
);

COMMENT ON TABLE iam.devices IS 'Registers and tracks trust scores for user devices.';

-- DB014: iam.geo_fences
-- Description: Geographic boundaries for access.
-- Business Case: This table enforces data sovereignty and physical security constraints. By defining polygons (geofences) or countries, the system can automatically deny access requests originating from unauthorized locations (e.g., blocking access to EU data from a non-EU IP). This is vital for complying with cross-border data transfer laws. The integration with PostGIS allows for complex spatial queries, such as checking if a user's current GPS coordinates fall within a specific allowed zone for a high-security facility.
-- KPIs: Geofence lookup latency, Violation detection rate.
-- Feature Reference: F013
CREATE TABLE IF NOT EXISTS iam.geo_fences (
    fence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    fence_type VARCHAR(50) NOT NULL CHECK (fence_type IN ('ALLOW', 'DENY')),
    geo_polygon GEOMETRY(POLYGON, 4326), -- PostGIS geometry
    country_codes VARCHAR(2)[], -- Array of ISO country codes for simpler checks
    priority INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);

COMMENT ON TABLE iam.geo_fences IS 'Defines geographic access control policies using PostGIS.';

-- DB015: iam.audit_masks
-- Description: Config for dynamic data masking.
-- Business Case: To enforce privacy (e.g., masking PANs or SSNs), this table defines which roles see which data and in what format (redacted, partial, hashed). When a query is executed, the Policy Enforcement Point consults this table to rewrite the SELECT statement on the fly. This ensures that sensitive PII is never exposed to unauthorized users, not even in the result set. It is a key component of the PARI platform's privacy promise, ensuring that a merchant sees a masked card number while a bank auditor sees the full number.
-- KPIs: Masking application overhead, Rule coverage.
-- Feature Reference: F007
CREATE TABLE IF NOT EXISTS iam.audit_masks (
    mask_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID NOT NULL,
    table_name VARCHAR(255) NOT NULL,
    column_name VARCHAR(255) NOT NULL,
    mask_function VARCHAR(100) NOT NULL, -- e.g., partial_mask, full_redact
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_masks_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.audit_masks IS 'Configuration for dynamic data masking based on user roles.';

-- DB016: iam.eidas_credentials
-- Description: Links PARI accounts to eIDAS identifiers.
-- Business Case: To support the EU Digital Identity Wallet (eIDAS 2.0), this table maps a local PARI user to their sovereign identity credentials. It stores the `eidas_id` and the country of issuance, allowing the system to validate signatures against national registries. This eliminates the need for passwords for EU citizens, relying instead on cryptographically verified assertions. This integration is a regulatory requirement for operating within the European financial sector.
-- KPIs: eIDAS verification latency, Credential linkage success rate.
-- Feature Reference: F008
CREATE TABLE IF NOT EXISTS iam.eidas_credentials (
    cred_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    eidas_id VARCHAR(255) NOT NULL UNIQUE,
    country CHAR(2) NOT NULL,
    certificate_pem TEXT,
    last_verified_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_eidas_credentials_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.eidas_credentials IS 'Links local users to EU Digital Identity Wallet credentials.';

-- DB017: iam.step_up_challenges
-- Description: MFA challenges issued.
-- Business Case: When the system detects a high-risk action (e.g., accessing sensitive audit logs) or an anomalous context, it issues a step-up challenge. This table tracks the lifecycle of that challenge (issued -> passed/failed). It ensures that MFA prompts are tied to a specific session and action, preventing replay attacks. By tracking the `challenge_type` (e.g., FIDO2, SMS), the system can analyze which methods are most reliable or frictionless for users.
-- KPIs: Step-up success rate, Challenge completion time.
-- Feature Reference: F009
CREATE TABLE IF NOT EXISTS iam.step_up_challenges (
    challenge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    challenge_type iam.enum_mfa_method NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PASSED', 'FAILED', 'EXPIRED')),
    payload JSONB, -- Stores nonce, encrypted challenge data
    passed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_step_up_challenges_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.step_up_challenges IS 'Tracks Multi-Factor Authentication challenges for step-up security.';

-- DB018: iam.access_reviews
-- Description: Periodic review campaigns.
-- Business Case: Governance requires that access rights be reviewed periodically to prevent "privilege creep". This table stores the results of these reviews—certifying whether a user still needs a specific role. It links a manager (reviewer) to a user and role, capturing their decision (Certify/Revoke). This automated workflow ensures that the organization maintains a clean least-privilege state over time, a key requirement for ISO 27001 and SOC2 audits.
-- KPIs: Review completion rate, Access revocation count via reviews.
-- Feature Reference: F079
CREATE TABLE IF NOT EXISTS iam.access_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reviewer_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    decision VARCHAR(20) CHECK (decision IN ('CERTIFIED', 'REVOKED', 'PENDING')),
    reviewed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_access_reviews_reviewer FOREIGN KEY (reviewer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_reviews_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_reviews_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.access_reviews IS 'Stores results of periodic access review and certification campaigns.';

-- DB019: iam.breach_attempts
-- Description: Failed login tracking.
-- Business Case: This table is a frontline defense against brute force and credential stuffing attacks. It logs every failed login attempt along with metadata (IP, username, reason). The data feeds into the AI anomaly detection engine to identify patterns (e.g., 100 failures on a specific username from 100 different IPs) and trigger automated lockouts or IP bans. It is essential for maintaining the availability and integrity of the authentication service.
-- KPIs: Detection accuracy, False positive rate (blocking legit users).
-- Feature Reference: F027
CREATE TABLE IF NOT EXISTS iam.breach_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    failure_reason VARCHAR(255) NOT NULL,
    user_agent TEXT
);

COMMENT ON TABLE iam.breach_attempts IS 'Logs failed authentication attempts for security analysis and lockout logic.';

-- DB020: iam.api_keys
-- Description: API keys for service accounts.
-- Business Case: Machine-to-machine communication (M2M) relies on API keys rather than interactive logins. This table stores hashed keys alongside their allowed scopes (e.g., `transactions:read`) and rate limits. It enables the system to enforce strict boundaries on what external services or internal bots can do. By tracking `expires_at`, the system ensures that keys are rotated regularly, minimizing the blast radius if a key is leaked.
-- KPIs: Key validation latency, Scope enforcement success.
-- Feature Reference: F096
CREATE TABLE IF NOT EXISTS iam.api_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    owner_id UUID NOT NULL, -- Could be a user_id or a service entity
    scopes TEXT[] NOT NULL, -- Array of allowed scopes
    rate_limit INTEGER DEFAULT 100, -- Requests per minute
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_api_keys_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.api_keys IS 'Manages API keys for programmatic access and service accounts.';

-- DB021: iam.consent_records
-- Description: User consent tracking.
-- Business Case: GDPR requires explicit user consent for data processing. This table acts as a digital ledger of that consent. It records *what* was consented to (purpose), *when* it was given, and *if/when* it was withdrawn. This table is the first point of reference for Data Protection Officers (DPOs) to prove compliance during audits. It integrates directly with the ABAC engine to block processing if valid consent is not present for a specific purpose.
-- KPIs: Consent capture rate, Withdrawal processing time.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS iam.consent_records (
    consent_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    purpose VARCHAR(255) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    legal_basis VARCHAR(100), -- e.g., 'contract', 'legitimate_interest'

    CONSTRAINT fk_consent_records_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.consent_records IS 'Tracks user consent for data processing purposes (GDPR compliance).';

-- DB022: iam.secrets
-- Description: Encrypted storage for sensitive vault data.
-- Business Case: This table acts as a secure vault for storing sensitive artifacts that need to be referenced by the IAM system but not exposed in plain text, such as OAuth client secrets, encryption keys, or recovery tokens. It uses `pgcrypto` to store an encrypted value (`encrypted_value`) and a nonce. By centralizing secret storage, the system can enforce strict access controls and audit trails for who retrieves secrets, which is critical for operational security.
-- KPIs: Secret retrieval latency, Encryption/decryption throughput.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS iam.secrets (
    secret_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    encrypted_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL, -- For GCM encryption
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE,
    accessed_by UUID
);

COMMENT ON TABLE iam.secrets IS 'Encrypted storage for sensitive system secrets and keys.';

-- DB023: iam.attribute_changes
-- Description: History of user attribute modifications.
-- Business Case: To maintain a chain of custody for identity data, this table logs every change to user attributes (DB007). It stores the old and new values, allowing auditors to see the history of a clearance level change or a department transfer. This non-repudiation is vital for investigating security incidents where an attacker might have modified attributes to gain access. It ensures that any state change is reversible and traceable.
-- KPIs: Audit completeness, History query performance.
-- Feature Reference: F004
CREATE TABLE IF NOT EXISTS iam.attribute_changes (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    attr_name VARCHAR(100) NOT NULL,
    old_val JSONB,
    new_val JSONB,
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attr_changes_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.attribute_changes IS 'Audit log tracking history of changes to user ABAC attributes.';

-- DB024: iam.rule_exclusions
-- Description: Explicit deny rules (Blacklisting).
-- Business Case: While ABAC uses "Allow" policies, specific edge cases or sanctions require "Explicit Deny" entries that cannot be overridden. This table handles negative access control, such as blocking a specific user from accessing the HR system entirely, or blacklisting a compromised IP address. It ensures that in the event of a policy conflict, the Deny takes precedence, which is a standard security best practice (Fail Safe).
-- KPIs: Deny rule effectiveness, Rule update propagation time.
-- Feature Reference: F102
CREATE TABLE IF NOT EXISTS iam.rule_exclusions (
    exclusion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    resource_id VARCHAR(255),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT fk_rule_exclusions_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.rule_exclusions IS 'Stores explicit deny rules to override standard Allow policies.';

-- DB025: iam.session_locks
-- Description: Admin-initiated session locks.
-- Business Case: In response to a security incident, administrators may need to immediately freeze a specific session without deleting it (preserving evidence). This table marks sessions as `LOCKED`, preventing any further actions while allowing forensic analysis of the session state. It provides a granular control mechanism beyond just "killing" a user, enabling a "hold" state for investigation.
-- KPIs: Lock application latency, Unlock processing time.
-- Feature Reference: F044
CREATE TABLE IF NOT EXISTS iam.session_locks (
    lock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    locked_by UUID NOT NULL,

    CONSTRAINT fk_session_locks_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.session_locks IS 'Administrative locks placed on specific user sessions for security purposes.';

-- DB026: iam.dynamic_groups
-- Description: User-defined or computed groups.
-- Business Case: Static roles are often too rigid. This table defines dynamic groups based on criteria (e.g., "All users in 'Finance' AND 'Level 5+'"). The `criteria_json` defines the logic. Users are dynamically added to these groups at runtime by the IAM engine, simplifying management. For example, instead of manually adding 100 new hires to the "New Employees" group, the logic automatically includes them. This significantly reduces administrative overhead in large organizations.
-- KPIs: Group calculation accuracy, Group evaluation performance.
-- Feature Reference: F111
CREATE TABLE IF NOT EXISTS iam.dynamic_groups (
    group_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    criteria_json JSONB NOT NULL, -- Logic defining group membership
    owner_id UUID NOT NULL, -- Admin responsible for the group
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dynamic_groups_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.dynamic_groups IS 'Defines group membership based on dynamic ABAC criteria.';

-- DB027: iam.user_groups
-- Description: Mapping users to dynamic groups.
-- Business Case: This materialized view (or cache table) maps users to the dynamic groups defined in DB026. While group membership is calculated logically, caching the result in this table allows for performant lookups during authorization checks. It decouples the heavy evaluation logic from the hot path of request processing. The table is refreshed periodically or upon attribute change.
-- KPIs: Cache refresh rate, Lookup speed.
-- Feature Reference: F111
CREATE TABLE IF NOT EXISTS iam.user_groups (
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, group_id),
    CONSTRAINT fk_user_groups_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_groups_group FOREIGN KEY (group_id) REFERENCES iam.dynamic_groups(group_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.user_groups IS 'Materialized mapping of users to computed dynamic groups.';

-- DB028: iam.risk_scores
-- Description: Historical risk scores for AI model.
-- Business Case: Access control decisions are increasingly risk-based. This table stores the history of risk scores calculated for users. This historical data is crucial for retraining and tuning the AI anomaly detection models. It allows analysts to spot trends (e.g., "User X's risk score has been slowly increasing over 3 months") and take proactive action before a threshold breach occurs.
-- KPIs: Score calculation frequency, Model input volume.
-- Feature Reference: F054
CREATE TABLE IF NOT EXISTS iam.risk_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    score NUMERIC(5,2) NOT NULL CHECK (score >= 0 AND score <= 100),
    factors_json JSONB, -- Breakdown of why score is high (e.g., 'new_ip': 20, 'off_hours': 10)
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_risk_scores_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.risk_scores IS 'Historical log of user risk scores calculated by the AI engine.';

-- DB029: iam.anomaly_alerts
-- Description: Generated alerts from AI engine.
-- Business Case: When the AI detects an anomaly (impossible travel, bulk data export), it generates an alert in this table. This serves as the queue for the Security Operations Center (SOC) analysts. It captures the severity and the context of the anomaly, allowing for triage. The `status` field tracks the lifecycle from DETECTED to INVESTIGATING to RESOLVED, ensuring no potential threat is lost.
-- KPIs: Alert fidelity (True Positive Rate), Mean Time to Respond (MTTR).
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.anomaly_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    anomaly_type VARCHAR(100) NOT NULL,
    severity iam.enum_risk_level NOT NULL,
    status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    details_json JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_anomaly_alerts_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);

COMMENT ON TABLE iam.anomaly_alerts IS 'Stores security alerts generated by the AI anomaly detection engine.';

-- DB030: iam.cert_revocation_list
-- Description: Cached CRLs for external CAs.
-- Business Case: To validate x509 certificates (e.g., from eIDAS or mTLS), the system must check against Certificate Revocation Lists (CRLs). Downloading CRLs in real-time is too slow. This table caches the CRLs, mapping serial numbers to revocation dates. This allows for high-performance certificate validation while ensuring that compromised certificates are rejected immediately upon cache update.
-- KPIs: Cache freshness, Revocation check speed.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS iam.cert_revocation_list (
    crl_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    issuer VARCHAR(255) NOT NULL,
    serial_number VARCHAR(255) NOT NULL,
    revocation_date TIMESTAMP WITH TIME ZONE,

    CONSTRAINT uk_crl_serial UNIQUE (issuer, serial_number)
);

COMMENT ON TABLE iam.cert_revocation_list IS 'Cache for external Certificate Revocation Lists (CRL) to speed up validation.';

-- DB031: iam.access_request_bundles
-- Description: Bundled permission requests.
-- Business Case: Users often need multiple permissions to complete a single task (e.g., onboarding). This table groups multiple permission requests into a single "bundle" workflow. Instead of approving 10 separate requests, a manager approves one bundle. This improves the User Experience (UX) for requestors and reduces the approval burden on managers, streamlining the access request process.
-- KPIs: Request completion time, Bundle approval rate.
-- Feature Reference: F068
CREATE TABLE IF NOT EXISTS iam.access_request_bundles (
    bundle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requestor_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_access_request_bundles_requestor FOREIGN KEY (requestor_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.access_request_bundles IS 'Groups multiple permission requests into a single approval workflow.';

-- DB032: iam.bundle_items
-- Description: Items inside a bundle request.
-- Business Case: This junction table links a bundle (DB031) to the specific permissions or roles being requested. It ensures that when the parent bundle is approved, all constituent items are granted. This structure allows for atomicity—either the whole bundle is granted or none of it is, preventing partial access states that could break business processes.
-- KPIs: Item processing success rate.
-- Feature Reference: F068
CREATE TABLE IF NOT EXISTS iam.bundle_items (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bundle_id UUID NOT NULL,
    permission_id UUID, -- Link to permission OR role depending on design
    role_id UUID,

    CONSTRAINT fk_bundle_items_bundle FOREIGN KEY (bundle_id) REFERENCES iam.access_request_bundles(bundle_id) ON DELETE CASCADE,
    CONSTRAINT fk_bundle_items_perm FOREIGN KEY (permission_id) REFERENCES iam.permissions(perm_id) ON DELETE CASCADE,
    CONSTRAINT fk_bundle_items_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT chk_bundle_item_target CHECK (permission_id IS NOT NULL OR role_id IS NOT NULL)
);

COMMENT ON TABLE iam.bundle_items IS 'Individual permission or role requests inside a bundle.';

-- DB033: iam.tenant_configs
-- Description: Multi-tenant isolation settings.
-- Business Case: The PARI platform serves multiple tenants (e.g., different banks or regions). This table stores tenant-specific configurations, such as password policies, retention periods, or branding settings. It enables a SaaS multi-tenancy model where data is logically isolated but runs on shared infrastructure. The `settings_json` column provides flexibility to add new config options without schema changes.
-- KPIs: Config lookup latency, Tenant isolation verification.
-- Feature Reference: F047
CREATE TABLE IF NOT EXISTS iam.tenant_configs (
    tenant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    settings_json JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE iam.tenant_configs IS 'Stores configuration settings for multi-tenant isolation.';

-- DB034: iam.offline_tokens
-- Description: Short-lived offline revocation tokens.
-- Business Case: For field agents operating in disconnected environments, standard online revocation is impossible. This table stores short-lived tokens that represent the "allowed state" of a user at the time of disconnection. The local device checks this token periodically. If the token expires, access is cut. This provides a balance between offline functionality and security control.
-- KPIs: Token expiration handling, Offline authorization rate.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS iam.offline_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    expiry_seq INTEGER NOT NULL, -- Sequence number to prevent replay of old tokens
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_offline_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.offline_tokens IS 'Tokens used to handle authorization in offline/disconnected modes.';

-- DB035: iam.policy_simulations
-- Description: Results of policy dry-runs.
-- Business Case: Changing access policies is risky. This table stores the results of "what-if" simulations run before deploying changes. It records which users would be granted or denied access under the new policy. This allows administrators to catch unintended side effects (e.g., locking out the CEO) before they reach production, ensuring business continuity and policy correctness.
-- KPIs: Simulation accuracy, Pre-production issue catch rate.
-- Feature Reference: F017
CREATE TABLE IF NOT EXISTS iam.policy_simulations (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    user_id UUID NOT NULL,
    result VARCHAR(20) CHECK (result IN ('ALLOW', 'DENY')),
    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_policy_sims_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_policy_sims_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.policy_simulations IS 'Stores results of dry-run policy simulations before deployment.';

-- DB036: iam.biometric_templates
-- Description: Encrypted biometric data.
-- Business Case: To support passwordless login (e.g., FaceID), biometric templates must be stored securely. This table stores the encrypted template. Crucially, the actual biometric image is never stored, only the mathematical template. This table is subject to the highest security controls due to the sensitive nature of biometric data (immutable personal identifier). It enables the "Passive Detection" feature mentioned in the module summary.
-- KPIs: Biometric match accuracy, Template storage security.
-- Feature Reference: F131
CREATE TABLE IF NOT EXISTS iam.biometric_templates (
    bio_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    template_encrypted BYTEA NOT NULL,
    template_type VARCHAR(50) NOT NULL, -- e.g., face, voice, fingerprint
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bio_templates_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.biometric_templates IS 'Securely stores encrypted biometric templates for authentication.';

-- DB037: iam.data_labels
-- Description: Labels for data classification.
-- Business Case: Data must be classified (e.g., PUBLIC, CONFIDENTIAL, RESTRICTED) to enforce ABAC. This table stores these labels and links them to resources. The Policy Engine checks these labels to determine if a user's clearance matches the data's sensitivity. This is foundational for automated data governance and preventing data leakage (e.g., preventing a Confidential file from being emailed to a Public account).
-- KPIs: Label coverage percentage, Label enforcement accuracy.
-- Feature Reference: F133
CREATE TABLE IF NOT EXISTS iam.data_labels (
    label_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(255) NOT NULL,
    label_name VARCHAR(100) NOT NULL, -- e.g., 'CONFIDENTIAL'
    confidence NUMERIC(3,2), -- If label was auto-detected by AI
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE iam.data_labels IS 'Stores classification labels assigned to data resources for ABAC enforcement.';

-- DB038: iam.delegated_access
-- Description: Temporary delegation records.
-- Business Case: Managers often need to delegate authority temporarily (e.g., during vacation). This table records such delegations—User A delegates Role B to User C for a specific duration. It ensures that the delegation is time-bound and auditable. This prevents permanent privilege creep while allowing business continuity during absences.
-- KPIs: Delegation expiration rate, Revocation speed.
-- Feature Reference: F066
CREATE TABLE IF NOT EXISTS iam.delegated_access (
    delegation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    delegator_id UUID NOT NULL,
    delegatee_id UUID NOT NULL,
    role_id UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_delegated_access_delegator FOREIGN KEY (delegator_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_delegated_access_delegatee FOREIGN KEY (delegatee_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_delegated_access_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.delegated_access IS 'Records temporary delegation of roles from one user to another.';

-- DB039: iam.break_glass_logs
-- Description: Audit of emergency overrides.
-- Business Case: In emergencies (e.g., system failure), standard access controls might hinder recovery. "Break Glass" allows users to override controls temporarily. This table logs every instance of break glass usage—WHO did it, WHY (reason), and for HOW LONG. This is heavily scrutinized by auditors, so the data integrity and completeness are paramount.
-- KPIs: Break glass usage frequency, Override duration.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS iam.break_glass_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    reason TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    initiated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_break_glass_logs_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.break_glass_logs IS 'Audits emergency access overrides (break-glass events).';

-- DB040: iam.resource_tags
-- Description: Tags for ABAC matching.
-- Business Case: Resources often have arbitrary metadata (e.g., `project=alpha`, `region=eu-west`). This table stores these key-value tags. The ABAC engine queries this table to match user attributes against resource tags (e.g., User has `region=eu-west`, Resource has `region=eu-west` -> ALLOW). It provides a flexible way to secure resources without hardcoding rules for every single resource ID.
-- KPIs: Tag lookup performance, Tag assignment volume.
-- Feature Reference: F067
CREATE TABLE IF NOT EXISTS iam.resource_tags (
    tag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(255) NOT NULL,
    tag_key VARCHAR(100) NOT NULL,
    tag_value VARCHAR(255) NOT NULL,

    CONSTRAINT uk_resource_tags UNIQUE (resource_id, tag_key, tag_value)
);

COMMENT ON TABLE iam.resource_tags IS 'Stores key-value tags associated with resources for dynamic ABAC matching.';

-- DB041: iam.access_stats
-- Description: Aggregated statistics for dashboard.
-- Business Case: Security dashboards require high-performance queries for metrics like "Failed logins by role" or "Access count by day". Querying raw logs (DB009) is too slow. This table aggregates this data (Materialized View concept). It is updated periodically (e.g., hourly) to provide near real-time insights without impacting the performance of the transactional logging system.
-- KPIs: Dashboard load time, Data freshness.
-- Feature Reference: F016
CREATE TABLE IF NOT EXISTS iam.access_stats (
    stat_date DATE NOT NULL,
    role_id UUID,
    access_count BIGINT DEFAULT 0,
    denial_count BIGINT DEFAULT 0,
    PRIMARY KEY (stat_date, role_id),

    CONSTRAINT fk_access_stats_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.access_stats IS 'Aggregated access statistics for reporting and dashboarding.';

-- DB042: iam.notification_queue
-- Description: Queue for access alerts.
-- Business Case: Asynchronous communication (email, SMS) is required for alerts like "New Login from New Device". This table acts as a queue for these messages. The IAM engine pushes an event here, and a worker service reads it to send the notification. This decoupling ensures that the authentication process doesn't slow down if the email gateway is slow.
-- KPIs: Queue throughput, Delivery success rate.
-- Feature Reference: F075
CREATE TABLE IF NOT EXISTS iam.notification_queue (
    msg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    message TEXT NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENT', 'FAILED')),

    CONSTRAINT fk_notification_queue_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.notification_queue IS 'Queue for outbound security notifications to users.';

-- DB043: iam.password_history
-- Description: History of password hashes to prevent reuse.
-- Business Case: To enforce password history policies (e.g., "cannot reuse last 10 passwords"), this table stores historical hashes. When a user changes their password, the new hash is compared against this history. This prevents users from cycling through old passwords, a common practice that weakens security over time.
-- KPIs: Password reuse prevention rate.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS iam.password_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.password_history IS 'Stores historical password hashes to enforce reuse policies.';

-- DB044: iam.admin_actions
-- Description: Specific audit for admin activities.
-- Business Case: Administrative actions (deleting roles, changing policies) are high-risk. This table provides a dedicated, high-granularity log for these events. Unlike the general access log, this captures the `target_id` of the change and the `action_type` explicitly. This makes it easier to generate "Activity Reports" for compliance officers focusing on insider threat or administrative abuse.
-- KPIs: Admin action log completeness.
-- Feature Reference: F125
CREATE TABLE IF NOT EXISTS iam.admin_actions (
    action_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    admin_id UUID NOT NULL,
    action_type VARCHAR(100) NOT NULL, -- e.g., 'DELETE_ROLE', 'UPDATE_POLICY'
    target_id UUID NOT NULL,
    target_type VARCHAR(50) NOT NULL, -- e.g., 'ROLE', 'USER'
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_admin_actions_admin FOREIGN KEY (admin_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.admin_actions IS 'Detailed audit trail specifically for high-privilege administrative actions.';

-- DB045: iam.webhooks
-- Description: Webhook endpoints for events.
-- Business Case: Modern integrations (e.g., SIEM tools like Splunk) often consume data via Webhooks. This table stores webhook configurations (URL, secret). When a significant security event occurs, the system triggers this webhook. The `secret_hash` is used to sign the payload, ensuring the receiver can verify the data integrity and source.
-- KPIs: Webhook delivery success rate, Latency.
-- Feature Reference: F097
CREATE TABLE IF NOT EXISTS iam.webhooks (
    hook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url TEXT NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL, -- List of event types to subscribe to
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE iam.webhooks IS 'Stores external webhook endpoints for real-time security event streaming.';

-- DB046: iam.failed_analytics
-- Description: Analysis of failed auth reasons.
-- Business Case: Simply logging failures isn't enough; we need to analyze *why*. This aggregated table groups failures by reason (e.g., "Wrong Password", "Account Locked", "MFA Failed") and date. This data drives product improvements—if "Wrong Password" spikes, maybe the user interface is confusing. If "MFA Failed" spikes, maybe the provider is down.
-- KPIs: Analytics query performance.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS iam.failed_analytics (
    reason_code VARCHAR(50) NOT NULL,
    count BIGINT DEFAULT 0,
    date DATE NOT NULL,
    PRIMARY KEY (reason_code, date)
);

COMMENT ON TABLE iam.failed_analytics IS 'Aggregated analysis of authentication failure reasons.';

-- DB047: iam.compliance_reports
-- Description: Generated compliance artifacts.
-- Business Case: Preparing for audits (SOC2, ISO27001) involves generating massive reports. This table stores metadata about generated reports—what type they are, where the file is stored (`file_url`), and when they were generated. This creates a history of evidence, allowing auditors to quickly retrieve the "state of compliance" for any past period.
-- KPIs: Report generation time, Report retrieval speed.
-- Feature Reference: F060
CREATE TABLE IF NOT EXISTS iam.compliance_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(50) NOT NULL, -- e.g., 'SOC2_TYPE_2', 'ISO27001'
    file_url TEXT NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    generated_by UUID NOT NULL,

    CONSTRAINT fk_compliance_reports_user FOREIGN KEY (generated_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);

COMMENT ON TABLE iam.compliance_reports IS 'Metadata for compliance audit reports generated by the system.';

-- DB048: iam.feature_flags
-- Description: Toggles for security features.
-- Business Case: To deploy features safely (e.g., new MFA method) or disable them instantly in case of a vulnerability, this table stores feature flags. It allows operations teams to turn specific IAM features on or off without a code deployment. For example, if a specific auth flow is under attack, the flag can be set to FALSE immediately.
-- KPIs: Flag update propagation time.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.feature_flags (
    flag_name VARCHAR(100) PRIMARY KEY,
    is_enabled BOOLEAN DEFAULT FALSE,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID
);

COMMENT ON TABLE iam.feature_flags IS 'Feature toggles to dynamically enable or disable security capabilities.';

-- DB049: iam.sop_documents
-- Description: Standard Operating Procedures linked to roles.
-- Business Case: Compliance often dictates that users must follow specific procedures (SOPs) before accessing high-risk data. This table links documents (stored externally) to roles. When a user with that role logs in, the system can prompt them to read/re-acknowledge the SOP. This ensures that access is always coupled with the latest procedural knowledge.
-- KPIs: SOP acknowledgement rate.
-- Feature Reference: F055
CREATE TABLE IF NOT EXISTS iam.sop_documents (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID NOT NULL,
    file_url TEXT NOT NULL,
    title VARCHAR(255),
    version VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sop_documents_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.sop_documents IS 'Links Standard Operating Procedure (SOP) documents to specific roles.';

-- DB050: iam.captcha_challenges
-- Description: CAPTCHA session tracking.
-- Business Case: To distinguish humans from bots during logins, CAPTCHAs are used. This table tracks the state of the CAPTCHA challenge—the ID of the puzzle, the correct solution (or hash of it), and whether it was solved. It prevents replay attacks where a valid CAPTCHA answer is reused multiple times.
-- KPIs: Bot detection accuracy, Solve rate.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS iam.captcha_challenges (
    captcha_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID,
    solved BOOLEAN DEFAULT FALSE,
    solution_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_captcha_challenges_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.captcha_challenges IS 'Tracks CAPTCHA challenges to prevent automated bot access.';

-- 5. Indexes (Partial Implementation for first 50 tables)
-- ================================================================================

-- Users
CREATE INDEX idx_users_email ON iam.users (email);
CREATE INDEX idx_users_username ON iam.users (username);
CREATE INDEX idx_users_status ON iam.users (status);

-- Sessions
CREATE INDEX idx_sessions_token ON iam.sessions (token_hash);
CREATE INDEX idx_sessions_user ON iam.sessions (user_id);
CREATE INDEX idx_sessions_expiry ON iam.sessions (expires_at) WHERE status = 'ACTIVE';

-- Access Logs
CREATE INDEX idx_access_logs_user ON iam.access_logs (user_id);
CREATE INDEX idx_access_logs_timestamp ON iam.access_logs (timestamp DESC);
CREATE INDEX idx_access_logs_decision ON iam.access_logs (decision);

-- Roles / Permissions
CREATE INDEX idx_role_permissions_role ON iam.role_permissions (role_id);
CREATE INDEX idx_user_roles_user ON iam.user_roles (user_id);

-- Breach Attempts
CREATE INDEX idx_breach_attempts_ip ON iam.breach_attempts (ip_address);
CREATE INDEX idx_breach_attempts_timestamp ON iam.breach_attempts (timestamp DESC);

-- RLS Example (Demonstrated on iam.users)
-- ================================================================================
ALTER TABLE iam.users ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation_policy ON iam.users
    FOR ALL
    USING (
        -- Users can see their own record, or admins can see all
        user_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (
            SELECT 1 FROM iam.user_roles ur
            JOIN iam.roles r ON r.role_id = ur.role_id
            WHERE ur.user_id = current_setting('app.current_user_id', true)::UUID
            AND r.role_name = 'ADMIN'
        )
    );

-- 6. Trigger Application (Generic Update Timestamp)
-- ================================================================================
-- Apply triggers to all created tables that have updated_at column
CREATE TRIGGER trg_users_update BEFORE UPDATE ON iam.users FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_roles_update BEFORE UPDATE ON iam.roles FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_permissions_update BEFORE UPDATE ON iam.permissions FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_policies_update BEFORE UPDATE ON iam.policies FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_feature_flags_update BEFORE UPDATE ON iam.feature_flags FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();



-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 2
-- Scope: Database Objects DB051 - DB100 (Tables)
-- ================================================================================

-- Prerequisite: Create reference schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS ref AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA ref IS 'Reference data schema for lookups (countries, timezones, etc.).';

-- ================================================================================
-- DDL Statements (Tables DB051 - DB100)
-- ================================================================================

-- DB051: iam.magic_links
-- Description: One-time login tokens.
-- Business Case: Magic links provide a passwordless authentication mechanism, improving user experience by removing the friction of password management while maintaining security. The user receives a link via email; clicking it validates the token and logs them in. This table stores the hash of the token and its expiration. The `used` flag ensures that the link is single-use, preventing replay attacks if the link is intercepted. It's particularly useful for low-risk scenarios or initial account recovery, aligning with the PARI platform's goal of phishing-resistant authentication flows.
-- KPIs: Link click-through rate, Link expiration rate, Token generation speed.
-- Feature Reference: F128
CREATE TABLE IF NOT EXISTS iam.magic_links (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    used BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_magic_links_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.magic_links IS 'Stores one-time magic links for passwordless authentication.';

-- DB052: iam.pairwise_identifiers
-- Description: Pseudonymous IDs for privacy (ZKP).
-- Business Case: To achieve true unlinkability under GDPR, a user should have different identifiers for different services (relying parties). If a user logs into "Service A" and "Service B", they should appear as two different people. This table stores these pairwise IDs, linked to the user's master ID but exposed only to the specific relying party. It supports Zero-Knowledge Proofs (ZKP) where the system can verify the user is who they say they are without revealing their global identity. This is critical for the PARI privacy architecture.
-- KPIs: ID lookup latency, Unlinkability verification success.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS iam.pairwise_identifiers (
    pairwise_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    relying_party_id VARCHAR(255) NOT NULL,
    sector_identifier VARCHAR(255),

    CONSTRAINT uk_pairwise UNIQUE (user_id, relying_party_id),
    CONSTRAINT fk_pairwise_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pairwise_identifiers IS 'Stores pseudonymous identifiers to prevent correlation across services (Privacy by Design).';

-- DB053: iam.lease_records
-- Description: Lease tracking for JIT secrets.
-- Business Case: Secrets (like database credentials) should not be long-lived. This table tracks "leases" of secrets from a Vault (e.g., HashiCorp Vault). When a service needs a DB credential, it requests a lease. This table records the `lessee_id`, the `secret_id`, and the `expires_at` time. The system can automatically revoke the secret in the Vault when this lease expires or is deleted. This enforces the principle of least privilege at the infrastructure level, ensuring credentials have a strictly limited lifespan.
-- KPIs: Lease rotation frequency, Secret expiration adherence.
-- Feature Reference: F130
CREATE TABLE IF NOT EXISTS iam.lease_records (
    lease_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id VARCHAR(255) NOT NULL, -- Reference to external secret ID
    lessee_id UUID NOT NULL, -- The service or user holding the lease
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.lease_records IS 'Tracks temporary leases of secrets from external vaults.';

-- DB054: iam.consent_receipts
-- Description: Machine-readable consent receipts.
-- Business Case: The Kantara Initiative Consent Receipt standard provides a structured way to give users proof of their consent. This table stores the JSON Web Signature (JWS) or token representing this receipt. It contains exactly what the user agreed to, when, and with whom. If a user or regulator questions whether consent was obtained, this table provides the cryptographic proof. It's an essential component for GDPR Article 7 (Demonstration of Consent) within the PARI platform.
-- KPIs: Receipt generation time, Verification success rate.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.consent_receipts (
    receipt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    consent_jws TEXT NOT NULL, -- The signed receipt token
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_consent_receipts_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.consent_receipts IS 'Stores cryptographic consent receipts for regulatory proof.';

-- DB055: iam.cloud_sync_status
-- Description: Sync status for external IAM.
-- Business Case: Modern cloud environments use native IAM (AWS IAM, Azure RBAC). This table tracks the synchronization status between the PARI IAM module and these external providers. It ensures that if a user is de-provisioned in PARI, their corresponding cloud access is revoked. The table logs the `last_synced` timestamp and `status` (SUCCESS, FAILED) to allow alerts if the identity bridge breaks, preventing "zombie" access in the cloud.
-- KPIs: Sync latency, Sync failure rate.
-- Feature Reference: F137
CREATE TABLE IF NOT EXISTS iam.cloud_sync_status (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider VARCHAR(50) NOT NULL, -- e.g., AWS, AZURE, GCP
    external_id VARCHAR(255) NOT NULL, -- The ID in the cloud provider
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SYNCED', 'FAILED')),
    last_synced TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);
COMMENT ON TABLE iam.cloud_sync_status IS 'Tracks synchronization status of identities with external cloud providers.';

-- DB056: iam.logic_bombs
-- Description: Detected suspicious scheduled tasks.
-- Business Case: A logic bomb is malicious code that executes only when specific conditions are met (e.g., a date or time). This table stores detected patterns that look like scheduled privilege escalations or data deletions. By proactively identifying these "ticks" in the system, the Security Operations Center can intervene before the bomb detonates. It acts as a preventive measure against insider threats or compromised admin accounts setting up future destruction.
-- KPIs: Detection accuracy, False positive rate.
-- Feature Reference: F136
CREATE TABLE IF NOT EXISTS iam.logic_bombs (
    bomb_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    trigger_time TIMESTAMP WITH TIME ZONE NOT NULL,
    suspicious_code_snippet TEXT,
    status VARCHAR(20) DEFAULT 'DETECTED' CHECK (status IN ('DETECTED', 'INVESTIGATING', 'NEUTRALIZED', 'FALSE_POSITIVE')),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_logic_bombs_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.logic_bombs IS 'Stores detected logic bombs or suspicious scheduled tasks.';

-- DB057: iam.training_data
-- Description: Anonymized data for ML model training.
-- Business Case: To train the AI anomaly detection models without violating privacy, we use anonymized data. This table stores `features_json` (e.g., login time, IP, device type) stripped of PII. It serves as the corpus for training and retraining models. Strict access controls are enforced here to ensure that even training data doesn't leak sensitive information. The `label` field indicates whether the behavior was malicious, used for supervised learning.
-- KPIs: Data volume, Feature completeness.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.training_data (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    features_json JSONB NOT NULL,
    label VARCHAR(20) CHECK (label IN ('BENIGN', 'ANOMALOUS', 'FRAUD')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.training_data IS 'Anonymized dataset for training AI/ML security models.';

-- DB058: iam.version_audit
-- Description: Schema version tracking for migration.
-- Business Case: In a distributed database, knowing the exact schema version is critical for rolling back or debugging migrations. This table tracks the `version_num` and `deployed_at` timestamp for every schema change. It ensures that all nodes in the PARI cluster are running the same schema version, preventing data inconsistency issues during zero-downtime deployments.
-- KPIs: Migration success rate, Version consistency.
-- Feature Reference: F053
CREATE TABLE IF NOT EXISTS iam.version_audit (
    version_num VARCHAR(20) PRIMARY KEY,
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);
COMMENT ON TABLE iam.version_audit IS 'Tracks database schema versions and deployment history.';

-- DB059: iam.ip_reputation
-- Description: Cached reputation of IP addresses.
-- Business Case: Querying external threat intelligence APIs for every login is too slow. This table caches the reputation score and category of IP addresses. When a user logs in, the system checks this cache first. It reduces latency while maintaining security by allowing periodic refreshes of the reputation data (e.g., every 24 hours). High-risk IPs can be blocked immediately based on this cache.
-- KPIs: Cache hit ratio, Reputation update frequency.
-- Feature Reference: F063
CREATE TABLE IF NOT EXISTS iam.ip_reputation (
    ip_address INET PRIMARY KEY,
    score INTEGER CHECK (score >= 0 AND score <= 100),
    category VARCHAR(50), -- e.g., TOR, BOTNET, ISP
    provider VARCHAR(50),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.ip_reputation IS 'Caches threat intelligence scores for IP addresses.';

-- DB060: iam.device_trust_history
-- Description: Historical trust scores of devices.
-- Business Case: A device's trustworthiness can fluctuate. A device that was secure yesterday might be jailbroken today. This table maintains a time-series history of `device_id` and `trust_score`. This historical context is vital for the AI engine to detect trends—e.g., a score dropping slowly over time might indicate a gradual compromise or infection. It also supports forensics by showing the trust state of a device at the time of a security incident.
-- KPIs: History retention period, Score volatility tracking.
-- Feature Reference: F014
CREATE TABLE IF NOT EXISTS iam.device_trust_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL,
    score NUMERIC(3,2) CHECK (score >= 0 AND score <= 1),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_device_trust_history_device FOREIGN KEY (device_id) REFERENCES iam.devices(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.device_trust_history IS 'Historical log of device trust scores for trend analysis.';

-- DB061: iam.audit_signatures
-- Description: Cryptographic signatures over audit logs.
-- Business Case: To ensure that audit logs cannot be tampered with by even a database administrator with root access, we use cryptographic chaining. This table stores the signature (hash) of batches of logs. Each signature depends on the previous one, creating a chain. If an attacker modifies a log entry in the `access_logs` table, the chain breaks, and verification fails. This is the highest level of assurance for forensic integrity required for financial audits.
-- KPIs: Signing latency, Chain integrity verification time.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS iam.audit_signatures (
    signature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_batch_id VARCHAR(255) NOT NULL, -- Reference to the range of logs
    signature BYTEA NOT NULL, -- Cryptographic signature
    previous_signature_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.audit_signatures IS 'Stores cryptographic signatures to ensure the immutability of audit logs.';

-- DB062: iam.password_policies
-- Description: Configurable password rules.
-- Business Case: Not all roles require the same password strength. A generic user might need standard complexity, while a super-admin might require a passphrase and hardware key. This table stores per-role password policies (length, regex complexity, rotation period). It allows the IAM module to enforce these rules dynamically during password changes, balancing security with usability.
-- KPIs: Policy configuration coverage, Enforcement latency.
-- Feature Reference: F058
CREATE TABLE IF NOT EXISTS iam.password_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID, -- NULL implies default policy
    min_length INTEGER DEFAULT 8 CHECK (min_length >= 6),
    complexity_regex TEXT, -- Regex to enforce complexity
    rotation_days INTEGER,
    history_count INTEGER DEFAULT 5, -- Remember last N passwords
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_password_policies_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.password_policies IS 'Stores configurable password complexity and rotation rules per role.';

-- DB063: iam.auth_counts
-- Description: Counter for rate limiting per user.
-- Business Case: To prevent brute-force attacks or DoS, we must rate limit authentication attempts. This table acts as a sliding window counter. It stores the number of attempts (`count`) for a `user_id` within a specific time window (`window_start`). If the count exceeds the threshold defined in the `rate_limits` table, the user is throttled. This table is a high-write table, so optimizations like frequent vacuuming or partitioning may be needed.
-- KPIs: Write throughput, Accuracy of limit enforcement.
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.auth_counts (
    user_id UUID NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    count INTEGER DEFAULT 0 CHECK (count >= 0),

    PRIMARY KEY (user_id, window_start),
    CONSTRAINT fk_auth_counts_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.auth_counts IS 'High-frequency counter for implementing sliding window rate limits.';

-- DB064: ref.countries
-- Description: Reference data for ISO country codes.
-- Business Case: This reference table maps ISO 3166-1 alpha-2 or alpha-3 codes to full country names. It is used for validating user inputs, enforcing geo-fencing policies (e.g., checking if an IP belongs to a sanctioned country), and formatting addresses. Standardizing on ISO codes ensures interoperability with external compliance lists and geolocation services.
-- KPIs: Data completeness.
-- Feature Reference: F013
CREATE TABLE IF NOT EXISTS ref.countries (
    code CHAR(2) PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);
COMMENT ON TABLE ref.countries IS 'Reference table for ISO 3166 country codes.';

-- DB065: ref.timezones
-- Description: Reference timezones.
-- Business Case: Accurate timekeeping is critical for security logs and JIT expiration. This table stores IANA timezone identifiers (e.g., "America/New_York", "Europe/London"). It ensures that timestamps are stored and displayed correctly according to the user's locale, preventing confusion about when an event actually occurred, especially in cross-border financial transactions.
-- KPIs: Data accuracy.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS ref.timezones (
    tz_name VARCHAR(50) PRIMARY KEY,
    utc_offset NUMERIC(3,1) -- For quick sorting, though tz database handles DST
);
COMMENT ON TABLE ref.timezones IS 'Reference table for IANA timezone identifiers.';

-- DB066: ref.locales
-- Description: Supported languages for UI.
-- Business Case: To support the diverse user base of the PARI platform, this table defines supported locales (e.g., "en-US", "fr-FR", "de-DE"). It drives the localization of error messages, consent forms, and administrative interfaces. Ensuring that security prompts are in the user's native language improves comprehension and reduces the risk of users inadvertently accepting security risks due to language barriers.
-- KPIs: Supported language count.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS ref.locales (
    locale_code VARCHAR(10) PRIMARY KEY, -- e.g. en-US
    name VARCHAR(50) NOT NULL
);
COMMENT ON TABLE ref.locales IS 'Reference table for supported UI locales and languages.';

-- DB067: ref.mfa_methods
-- Description: Supported MFA methods.
-- Business Case: This table defines the available multi-factor authentication methods (e.g., TOTP, FIDO2, SMS). It acts as a configuration source for the UI and the backend validation logic. By making this a database table rather than a code constant, new MFA methods (e.g., a new biometric standard) can be added via configuration without deploying new code.
-- KPIs: Method availability.
-- Feature Reference: F039
CREATE TABLE IF NOT EXISTS ref.mfa_methods (
    method_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE ref.mfa_methods IS 'Reference table defining available multi-factor authentication methods.';

-- DB068: iam.user_settings
-- Description: User UI preferences.
-- Business Case: This table stores non-security-critical user preferences, such as theme (dark/light mode), default language, or dashboard layout. Separating these from the core `users` table keeps the security profile lean while allowing for personalization. It improves user adoption and satisfaction without impacting the performance of authentication queries.
-- KPIs: Preference retrieval latency.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.user_settings (
    user_id UUID PRIMARY KEY,
    theme VARCHAR(20) DEFAULT 'LIGHT',
    locale VARCHAR(10) DEFAULT 'en_US',
    timezone VARCHAR(50),
    notification_email BOOLEAN DEFAULT TRUE,
    notification_sms BOOLEAN DEFAULT FALSE,

    CONSTRAINT fk_user_settings_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_settings IS 'Stores user interface and preference settings.';

-- DB069: iam.public_keys
-- Description: Public keys for users (for JWT verification).
-- Business Case: In a decentralized or federated model, users may have their own key pairs. This table stores the public keys associated with a user. These keys can be used to verify signatures on JWTs or requests, enabling strong cryptographic authentication that doesn't rely on shared secrets (passwords). It is a building block for the "User-Centric Identity" model.
-- KPIs: Key validation speed.
-- Feature Reference: F030
CREATE TABLE IF NOT EXISTS iam.public_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    key_pem TEXT NOT NULL,
    key_type VARCHAR(20) DEFAULT 'RSA', -- RSA, ECDSA, ED25519
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_public_keys_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.public_keys IS 'Stores public keys for cryptographic verification of user actions.';

-- DB070: iam.private_keys_enc
-- Description: Encrypted private keys.
-- Business Case: For certain operations (like signing data on behalf of the user), the system might need to hold a private key securely. This table stores the encrypted form of such keys. The `key_encrypted` field uses `pgcrypto` or a KMS envelope encryption pattern. This ensures that even if the database dump is stolen, the private keys remain secure. Access to this table should be extremely restricted.
-- KPIs: Decryption latency, Key security posture.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS iam.private_keys_enc (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_encrypted BYTEA NOT NULL,
    encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.private_keys_enc IS 'Securely stores encrypted private keys for system or user operations.';

-- DB071: iam.federation_providers
-- Description: External SSO providers (SAML/OIDC).
-- Business Case: Enterprises often use centralized Identity Providers (IdP) like Active Directory (ADFS) or Okta. This table stores the metadata for these external providers (metadata URL, protocol type). It enables the PARI platform to act as a Service Provider (SP), trusting assertions from these IdPs. This is critical for B2B integration and allowing enterprise employees to log in using their corporate credentials.
-- KPIs: Federation success rate.
-- Feature Reference: F091
CREATE TABLE IF NOT EXISTS iam.federation_providers (
    provider_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    metadata_url TEXT,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('SAML', 'OIDC', 'OAUTH2')),
    client_id VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.federation_providers IS 'Configuration for external SSO and identity federation providers.';

-- DB072: iam.federated_users
-- Description: Mapping of external IDs to local users.
-- Business Case: When a user logs in via a federated provider (e.g., Google or Corporate AD), they have a unique ID in that system (`external_id`). This table maps that external ID to the local `user_id` in the PARI system. It allows the same local user to be linked to multiple providers (e.g., a corporate account and a social login) and ensures that subsequent logins are recognized as the same person.
-- KPIs: Link resolution speed.
-- Feature Reference: F091
CREATE TABLE IF NOT EXISTS iam.federated_users (
    local_user_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    external_id VARCHAR(255) NOT NULL,

    PRIMARY KEY (local_user_id, provider_id, external_id),
    CONSTRAINT fk_fed_users_local FOREIGN KEY (local_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_fed_users_provider FOREIGN KEY (provider_id) REFERENCES iam.federation_providers(provider_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.federated_users IS 'Maps external identity provider IDs to local user accounts.';

-- DB073: iam.role_templates
-- Description: Templates for creating new roles.
-- Business Case: To accelerate role deployment and maintain consistency, this table stores role templates. A template "Auditor Template" might come pre-loaded with all standard audit permissions. When a new tenant or department is created, they can instantiate a role from this template rather than manually selecting 50 permissions. This reduces the risk of human error during role provisioning.
-- KPIs: Role creation time.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS iam.role_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    permissions_json JSONB NOT NULL, -- Array of permission IDs or resource/action pairs
    description TEXT
);
COMMENT ON TABLE iam.role_templates IS 'Pre-defined templates for quickly creating new roles with standard permissions.';

-- DB074: iam.pending_approvals
-- Description: Staging area for role requests.
-- Business Case: This table acts as a holding area for access requests that require approval. Before a role is actually granted to a user in `user_roles`, the request sits here. This separation of "requested" and "granted" is essential for enforcing the Segregation of Duties (SoD). The system can validate that the approver is not conflicted before moving the request from this table to the live `user_roles` table.
-- KPIs: Staging to production latency.
-- Feature Reference: F011
CREATE TABLE IF NOT EXISTS iam.pending_approvals (
    req_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requestor_id UUID NOT NULL,
    role_id UUID NOT NULL,
    justification TEXT,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pending_approvals_requestor FOREIGN KEY (requestor_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_pending_approvals_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pending_approvals IS 'Staging table for access requests awaiting approval.';

-- DB075: iam.approval_chain
-- Description: Sequential approvers for a request.
-- Business Case: High-privilege access often requires multiple levels of approval (Manager -> Security Officer -> Data Owner). This table defines the sequence (`order`) of approvers for a specific request. It enforces the workflow logic, ensuring that a request cannot advance to step 3 until step 2 is signed off. This is a core component of Governance, Risk, and Compliance (GRC) workflows.
-- KPIs: Workflow cycle time.
-- Feature Reference: F011
CREATE TABLE IF NOT EXISTS iam.approval_chain (
    req_id UUID NOT NULL,
    approver_id UUID NOT NULL,
    "order" INTEGER NOT NULL CHECK ("order" > 0),
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'SKIPPED')),

    PRIMARY KEY (req_id, approver_id, "order"),
    CONSTRAINT fk_approval_chain_req FOREIGN KEY (req_id) REFERENCES iam.pending_approvals(req_id) ON DELETE CASCADE,
    CONSTRAINT fk_approval_chain_approver FOREIGN KEY (approver_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.approval_chain IS 'Defines the sequence of approvers for a specific access request.';

-- DB076: iam.session_activities
-- Description: Heartbeats/activities within a session.
-- Business Case: To detect zombie sessions or session hijacking, we track activity. This table logs heartbeats or significant actions (clicks, API calls) linked to a session ID. If the interval between activities suggests impossible travel (action in Paris, then 5 mins later in Tokyo), the session can be flagged. It also enables accurate idle timeout enforcement.
-- KPIs: Activity log volume.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.session_activities (
    activity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL, -- e.g. HEARTBEAT, API_CALL, DOWNLOAD
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_activities_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_activities IS 'Logs user activities within a session for security monitoring and idle timeouts.';

-- DB077: iam.deleted_users
-- Description: Archive of deleted users for audit.
-- Business Case: When a user is deleted (GDPR Right to Erasure), their active record is removed from `users`. However, for security auditing (e.g., investigating a breach that happened 3 years ago), we might need to know that this user *once existed*. This table stores a minimal archive (ID, deleted_at, deleted_by). It retains the identity reference without retaining personal data, balancing privacy with the need for historical forensic accountability.
-- KPIs: Retention compliance.
-- Feature Reference: F020
CREATE TABLE IF NOT EXISTS iam.deleted_users (
    old_user_id UUID PRIMARY KEY,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_by UUID NOT NULL,
    reason TEXT
);
COMMENT ON TABLE iam.deleted_users IS 'Archive of deleted user IDs for historical audit reference.';

-- DB078: iam.archived_logs
-- Description: Cold storage for old access logs.
-- Business Case: The `access_logs` table is "hot" and optimized for writes. Over time, logs must be moved to cheaper "cold" storage to save costs and maintain performance. This table stores the JSON blob of the original log entry. It might use compression or columnar storage techniques (though here represented as standard JSONB/TEXT). This table is rarely queried, serving primarily for long-term compliance retention (e.g., 7-year retention for financial data).
-- KPIs: Storage cost efficiency.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS iam.archived_logs (
    log_id UUID PRIMARY KEY,
    log_data JSONB NOT NULL, -- The full original log
    archived_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.archived_logs IS 'Cold storage for access logs to optimize hot database performance.';

-- DB079: iam.encryption_keys
-- Description: Metadata for data encryption keys.
-- Business Case: To support Field Level Encryption (FLE) or application-level encryption, we need to manage keys. This table stores metadata about keys (`key_version`, `status`). The actual key material might be in an HSM, but this table tracks which version is active. It enables key rotation—creating a new version and marking the old one as deprecated—without breaking existing data.
-- KPIs: Key rotation speed.
-- Feature Reference: F117
CREATE TABLE IF NOT EXISTS iam.encryption_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,
    key_version INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'COMPROMISED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.encryption_keys IS 'Metadata for managing data encryption key versions and status.';

-- DB080: iam.masking_functions
-- Description: Definitions of custom masking logic.
-- Business Case: Different data types require different masking (e.g., credit cards need middle digits hidden, emails need asterisks). This table stores the definitions of these functions (e.g., a regex pattern or a SQL snippet). Instead of hardcoding masking logic in the application, the database looks up the `logic_code` here and applies it. This allows security officers to change masking rules without code deployments.
-- KPIs: Masking rule flexibility.
-- Feature Reference: F007
CREATE TABLE IF NOT EXISTS iam.masking_functions (
    func_name VARCHAR(100) PRIMARY KEY,
    logic_code TEXT NOT NULL, -- SQL function body or Regex
    description TEXT
);
COMMENT ON TABLE iam.masking_functions IS 'Stores definitions of custom data masking logic.';

-- DB081: iam.access_changes
-- Description: Log of permission grants/revokes.
-- Business Case: While `access_logs` tracks READ/WRITE actions, this table specifically tracks the *management* of access—when a permission is granted or revoked from a role. This is a higher-level audit used for governance reviews to answer "Who changed the permissions structure and when?". It is distinct from user activity logs, focusing on administrative intent.
-- KPIs: Audit trail completeness.
-- Feature Reference: F020
CREATE TABLE IF NOT EXISTS iam.access_changes (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    perm_id UUID,
    role_id UUID,
    delta VARCHAR(20) NOT NULL CHECK (delta IN ('GRANTED', 'REVOKED')),
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_access_changes_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_changes_perm FOREIGN KEY (perm_id) REFERENCES iam.permissions(perm_id) ON DELETE SET NULL,
    CONSTRAINT fk_access_changes_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.access_changes IS 'Audit log for changes to permission assignments.';

-- DB082: iam.risk_factors
-- Description: Definition of factors influencing risk score.
-- Business Case: The AI risk engine considers multiple factors (New Device, Off-Hours, Velocity). This table defines these factors and their `weight` in the overall score. By storing weights in the database, risk models can be tuned (e.g., increasing the weight of "Failed Login" during a known attack period) without rebuilding the machine learning model.
-- KPIs: Model tuning agility.
-- Feature Reference: F054
CREATE TABLE IF NOT EXISTS iam.risk_factors (
    factor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL, -- e.g. 'NEW_IP', 'FAILED_MFA'
    weight NUMERIC(5,2) CHECK (weight >= 0 AND weight <= 1), // 0.0 to 1.0
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.risk_factors IS 'Defines the factors and their weights used in calculating risk scores.';

-- DB083: iam.quarantine_users
-- Description: Users blocked due to compromise suspicion.
-- Business Case: When the AI detects high-risk behavior, the system might place a user in "quarantine". This table tracks those users and the reason. It's a soft state—the account still exists, but access is denied until reviewed. This allows the organization to investigate potential compromises without locking the user out entirely (which might alert the attacker), although typically quarantine implies access revocation.
-- KPIs: Quarantine duration, False positive rate.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS iam.quarantine_users (
    user_id UUID PRIMARY KEY,
    reason TEXT NOT NULL,
    quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    quarantined_by UUID NOT NULL,

    CONSTRAINT fk_quarantine_users FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.quarantine_users IS 'Tracks users placed in security quarantine due to suspicious activity.';

-- DB084: iam.synthetic_users
-- Description: Users used for synthetic monitoring.
-- Business Case: To ensure the login and auth pipeline always works, we create "synthetic" users that log in automatically every few minutes. This table identifies these users so they can be excluded from analytics (e.g., don't alert on "impossible travel" for a bot) and given special privileges to perform health checks without triggering MFA. Their presence validates the system's availability and performance.
-- KPIs: Monitoring success rate.
-- Feature Reference: F112
CREATE TABLE IF NOT EXISTS iam.synthetic_users (
    user_id UUID PRIMARY KEY,
    is_synthetic BOOLEAN DEFAULT TRUE,
    tag VARCHAR(50), -- e.g. 'HEALTH_CHECK_US_EAST'

    CONSTRAINT fk_synthetic_users FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.synthetic_users IS 'Identifies synthetic users used for automated health monitoring.';

-- DB085: iam.dependency_graph
-- Description: Pre-calculated policy dependencies.
-- Business Case: Policies often depend on other policies or roles. Calculating this dependency tree at runtime is expensive. This table pre-calculates the edges of the dependency graph (`parent_id`, `child_id`). It allows the Policy Engine to quickly assess the impact of a change (e.g., "If I delete Role A, what other policies break?"). It is essential for the `Policy Impact Analysis` feature.
-- KPIs: Impact analysis speed.
-- Feature Reference: F122
CREATE TABLE IF NOT EXISTS iam.dependency_graph (
    parent_id UUID NOT NULL,
    child_id UUID NOT NULL,
    depth INTEGER NOT NULL, -- How deep in the hierarchy
    graph_type VARCHAR(50) NOT NULL, -- e.g. 'POLICY_DEPENDENCY', 'ROLE_HIERARCHY'

    CONSTRAINT uk_dependency UNIQUE (parent_id, child_id, graph_type)
);
COMMENT ON TABLE iam.dependency_graph IS 'Stores pre-calculated dependency relationships for policies and roles.';

-- DB086: iam.login_flows
-- Description: Configured login flows per tenant.
-- Business Case: Different tenants or security levels may require different login steps. One might need Username -> Password -> MFA. Another might use just SSO. This table defines the sequence of steps (`steps_json`) for a specific flow. It allows the PARI platform to offer a highly customizable authentication experience (Drag-and-drop builder) without hardcoding flows.
-- KPIs: Flow configuration flexibility.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.login_flows (
    flow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL, -- Links to tenant_configs
    steps_json JSONB NOT NULL, -- Ordered list of steps
    is_default BOOLEAN DEFAULT FALSE,

    CONSTRAINT fk_login_flows_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.login_flows IS 'Defines the sequence of steps for customizable login workflows.';

-- DB087: iam.consent_versions
-- Description: Versioning of consent text.
-- Business Case: Legal privacy policies and consent texts change over time. To prove that a user agreed to the text that was valid *at that time*, we version the text. This table stores each version of the consent document with its effective date. When linking a user to consent, we link to a specific version ID, not just the consent type.
-- KPIs: Version tracking accuracy.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.consent_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    text_hash VARCHAR(255) NOT NULL, -- Hash to detect if text actually changed
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    legal_text TEXT
);
COMMENT ON TABLE iam.consent_versions IS 'Version history of legal consent documents.';

-- DB088: iam.user_consent_history
-- Description: Linking user to specific consent version.
-- Business Case: This is the intersection of users and consent versions. It proves that User X agreed to Consent Version Y on Date Z. It is the ultimate source of truth for consent audits. By storing the specific version ID, we ensure that even if the policy changes later, we know exactly what the user agreed to originally.
-- KPIs: Retrieval speed for audits.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.user_consent_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    consent_id UUID NOT NULL, -- Links to the general consent type
    version_id UUID NOT NULL, -- Links to the specific version
    agreed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_user_consent_history_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_consent_history_version FOREIGN KEY (version_id) REFERENCES iam.consent_versions(version_id)
);
COMMENT ON TABLE iam.user_consent_history IS 'Records which specific version of a consent a user agreed to.';

-- DB089: iam.audit_filters
-- Description: Saved filters for audit log viewers.
-- Business Case: Auditors often run the same complex queries daily (e.g., "Show all Admin access failures"). This table stores these saved filter configurations (`filter_json`). It improves auditor productivity and ensures consistency in reporting. The filters are user-specific, allowing each auditor to have their own set of tools.
-- KPIs: Auditor query efficiency.
-- Feature Reference: F016
CREATE TABLE IF NOT EXISTS iam.audit_filters (
    filter_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    filter_name VARCHAR(100) NOT NULL,
    filter_json JSONB NOT NULL, -- The query params
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_filters_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.audit_filters IS 'Stores saved search filters for audit log analysis.';

-- DB090: iam.export_jobs
-- Description: Asynchronous export jobs for logs.
-- Business Case: Exporting millions of log rows is a heavy operation that should not block the API. This table tracks asynchronous export jobs. It records the status (PENDING, PROCESSING, COMPLETED) and the `file_url` where the result is stored (e.g., S3). This allows users to request a large report and receive a download link later via email or notification.
-- KPIs: Job completion time.
-- Feature Reference: F090
CREATE TABLE IF NOT EXISTS iam.export_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    file_url TEXT,
    filters_json JSONB, -- What was exported
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_export_jobs_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.export_jobs IS 'Tracks the status of asynchronous data export jobs.';

-- DB091: iam.test_cases
-- Description: Auto-generated test cases for policies.
-- Business Case: Before deploying a policy change, we want to test it. This table stores test cases (`input_json`) and the expected output (`expected_output`). The QA system runs these inputs against the policy engine and checks if the result matches the expectation. This automates the regression testing of security policies, preventing accidental lockdowns or privilege escalations.
-- KPIs: Test coverage percentage.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS iam.test_cases (
    case_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    input_json JSONB NOT NULL, -- Simulated request context
    expected_output VARCHAR(20) NOT NULL, -- ALLOW or DENY
    created_by UUID NOT NULL,

    CONSTRAINT fk_test_cases_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.test_cases IS 'Stores input/output pairs for automated policy testing.';

-- DB092: iam.test_results
-- Description: Results of running test cases.
-- Business Case: This table records the execution of test cases (DB091). It stores the `actual_output` and whether the test `passed`. Over time, this creates a history of policy quality. If a test starts failing, it alerts the admin that a recent change broke a security guarantee.
-- KPIs: Test pass rate.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS iam.test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,
    actual_output VARCHAR(20) NOT NULL,
    passed BOOLEAN NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_test_results_case FOREIGN KEY (case_id) REFERENCES iam.test_cases(case_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.test_results IS 'Stores the results of automated policy test runs.';

-- DB093: iam.incident_links
-- Description: Linking alerts to security incidents.
-- Business Case: Anomaly alerts (DB029) might be isolated, but often they form part of a larger "Incident". This table links individual alerts to a parent incident ID. This allows SOC analysts to view a complete timeline of an attack (e.g., Phishing email -> Failed Login -> Success Login -> Data Exfiltration) all in one place.
-- KPIs: Incident correlation efficiency.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.incident_links (
    incident_id UUID NOT NULL,
    alert_id UUID NOT NULL,

    PRIMARY KEY (incident_id, alert_id),
    CONSTRAINT fk_incident_links_alert FOREIGN KEY (alert_id) REFERENCES iam.anomaly_alerts(alert_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.incident_links IS 'Links individual security alerts to broader security incidents.';

-- DB094: iam.watchlist_users
-- Description: Users requiring additional scrutiny.
-- Business Case: Certain users (VIPs, high-profile targets, or employees under investigation) are placed on a watchlist. This table identifies them. The system can then apply stricter rules to these users, such as forcing MFA on every login or analyzing every API call for anomalies, providing enhanced protection for high-risk accounts.
-- KPIs: Monitoring effectiveness.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.watchlist_users (
    user_id UUID PRIMARY KEY,
    added_by UUID NOT NULL,
    reason TEXT,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_watchlist_users FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.watchlist_users IS 'Marks users for heightened security monitoring.';

-- DB095: iam.session_videos
-- Description: References to recorded session videos.
-- Business Case: For highly privileged sessions (Admin), the PARI platform records the session (video or high-frequency logs). This table stores the metadata (`storage_path`, `size`) for these recordings. In the event of a breach, these recordings can be replayed to see exactly what the attacker did (screen sharing, mouse movements). It is the ultimate "Black Box" for forensic analysis.
-- KPIs: Recording reliability.
-- Feature Reference: F125
CREATE TABLE IF NOT EXISTS iam.session_videos (
    video_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    storage_path TEXT NOT NULL,
    size_bytes BIGINT,
    duration_seconds INTEGER,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_videos_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_videos IS 'References session recordings for forensic analysis.';

-- DB096: iam.custom_fields
-- Description: User-defined attribute fields.
-- Business Case: Different businesses have different data requirements. This table allows admins to define new fields (e.g., `employee_id`, `cost_center`) dynamically. It defines the `name`, `type`, and `validation_regex`. Combined with DB097, it implements a schema-less extension mechanism on top of the rigid SQL schema.
-- KPIs: Field creation flexibility.
-- Feature Reference: F084
CREATE TABLE IF NOT EXISTS iam.custom_fields (
    field_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('STRING', 'INTEGER', 'DATE', 'BOOLEAN')),
    validation_regex TEXT,
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.custom_fields IS 'Defines custom user attribute fields (metadata).';

-- DB097: iam.field_values
-- Description: Values for custom fields per user.
-- Business Case: Stores the actual data for the custom fields defined in DB096. This is an Entity-Attribute-Value (EAV) model. It allows storing an arbitrary number of extra attributes for a user without altering the `users` table structure. This is crucial for a multi-tenant SaaS platform where every tenant might need different user metadata.
-- KPIs: Query performance (EAV optimization).
-- Feature Reference: F084
CREATE TABLE IF NOT EXISTS iam.field_values (
    value_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    field_id UUID NOT NULL,
    value TEXT NOT NULL, -- Stored as text, casted by app based on field type

    CONSTRAINT uk_field_values UNIQUE (user_id, field_id),
    CONSTRAINT fk_field_values_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_field_values_field FOREIGN KEY (field_id) REFERENCES iam.custom_fields(field_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.field_values IS 'Stores values for custom user attributes.';

-- DB098: iam.rate_limits
-- Description: Rate limit configurations.
-- Business Case: This table defines the *rules* for rate limiting (e.g., Role "External API" gets 1000 req/min, Role "Standard" gets 100 req/min). The `auth_counts` table (DB063) holds the counters, but this table holds the thresholds. By centralizing rules here, the API Gateway can quickly look up the limit for a user's role and enforce it.
-- KPIs: Limit enforcement accuracy.
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.rate_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID, -- NULL implies global default
    requests_per_minute INTEGER NOT NULL CHECK (requests_per_minute > 0),
    description TEXT,

    CONSTRAINT fk_rate_limits_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.rate_limits IS 'Stores configuration for API rate limits per role.';

-- DB099: iam.throttled_requests
-- Description: Log of throttled requests.
-- Business Case: When a user exceeds their rate limit, the request is throttled (rejected). This table logs those rejections. It is valuable for identifying abusive users, detecting DoS attacks, or understanding if rate limits are too strict (business disruption). It acts as a feedback loop for tuning the `rate_limits` configuration.
-- KPIs: Throttle frequency.
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.throttled_requests (
    req_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    limit_exceeded INTEGER NOT NULL
);
COMMENT ON TABLE iam.throttled_requests IS 'Logs requests that were blocked due to rate limiting.';

-- DB100: iam.backup_codes
-- Description: Backup codes for MFA recovery.
-- Business Case: If a user loses their MFA device (e.g., phone breaks), they are locked out. Backup codes (one-time use codes) provide a recovery mechanism. This table stores hashed backup codes. When a user redeems a code, it is marked as used. This ensures that users are never permanently locked out of their accounts, maintaining availability.
-- KPIs: Code redemption success rate.
-- Feature Reference: F093
CREATE TABLE IF NOT EXISTS iam.backup_codes (
    code_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_backup_codes_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.backup_codes IS 'Stores one-time backup codes for MFA recovery.';

-- ================================================================================
-- Indexes and Constraints for Part 2 Tables
-- ================================================================================

-- General Indexes
CREATE INDEX IF NOT EXISTS idx_pairwise_user ON iam.pairwise_identifiers(user_id);
CREATE INDEX IF NOT EXISTS idx_lease_lessee ON iam.lease_records(lessee_id);
CREATE INDEX IF NOT EXISTS idx_logic_bombs_trigger ON iam.logic_bombs(trigger_time) WHERE status = 'DETECTED';
CREATE INDEX IF NOT EXISTS idx_device_history_device ON iam.device_trust_history(device_id);
CREATE INDEX IF NOT EXISTS idx_auth_counts_window ON iam.auth_counts(window_start);
CREATE INDEX IF NOT EXISTS idx_federated_external ON iam.federated_users(external_id);
CREATE INDEX IF NOT EXISTS idx_session_activities_session ON iam.session_activities(session_id);
CREATE INDEX IF NOT EXISTS idx_field_values_user ON iam.field_values(user_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_policy ON iam.test_cases(policy_id);

-- Specific Indexes for High-Volume Tables (Partitions often used here in real prod)
CREATE INDEX IF NOT EXISTS idx_session_activities_timestamp ON iam.session_activities(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_archive_date ON iam.archived_logs(archived_date);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 2 Tables
-- ================================================================================

-- Enable RLS on sensitive data
ALTER TABLE iam.consent_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.backup_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.field_values ENABLE ROW LEVEL SECURITY;

-- Policy for Consent Receipts (User can see own)
CREATE POLICY consent_user_isolation ON iam.consent_receipts
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Policy for Backup Codes (User can see own active codes)
CREATE POLICY backup_codes_user_isolation ON iam.backup_codes
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Policy for Custom Field Values (User can see own)
CREATE POLICY field_values_user_isolation ON iam.field_values
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- ================================================================================
-- Triggers for Part 2 Tables
-- ================================================================================

-- Apply update triggers
CREATE TRIGGER trg_pairwise_update BEFORE UPDATE ON iam.pairwise_identifiers FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_lease_records_update BEFORE UPDATE ON iam.lease_records FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_training_data_update BEFORE UPDATE ON iam.training_data FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_ip_reputation_update BEFORE UPDATE ON iam.ip_reputation FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_user_settings_update BEFORE UPDATE ON iam.user_settings FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_federation_providers_update BEFORE UPDATE ON iam.federation_providers FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_masking_functions_update BEFORE UPDATE ON iam.masking_functions FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_login_flows_update BEFORE UPDATE ON iam.login_flows FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_audit_filters_update BEFORE UPDATE ON iam.audit_filters FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_custom_fields_update BEFORE UPDATE ON iam.custom_fields FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_rate_limits_update BEFORE UPDATE ON iam.rate_limits FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();

-- Specialized Trigger for Backup Codes (Mark used)
-- Example: Prevent reuse logic might be better in app, but DB constraint 'used' helps.

-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 3
-- Scope: Database Objects DB101 - DB150 (Tables)
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB101 - DB150)
-- ================================================================================

-- DB101: iam.automated_user_provisioning
-- Description: Stores SCIM-based provisioning jobs and results.
-- Business Case: Managing user lifecycles manually is error-prone and slow. This table supports SCIM (System for Cross-domain Identity Management) by logging automated provisioning jobs. When an HR system pushes a "New Hire" event, this table tracks the job status, the source system, and the result (Success/Failure). It ensures that user accounts are created instantly with the correct default roles, accelerating onboarding. It also tracks synchronization updates (changes in attributes) to keep the IAM system aligned with the source of truth, reducing administrative overhead and ensuring consistency.
-- KPIs: Job success rate, Provisioning latency, Error categorization.
-- Feature Reference: F101
CREATE TABLE IF NOT EXISTS iam.automated_user_provisioning (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_system VARCHAR(100) NOT NULL, -- e.g., WORKDAY, SAP
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('CREATE', 'UPDATE', 'DEACTIVATE')),
    external_user_id VARCHAR(255) NOT NULL, -- ID in source system
    target_user_id UUID, -- ID in PARI system
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    error_message TEXT,
    payload_json JSONB, -- Full data received from SCIM
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auto_prov_user FOREIGN KEY (target_user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.automated_user_provisioning IS 'Tracks automated SCIM provisioning jobs for user lifecycle management.';

-- DB102: iam.explicit_denies
-- Description: Explicit deny rules that override allows.
-- Business Case: While the general philosophy is "whitelisting", certain security scenarios require absolute blacklisting. This table stores explicit "DENY" rules that cannot be overridden by standard RBAC or ABAC policies. For example, if a user is placed on a sanctions list, this table ensures they are blocked regardless of their assigned roles. It serves as a fail-safe mechanism for immediate security response, ensuring that高危 (high-risk) actors are permanently cut off from specific resources or the entire system.
-- KPIs: Deny rule enforcement speed, Rule update latency.
-- Feature Reference: F102
CREATE TABLE IF NOT EXISTS iam.explicit_denies (
    deny_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID, -- NULL if global/denied for anonymous
    resource VARCHAR(255), -- NULL if global deny
    action iam.enum_access_action, -- NULL if all actions
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_explicit_denies_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.explicit_denies IS 'Stores high-priority deny rules that override all standard access policies.';

-- DB103: iam.retention_policies
-- Description: Auto-deletion of access logs older than X years.
-- Business Case: GDPR and other regulations mandate that personal data cannot be retained indefinitely. This table defines retention policies for different types of data (e.g., "Access Logs: 7 years", "Failed Logins: 1 year"). A scheduled job consults this table to move old data to archive or delete it permanently. This automated enforcement ensures legal compliance and manages database storage costs effectively without relying on manual administrative intervention.
-- KPIs: Policy adherence rate, Storage cost savings.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS iam.retention_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    data_type VARCHAR(50) NOT NULL, -- e.g., ACCESS_LOG, LOGIN_LOG
    retention_years INTEGER NOT NULL CHECK (retention_years > 0),
    action_type VARCHAR(20) CHECK (action_type IN ('DELETE', 'ARCHIVE', 'ANONYMIZE')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.retention_policies IS 'Defines data retention and deletion policies for legal compliance.';

-- DB104: iam.collaboration_locks
-- Description: Preventing two admins from editing same policy.
-- Business Case: When policies are edited by multiple administrators simultaneously, "last write wins" can cause critical security rules to be lost. This table implements pessimistic locking for collaborative editing. When an admin opens a policy for editing, a lock is created here. Other admins are prevented from editing until the lock is released or expires. This ensures data integrity and prevents conflicting updates to the security configuration.
-- KPIs: Lock contention rate, Edit collision prevention.
-- Feature Reference: F104
CREATE TABLE IF NOT EXISTS iam.collaboration_locks (
    lock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- POLICY, ROLE
    resource_id UUID NOT NULL,
    locked_by UUID NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Auto-expiry to prevent permanent locks

    CONSTRAINT fk_collab_locks_user FOREIGN KEY (locked_by) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.collaboration_locks IS 'Manages locks for concurrent editing of security policies and roles.';

-- DB105: iam.liveness_checks
-- Description: Ensures biometric auth is from a live human.
-- Business Case: Biometric spoofing (using photos or recordings) is a significant threat. This table stores the results of liveness detection challenges (e.g., asking the user to blink, turn their head, or analyzing depth). It records the `score` and binary `result` of the check. This data is crucial for fraud analysis—if a specific device or location frequently fails liveness checks, it indicates a bot or attack pattern. It enhances the security of passwordless authentication flows.
-- KPIs: Spoof detection accuracy, User experience impact (completion rate).
-- Feature Reference: F105
CREATE TABLE IF NOT EXISTS iam.liveness_checks (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    challenge_type VARCHAR(50) NOT NULL, -- BLINK, SMILE, DEPTH
    result BOOLEAN NOT NULL,
    score NUMERIC(5,2), -- Confidence score
    provider VARCHAR(50), -- e.g., ONFIDO, AWS REKOGNITION
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_liveness_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.liveness_checks IS 'Stores results of biometric liveness detection to prevent spoofing.';

-- DB106: iam.error_help_texts
-- Description: Explains why access was denied.
-- Business Case: Cryptic error messages (e.g., "Error 403") frustrate users and increase support ticket volume. This table maps error codes (e.g., "POLICY_DENY_GEO_FENCE") to localized, user-friendly help texts. By providing context ("Access denied because you are outside the EU region"), the system educates users on security policies and reduces friction. This improves the overall user experience while maintaining strict security boundaries.
-- KPIs: Ticket reduction rate, User comprehension score.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS iam.error_help_texts (
    error_code VARCHAR(50) PRIMARY KEY,
    locale VARCHAR(10) NOT NULL DEFAULT 'en_US',
    title VARCHAR(255),
    detailed_text TEXT NOT NULL,
    suggested_action TEXT,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARN', 'ERROR'))
);
COMMENT ON TABLE iam.error_help_texts IS 'Stores localized user-friendly explanations for access denial errors.';

-- DB107: iam.offline_revocation_tokens
-- Description: Short-lived tokens to revoke rights when offline.
-- Business Case: For offline-first mobile apps, validating the current state of a user's permissions against the server is impossible. This table stores short-lived "revocation tokens". The client periodically fetches these tokens. If the user's rights are revoked, a token is issued here, and the app caches it. When the app detects a cached revocation token, it immediately locks the app. This provides a balance between offline functionality and the ability to instantly disable access.
-- KPIs: Offline sync success rate, Revocation propagation latency.
-- Feature Reference: F107
CREATE TABLE IF NOT EXISTS iam.offline_revocation_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_offline_rev_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.offline_revocation_tokens IS 'Short-lived tokens to signal access revocation to offline clients.';

-- DB108: iam.policy_git_repo
-- Description: Storing policies in Git repo for CI/CD.
-- Business Case: Infrastructure as Code (IaC) extends to security policies. This table tracks the metadata of policies stored in a Git repository. It maps a policy ID to a specific file path, commit hash, and branch. This enables a GitOps workflow where policy changes are proposed via Pull Requests, reviewed by code, and then deployed via CI/CD pipelines. This drastically improves the auditability and version control of security rules compared to manual database updates.
-- KPIs: Deployment success rate, PR merge time.
-- Feature Reference: F108
CREATE TABLE IF NOT EXISTS iam.policy_git_repo (
    repo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    file_path TEXT NOT NULL,
    branch VARCHAR(100) NOT NULL,
    commit_hash VARCHAR(40),
    last_synced_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_git_repo_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_git_repo IS 'Links database policies to their source files in a Git repository (Policy as Code).';

-- DB109: iam.third_party_risks
-- Description: Scoring external OAuth apps based on permission requests.
-- Business Case: Third-party applications often request broad permissions that users blindly accept. This table aggregates a "risk score" for these apps based on their requested scopes, vendor reputation, and behavior. If an app requests `read:email`, `read:contacts`, and `write:transactions`, its risk score increases. The system can then warn users or block the integration if the score exceeds a threshold, preventing over-granting of privileges to external entities.
-- KPIs: Risk assessment accuracy, Blocked risky integration count.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS iam.third_party_risks (
    app_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    vendor_name VARCHAR(255),
    risk_score NUMERIC(5,2) CHECK (risk_score >= 0 AND risk_score <= 100),
    permission_count INTEGER DEFAULT 0,
    last_scanned TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.third_party_risks IS 'Tracks risk scores for external third-party OAuth applications.';

-- DB110: iam.hash_salts
-- Description: Changing salts per hash iteration for audit logs.
-- Business Case: Storing hashes (like email or username hashes) without salt or with a static salt is vulnerable to rainbow table attacks. This table manages a "dynamic salt" strategy. It stores versions of salts used over time (`salt_value`, `active_from`). When hashing data for audit logs or exports, the system selects the currently active salt. By rotating salts periodically and recording the history, the system ensures that even if the database is leaked, attackers cannot easily crack the hashed values.
-- KPIs: Salt rotation frequency, Hash entropy.
-- Feature Reference: F110
CREATE TABLE IF NOT EXISTS iam.hash_salts (
    salt_ver_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    salt_value VARCHAR(255) NOT NULL UNIQUE,
    active_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.hash_salts IS 'Manages dynamic salts for hashing operations to enhance security.';

-- DB111: iam.self_service_groups
-- Description: Letting users manage their own dynamic groups.
-- Business Case: IT is often a bottleneck for simple permission changes. This table enables user-managed groups. For example, a project manager can create a "Project Alpha" group and add members themselves without opening a ticket. The `owner_id` ensures accountability. This democratization of access management improves agility while still auditing who added whom. It is restricted to low-risk scopes to maintain security.
-- KPIs: Ticket deflection rate, Group modification frequency.
-- Feature Reference: F111
CREATE TABLE IF NOT EXISTS iam.self_service_groups (
    group_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL, -- The user allowed to manage this group
    max_members INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_self_service_groups_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.self_service_groups IS 'Defines user-managed groups for delegated low-risk access management.';

-- DB112: iam.synthetic_transactions
-- Description: Running fake auth transactions to monitor health.
-- Business Case: Passive monitoring (just checking server uptime) isn't enough; we need to test the actual auth path. This table schedules and stores results of "synthetic transactions"—automated scripts that mimic a real user login, MFA challenge, and data access. If any step fails or takes too long, an alert is triggered. This proactive monitoring ensures that the authentication pipeline is functional 24/7, crucial for a financial platform like PARI.
-- KPIs: Availability percentage, Synthetic transaction success rate.
-- Feature Reference: F112
CREATE TABLE IF NOT EXISTS iam.synthetic_transactions (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    script_id VARCHAR(100) NOT NULL, -- Name of the test script
    scenario VARCHAR(100) NOT NULL, -- e.g., STANDARD_LOGIN, MFA_FLOW
    last_run TIMESTAMP WITH TIME ZONE,
    result VARCHAR(20) CHECK (result IN ('SUCCESS', 'FAILURE', 'TIMEOUT')),
    latency_ms INTEGER,
    error_log TEXT
);
COMMENT ON TABLE iam.synthetic_transactions IS 'Stores results of synthetic user journey tests for active monitoring.';

-- DB113: iam.certificate_authorities
-- Description: Internal CAs for mTLS.
-- Business Case: Zero Trust networking relies on mTLS (Mutual TLS). This table stores the metadata for the Certificate Authority (CA) roots that the PARI platform trusts. It includes the PEM certificate, key identifiers, and hierarchy info. By managing internal CAs, the platform can issue short-lived certificates for services and verify them without relying on external CAs, establishing a strong internal cryptographic trust fabric.
-- KPIs: Certificate issuance volume, Validation latency.
-- Feature Reference: F113
CREATE TABLE IF NOT EXISTS iam.certificate_authorities (
    ca_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    cert_pem TEXT NOT NULL,
    key_enc BYTEA, -- Encrypted private key (if managing key)
    parent_ca_id UUID, -- For hierarchy
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ca_parent FOREIGN KEY (parent_ca_id) REFERENCES iam.certificate_authorities(ca_id)
);
COMMENT ON TABLE iam.certificate_authorities IS 'Stores internal Certificate Authority roots for mTLS trust management.';

-- DB114: iam.apt_detections
-- Description: Long-term correlation of low-and-slow access anomalies.
-- Business Case: Advanced Persistent Threats (APTs) are sophisticated attacks that evade standard detection by acting very slowly over months. This table stores detected patterns that match this "low-and-slow" profile, such as a user consistently downloading exactly 1MB of data every Tuesday at 3 AM. It links these patterns to alerts. Correlating these subtle events over time is essential for catching stealthy attackers who are otherwise invisible to real-time anomaly detection.
-- KPIs: APT detection rate, False positive rate.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.apt_detections (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    pattern_description TEXT NOT NULL,
    confidence_score NUMERIC(3,2),
    status VARCHAR(20) DEFAULT 'OPEN',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_apt_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.apt_detections IS 'Stores detections of long-term, low-and-slow attack patterns (APT).';

-- DB115: iam.user_entropy
-- Description: Measuring randomness/predictability of access patterns.
-- Business Case: Humans have randomness in their behavior (login times, clicked buttons), while bots are often highly regular or repetitive. This table stores the calculated "entropy" score for a user's access patterns. A sudden drop in entropy (becoming very predictable) or a spike (chaotic behavior) can indicate automation or account takeover. This metric is used as an input feature for the AI risk engine.
-- KPIs: Entropy calculation frequency, Anomaly correlation.
-- Feature Reference: F115
CREATE TABLE IF NOT EXISTS iam.user_entropy (
    entropy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    score NUMERIC(10,2) NOT NULL, -- Shannon entropy value
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_entropy_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_entropy IS 'Stores entropy scores measuring the randomness of user behavior.';

-- DB116: iam.role_catalog
-- Description: Pre-built roles for common job functions.
-- Business Case: To accelerate deployment, the system needs a catalog of "best practice" roles (e.g., "Auditor", "Cashier", "Compliance Officer"). Unlike "templates" which are skeletons, these are fully defined roles ready for assignment. This table stores these pre-built definitions. When a new tenant is onboarded, they can import these roles instantly, ensuring they start with a security-compliant baseline configuration.
-- KPIs: Role import speed, Catalog usage.
-- Feature Reference: F116
CREATE TABLE IF NOT EXISTS iam.role_catalog (
    catalog_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB NOT NULL, -- Serialized list of permission IDs/definitions
    category VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.role_catalog IS 'Stores fully defined, pre-built roles for immediate use.';

-- DB117: iam.field_level_encryption
-- Description: Encrypting specific sensitive fields before DB storage.
-- Business Case: Encrypting the whole database is standard, but Field Level Encryption (FLE) protects specific columns even from DB admins. This table tracks which columns in which tables are encrypted and which key ID to use. When data is inserted/selected, the application consults this table to apply encryption/decryption transparently. This is critical for "defense in depth" to protect data at rest even if the database infrastructure is compromised.
-- KPIs: Encryption/Decryption latency, Protected field coverage.
-- Feature Reference: F117
CREATE TABLE IF NOT EXISTS iam.field_level_encryption (
    encryption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    key_id VARCHAR(255) NOT NULL, -- Reference to encryption key
    algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',

    CONSTRAINT uk_fle_table_column UNIQUE (table_name, column_name)
);
COMMENT ON TABLE iam.field_level_encryption IS 'Tracks which database columns require Field Level Encryption (FLE).';

-- DB118: iam.distributed_trace_context
-- Description: Passing trace IDs through auth calls.
-- Business Case: In a microservices architecture, a single request traverses many services. To debug failures (e.g., "Why did auth fail?"), we need a Trace ID that propagates through every service. This table (or buffer) stores the context for active traces passing through the IAM module. It links the `trace_id` to the user session, allowing for distributed tracing tools (like OpenTelemetry) to reconstruct the full timeline of an authentication attempt.
-- KPIs: Trace completeness, Context propagation success.
-- Feature Reference: F118
CREATE TABLE IF NOT EXISTS iam.distributed_trace_context (
    trace_id VARCHAR(64) PRIMARY KEY,
    parent_span_id VARCHAR(64),
    user_id UUID,
    service_name VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_trace_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.distributed_trace_context IS 'Stores context for distributed tracing of authentication flows.';

-- DB119: iam.login_ui_configs
-- Description: Drag-and-drop login page builder.
-- Business Case: Branding is crucial for B2B partners. This table stores the JSON configuration for custom login pages. It defines the layout, background images, logo, and field arrangement. By treating the login page as configuration, the PARI platform can offer a white-label experience where every client feels they are logging into their own system, without code changes.
-- KPIs: Configuration retrieval speed, UI customization complexity.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.login_ui_configs (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    layout_json JSONB NOT NULL,
    css_override TEXT,
    created_by UUID NOT NULL,

    CONSTRAINT fk_login_ui_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.login_ui_configs IS 'Stores UI configuration for customizable login pages.';

-- DB120: iam.identity_bridge
-- Description: Connecting to mainframe/legacy auth systems.
-- Business Case: Many financial institutions still run on mainframes. This table configures the "bridge" or adapter that connects the modern PARI IAM to these legacy systems (e.g., RACF, ACF2). It stores connection parameters and protocol details. It allows for a phased migration strategy where users can be authenticated against the legacy system while their session is managed by the modern PARI platform.
-- KPIs: Bridge latency, Legacy system availability.
-- Feature Reference: F120
CREATE TABLE IF NOT EXISTS iam.identity_bridge (
    bridge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    system_type VARCHAR(50) NOT NULL, -- MAINFRAME, LDAP
    connection_string TEXT, -- Encrypted
    protocol VARCHAR(50),
    status VARCHAR(20) DEFAULT 'CONNECTED'
);
COMMENT ON TABLE iam.identity_bridge IS 'Configuration for connecting to legacy authentication systems.';

-- DB121: iam.smart_password_analysis
-- Description: Checking passwords against leaked breach corpuses.
-- Business Case: Users often reuse passwords. This table (or cache) stores the results of checking a password hash against known leaked databases (e.g., HaveIBeenPwned). It flags weak or compromised passwords *before* they are set. This proactive security measure prevents attackers from using credential stuffing to access accounts where users have reused passwords from other breached sites.
-- KPIs: Weak password rejection rate, Breach check latency.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS iam.smart_password_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    is_compromised BOOLEAN NOT NULL,
    breach_source VARCHAR(255), -- Name of the breach corpus
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.smart_password_analysis IS 'Stores results of password checks against security breach databases.';

-- DB122: iam.policy_dependency_mapping
-- Description: Visualizing which policies depend on others.
-- Business Case: Deleting a policy that others depend on can break access. This table maps the dependency graph (`parent_policy` depends on `child_policy` or vice versa). It is used by the admin UI to visualize dependencies and by the backend to prevent accidental deletion of "base" policies. This ensures stability and maintainability of the complex ABAC rule set.
-- KPIs: Dependency detection accuracy.
-- Feature Reference: F122
CREATE TABLE IF NOT EXISTS iam.policy_dependency_mapping (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    dependent_policy_id UUID NOT NULL,
    dependency_type VARCHAR(50) CHECK (dependency_type IN ('USES', 'EXCLUDES', 'MODIFIES')),

    CONSTRAINT fk_policy_map_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_policy_map_dep FOREIGN KEY (dependent_policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_dependency_mapping IS 'Maps dependencies between access control policies.';

-- DB123: iam.rate_limit_per_user
-- Description: Individual limits to prevent noisy neighbors.
-- Business Case: Global rate limits might be too restrictive for power users or too loose for others. This table defines user-specific limits. It allows for fair usage policies where a trusted API consumer gets a higher quota than a new one. It ensures that one user's activity cannot degrade system performance for others.
-- KPIs: Enforcement accuracy, User satisfaction (reduced throttling).
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.rate_limit_per_user (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    requests_per_minute INTEGER NOT NULL,
    burst_limit INTEGER, -- Allowed burst capacity
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rate_limit_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.rate_limit_per_user IS 'Defines individualized rate limits for specific users.';

-- DB124: iam.access_certification
-- Description: Digital sign-off by managers on user rights.
-- Business Case: Compliance requires managers to periodically certify that their direct reports still need their access. This table stores the records of these certifications. It captures who certified what, when, and the outcome (Certify/Revoke). This formal sign-off is a legal artifact proving that the organization is actively managing access, a requirement for SOX and ISO audits.
-- KPIs: Certification completion rate, Access revocation resulting from reviews.
-- Feature Reference: F124
CREATE TABLE IF NOT EXISTS iam.access_certification (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    certifier_id UUID NOT NULL, -- The manager
    role_id UUID NOT NULL,
    decision VARCHAR(20) CHECK (decision IN ('CERTIFIED', 'REVOKED', 'NO_DECISION')),
    signature_hash VARCHAR(255), -- Digital signature of the certification
    certified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cert_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_cert_certifier FOREIGN KEY (certifier_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_cert_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_certification IS 'Stores digital sign-offs for periodic access reviews.';

-- DB125: iam.session_recording_metadata
-- Description: Metadata for recorded admin sessions.
-- Business Case: For security investigations, having the actual video (DB095) is key, but metadata helps search it. This table stores details about the recording: which admin, what time, duration, and specifically *what* UI elements were accessed. This allows forensic analysts to quickly jump to the part of the video where a specific setting was changed, rather than watching hours of mouse movements.
-- KPIs: Search precision, Metadata accuracy.
-- Feature Reference: F125
CREATE TABLE IF NOT EXISTS iam.session_recording_metadata (
    recording_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    duration_seconds INTEGER,
    ui_elements_accessed TEXT[], -- List of UI paths visited
    storage_backend VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_recording_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_recording_metadata IS 'Stores searchable metadata for session recordings.';

-- DB126: iam.branding_themes
-- Description: Customizing login for different tenants.
-- Business Case: Similar to DB119, but focused on visual themes. This table stores CSS, color palettes, and image URLs. It enables multi-tenancy where Tenant A sees a Blue interface and Tenant B sees a Red one. It improves user trust by presenting a familiar brand interface during authentication.
-- KPIs: Theme application consistency.
-- Feature Reference: F126
CREATE TABLE IF NOT EXISTS iam.branding_themes (
    theme_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    theme_name VARCHAR(100),
    primary_color CHAR(6), -- Hex
    logo_url TEXT,
    css_bundle TEXT,

    CONSTRAINT fk_branding_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.branding_themes IS 'Stores visual branding assets for multi-tenant customization.';

-- DB127: iam.captcha_v2_challenges
-- Description: Captcha generation and validation records (V2).
-- Business Case: As CAPTCHA providers evolve (e.g., moving from text to image recognition), the system needs to support multiple versions. This table tracks V2 specific challenges (e.g., image selection). It stores the reference to the image set and the user's response. Supporting multiple CAPTCHA versions ensures the system can always use the most effective bot deterrent available.
-- KPIs: Solve rate, Bot deterrence.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS iam.captcha_v2_challenges (
    challenge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID,
    image_set_id VARCHAR(255),
    user_solution TEXT,
    expected_solution TEXT,
    solved BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_captcha_v2_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.captcha_v2_challenges IS 'Tracks advanced (image-based) CAPTCHA challenges.';

-- DB128: iam.magic_link_history
-- Description: Tracking of one-time magic link usage.
-- Business Case: While DB051 stores the active link, this table logs the *usage* of magic links. It tracks the IP, time, and user agent of the click. This history is vital for detecting patterns of abuse, such as requesting a magic link from one country but clicking it from another, or requesting links at a high frequency. It adds a layer of security to the passwordless login flow.
-- KPIs: Fraudulent link usage detection.
-- Feature Reference: F128
CREATE TABLE IF NOT EXISTS iam.magic_link_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    link_id UUID NOT NULL,
    used_ip INET,
    used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,

    CONSTRAINT fk_magic_hist_link FOREIGN KEY (link_id) REFERENCES iam.magic_links(link_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.magic_link_history IS 'Audit log tracking when and where magic links were used.';

-- DB129: iam.access_revocation_workflow
-- Description: UI for instant mass revocation.
-- Business Case: In an emergency (e.g., contractor leaves or breach is detected), admins need to revoke access instantly, potentially for many users. This table tracks the execution of these bulk revocation jobs. It records *who* initiated the mass revocation, *why*, and *which* users were affected. This audit trail is essential for proving that prompt action was taken to contain a security incident.
-- KPIs: Revocation execution speed, Job coverage accuracy.
-- Feature Reference: F129
CREATE TABLE IF NOT EXISTS iam.access_revocation_workflow (
    workflow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    initiated_by UUID NOT NULL,
    reason TEXT NOT NULL,
    target_criterion JSONB, -- e.g., "role": "CONTRACTOR"
    affected_users_count INTEGER,
    status VARCHAR(20) DEFAULT 'RUNNING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.access_revocation_workflow IS 'Tracks mass access revocation jobs for emergency response.';

-- DB130: iam.just_in_time_secret_access
-- Description: Temporary access to secrets in Vault.
-- Business Case: Developers often need DB credentials, but they shouldn't have them long-term. This table records instances of JIT secret access from a Vault. It links the request to a specific ticket or justification (JIT request) and logs the duration of the lease. This ensures that secret access is always tied to a temporary, authorized task, supporting the "Zero Standing Privilege" principle for infrastructure secrets.
-- KPIs: Secret lease duration, Justification linkage rate.
-- Feature Reference: F130
CREATE TABLE IF NOT EXISTS iam.just_in_time_secret_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_path TEXT NOT NULL,
    leased_by UUID NOT NULL,
    lease_duration_seconds INTEGER,
    justification_ref_id UUID, -- Links to a ticket or JIT request
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_jit_secret_user FOREIGN KEY (leased_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.just_in_time_secret_access IS 'Logs temporary access grants to infrastructure secrets.';

-- DB131: iam.biometric_template_encryption
-- Description: Encrypting stored biometric templates.
-- Business Case: Biometric data is immutable and highly sensitive. Losing the original template means the user can never use that biometric again. This table stores the metadata about the encryption applied to biometric templates stored elsewhere (or acts as the store). It ensures that the template is encrypted at rest using strong FPE (Format Preserving Encryption) or AES, and tracks the key version used to support future key rotation without invalidating the biometric.
-- KPIs: Encryption strength, Key rotation success.
-- Feature Reference: F131
CREATE TABLE IF NOT EXISTS iam.biometric_template_encryption (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    key_id UUID NOT NULL,
    algorithm VARCHAR(50),

    CONSTRAINT fk_bio_enc_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.biometric_template_encryption IS 'Securely stores and manages encryption of biometric templates.';

-- DB132: iam.policy_test_case_generator
-- Description: Auto-generating test cases for policies.
-- Business Case: Writing test cases for complex ABAC policies is tedious. This table stores the configuration for the "Test Case Generator". It defines the range of inputs (e.g., "Random IP in EU", "Role: Admin", "Time: Night") to use for automated fuzzing. The system then executes these inputs against the policy to find edge cases. This improves the robustness and security of the access control logic by identifying logic bugs before deployment.
-- KPIs: Bug detection rate in pre-production.
-- Feature Reference: F132
CREATE TABLE IF NOT EXISTS iam.policy_test_case_generator (
    generator_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    generation_strategy JSONB, -- Config for fuzzing or random generation
    last_run_at TIMESTAMP WITH TIME ZONE,
    bugs_found INTEGER DEFAULT 0,

    CONSTRAINT fk_test_gen_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_test_case_generator IS 'Configuration for automated fuzzing/generation of policy test cases.';

-- DB133: iam.dynamic_data_labeling
-- Description: Auto-labeling data fields based on content.
-- Business Case: Manual data labeling is impossible at scale. This table stores the results of AI-driven data labeling. The AI scans database columns (e.g., "email", "ssn") and assigns a label (e.g., "PII", "CONFIDENTIAL") and a `confidence` score. These labels are then used by the ABAC engine to enforce protection policies automatically, ensuring new sensitive data is protected without manual intervention.
-- KPIs: Labeling accuracy, Auto-protection coverage.
-- Feature Reference: F133
CREATE TABLE IF NOT EXISTS iam.dynamic_data_labeling (
    label_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(255) NOT NULL, -- Table.Column or File ID
    label_name VARCHAR(100) NOT NULL,
    confidence NUMERIC(3,2),
    algorithm VARCHAR(50),
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.dynamic_data_labeling IS 'Stores AI-assigned sensitivity labels for data resources.';

-- DB134: iam.federated_query_governance
-- Description: Controlling access to cross-database queries.
-- Business Case: Data warehouses often span multiple databases. A user might be allowed to query Table A in DB1 but not Table B in DB2. This table stores governance rules for federated queries. It checks the `source` and `target` of a cross-database join request and enforces access controls. This prevents "Trojan Horse" queries where a user leverages access in one DB to extract data from another via a JOIN.
-- KPIs: Query block rate, Policy enforcement latency.
-- Feature Reference: F134
CREATE TABLE IF NOT EXISTS iam.federated_query_governance (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    source_db VARCHAR(100),
    target_db VARCHAR(100),
    allowed BOOLEAN,
    created_by UUID NOT NULL,

    CONSTRAINT fk_fed_query_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.federated_query_governance IS 'Governance rules for cross-database data access.';

-- DB135: iam.identity_wallet_pairing
-- Description: QR code flow to pair mobile wallet with desktop.
-- Business Case: To enable mobile-based authentication (like scanning a QR code with a banking app), we need a pairing mechanism. This table stores the temporary "pairing tokens" displayed as QR codes. When the mobile app scans the code, it validates against this table. This establishes a trusted channel between the desktop browser and the mobile wallet, facilitating secure push notifications or transaction signing on the mobile device.
-- KPIs: Pairing success rate, Time to pair.
-- Feature Reference: F135
CREATE TABLE IF NOT EXISTS iam.identity_wallet_pairing (
    pairing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    session_id UUID, -- The desktop session
    qr_string VARCHAR(255) NOT NULL,
    paired_device_id VARCHAR(255), -- ID of the mobile wallet after pairing
    status VARCHAR(20) DEFAULT 'PENDING',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_pairing_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.identity_wallet_pairing IS 'Manages the pairing process between desktop sessions and mobile wallets.';

-- DB136: iam.logic_bomb_rules
-- Description: Patterns defining a logic bomb.
-- Business Case: To automatically detect logic bombs (malicious scheduled tasks), we need rules defining what they look like. This table stores these patterns, expressed as regex or code snippets (e.g., "IF date = '2025-01-01' THEN DELETE"). The scanning engine compares these rules against code repositories or database procedures. Matching rules generate alerts in DB056.
-- KPIs: Rule detection coverage, False positive rate.
-- Feature Reference: F136
CREATE TABLE IF NOT EXISTS iam.logic_bomb_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_regex TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'HIGH',
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.logic_bomb_rules IS 'Stores pattern definitions for detecting logic bombs in code or procedures.';

-- DB137: iam.cloud_provider_iam_sync
-- Description: Syncing roles with AWS/Azure/GCP IAM.
-- Business Case: To enforce cloud security, roles defined in PARI must be mirrored in cloud providers. This table stores the mapping (PARI Role -> Cloud Role) and the status of the sync. It ensures that if a user leaves PARI, their corresponding AWS/IAM role is simultaneously deleted. This unified governance prevents "cloud drift" where local revocation doesn't affect cloud access.
-- KPIs: Sync consistency, Role reconciliation success.
-- Feature Reference: F137
CREATE TABLE IF NOT EXISTS iam.cloud_provider_iam_sync (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider VARCHAR(20) NOT NULL, -- AWS, AZURE
    local_role_id UUID NOT NULL,
    cloud_role_arn TEXT, -- AWS Resource Name or Azure ID
    last_sync_status VARCHAR(20),
    last_synced_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_cloud_sync_role FOREIGN KEY (local_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.cloud_provider_iam_sync IS 'Maps and syncs PARI roles to cloud provider IAM roles.';

-- DB138: iam.access_pattern_normalization
-- Description: Normalizing time-series access data for ML.
-- Business Case: Raw access data is messy. Machine learning models require normalized, time-series data to detect anomalies effectively. This table stores the processed vectors or normalized data points (e.g., logins per hour vs average). It acts as the "Feature Store" for the anomaly detection models, ensuring that inputs are standardized for training and inference.
-- KPIs: Data quality score, Normalization throughput.
-- Feature Reference: F138
CREATE TABLE IF NOT EXISTS iam.access_pattern_normalization (
    norm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    metric_name VARCHAR(100) NOT NULL, -- e.g. LOGIN_FREQUENCY, DATA_TRANSFER_MB
    normalized_value NUMERIC(10,2),
    window_timestamp TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_norm_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_pattern_normalization IS 'Stores normalized time-series data for ML anomaly detection.';

-- DB139: iam.policy_diff_tool
-- Description: Comparing two versions of a policy set.
-- Business Case: Before approving a policy change, reviewers need to see exactly what changed. This table stores the results of the diff (comparison) between Policy Version A and Policy Version B. It highlights added lines, removed lines, and modifications. This visual diff tool is essential for code-review style governance of security policies, reducing the chance of accidental malicious insertions.
-- KPIs: Diff generation speed.
-- Feature Reference: F139
CREATE TABLE IF NOT EXISTS iam.policy_diff_tool (
    diff_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    version_a VARCHAR(20),
    version_b VARCHAR(20),
    diff_json JSONB NOT NULL, -- Structured representation of changes
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.policy_diff_tool IS 'Stores the differences (diff) between versions of policies.';

-- DB140: iam.privacy_impact_assessment
-- Description: Assessing impact of new access rights on privacy.
-- Business Case: Before granting a new set of permissions (e.g., "View all transactions"), we must assess the privacy impact. This table records these PIAs. It scores the risk of accessing the data (e.g., "High" because it contains PII) and mandates mitigation (e.g., "Require Consent"). This ensures that the Principle of Data Protection by Design is followed for every permission change.
-- KPIs: Assessment completion rate, Risk mitigation tracking.
-- Feature Reference: F140
CREATE TABLE IF NOT EXISTS iam.privacy_impact_assessment (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    change_request_id UUID,
    impact_score INTEGER CHECK (impact_score >= 0 AND impact_score <= 10),
    assessed_by UUID NOT NULL,
    findings TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pia_user FOREIGN KEY (assessed_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.privacy_impact_assessment IS 'Stores Privacy Impact Assessments for permission changes.';

-- DB141: iam.decentralized_access_tokens
-- Description: Verifiable Credentials (VCs) for access.
-- Business Case: Moving towards Self-Sovereign Identity (SSI), access can be granted via Verifiable Credentials stored in a user's wallet. This table tracks the issuance and status of these VCs. The user holds the VC, and the PARI platform acts as the verifier. This table ensures that a VC hasn't been revoked, enabling a decentralized, privacy-preserving access model where the user proves their right to access without revealing all their identity data.
-- KPIs: VC verification speed, Revocation check latency.
-- Feature Reference: F141
CREATE TABLE IF NOT EXISTS iam.decentralized_access_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vc_hash VARCHAR(255) NOT NULL UNIQUE, -- Hash of the Verifiable Credential
    user_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_dec_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.decentralized_access_tokens IS 'Tracks issued Verifiable Credentials for decentralized access.';

-- DB142: iam.audit_log_compression
-- Description: Compressing logs for storage cost reduction.
-- Business Case: Storing terabytes of JSON logs is expensive. This table manages the compression jobs. It identifies batches of logs (from `access_logs`), compresses them using ZSTD or LZ4, and stores the binary blob. It retains the metadata to allow decompression on demand. This optimizes storage costs while ensuring that historical data remains retrievable for long-term audits.
-- KPIs: Compression ratio, Decompression speed.
-- Feature Reference: F142
CREATE TABLE IF NOT EXISTS iam.audit_log_compression (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_log_range TEXT, -- e.g., "log_1 to log_1000"
    compressed_data BYTEA NOT NULL,
    compression_algorithm VARCHAR(20),
    original_size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.audit_log_compression IS 'Stores compressed batches of audit logs for cost optimization.';

-- DB143: iam.machine_identity_management
-- Description: Managing auth for bots/IoT devices.
-- Business Case: Machines (APIs, IoT) need identities too. This table manages non-human identities. It stores their certificates, API keys, and allowed scopes. Unlike humans, machines have strict lifecycles and often rotate credentials automatically. This table ensures that machine-to-machine communication is secured, authenticated, and authorized just like human users, extending Zero Trust to the IoT layer.
-- KPIs: Machine auth success rate, Credential rotation compliance.
-- Feature Reference: F143
CREATE TABLE IF NOT EXISTS iam.machine_identity_management (
    machine_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) CHECK (type IN ('BOT', 'IOT', 'SERVICE')),
    credentials JSONB, -- Encrypted keys/certs
    owner_id UUID,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_machine_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.machine_identity_management IS 'Manages identities for non-human actors (bots, services, IoT).';

-- DB144: iam.secure_delegation_tokens
-- Description: Tokens that allow passing auth to a subprocess.
-- Business Case: Complex workflows (e.g., a backend service calling another on behalf of a user) require passing authentication context securely. This table stores short-lived delegation tokens. The primary user generates a token with specific scopes, and the subprocess uses it. This ensures the subprocess has only the permissions explicitly delegated to it, adhering to the principle of least privilege in distributed systems.
-- KPIs: Token usage validity, Delegation scope accuracy.
-- Feature Reference: F144
CREATE TABLE IF NOT EXISTS iam.secure_delegation_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_session_id UUID NOT NULL,
    delegated_to VARCHAR(255) NOT NULL, -- Service ID or Sub-process name
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_delegation_parent FOREIGN KEY (parent_session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.secure_delegation_tokens IS 'Stores tokens for delegating specific auth scopes to subprocesses.';

-- DB145: iam.role_activation_code
-- Description: Requiring a code to activate a high-privilege role.
-- Business Case: For highly sensitive roles (e.g., "Super Admin"), we might require a second factor even *after* login to activate the role. This table stores the activation codes (OTP). The user logs in, but only gets admin rights after entering a valid code from this table (delivered via a different channel like SMS or hardware token). This is a "Two-Man Rule" or "Step-Up" implementation for roles.
-- KPIs: Activation latency, Code interception resistance.
-- Feature Reference: F145
CREATE TABLE IF NOT EXISTS iam.role_activation_code (
    code_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_role_act_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_role_act_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.role_activation_code IS 'Stores one-time codes required to activate sensitive roles.';

-- DB146: iam.watermarking_of_exported_data
-- Description: Embedding user ID in downloaded files.
-- Business Case: If a sensitive dataset is leaked, we need to know *who* leaked it. This table tracks the watermarking process. When a user exports a file (e.g., CSV), a unique watermark (invisible string or slight data perturbation) containing their user ID is injected. This table links the export job to the watermark signature, enabling forensic tracing of leaks back to the specific user account.
-- KPIs: Watermark detectability, Data integrity impact.
-- Feature Reference: F146
CREATE TABLE IF NOT EXISTS iam.watermarking_of_exported_data (
    watermark_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    export_id UUID NOT NULL, -- Links to export_jobs (DB090)
    user_id UUID NOT NULL,
    watermark_signature TEXT NOT NULL, -- The hidden identifier
    method VARCHAR(50), -- STEGANOGRAPHY, HEADER_INJECTION

    CONSTRAINT fk_watermark_export FOREIGN KEY (export_id) REFERENCES iam.export_jobs(export_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.watermarking_of_exported_data IS 'Tracks watermarking signatures applied to exported files for leak tracing.';

-- DB147: iam.browser_isolation_for_admins
-- Description: Running admin sessions in remote browser.
-- Business Case: Admin sessions are high-value targets. Malware on the admin's laptop could steal credentials or modify data. This table manages remote browser isolation sessions. The admin's browser actually runs in a disposable container in the cloud, streaming only the video/rendering to the local device. This ensures that zero code executes on the admin's endpoint, providing endpoint protection.
-- KPIs: Session latency, Isolation reliability.
-- Feature Reference: F147
CREATE TABLE IF NOT EXISTS iam.browser_isolation_for_admins (
    iso_session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    local_session_id UUID NOT NULL,
    remote_ip INET,
    isolation_provider VARCHAR(50),
    status VARCHAR(20) DEFAULT 'ACTIVE',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_browser_isolation_session FOREIGN KEY (local_session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.browser_isolation_for_admins IS 'Manages remote browser sessions for high-security admin activities.';

-- DB148: iam.consent_receipt_generation
-- Description: Providing proof of consent for auth.
-- Business Case: Similar to DB054, this table specifically handles the *generation* event of the receipt. It links the specific authentication event or consent action to the generated receipt artifact (JWS). It ensures that a receipt is generated for every single consent transaction, creating a perfect chain of custody for GDPR compliance.
-- KPIs: Receipt generation success, Verification readiness.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.consent_receipt_generation (
    receipt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_id UUID NOT NULL, -- The event triggering consent (e.g. login, data access)
    user_id UUID NOT NULL,
    receipt_jws TEXT NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_consent_gen_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.consent_receipt_generation IS 'Tracks the generation of consent receipts for specific events.';

-- DB149: iam.adaptive_ui_based_on_role
-- Description: Hiding/showing UI elements based on permissions.
-- Business Case: To reduce user confusion and data leakage, the UI should only show elements the user can access. This table maps UI paths (e.g., `/admin/settings`) to permissions. The frontend queries this table (or receives a derived JSON) to render the navigation menu. If a user doesn't have the permission, the button doesn't appear. This is a UI-level enforcement of the principle of least privilege.
-- KPIs: UI rendering correctness, Unauthorized click attempts.
-- Feature Reference: F149
CREATE TABLE IF NOT EXISTS iam.adaptive_ui_based_on_role (
    ui_config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID NOT NULL,
    element_path VARCHAR(255) NOT NULL, -- CSS Selector or Route
    visibility BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_adaptive_ui_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.adaptive_ui_based_on_role IS 'Defines UI element visibility based on user roles.';

-- DB150: iam.end_to_end_encryption_keys
-- Description: Managing keys for E2EE where access control decrypts.
-- Business Case: In some architectures, data is encrypted on the client side (End-to-End). This table stores the public keys of users so others can encrypt data for them. It also stores encrypted private keys for users (which the system decrypts and re-encrypts to the user's session only upon authentication). This allows the system to manage E2EE keys while ensuring that even the server cannot read the user's private data in clear text.
-- KPIs: Key retrieval latency, Key security strength.
-- Feature Reference: F150
CREATE TABLE IF NOT EXISTS iam.end_to_end_encryption_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    owner_id UUID NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key BYTEA, -- Wrapped by a master key
    key_version INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_e2e_keys_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.end_to_end_encryption_keys IS 'Manages public/private key pairs for client-side E2EE.';

-- ================================================================================
-- Indexes and Constraints for Part 3 Tables
-- ================================================================================

-- Automated User Provisioning
CREATE INDEX IF NOT EXISTS idx_auto_prov_external ON iam.automated_user_provisioning(external_user_id);
CREATE INDEX IF NOT EXISTS idx_auto_prov_status ON iam.automated_user_provisioning(status);

-- Explicit Denies
CREATE INDEX IF NOT EXISTS idx_explicit_denies_user ON iam.explicit_denies(user_id);
CREATE INDEX IF NOT EXISTS idx_explicit_denies_resource ON iam.explicit_denies(resource);

-- Retention Policies
CREATE INDEX IF NOT EXISTS idx_retention_active ON iam.retention_policies(is_active) WHERE is_active = TRUE;

-- Collaboration Locks
CREATE INDEX IF NOT EXISTS idx_collab_locks_resource ON iam.collaboration_locks(resource_type, resource_id);

-- Liveness Checks
CREATE INDEX IF NOT EXISTS idx_liveness_user ON iam.liveness_checks(user_id);

-- Policy Git Repo
CREATE INDEX IF NOT EXISTS idx_git_repo_policy ON iam.policy_git_repo(policy_id);

-- Third Party Risks
CREATE INDEX IF NOT EXISTS idx_third_party_risk_score ON iam.third_party_risks(risk_score);

-- Hash Salts
CREATE INDEX IF NOT EXISTS idx_hash_salts_active ON iam.hash_salts(is_active) WHERE is_active = TRUE;

-- Synthetic Transactions
CREATE INDEX IF NOT EXISTS idx_synthetic_result ON iam.synthetic_transactions(result);
CREATE INDEX IF NOT EXISTS idx_synthetic_last_run ON iam.synthetic_transactions(last_run DESC);

-- Certificate Authorities
CREATE INDEX IF NOT EXISTS idx_ca_parent ON iam.certificate_authorities(parent_ca_id);

-- APT Detections
CREATE INDEX IF NOT EXISTS idx_apt_detected ON iam.apt_detections(detected_at DESC);

-- User Entropy
CREATE INDEX IF NOT EXISTS idx_entropy_user_time ON iam.user_entropy(user_id, window_end DESC);

-- Field Level Encryption
CREATE INDEX IF NOT EXISTS idx_fle_table ON iam.field_level_encryption(table_name, column_name);

-- Smart Password Analysis
CREATE INDEX IF NOT EXISTS idx_pwd_compromised ON iam.smart_password_analysis(is_compromised) WHERE is_compromised = TRUE;

-- Policy Dependency Mapping
CREATE INDEX IF NOT EXISTS idx_policy_dep_policy ON iam.policy_dependency_mapping(policy_id);

-- Rate Limit Per User
CREATE INDEX IF NOT EXISTS idx_rate_limit_user ON iam.rate_limit_per_user(user_id);

-- Session Recording Metadata
CREATE INDEX IF NOT EXISTS idx_recording_session ON iam.session_recording_metadata(session_id);

-- Magic Link History
CREATE INDEX IF NOT EXISTS idx_magic_hist_link ON iam.magic_link_history(link_id);

-- Identity Wallet Pairing
CREATE INDEX IF NOT EXISTS idx_pairing_qr ON iam.identity_wallet_pairing(qr_string);
CREATE INDEX IF NOT EXISTS idx_pairing_expires ON iam.identity_wallet_pairing(expires_at) WHERE status = 'PENDING';

-- Logic Bomb Rules
CREATE INDEX IF NOT EXISTS idx_logic_bomb_active ON iam.logic_bomb_rules(is_active) WHERE is_active = TRUE;

-- Cloud Provider IAM Sync
CREATE INDEX IF NOT EXISTS idx_cloud_sync_role ON iam.cloud_provider_iam_sync(local_role_id);

-- Access Pattern Normalization
CREATE INDEX IF NOT EXISTS idx_norm_metric_user ON iam.access_pattern_normalization(metric_name, user_id);

-- Policy Diff Tool
CREATE INDEX IF NOT EXISTS idx_policy_diff_policy ON iam.policy_diff_tool(policy_id);

-- Privacy Impact Assessment
CREATE INDEX IF NOT EXISTS idx_pia_change ON iam.privacy_impact_assessment(change_request_id);

-- Decentralized Access Tokens
CREATE INDEX IF NOT EXISTS idx_dec_tokens_user ON iam.decentralized_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_dec_tokens_hash ON iam.decentralized_access_tokens(vc_hash);

-- Machine Identity Management
CREATE INDEX IF NOT EXISTS idx_machine_owner ON iam.machine_identity_management(owner_id);

-- Secure Delegation Tokens
CREATE INDEX IF NOT EXISTS idx_delegation_parent ON iam.secure_delegation_tokens(parent_session_id);

-- Role Activation Code
CREATE INDEX IF NOT EXISTS idx_role_act_user ON iam.role_activation_code(user_id);

-- Watermarking of Exported Data
CREATE INDEX IF NOT EXISTS idx_watermark_export ON iam.watermarking_of_exported_data(export_id);

-- Browser Isolation
CREATE INDEX IF NOT EXISTS idx_browser_iso_session ON iam.browser_isolation_for_admins(local_session_id);

-- Consent Receipt Generation
CREATE INDEX IF NOT EXISTS idx_consent_gen_event ON iam.consent_receipt_generation(event_id);

-- Adaptive UI
CREATE INDEX IF NOT EXISTS idx_adaptive_ui_role ON iam.adaptive_ui_based_on_role(role_id);

-- E2E Encryption Keys
CREATE INDEX IF NOT EXISTS idx_e2e_owner ON iam.end_to_end_encryption_keys(owner_id);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 3 Tables
-- ================================================================================

-- Enable RLS on sensitive tables
ALTER TABLE iam.explicit_denies ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.collaboration_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.error_help_texts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.self_service_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.rate_limit_per_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.machine_identity_management ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.end_to_end_encryption_keys ENABLE ROW LEVEL SECURITY;

-- Policy for Explicit Denies (Only security team can see)
CREATE POLICY explicit_denies_restricted ON iam.explicit_denies
    FOR ALL
    USING (EXISTS (
        SELECT 1 FROM iam.user_roles ur
        JOIN iam.roles r ON r.role_id = ur.role_id
        WHERE ur.user_id = current_setting('app.current_user_id', true)::UUID
        AND r.role_name = 'SECURITY_ADMIN'
    ));

-- Policy for Collaboration Locks (User can see their own locks or Admins see all)
CREATE POLICY collab_locks_isolation ON iam.collaboration_locks
    FOR ALL
    USING (
        locked_by = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE)
    );

-- Policy for Error Help Texts (Users can only see active texts)
CREATE POLICY error_help_texts_active ON iam.error_help_texts
    FOR SELECT
    USING (true); -- Public readability, but maybe restrict write to admins

-- Policy for Self Service Groups (Owner can manage)
CREATE POLICY self_service_groups_owner ON iam.self_service_groups
    FOR ALL
    USING (owner_id = current_setting('app.current_user_id', true)::UUID);

-- Policy for Rate Limit Per User (User can see their own limits)
CREATE POLICY rate_limit_user_isolation ON iam.rate_limit_per_user
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Policy for Machine Identity (Owner or Admin)
CREATE POLICY machine_identity_owner ON iam.machine_identity_management
    FOR ALL
    USING (
        owner_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE)
    );

-- Policy for E2E Keys (Owner only)
CREATE POLICY e2e_keys_owner ON iam.end_to_end_encryption_keys
    FOR ALL
    USING (owner_id = current_setting('app.current_user_id', true)::UUID);

-- ================================================================================
-- Triggers for Part 3 Tables
-- ================================================================================

-- Apply update triggers
CREATE TRIGGER trg_auto_prov_update BEFORE UPDATE ON iam.automated_user_provisioning FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_retention_policies_update BEFORE UPDATE ON iam.retention_policies FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_policy_git_repo_update BEFORE UPDATE ON iam.policy_git_repo FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_third_party_risks_update BEFORE UPDATE ON iam.third_party_risks FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_login_ui_configs_update BEFORE UPDATE ON iam.login_ui_configs FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_access_revocation_workflow_update BEFORE UPDATE ON iam.access_revocation_workflow FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_machine_identity_update BEFORE UPDATE ON iam.machine_identity_management FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_adaptive_ui_update BEFORE UPDATE ON iam.adaptive_ui_based_on_role FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();


-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 4
-- Scope: Database Objects DB151 - DB200 (Tables)
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB151 - DB200)
-- ================================================================================

-- DB151: iam.api_scopes
-- Description: Definition of OAuth scopes.
-- Business Case: In an OAuth 2.0 framework, scopes define the specific permissions an application is requesting (e.g., `read:transactions`, `profile:email`). This table acts as the registry for these scopes. It allows the authorization server to validate incoming authorization requests and ensures that only well-defined, approved scopes are granted. By centralizing scope definitions, the platform can enforce fine-grained access control for third-party applications, preventing over-privileged API access. This is critical for maintaining the security boundary of the PARI platform's public API.
-- KPIs: Scope validation accuracy, Unique scope count.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.api_scopes (
    scope_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.api_scopes IS 'Registry of valid OAuth 2.0 scopes for API permission control.';

-- DB152: iam.client_applications
-- Description: Registered OAuth client apps.
-- Business Case: Third-party developers or internal microservices must register as "clients" to use the PARI API. This table stores their credentials (`client_id`, `client_secret_hash`) and configuration (`redirect_uris`, `grant_types`). It acts as the whitelist for allowed applications, ensuring that unauthorized apps cannot authenticate. The separation of client types (Confidential vs Public) allows the platform to enforce appropriate security policies, such as requiring PKCE for public clients (mobile apps) to prevent interception attacks.
-- KPIs: Client registration rate, Secret rotation compliance.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.client_applications (
    client_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_secret_hash VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types VARCHAR(50)[] NOT NULL, -- e.g., authorization_code, client_credentials
    client_type VARCHAR(20) CHECK (client_type IN ('CONFIDENTIAL', 'PUBLIC')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE iam.client_applications IS 'Stores registered OAuth 2.0 client applications and their credentials.';

-- DB153: iam.client_scopes
-- Description: Scopes allowed for specific clients.
-- Business Case: Not every client should have access to every scope, even if the user authorizes it. This table maps allowed scopes to specific clients (whitelisting). For example, a "Mobile Read-Only App" might be restricted to `read:transactions` only, while a "Desktop Admin App" allows `write:transactions`. This restriction applies at the client level, ensuring that even a compromised user account cannot leak more data than the specific client is allowed to see. This is a defense-in-depth measure.
-- KPIs: Scope enforcement validity, Configuration coverage.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.client_scopes (
    client_id UUID NOT NULL,
    scope_id UUID NOT NULL,

    PRIMARY KEY (client_id, scope_id),
    CONSTRAINT fk_client_scopes_client FOREIGN KEY (client_id) REFERENCES iam.client_applications(client_id) ON DELETE CASCADE,
    CONSTRAINT fk_client_scopes_scope FOREIGN KEY (scope_id) REFERENCES iam.api_scopes(scope_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.client_scopes IS 'Maps allowed OAuth scopes to specific client applications.';

-- DB154: iam.access_tokens
-- Description: Active OAuth access tokens.
-- Business Case: Access tokens are the bearer credentials used to access APIs. This table stores metadata about active tokens, linking them to the user, client, and session. While the token itself might be stateless (JWT), storing a record here enables revocation (`revoked_at`) and introspection (checking if a token is still valid without decoding the JWT). This hybrid approach balances the performance of stateless tokens with the security control of stateful revocation.
-- KPIs: Token lookup latency, Revocation propagation speed.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.access_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_jti VARCHAR(255) UNIQUE NOT NULL, -- JWT ID
    user_id UUID,
    client_id UUID NOT NULL,
    scopes TEXT[],
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_access_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_tokens_client FOREIGN KEY (client_id) REFERENCES iam.client_applications(client_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_tokens IS 'Stores metadata for active OAuth access tokens to support revocation.';

-- DB155: iam.refresh_tokens
-- Description: Refresh tokens for session renewal.
-- Business Case: Refresh tokens are long-lived credentials used to obtain new access tokens without user interaction. This table stores them securely (hashed). Because they are powerful, they must be strictly managed and revocable. Storing them allows the system to detect reuse attacks (if a token is used twice, it indicates theft) and revoke them immediately upon user logout or password change. This is essential for maintaining session security over long periods.
-- KPIs: Token security, Rotation frequency.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.refresh_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    client_id UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES iam.client_applications(client_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.refresh_tokens IS 'Securely stores OAuth refresh tokens for session renewal.';

-- DB156: iam.auth_codes
-- Description: Authorization codes for OAuth flow.
-- Business Case: In the Authorization Code flow, a temporary code is exchanged for a token. This table stores these short-lived codes to prevent interception attacks (Authorization Code Interception). It binds the code to the client ID and redirect URI, ensuring that a malicious actor cannot intercept the code and use it from a different location. The code has a very short TTL (TTL ~10 mins) and is single-use.
-- KPIs: Code exchange security, Time-to-live adherence.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.auth_codes (
    code_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    code_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    client_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(255), -- PKCE code_challenge
    code_method VARCHAR(10), -- PKCE code_challenge_method
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_auth_codes_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_auth_codes_client FOREIGN KEY (client_id) REFERENCES iam.client_applications(client_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.auth_codes IS 'Stores short-lived OAuth authorization codes to prevent interception.';

-- DB157: iam.oidc_discovery
-- Description: Cached OIDC discovery documents.
-- Business Case: OpenID Connect (OIDC) relies on "Discovery" documents to find authorization and token endpoints. Fetching these over the network for every login is inefficient. This table caches the discovery JSON from external Identity Providers. It includes versioning (`updated_at`) to ensure the cache is refreshed periodically. This optimizes the latency of federated login flows while ensuring configuration remains up-to-date.
-- KPIs: Cache hit ratio, Configuration freshness.
-- Feature Reference: F091
CREATE TABLE IF NOT EXISTS iam.oidc_discovery (
    provider_id UUID NOT NULL,
    discovery_json JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_oidc_disc_provider FOREIGN KEY (provider_id) REFERENCES iam.federation_providers(provider_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.oidc_discovery IS 'Caches OpenID Connect discovery documents for federated identity.';

-- DB158: iam.pairwise_id_subjects
-- Description: Mapping for pairwise subject IDs.
-- Business Case: In OIDC, a "Subject" identifier can be public (always the same) or pairwise (different for each RP). To map a pairwise subject back to the actual user ID in PARI, we need this mapping. It links the `subject_id` (received from the IDP) to the `sector_id` (relying party) and the local `user_id`. This ensures that even if the identifier changes per RP, the system always knows which user is authenticating.
-- KPIs: Mapping resolution speed.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS iam.pairwise_id_subjects (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sector_id VARCHAR(255) NOT NULL, -- URL of the Relying Party
    user_id UUID NOT NULL,

    CONSTRAINT uk_pairwise_subject UNIQUE (sector_id, user_id),
    CONSTRAINT fk_pairwise_sub_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pairwise_id_subjects IS 'Maps pairwise subject identifiers to local user IDs.';

-- DB159: iam.sector_identifiers
-- Description: Allowed sector identifiers for pairwise IDs.
-- Business Case: When using pairwise IDs, the IDP needs a list of allowed "Sector Identifier URIs" (the redirect URIs of the RPs) to generate the consistent sub ID. This table stores the whitelist of sectors registered with the PARI platform. It ensures that pairwise IDs are only generated for valid, registered redirect URIs, preventing open redirects or ID confusion attacks.
-- KPIs: Sector validation accuracy.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS iam.sector_identifiers (
    sector_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    redirect_uri TEXT NOT NULL UNIQUE
);
COMMENT ON TABLE iam.sector_identifiers IS 'Whitelist of allowed sector identifiers for pairwise ID generation.';

-- DB160: iam.jwks_keys
-- Description: JSON Web Key Set for internal signing.
-- Business Case: To sign JWTs (Access Tokens, ID Tokens) issued by PARI, the platform needs a JSON Web Key Set (JWKS). This table stores the public keys and encrypted private keys for the platform's signing keys. It supports key rotation by storing multiple keys with `active` flags. External parties (Resource Servers) fetch the public keys from this table (via a JWKS endpoint) to verify the signature of tokens issued by PARI.
-- KPIs: Key rotation frequency, Signing latency.
-- Feature Reference: F078
CREATE TABLE IF NOT EXISTS iam.jwks_keys (
    kid VARCHAR(50) PRIMARY KEY, -- Key ID
    key_type VARCHAR(10) NOT NULL CHECK (key_type IN ('RSA', 'EC', 'OKP')),
    public_key TEXT NOT NULL, -- PEM format
    private_key_enc BYTEA NOT NULL,
    algorithm VARCHAR(10) NOT NULL, -- RS256, ES256, etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.jwks_keys IS 'Stores the internal cryptographic keys used to sign JWTs.';

-- DB161: iam.external_jwks
-- Description: Cached external JWKS (for eIDAS verification).
-- Business Case: To verify signatures from external Identity Providers (like eIDAS 2.0 wallets), PARI needs their public keys. Fetching these JWKS (JSON Web Key Sets) for every request is too slow. This table caches the public keys of trusted external providers. It periodically refreshes them to handle key rotation at the provider side. This enables efficient and secure verification of external tokens and assertions.
-- KPIs: Cache freshness, Verification speed.
-- Feature Reference: F008
CREATE TABLE IF NOT EXISTS iam.external_jwks (
    provider_url TEXT PRIMARY KEY,
    keys_json JSONB NOT NULL, -- The JWKS content
    last_fetched TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE iam.external_jwks IS 'Caches public keys (JWKS) from external identity providers.';

-- DB162: iam.consent_receipt_issuer
-- Description: Config for receipt issuer.
-- Business Case: To issue cryptographically verifiable Consent Receipts (Kantara Initiative), the system needs an issuer configuration. This table stores the `issuer_id`, the signing key reference, and the issuance parameters. It ensures that all receipts are signed by a consistent, trusted authority, allowing third parties to verify the integrity of the consent proof.
-- KPIs: Issuance success rate, Key management compliance.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.consent_receipt_issuer (
    issuer_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    issuer_key_id VARCHAR(50) NOT NULL, -- References iam.jwks_keys
    issuer_url VARCHAR(255) NOT NULL
);
COMMENT ON TABLE iam.consent_receipt_issuer IS 'Configuration for the Consent Receipt issuer authority.';

-- DB163: iam.consent_jwt
-- Description: Issued consent JWTs.
-- Business Case: Consent Receipts are often issued as signed JWTs (JWS). This table stores the full JWS string for audit and re-issuance purposes. It links the JWT to the user and the specific consent instance. By storing the JWT, the system can re-transmit it to the user if requested and can prove the exact content of the consent at the time of issuance.
-- KPIs: JWT storage size, Retrieval speed.
-- Feature Reference: F148
CREATE TABLE IF NOT EXISTS iam.consent_jwt (
    jwt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    jti VARCHAR(255) NOT NULL UNIQUE, -- JWT ID
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.consent_jwt IS 'Stores the actual signed JWTs representing consent receipts.';

-- DB164: iam.audit_signature_chain
-- Description: Chain of custody for audit logs.
-- Business Case: To make audit logs tamper-evident, we use a blockchain-like chain. Each entry contains the hash of the previous entry (`prev_hash`) and the current data's hash (`current_hash`). This table manages these links. If an attacker modifies a historical log, the chain breaks, and the system can detect the tampering immediately. This is the highest standard of audit integrity for financial systems.
-- KPIs: Chain integrity verification time, Link creation latency.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS iam.audit_signature_chain (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prev_hash VARCHAR(255), -- NULL for genesis block
    current_hash VARCHAR(255) NOT NULL,
    root_hash VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.audit_signature_chain IS 'Cryptographic chain linking audit logs to ensure immutability.';

-- DB165: iam.zero_trust_scores
-- Description: Aggregated zero-trust scores for sessions.
-- Business Case: Zero Trust is about "Never Trust, Always Verify". This table stores the aggregated Zero Trust (ZT) score for a session. The score is calculated based on device health, user behavior, location, and network security. A low ZT score might trigger step-up authentication or limit access to sensitive resources. It provides a single, dynamic metric representing the trustworthiness of a session in real-time.
-- KPIs: Score calculation accuracy, Real-time aggregation latency.
-- Feature Reference: F031
CREATE TABLE IF NOT EXISTS iam.zero_trust_scores (
    session_id UUID PRIMARY KEY,
    zt_score NUMERIC(3,2) CHECK (zt_score >= 0 AND zt_score <= 1),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_zt_scores_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.zero_trust_scores IS 'Stores real-time Zero Trust scores for active sessions.';

-- DB166: iam.spiffe_ids
-- Description: SPIFFE identities for services.
-- Business Case: In Zero Trust networks (using SPIFFE/SPIRE), every service (microservice) needs an identity just like a user. This table stores the SPIFFE ID (e.g., `spiffe://finance.pari.net/payment-service`) which acts as the service's X.509 certificate identity. It enables mutual TLS (mTLS) where services authenticate each other strictly based on these registered identities, eliminating shared secrets for service-to-service communication.
-- KPIs: ID issuance speed, Identity collision rate.
-- Feature Reference: F031
CREATE TABLE IF NOT EXISTS iam.spiffe_ids (
    spiffe_id VARCHAR(255) PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    parent_id UUID, -- Trust domain parent
    status VARCHAR(20) DEFAULT 'ACTIVE'
);
COMMENT ON TABLE iam.spiffe_ids IS 'Stores SPIFFE identities for Zero Trust service authentication.';

-- DB167: iam.spiffe_bundles
-- Description: SPIFFE trust bundles.
-- Business Case: SPIRE uses "Trust Bundles" (sets of root CA certificates) to verify identities. This table stores the trust bundle JSON for specific trust domains. It allows services to verify the authenticity of peer SPIFFE IDs. Rotating these bundles is critical for security; this table tracks the active bundle and its version to ensure trust is maintained correctly.
-- KPIs: Bundle update latency, Verification success.
-- Feature Reference: F031
CREATE TABLE IF NOT EXISTS iam.spiffe_bundles (
    bundle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trust_domain VARCHAR(255) NOT NULL,
    bundle_jwt TEXT NOT NULL,
    sequence_number BIGINT NOT NULL,
    refreshed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.spiffe_bundles IS 'Stores SPIFFE Trust Bundles for X.509-SVID verification.';

-- DB168: iam.service_svids
-- Description: Short-lived SVIDs for services.
-- Business Case: X.509-SVIDs (SPIFFE Verifiable Identity Documents) are short-lived certificates issued to services. This table tracks the issuance of these SVIDs. It maps the certificate to the `spiffe_id` and tracks its expiry. The short lifespan limits the damage if a private key is compromised. This table is used by the CA to monitor which certificates are currently valid in the mesh.
-- KPIs: Certificate rotation frequency, Issuance throughput.
-- Feature Reference: F031
CREATE TABLE IF NOT EXISTS iam.service_svids (
    svid_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    spiffe_id VARCHAR(255) NOT NULL,
    cert_pem TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_service_svids_spiffe FOREIGN KEY (spiffe_id) REFERENCES iam.spiffe_ids(spiffe_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.service_svids IS 'Tracks issued short-lived X.509 certificates for services.';

-- DB169: iam.x509_certs
-- Description: General x509 certificate store.
-- Business Case: Beyond SPIFFE, the platform may need to store arbitrary X.509 certificates for users or devices (e.g., smart cards, legacy systems). This table is a generic store for these certificates. It indexes by serial number and subject to allow for revocation checks and validation. It supports the management of the Public Key Infrastructure (PKI) for the entire platform.
-- KPIs: Certificate lookup speed, Revocation check accuracy.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.x509_certs (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    serial_number VARCHAR(255) NOT NULL,
    ca_id UUID, -- Issuing CA
    subject VARCHAR(255),
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'VALID',

    CONSTRAINT fk_x509_ca FOREIGN KEY (ca_id) REFERENCES iam.certificate_authorities(ca_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.x509_certs IS 'General repository for storing X.509 certificates.';

-- DB170: iam.certificate_authorities
-- NOTE: This table is a duplicate of DB113 created in Part 3.
-- Description: Internal CAs.
-- Business Case: Duplicate of DB113. Refer to iam.certificate_authorities (DB113).
-- KPIs: (See DB113)
-- Feature Reference: (See DB113)
-- The DDL is skipped to prevent runtime errors. Logic handled in DB113.

-- DB171: iam.crl_distribution_points
-- Description: URLs for CRLs.
-- Business Case: CRLs (Certificate Revocation Lists) are often hosted at specific URLs defined within the certificate (CDP extension). This table stores these URLs linked to the issuing CA. It allows the revocation checker to fetch the latest CRL from the correct source. Ensuring the correct URL is critical for preventing the acceptance of revoked certificates.
-- KPIs: URL accuracy, Fetch success rate.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS iam.crl_distribution_points (
    dp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ca_id UUID NOT NULL,
    url TEXT NOT NULL,

    CONSTRAINT fk_crl_dp_ca FOREIGN KEY (ca_id) REFERENCES iam.certificate_authorities(ca_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.crl_distribution_points IS 'Stores CRL Distribution Point URLs for Certificate Authorities.';

-- DB172: iam.ocsp_responses
-- Description: Cached OCSP responses.
-- Business Case: OCSP (Online Certificate Status Protocol) is a more modern alternative to CRLs, providing real-time status. This table caches the OCSP responses to avoid hitting the OCSP responder for every single connection. It stores the `next_update` time to know when to invalidate the cache. This balances the need for real-time revocation status with the performance requirements of high-throughput TLS.
-- KPIs: Cache hit ratio, Response freshness.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS iam.ocsp_responses (
    serial_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    serial_number VARCHAR(255) NOT NULL,
    response BYTEA NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE iam.ocsp_responses IS 'Caches OCSP responses for efficient certificate validation.';

-- DB173: iam.ocsp_stapling
-- Description: Data for OCSP stapling.
-- Business Case: OCSP Stapling allows the server (not the client) to check the certificate status and staple the response to the TLS handshake. This table stores the stapled response data for the server's own certificates. It ensures that the server always has an up-to-date OCSP response ready to send, optimizing the handshake by saving the client a round-trip.
-- KPIs: Staple validity period, Handshake optimization.
-- Feature Reference: F046
CREATE TABLE IF NOT EXISTS iam.ocsp_stapling (
    staple_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cert_id UUID NOT NULL,
    response BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_ocsp_stapling_cert FOREIGN KEY (cert_id) REFERENCES iam.x509_certs(cert_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.ocsp_stapling IS 'Stores stapled OCSP responses for server TLS optimization.';

-- DB174: iam.tls_handshakes
-- Description: Logs of TLS handshakes for anomaly detection.
-- Business Case: Monitoring TLS handshake details (Cipher Suite, TLS Version, Client IP) can reveal attacks. For example, an ancient TLS version might indicate a legacy client or a specific exploit tool. This table logs these details. Security tools can query this table to detect anomalies like a sudden spike in connections using weak ciphers, which could indicate an active scanning or attack campaign.
-- KPIs: Anomaly detection accuracy, Log volume handling.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.tls_handshakes (
    handshake_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_ip INET NOT NULL,
    cipher_suite VARCHAR(50),
    tls_version VARCHAR(20),
    server_name_indication VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.tls_handshakes IS 'Logs TLS handshake metadata for security analysis.';

-- DB175: iam.cipher_suites
-- Description: Allowed/disallowed cipher suites.
-- Business Case: Not all encryption algorithms are secure. This table maintains the whitelist of allowed cipher suites for the PARI platform (e.g., TLS_AES_256_GCM_SHA384). By updating this table, the platform can globally disable a weak cipher if a vulnerability is found, enforcing cryptographic agility and compliance without code changes.
-- KPIs: Configuration enforcement rate.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.cipher_suites (
    suite_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    openssl_name VARCHAR(100),
    allowed BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.cipher_suites IS 'Defines the whitelist of allowed TLS cipher suites.';

-- DB176: iam.tls_versions
-- Description: Allowed TLS versions.
-- Business Case: Protocols like TLS 1.0 and 1.1 are deprecated and insecure. This table defines which TLS versions are enabled on the platform. It provides a central switch to enforce minimum security standards, ensuring that legacy clients using broken protocols are rejected immediately at the transport layer.
-- KPIs: Protocol enforcement success.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.tls_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_num VARCHAR(20) NOT NULL, -- e.g. 1.2, 1.3
    allowed BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.tls_versions IS 'Defines allowed TLS protocol versions.';

-- DB177: iam.pki_hierarchy
-- Description: CA hierarchy structure.
-- Business Case: PKI (Public Key Infrastructure) relies on a hierarchy (Root CA -> Intermediate CA -> Leaf Cert). This table maps these relationships. It allows the system to visualize the chain of trust and ensures that certificates are issued from the correct intermediate CA. This structure is essential for managing large-scale certificate deployments and ensuring that revocation of an intermediate CA invalidates all leaves correctly.
-- KPIs: Hierarchy validation speed.
-- Feature Reference: F113
CREATE TABLE IF NOT EXISTS iam.pki_hierarchy (
    parent_ca_id UUID NOT NULL,
    child_ca_id UUID NOT NULL,

    PRIMARY KEY (parent_ca_id, child_ca_id),
    CONSTRAINT fk_pki_parent FOREIGN KEY (parent_ca_id) REFERENCES iam.certificate_authorities(ca_id) ON DELETE CASCADE,
    CONSTRAINT fk_pki_child FOREIGN KEY (child_ca_id) REFERENCES iam.certificate_authorities(ca_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pki_hierarchy IS 'Defines the parent-child relationships in the PKI hierarchy.';

-- DB178: iam.key_usage
-- Description: Key usage extensions.
-- Business Case: X.509 certificates have "Key Usage" extensions (e.g., Digital Signature, Key Encipherment, Certificate Sign). This table maps usage types to descriptions. When issuing or validating a certificate, the system checks this table to ensure the key is being used for its intended purpose (e.g., a key meant only for signing cannot be used for encryption). This prevents cryptographic misuse.
-- KPIs: Usage validation accuracy.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.key_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(50) NOT NULL, -- e.g., digitalSignature, keyEncipherment
    oid VARCHAR(50) NOT NULL -- Object Identifier
);
COMMENT ON TABLE iam.key_usage IS 'Reference table for X.509 Key Usage extensions.';

-- DB179: iam.cert_attributes
-- Description: Custom attributes in x509 certs.
-- Business Case: Standard X.509 fields might not be enough. Applications often embed custom data (e.g., User ID, Department) in the certificate as extensions. This table stores definitions of these custom attributes (OID and type). It allows the issuance engine to inject specific organizational data into the certificates, enabling identity verification based solely on the certificate content.
-- KPIs: Attribute injection accuracy.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.cert_attributes (
    attr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    oid VARCHAR(100) NOT NULL,
    value TEXT NOT NULL,
    is_critical BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.cert_attributes IS 'Stores custom attributes to be embedded in X.509 certificates.';

-- DB180: iam.pkcs12_blobs
-- Description: Encrypted PKCS12 archives for export.
-- Business Case: Users or devices sometimes need to export their keypair in a standard format like PKCS#12 (PFX). This table stores these encrypted blobs. They are usually generated on-demand and have a short TTL for download. Storing them allows for secure delivery mechanisms (e.g., "Click here to download"). The encryption ensures that even if the DB is accessed, the private keys inside the blobs remain safe.
-- KPIs: Generation security, Download success rate.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS iam.pkcs12_blobs (
    blob_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    container_enc BYTEA NOT NULL,
    filename VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    downloaded_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_pkcs12_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pkcs12_blobs IS 'Stores temporary, encrypted PKCS#12 archives for user export.';

-- DB181: iam.hardware_tokens
-- Description: Physical security tokens (YubiKey).
-- Business Case: Hardware tokens (FIDO2, YubiKey) provide phishing-resistant authentication. This table registers these tokens to users. It stores the `public_id` (handle) and potentially a counter to prevent cloning. It links the physical device to the digital identity, allowing the system to require the specific hardware token for authentication, adding a layer of "something you have".
-- KPIs: Token registration count, Authentication success rate.
-- Feature Reference: F057
CREATE TABLE IF NOT EXISTS iam.hardware_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    public_id VARCHAR(255) NOT NULL UNIQUE, -- The credential ID
    attestation_type VARCHAR(50), -- e.g., PACKED, BASIC
    device_type VARCHAR(50), -- e.g. SINGLE_BUTTON, TOUCHSCREEN
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hw_tokens_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.hardware_tokens IS 'Registers physical hardware tokens (YubiKeys) to user accounts.';

-- DB182: iam.totp_secrets
-- Description: TOTP shared secrets.
-- Business Case: TOTP (Time-based One-Time Password) apps like Google Authenticator rely on a shared secret seed. This table stores the encrypted seed for each user. It allows the server to calculate the valid code at any given time step to verify the user's input. Storing it encrypted is critical; if the DB is breached, attackers could generate valid codes for users.
-- KPIs: Validation accuracy, Secret security.
-- Feature Reference: F039
CREATE TABLE IF NOT EXISTS iam.totp_secrets (
    secret_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    secret_enc VARCHAR(255) NOT NULL, -- Encrypted TOTP seed
    last_used_step INTEGER, -- To prevent replay
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.totp_secrets IS 'Securely stores encrypted TOTP seeds for users.';

-- DB183: iam.backup_tokens
-- Description: Backup recovery tokens.
-- Business Case: If a user loses their MFA device, they need a way back in. Backup codes (one-time passwords) serve this purpose. This table stores these hashed codes. They are generated in batches and invalidated upon use. They are the last line of defense for account recovery, ensuring users are never permanently locked out.
-- KPIs: Redemption success rate, Unused token monitoring.
-- Feature Reference: F093
CREATE TABLE IF NOT EXISTS iam.backup_tokens (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    used_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_backup_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.backup_tokens IS 'Stores hashed one-time backup codes for emergency recovery.';

-- DB184: iam.push_challenges
-- Description: Mobile push notification challenges.
-- Business Case: Push-based MFA (e.g., Duo, Auth0) sends a prompt to the user's phone ("Approve login?"). This table stores the state of these challenges. It tracks the request ID, the status (PENDING, APPROVED, DENIED), and the expiration. It allows the async nature of the mobile approval workflow to be synchronized with the synchronous web login request.
-- KPIs: Response time, User approval rate.
-- Feature Reference: F039
CREATE TABLE IF NOT EXISTS iam.push_challenges (
    push_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    transaction_id VARCHAR(255) NOT NULL, -- Links push to login attempt
    status VARCHAR(20) DEFAULT 'PENDING',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_push_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.push_challenges IS 'Tracks mobile push MFA challenges and their results.';

-- DB185: iam.biometric_challenges
-- Description: Biometric auth challenges.
-- Business Case: When a user logs in via biometrics (FaceID, TouchID), the device sends a signed assertion. This table records the challenge details. It stores the `template_enc` (or reference to it) and the result of the biometric match. This log is vital for investigating unauthorized access claims (proving the biometric was indeed used) and tuning the sensitivity of the biometric sensor.
-- KPIs: Match accuracy (FAR/FRR).
-- Feature Reference: F105
CREATE TABLE IF NOT EXISTS iam.biometric_challenges (
    bio_challenge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    template_enc BYTEA, -- Reference or encrypted template
    result BOOLEAN NOT NULL,
    score NUMERIC(5,2), -- Similarity score
    challenged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bio_challenge_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.biometric_challenges IS 'Records biometric authentication attempts and outcomes.';

-- DB186: iam.voiceprints
-- Description: Voice biometric templates.
-- Business Case: Voice authentication is used for phone banking or support. This table stores the encrypted voiceprint (a mathematical model of the voice). It links to the user and stores the model version. By centralizing voiceprints, the system can verify a caller's identity against a high-accuracy model, reducing fraud in voice channels.
-- KPIs: Verification accuracy, Template size.
-- Feature Reference: F072
CREATE TABLE IF NOT EXISTS iam.voiceprints (
    voice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    print_enc BYTEA NOT NULL,
    model_version VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_voiceprint_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.voiceprints IS 'Securely stores encrypted voice biometric templates.';

-- DB187: iam.keystroke_templates
-- Description: Keystroke dynamics templates.
-- Business Case: Keystroke dynamics analyzes typing rhythm (flight time, dwell time) as a behavioral biometric. This table stores the baseline template for a user. It allows for continuous, passive authentication—if the typing rhythm changes drastically, it might indicate a session hijack. This provides seamless security without interrupting the user.
-- KPIs: Template stability, Detection sensitivity.
-- Feature Reference: F073
CREATE TABLE IF NOT EXISTS iam.keystroke_templates (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    template_enc BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_keystroke_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.keystroke_templates IS 'Stores keystroke dynamics templates for behavioral authentication.';

-- DB188: iam.location_history
-- Description: Historical location data for users.
-- Business Case: Tracking the physical location of users over time is crucial for security. This table stores `lat`, `long`, and `accuracy` for user sessions or events. It is used to detect impossible travel (login in Paris, then 5 mins later in Tokyo) and to enforce geo-fencing. Historical data helps in forensic investigations to map the attacker's movements.
-- KPIs: Location accuracy, Historical query performance.
-- Feature Reference: F013
CREATE TABLE IF NOT EXISTS iam.location_history (
    loc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    lat NUMERIC(9,6) NOT NULL,
    long NUMERIC(9,6) NOT NULL,
    accuracy NUMERIC(10,2), -- Meters
    source VARCHAR(50), -- GPS, IP_GEO
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_loc_hist_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.location_history IS 'Stores historical geolocation data for security analysis.';

-- DB189: iam.ip_history
-- Description: History of IP addresses used by user.
-- Business Case: Users access the system from various IPs (Home, Office, Coffee Shop). This table logs every IP address seen associated with a user. It allows the system to flag "New IP" login attempts for step-up authentication. It also helps in correlating attacks—if multiple users suddenly start logging in from the same unusual IP, it suggests a botnet or compromised gateway.
-- KPIs: IP classification accuracy (New vs Known).
-- Feature Reference: F027
CREATE TABLE IF NOT EXISTS iam.ip_history (
    ip_hist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    ip_address INET NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ip_hist_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.ip_history IS 'History of IP addresses associated with user accounts.';

-- DB190: iam.user_agent_history
-- Description: History of User-Agents.
-- Business Case: The User-Agent string identifies the browser/app. This table logs the User-Agents used by a user. Sudden changes in User-Agent (e.g., switching from Chrome on Windows to Safari on iOS) might indicate a different device. This helps in detecting session hijacking where an attacker injects their own cookies into a different browser.
-- KPIs: Anomaly detection precision.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.user_agent_history (
    ua_hist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    user_agent TEXT NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ua_hist_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_agent_history IS 'History of User-Agent strings used by accounts.';

-- DB191: iam.device_history
-- Description: History of device IDs.
-- Business Case: Similar to IP history, but for device fingerprints. This table tracks which devices (identified by a fingerprint hash) have been used by a user. It enables "Remember this device" features and alerts on "Unrecognized device" logins. It is a key component of device-trust based authentication.
-- KPIs: Device recognition accuracy.
-- Feature Reference: F014
CREATE TABLE IF NOT EXISTS iam.device_history (
    dev_hist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    device_id UUID NOT NULL, -- References iam.devices
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dev_hist_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_dev_hist_device FOREIGN KEY (device_id) REFERENCES iam.devices(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.device_history IS 'History of device fingerprints associated with user accounts.';

-- DB192: iam.risk_events
-- Description: High-level risk events.
-- Business Case: When the risk score crosses a threshold, a "Risk Event" is triggered (e.g., Account Lockout, MFA Required). This table logs these events. It serves as a high-level summary for dashboards (e.g., "How many lockouts today?"). It abstracts away the noise of individual logs to provide actionable business intelligence on security posture.
-- KPIs: Event volume, Response time.
-- Feature Reference: F054
CREATE TABLE IF NOT EXISTS iam.risk_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    risk_score NUMERIC(5,2) NOT NULL,
    reason TEXT NOT NULL,
    action_taken VARCHAR(100), -- e.g., BLOCKED, CHALLENGED
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_risk_events_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.risk_events IS 'Logs high-level security risk events triggered by the risk engine.';

-- DB193: iam.incident_responses
-- Description: Automated response actions taken.
-- Business Case: Modern SOAR (Security Orchestration, Automation and Response) requires automated actions. This table records actions taken by the system (e.g., "Revoked Session", "Blocked IP", "Notified Admin") in response to an alert. It provides an audit trail of the automated security response, proving that the system acted correctly and immediately to contain threats.
-- KPIs: Response execution speed, Success rate.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.incident_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID,
    action_type VARCHAR(100) NOT NULL,
    details JSONB,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.incident_responses IS 'Records automated response actions taken for security incidents.';

-- DB194: iam.playbook_runs
-- Description: Execution of security playbooks.
-- Business Case: Security Playbooks are pre-defined workflows for handling threats (e.g., "Phishing Playbook"). This table tracks the execution of these playbooks. It records which playbook was run, against which target, and the final status (SUCCESS, FAILED). It allows security teams to measure the effectiveness of their incident response procedures.
-- KPIs: Playbook execution success, Mean time to remediate.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.playbook_runs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_id UUID NOT NULL,
    target_id UUID,
    status VARCHAR(20) DEFAULT 'RUNNING',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_playbook_runs_playbook FOREIGN KEY (playbook_id) REFERENCES iam.playbooks(playbook_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.playbook_runs IS 'Tracks the execution history of security playbooks.';

-- DB195: iam.playbooks
-- Description: Security response playbooks.
-- Business Case: This table defines the Security Playbooks. It stores the `steps_json` (a sequence of actions, conditions, and delays). By treating playbooks as data, the security team can update response logic without deploying new code. It enables agile adaptation to new threats (e.g., adding a new step to block a specific IoC).
-- KPIs: Playbook activation frequency.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.playbooks (
    playbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    steps_json JSONB NOT NULL, -- Workflow definition
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.playbooks IS 'Definitions of automated security response playbooks.';

-- DB196: iam.quarantine_rules
-- Description: Rules triggering automatic quarantine.
-- Business Case: Quarantine should be automated for high-fidelity threats. This table defines the rules (e.g., "If IP in Tor network" OR "If Malware detected"). When these conditions are met, the system automatically moves the user/session to the quarantine state. This immediate containment drastically reduces the blast radius of an active infection or attack.
-- KPIs: True positive rate, False positive rate.
-- Feature Reference: F083
CREATE TABLE IF NOT EXISTS iam.quarantine_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    condition_json JSONB NOT NULL,
    action VARCHAR(50), -- USER_QUARANTINE, SESSION_REVOKE
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.quarantine_rules IS 'Defines rules for automatic quarantine of users or sessions.';

-- DB197: iam.allowlist_ips
-- Description: Allowed IP ranges for admin access.
-- Business Case: For the most sensitive operations (like accessing the admin console or changing production secrets), we implement IP Whitelisting. This table stores the allowed CIDR ranges. Access is denied if the request does not originate from these trusted IP ranges. This is a strict network-level control for highly privileged actions.
-- KPIs: Allow coverage, Blocking accuracy.
-- Feature Reference: F086
CREATE TABLE IF NOT EXISTS iam.allowlist_ips (
    range_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cidr INET NOT NULL,
    description TEXT,
    created_by UUID NOT NULL
);
COMMENT ON TABLE iam.allowlist_ips IS 'Stores whitelisted IP CIDR ranges for privileged access.';

-- DB198: iam.denylist_ips
-- Description: Blocked IP ranges.
-- Business Case: This table is the blacklist for known bad IPs (botnets, attackers). It stores CIDR ranges that are explicitly blocked. Blocking at the edge (or auth layer) saves resources by preventing malicious actors from consuming CPU on password hashing or DB queries. It is a first line of defense.
-- KPIs: Block count, List maintenance freshness.
-- Feature Reference: F063
CREATE TABLE IF NOT EXISTS iam.denylist_ips (
    range_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cidr INET NOT NULL,
    reason VARCHAR(255),
    source VARCHAR(100), -- THREAT_INTEL, MANUAL
    expires_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.denylist_ips IS 'Stores blacklisted IP CIDR ranges for immediate blocking.';

-- DB199: iam.rate_limit_rules
-- Description: Global rate limit rules.
-- Business Case: This table defines the global rate limits for the platform (e.g., 1000 requests/sec for the login endpoint). It prevents the infrastructure from being overwhelmed by DDoS attacks or runaway clients. By storing these rules in the DB, the API Gateway can dynamically adjust limits (throttling) without a restart, maintaining availability during traffic spikes.
-- KPIs: Enforcement latency, DDoS mitigation effectiveness.
-- Feature Reference: F098
CREATE TABLE IF NOT EXISTS iam.rate_limit_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint VARCHAR(100) NOT NULL, -- /auth/login
    limit INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.rate_limit_rules IS 'Stores global rate limiting rules to protect against abuse.';

-- DB200: iam.dynamic_rate_limits
-- Description: User-specific rate limits (JIT).
-- Business Case: Sometimes a user needs a temporary rate limit increase (e.g., for a data migration job) or a temporary decrease (suspicious user). This table stores these user-specific overrides of the global rules. It allows for "Just-In-Time" quota management, ensuring that legitimate high-volume work can proceed without opening the floodgates for everyone.
-- KPIs: Override approval rate, Limit precision.
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.dynamic_rate_limits (
    dlimit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    limit INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_dlimit_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.dynamic_rate_limits IS 'Stores user-specific rate limit overrides for temporary needs.';

-- ================================================================================
-- Indexes and Constraints for Part 4 Tables
-- ================================================================================

-- API / OAuth
CREATE INDEX IF NOT EXISTS idx_access_tokens_jti ON iam.access_tokens(token_jti) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON iam.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_client_scopes_client ON iam.client_scopes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON iam.auth_codes(code_hash) WHERE used_at IS NULL;

-- PKI / Certificates
CREATE INDEX IF NOT EXISTS idx_x509_serial ON iam.x509_certs(serial_number);
CREATE INDEX IF NOT EXISTS idx_x509_subject ON iam.x509_certs(subject);
CREATE INDEX IF NOT EXISTS idx_service_svids_spiffe ON iam.service_svids(spiffe_id);

-- History / Context (High Volume)
CREATE INDEX IF NOT EXISTS idx_location_history_user ON iam.location_history(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ip_history_user ON iam.ip_history(user_id);
CREATE INDEX IF NOT EXISTS idx_ua_history_user ON iam.user_agent_history(user_id);
CREATE INDEX IF NOT EXISTS idx_device_history_user ON iam.device_history(user_id);

-- Security / Risk
CREATE INDEX IF NOT EXISTS idx_risk_events_user ON iam.risk_events(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incident_responses_incident ON iam.incident_responses(incident_id);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_playbook ON iam.playbook_runs(playbook_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_active ON iam.quarantine_rules(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_denylist_cidr ON iam.denylist_ips(cidr) USING gist (cidr inet_ops);
CREATE INDEX IF NOT EXISTS idx_allowlist_cidr ON iam.allowlist_ips(cidr) USING gist (cidr inet_ops);
CREATE INDEX IF NOT EXISTS idx_dlimit_user ON iam.dynamic_rate_limits(user_id);

-- Biometric / Tokens
CREATE INDEX IF NOT EXISTS idx_hw_tokens_public ON iam.hardware_tokens(public_id);
CREATE INDEX IF NOT EXISTS idx_push_transaction ON iam.push_challenges(transaction_id);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 4 Tables
-- ================================================================================

-- Enable RLS
ALTER TABLE iam.client_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.api_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.backup_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.hardware_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.location_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.ip_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_agent_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.device_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.playbooks ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY client_app_isolation ON iam.client_applications
    FOR ALL
    USING (created_by = current_setting('app.current_user_id', true)::UUID OR is_super_user = TRUE); -- Assuming is_super_user is accessible or similar logic

CREATE POLICY api_scopes_public ON iam.api_scopes
    FOR SELECT
    USING (true); -- Scopes are generally public info for devs, but restrict INSERT

CREATE POLICY backup_tokens_user_isolation ON iam.backup_tokens
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY hw_tokens_user_isolation ON iam.hardware_tokens
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY history_user_isolation ON iam.location_history
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY ip_history_user_isolation ON iam.ip_history
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY ua_history_user_isolation ON iam.user_agent_history
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY dev_history_user_isolation ON iam.device_history
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY playbooks_admin_only ON iam.playbooks
    FOR ALL
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

-- ================================================================================
-- Triggers for Part 4 Tables
-- ================================================================================

CREATE TRIGGER trg_client_apps_update BEFORE UPDATE ON iam.client_applications FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_jwks_keys_update BEFORE UPDATE ON iam.jwks_keys FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_external_jwks_update BEFORE UPDATE ON iam.external_jwks FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_crl_distribution_update BEFORE UPDATE ON iam.crl_distribution_points FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_ocsp_stapling_update BEFORE UPDATE ON iam.ocsp_stapling FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_cipher_suites_update BEFORE UPDATE ON iam.cipher_suites FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_tls_versions_update BEFORE UPDATE ON iam.tls_versions FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_key_usage_update BEFORE UPDATE ON iam.key_usage FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_cert_attributes_update BEFORE UPDATE ON iam.cert_attributes FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_playbooks_update BEFORE UPDATE ON iam.playbooks FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_rate_limit_rules_update BEFORE UPDATE ON iam.rate_limit_rules FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();



-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 5
-- Scope: Database Objects DB201 - DB250 (Tables)
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB201 - DB250)
-- ================================================================================

-- DB201: iam.kg_entities
-- Description: Nodes for the Knowledge Representation Graph (Users, Roles, Resources).
-- Business Case: The Knowledge Graph (KG) is the backbone of advanced policy analysis, enabling the system to visualize relationships like "User A -> Member Of -> Role B". This table stores the nodes (entities) within this graph. By representing identities, roles, and resources as graph nodes, we can run sophisticated graph algorithms (e.g., shortest path, connectivity analysis) to identify permission creep, hidden relationships, or attack paths that traditional table joins might miss. This supports the "Policy Impact Analysis" and "Role Mining" features by providing a structured, queryable graph model of the entire IAM ecosystem.
-- KPIs: Graph query performance, Node ingestion rate.
-- Feature Reference: F122, F140
CREATE TABLE IF NOT EXISTS iam.kg_entities (
    entity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN ('USER', 'ROLE', 'RESOURCE', 'PERMISSION', 'DEVICE')),
    label VARCHAR(255) NOT NULL,
    properties_json JSONB NOT NULL, -- Stores dynamic attributes
    source_system VARCHAR(100), -- e.g., 'LDAP', 'MANUAL'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.kg_entities IS 'Nodes for the Knowledge Representation Graph (Users, Roles, Resources).';

-- DB202: iam.kg_relationships
-- Description: Edges defining connections in the Knowledge Graph.
-- Business Case: While entities (DB201) are the nouns, relationships are the verbs (e.g., "HAS_PERMISSION", "MEMBER_OF", "OWNS"). This table stores the edges connecting the entities. It allows the KG to define the topology of access control. For instance, a weighted edge can represent the strength of a relationship (e.g., 'Trust Score'). This structure is essential for identifying "transitive trust" issues or complex dependencies that would be impossible to detect with standard SQL queries alone.
-- KPIs: Edge traversal speed, Relationship accuracy.
-- Feature Reference: F122, F140
CREATE TABLE IF NOT EXISTS iam.kg_relationships (
    edge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_entity_id UUID NOT NULL,
    target_entity_id UUID NOT NULL,
    relation_type VARCHAR(100) NOT NULL, -- e.g., GRANTED_TO, PART_OF
    weight NUMERIC(5,2) CHECK (weight >= 0 AND weight <= 1),
    properties_json JSONB,

    CONSTRAINT fk_kg_rel_source FOREIGN KEY (source_entity_id) REFERENCES iam.kg_entities(entity_id) ON DELETE CASCADE,
    CONSTRAINT fk_kg_rel_target FOREIGN KEY (target_entity_id) REFERENCES iam.kg_entities(entity_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.kg_relationships IS 'Edges defining connections between nodes in the Knowledge Graph.';

-- DB203: iam.audit_trail_chain
-- Description: Cryptographic chain (Merkle Tree roots) for immutable audit verification.
-- Business Case: To ensure that audit logs (DB009) are tamper-proof without relying solely on DB permissions, we use a cryptographic chain. This table stores the root hash of Merkle trees built from batches of logs. Each root depends on the previous one. If an attacker modifies a historical log entry, recalculating the hash will break the chain. This table provides the high-integrity anchor required for forensic investigations where the authenticity of the evidence is challenged in court.
-- KPIs: Hash calculation time, Integrity verification speed.
-- Feature Reference: F015, F094
CREATE TABLE IF NOT EXISTS iam.audit_trail_chain (
    chain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prev_hash VARCHAR(255), -- NULL for genesis block
    current_hash VARCHAR(255) NOT NULL, -- Root hash of the Merkle tree for this batch
    root_hash VARCHAR(255) NOT NULL, -- Alias for clarity
    batch_start_id UUID NOT NULL, -- Reference to first log ID in batch
    batch_end_id UUID NOT NULL, -- Reference to last log ID in batch
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.audit_trail_chain IS 'Stores Merkle tree roots to link audit logs into an immutable chain.';

-- DB204: iam.behavioral_profiles
-- Description: Aggregated profiles for behavioral biometrics.
-- Business Case: Passive authentication relies on establishing a baseline "normal" behavior for a user. This table stores the aggregated profile vector (e.g., average typing speed, mouse movement variance) generated from raw data. The profile serves as the reference point for real-time comparison. By storing these profiles, the system can adapt to the user's natural evolution over time (model versioning) without flagging them as anomalies, ensuring high detection accuracy with low false positives.
-- KPIs: Profile convergence time, Match accuracy.
-- Feature Reference: F022, F073
CREATE TABLE IF NOT EXISTS iam.behavioral_profiles (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    feature_vector JSONB NOT NULL, -- Encoded behavioral features
    model_version VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_behavior_profile_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.behavioral_profiles IS 'Stores aggregated biometric profiles for passive authentication.';

-- DB205: iam.raw_keystroke_logs
-- Description: High-frequency raw data for deep learning behavioral analysis.
-- Business Case: To build high-fidelity behavioral models, we need raw data (keystrokes, flight times). This table acts as a temporary buffer for this high-frequency telemetry. It captures granular details like `key_code` and `press_duration`. Because of the volume, data here is likely partitioned by date and has a short retention period (e.g., 7 days), after which it is aggregated into DB204 or deleted. This raw input is critical for training new ML models or re-training existing ones to detect sophisticated attack patterns.
-- KPIs: Ingestion throughput, Data retention compliance.
-- Feature Reference: F073
CREATE TABLE IF NOT EXISTS iam.raw_keystroke_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    key_code VARCHAR(10) NOT NULL,
    press_duration_ms INTEGER, -- Time key was held down
    flight_time_ms INTEGER, -- Time between this key and previous
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_keystroke_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.raw_keystroke_logs IS 'High-frequency buffer for raw keystroke data for behavioral analysis.';

-- DB206: iam.consent_purposes
-- Description: Granular purposes for which consent is granted (GDPR Art. 5(1)(b)).
-- Business Case: GDPR requires that consent be specific to a purpose. This table defines those purposes (e.g., "Fraud Detection", "Marketing", "Service Delivery"). When a user grants consent (DB207), they link it to a purpose defined here. This granularity ensures that data is not used for purposes the user did not agree to, protecting the platform from regulatory fines and building trust with the user.
-- KPIs: Purpose specificity index, Usage alignment rate.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS iam.consent_purposes (
    purpose_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    code VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    legal_basis VARCHAR(100) NOT NULL, -- e.g., CONSENT, CONTRACT, LEGAL_OBLIGATION
    is_sensitive BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.consent_purposes IS 'Defines valid legal purposes for data processing (GDPR).';

-- DB207: iam.consent_grants
-- Description: Mapping of user consent to specific purposes.
-- Business Case: This is the active record of what users have agreed to. It links a user to a purpose and records the timestamp. It also supports withdrawal (`revoked_at`). This table is queried by the ABAC engine to ensure that a data processing request is permitted only if a valid, non-revoked consent grant exists for that specific purpose. It is the operational implementation of the privacy policy.
-- KPIs: Consent coverage rate, Withdrawal latency.
-- Feature Reference: F026
CREATE TABLE IF NOT EXISTS iam.consent_grants (
    grant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    purpose_id UUID NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_consent_grants_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_consent_grants_purpose FOREIGN KEY (purpose_id) REFERENCES iam.consent_purposes(purpose_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.consent_grants IS 'Maps users to specific legal consent purposes.';

-- DB208: iam.threat_intel_cache
-- Description: Cached threat intelligence from external providers (IPs, Hashes).
-- Business Case: Real-time threat detection requires looking up Indicators of Compromise (IoC) like bad IPs or file hashes. Querying external APIs (e.g., VirusTotal, AlienVault) for every login is too slow. This table caches the threat intelligence data (`value`, `severity`) with a TTL. It allows the system to block threats instantly at the edge while keeping the data fresh via periodic background refreshes.
-- KPIs: Cache freshness, Threat lookup latency.
-- Feature Reference: F063, F114
CREATE TABLE IF NOT EXISTS iam.threat_intel_cache (
    threat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH')),
    value VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    source VARCHAR(100) NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE iam.threat_intel_cache IS 'Caches threat intelligence data for real-time blocking.';

-- DB209: iam.secret_versions
-- Description: Version history for secrets to support rollback.
-- Business Case: Rotation of secrets (DB credentials, API keys) can sometimes lead to application failures. This table maintains a version history of secrets. It stores the old `encrypted_value` and `version_num`. If a new secret fails, operations can instantly rollback to a previous version using this table. It provides a safety net for infrastructure operations, ensuring high availability during maintenance.
-- KPIs: Rollback success rate, Version retention period.
-- Feature Reference: F087
CREATE TABLE IF NOT EXISTS iam.secret_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL, -- References DB022 iam.secrets
    version_num INTEGER NOT NULL,
    encrypted_value BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_secret_versions_secret FOREIGN KEY (secret_id) REFERENCES iam.secrets(secret_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.secret_versions IS 'Stores historical versions of secrets to support rollback.';

-- DB210: iam.key_escrow
-- Description: Securely stored fragments of master keys for disaster recovery.
-- Business Case: If all HSMs (Hardware Security Modules) or admin keys are lost (e.g., disaster), the platform would be permanently unable to decrypt its own data. This table implements "Key Escrow" or Shamir's Secret Sharing. It stores fragments of master keys (`shard_enc`), each held by a different custodian (`holder_id`). Reconstructing the key requires a quorum of holders to provide their fragments, ensuring no single point of compromise or failure.
-- KPIs: Shard reconstruction success, Custodian availability.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS iam.key_escrow (
    fragment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL, -- Reference to the master key
    shard_enc BYTEA NOT NULL, -- Encrypted fragment
    holder_id UUID NOT NULL, -- The custodian holding this fragment

    CONSTRAINT fk_key_escrow_key FOREIGN KEY (key_id) REFERENCES iam.encryption_keys(key_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.key_escrow IS 'Stores fragments of master keys for disaster recovery via Secret Sharing.';

-- DB211: iam.dynamic_secrets
-- Description: Short-lived secrets generated for DB connections.
-- Business Case: Static credentials in configuration files are a major security risk. This table supports dynamic secret generation (like Vault). It generates a temporary DB credential (`username`, `password_hash`) for a specific lease duration. The application queries this table, uses the credential, and it expires automatically. This eliminates the need for developers to manage or hardcode passwords, significantly reducing the attack surface.
-- KPIs: Secret generation latency, Expiration enforcement accuracy.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS iam.dynamic_secrets (
    lease_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    db_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE iam.dynamic_secrets IS 'Stores short-lived dynamically generated database credentials.';

-- DB212: iam.admin_audit_review
-- Description: Marking logs as reviewed by an auditor.
-- Business Case: Auditing involves reviewing logs to confirm security compliance. This table tracks the completion of these reviews. It links a batch of logs (`log_batch_id`) to an auditor (`reviewer_id`) and their notes. This proves to external regulators that internal governance processes are active and that logs are being inspected, which is a requirement for standards like ISO 27001.
-- KPIs: Review completion rate, Log coverage percentage.
-- Feature Reference: F015
CREATE TABLE IF NOT EXISTS iam.admin_audit_review (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reviewer_id UUID NOT NULL,
    log_batch_id VARCHAR(255) NOT NULL, -- Reference to a time range or hash
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    CONSTRAINT fk_audit_review_reviewer FOREIGN KEY (reviewer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.admin_audit_review IS 'Tracks the review status of audit logs by internal auditors.';

-- DB213: iam.policy_impact_assessment
-- Description: Results of simulating a policy change across the user base.
-- Business Case: Before deploying a new policy, we must know its impact. This table stores the results of "Dry Run" simulations. It counts how many users would gain access (`allow_count`) or lose access (`deny_count`). This risk assessment prevents accidental outages or privilege escalations. It quantifies the risk of a policy change, allowing management to approve or reject based on data.
-- KPIs: Simulation accuracy, Assessment execution time.
-- Feature Reference: F100, F140
CREATE TABLE IF NOT EXISTS iam.policy_impact_assessment (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    affected_users_count INTEGER NOT NULL,
    allow_count INTEGER DEFAULT 0,
    deny_count INTEGER DEFAULT 0,
    risk_score NUMERIC(3,2),
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_policy_assessment_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_impact_assessment IS 'Stores results of policy impact simulations (dry-runs).';

-- DB214: iam.role_mining_candidates
-- Description: AI-suggested roles based on permission clustering.
-- Business Case: Over time, roles become bloated or misaligned with job functions. "Role Mining" uses AI to analyze current permission assignments and suggest new, cleaner role definitions. This table stores these candidates (`name`, `permissions_json`). By adopting these suggestions, admins can reduce role explosion and improve the efficiency of the IAM system, adhering to the principle of least privilege.
-- KPIs: Adoption rate of suggestions, Permission coverage efficiency.
-- Feature Reference: F065
CREATE TABLE IF NOT EXISTS iam.role_mining_candidates (
    candidate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    similar_permissions_json JSONB NOT NULL,
    confidence_score NUMERIC(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.role_mining_candidates IS 'Stores AI-suggested role definitions for cleanup and optimization.';

-- DB215: iam.privilege_escalation_log
-- Description: Specific log for any elevation of privileges (JIT or Permanent).
-- Business Case: Privilege escalation is a high-risk event. This table creates a dedicated, easily queryable log for every time a user gained higher rights. It tracks the `from_role`, `to_role`, and `approved_by`. This is crucial for forensic investigations into insider threats or compromised accounts, as it highlights the exact moment a user became "dangerous".
-- KPIs: Log completeness, Query latency for investigations.
-- Feature Reference: F010, F011
CREATE TABLE IF NOT EXISTS iam.privilege_escalation_log (
    escalation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    from_role_id UUID,
    to_role_id UUID NOT NULL,
    approved_by UUID,
    escalation_type VARCHAR(50) CHECK (escalation_type IN ('JIT', 'PERMANENT', 'DELEGATION')),
    escalated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_escalation_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_escalation_to_role FOREIGN KEY (to_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.privilege_escalation_log IS 'Dedicated log tracking all privilege elevation events.';

-- DB216: iam.quarantine_activities
-- Description: Actions taken while a user is in quarantine.
-- Business Case: When a user is quarantined (DB083), they might still attempt actions. This table logs those blocked attempts (`attempted_action`, `blocked`). It helps in analyzing the attacker's behavior—what were they trying to access? It also ensures that legitimate user activity during a false-positive quarantine can be reviewed and restored if necessary.
-- KPIs: Blocked action count, Quarantine duration analysis.
-- Feature Reference: F083
CREATE TABLE IF NOT EXISTS iam.quarantine_activities (
    activity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    attempted_action TEXT NOT NULL,
    blocked BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_quarantine_activity_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.quarantine_activities IS 'Logs actions attempted by users while in security quarantine.';

-- DB217: iam.password_breaches
-- Description: Log of password changes triggered by breach detection.
-- Business Case: When "Have I Been Pwned" or other breach sources flag a password, the system must force a change. This table records those events. It links the user to the `breach_source` and the `forced_change_at` timestamp. This provides an audit trail proving proactive security measures were taken in response to external credential leaks, satisfying compliance requirements for incident response.
-- KPIs: Forced change latency, Breach source diversity.
-- Feature Reference: F121
CREATE TABLE IF NOT EXISTS iam.password_breaches (
    breach_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    breach_source VARCHAR(100) NOT NULL,
    forced_change_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pwd_breach_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.password_breaches IS 'Logs forced password changes resulting from credential breach detection.';

-- DB218: iam.session_anomalies
-- Description: Specific anomalies detected within a session.
-- Business Case: A session is a stream of events. This table records specific anomalies detected *within* a session (e.g., `IMPOSSIBLE_TRAVEL`, `SPEED_CLICKING`, `BULK_DOWNLOAD`). These granular alerts allow the system to decide whether to kill the session immediately or just flag it. They provide context for the "risk_score" calculation.
-- KPIs: Anomaly classification accuracy, Detection latency.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.session_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    type VARCHAR(50) NOT NULL, -- e.g., IMPOSSIBLE_TRAVEL, BOT_BEHAVIOR
    severity VARCHAR(20) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_anomaly_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_anomalies IS 'Stores specific anomaly events detected during a session.';

-- DB219: iam.smart_lockout_history
-- Description: History of smart lockout triggers and releases.
-- Business Case: Simple account lockouts cause DoS (Denial of Service) for users. Smart lockouts increase the threshold and delay duration over time. This table tracks the history of these smart lockouts. It logs the `trigger_reason` (e.g., "Global Botnet Attack") and when the user was `released_at`. This allows the system to optimize the lockout algorithm based on historical effectiveness and user experience.
-- KPIs: Lockout effectiveness, User frustration metric.
-- Feature Reference: F082
CREATE TABLE IF NOT EXISTS iam.smart_lockout_history (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    trigger_reason VARCHAR(255) NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_smart_lockout_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.smart_lockout_history IS 'Tracks history of smart account lockouts and releases.';

-- DB220: iam.access_request_comments
-- Description: Comments/justification attached to JIT requests.
-- Business Case: When a user requests JIT access (DB010), they need to provide justification. Approvers might ask questions. This table stores the conversational thread attached to a request. It ensures that the "Why" is documented alongside the "What". This is critical for justifying privileged access during audits and preventing casual use of powerful roles.
-- KPIs: Comment thread length, Justification quality score.
-- Feature Reference: F011
CREATE TABLE IF NOT EXISTS iam.access_request_comments (
    comment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id UUID NOT NULL,
    author_id UUID NOT NULL,
    comment_text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_access_req_comments_request FOREIGN KEY (request_id) REFERENCES iam.jit_requests(request_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_req_comments_author FOREIGN KEY (author_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_request_comments IS 'Stores conversational comments on JIT access requests.';

-- DB221: iam.delegation_chain
-- Description: Tracking chains of delegated authority.
-- Business Case: Delegation can be transitive (A delegates to B, B delegates to C). This table tracks the depth and path of this chain. It links the `root_user_id` (the original owner) to the `current_holder_id`. By tracking the `depth`, we can enforce limits (e.g., "Max 2 levels deep") to prevent unauthorized spread of privileges. This ensures that delegated authority remains under control.
-- KPIs: Chain depth limit enforcement, Chain validity.
-- Feature Reference: F066
CREATE TABLE IF NOT EXISTS iam.delegation_chain (
    chain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    root_user_id UUID NOT NULL,
    current_holder_id UUID NOT NULL,
    depth INTEGER NOT NULL CHECK (depth > 0),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_delegation_chain_root FOREIGN KEY (root_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_delegation_chain_holder FOREIGN KEY (current_holder_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.delegation_chain IS 'Tracks the path and depth of delegated authority chains.';

-- DB222: iam.feature_metrics
-- Description: Granular metrics for feature flag usage.
-- Business Case: To evaluate the success of a new feature (e.g., "New MFA UI"), we need metrics. This table stores granular counts per `flag_name`, `user_segment`, and `exposure_count`. It helps Product Managers decide if a feature should be rolled out to 100% or rolled back. It separates feature analysis from general access logs, focusing on product usage rather than security events.
-- KPIs: Feature adoption rate, Segment-specific engagement.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.feature_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    user_segment VARCHAR(50), -- e.g., NEW_USERS, EU_REGION
    exposure_count BIGINT DEFAULT 0,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.feature_metrics IS 'Stores usage metrics for feature flags.';

-- DB223: iam.api_rate_limit_history
-- Description: Historical data for rate limit tuning.
-- Business Case: Rate limits (DB199) need to be tuned based on usage. If a limit is too high, it risks abuse; if too low, it blocks legitimate users. This table stores the history of limit settings and the resulting `requested_at` volumes. Analysts can query this to find the optimal threshold that maximizes utility while minimizing risk.
-- KPIs: Threshold optimization success, Traffic pattern visibility.
-- Feature Reference: F123
CREATE TABLE IF NOT EXISTS iam.api_rate_limit_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    limit_id UUID NOT NULL,
    user_id UUID, -- NULL if global
    limit_value INTEGER NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_api_limit_hist_limit FOREIGN KEY (limit_id) REFERENCES iam.rate_limits(limit_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.api_rate_limit_history IS 'Stores historical data for tuning API rate limits.';

-- DB224: iam.compliance_mappings
-- Description: Mapping of permissions to compliance controls.
-- Business Case: Compliance frameworks (ISO 27001, SOC2) require that we prove specific controls are in place. This table maps technical permissions (e.g., `transaction:read`) to compliance controls (e.g., "A.9.4 Access Control"). When an auditor asks "Who has access to this control?", we query the IAM system. This automated mapping simplifies the audit process significantly.
-- KPIs: Mapping coverage, Control verification speed.
-- Feature Reference: F060
CREATE TABLE IF NOT EXISTS iam.compliance_mappings (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    perm_id UUID NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    control_framework VARCHAR(50) NOT NULL, -- e.g., ISO27001, SOC2

    CONSTRAINT fk_comp_map_perm FOREIGN KEY (perm_id) REFERENCES iam.permissions(perm_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.compliance_mappings IS 'Maps IAM permissions to regulatory compliance controls.';

-- DB225: iam.control_frameworks
-- Description: Reference data for compliance frameworks.
-- Business Case: This is the library of supported compliance frameworks. It stores `name`, `version`, and `description`. When importing controls or mappings, this table ensures consistency (e.g., ensuring we don't have "SOC 2" and "SOC2" as two different strings). It is the master data for the compliance engine.
-- KPIs: Framework version coverage.
-- Feature Reference: F060
CREATE TABLE IF NOT EXISTS iam.control_frameworks (
    framework_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL,
    description TEXT
);
COMMENT ON TABLE iam.control_frameworks IS 'Reference data for supported compliance frameworks.';

-- DB226: iam.evidence_locker
-- Description: Secure storage for evidence required for audits.
-- Business Case: Audits require evidence (screenshots, logs, config dumps). This table acts as a secure "locker" for these artifacts. It stores the `artifact_url` and links it to the `control_id` it satisfies. By centralizing evidence, we ensure that audit readiness is continuous and not a scramble at the end of the year.
-- KPIs: Evidence retrieval speed, Completeness score.
-- Feature Reference: F060
CREATE TABLE IF NOT EXISTS iam.evidence_locker (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,
    artifact_url TEXT NOT NULL,
    uploaded_by UUID NOT NULL,
    upload_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_evidence_uploader FOREIGN KEY (uploaded_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.evidence_locker IS 'Stores secure links to evidence artifacts for compliance audits.';

-- DB227: iam.shadow_it_patterns
-- Description: Learned patterns of unauthorized access tools.
-- Business Case: Employees sometimes use unsanctioned tools (Shadow IT) that bypass security controls. This table stores learned "signatures" of these tools (`tool_signature`). When the anomaly detection engine sees traffic matching a signature (e.g., specific User-Agent + IP range), it flags it. This helps IT Security identify and formally approve or block risky tools.
-- KPIs: Shadow IT discovery rate, Pattern uniqueness.
-- Feature Reference: F043
CREATE TABLE IF NOT EXISTS iam.shadow_it_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    tool_signature JSONB NOT NULL, -- Unique fingerprint of the tool
    risk_score NUMERIC(5,2),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.shadow_it_patterns IS 'Stores learned patterns of unauthorized (Shadow IT) tools.';

-- DB228: iam.session_recordings
-- Description: Metadata for recorded admin sessions.
-- Business Case: DB095 `session_videos` stores the video file. This table stores the metadata for the *recording job* itself. It tracks the `recording_type` (VIDEO, LOGS, SCREENSHOT), the status (RECORDING, COMPLETED), and any error logs. It separates the management of the recording process from the storage of the media, allowing for retries and monitoring of the recording infrastructure.
-- KPIs: Recording success rate, Storage capacity planning.
-- Feature Reference: F125
CREATE TABLE IF NOT EXISTS iam.session_recordings (
    rec_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    recording_type VARCHAR(20) CHECK (recording_type IN ('VIDEO', 'METADATA', 'SCREENSHOT')),
    status VARCHAR(20) DEFAULT 'PENDING',
    size_bytes BIGINT,
    duration_seconds INTEGER,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_session_rec_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_recordings IS 'Metadata for session recording jobs and processes.';

-- DB229: iam.synthetic_monitoring
-- Description: Config and results for synthetic auth tests.
-- Business Case: While DB112 stores the *results* of a single test, this table stores the *configuration* of the monitoring monitors. It defines `test_id`, `script_id`, and the `schedule` (e.g., "Every 5 mins"). It is the control plane for synthetic monitoring, allowing Ops teams to enable/disable specific health checks without code changes.
-- KPIs: Monitor availability, Config change latency.
-- Feature Reference: F112
CREATE TABLE IF NOT EXISTS iam.synthetic_monitoring (
    monitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    script_id VARCHAR(100) NOT NULL,
    schedule_cron VARCHAR(50), -- e.g., "*/5 * * * *"
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.synthetic_monitoring IS 'Configuration for synthetic authentication health monitors.';

-- DB230: iam.pairwise_subject_cache
-- Description: Cache for pairwise subject identifiers.
-- Business Case: Pairwise IDs are computationally expensive to generate (hashing RP ID + User ID). To speed up login, we cache the result in this table. It maps the `sector_id` (Relying Party) and `user_id` to the pre-calculated `subject_id`. This significantly reduces the CPU load on the identity server during high-traffic periods.
-- KPIs: Cache hit ratio, Login latency improvement.
-- Feature Reference: F052
CREATE TABLE IF NOT EXISTS iam.pairwise_subject_cache (
    cache_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sector_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uk_pairwise_cache UNIQUE (sector_id, user_id),
    CONSTRAINT fk_pairwise_cache_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.pairwise_subject_cache IS 'Caches calculated pairwise subject IDs for performance.';

-- DB231: iam.oauth_authorization_details
-- Description: Detailed authorization parameters per OAuth spec.
-- Business Case: OAuth flows can have extended parameters (e.g., `prompt=consent`, `max_age`). This table stores the detailed JSON payload associated with an authorization code or request. By storing the full `details_json`, we support complex extensions to the OAuth protocol without needing to alter the schema every time a new parameter is introduced.
-- KPIs: Parameter support flexibility.
-- Feature Reference: F024
CREATE TABLE IF NOT EXISTS iam.oauth_authorization_details (
    auth_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_id UUID NOT NULL,
    details_json JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_oauth_auth_details_client FOREIGN KEY (client_id) REFERENCES iam.client_applications(client_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.oauth_authorization_details IS 'Stores detailed parameters for OAuth authorization requests.';

-- DB232: iam.saml_attribute_mapping
-- Description: Mapping of SAML attributes to local user attributes.
-- Business Case: SAML responses from IdPs contain attributes (e.g., `EmailAddress`, `Department`) in a specific format. This table maps those incoming SAML attribute names to local `user_attributes` (DB007). This abstraction layer allows the PARI platform to integrate with any SAML provider without hardcoding attribute names, facilitating easy onboarding of new partners.
-- KPIs: Mapping flexibility, Attribute drop rate.
-- Feature Reference: F091
CREATE TABLE IF NOT EXISTS iam.saml_attribute_mapping (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_id UUID NOT NULL,
    saml_attr VARCHAR(255) NOT NULL, -- Incoming attribute name
    local_attr VARCHAR(100) NOT NULL, -- Target attribute name in PARI

    CONSTRAINT fk_saml_map_provider FOREIGN KEY (provider_id) REFERENCES iam.federation_providers(provider_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.saml_attribute_mapping IS 'Maps SAML assertion attributes to local user attributes.';

-- DB233: iam.oidc_claims_mapping
-- Description: Mapping of OIDC claims to local user attributes.
-- Business Case: Similar to SAML mapping (DB232), but for OIDC standard claims (e.g., `given_name`, `family_name`). This table maps JWT claims to local user fields. It ensures that regardless of which OpenID Provider is used (Google, Auth0), the user data is consistently populated in the PARI `users` table.
-- KPIs: Claim consistency, Mapping error rate.
-- Feature Reference: F091
CREATE TABLE IF NOT EXISTS iam.oidc_claims_mapping (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_id UUID NOT NULL,
    claim_name VARCHAR(255) NOT NULL, -- e.g., email, groups
    local_attr VARCHAR(100) NOT NULL, -- Target column or attribute

    CONSTRAINT fk_oidc_map_provider FOREIGN KEY (provider_id) REFERENCES iam.federation_providers(provider_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.oidc_claims_mapping IS 'Maps OIDC JWT claims to local user attributes.';

-- DB234: iam.user_event_stream
-- Description: Kafka-sourced event stream for users (CDC).
-- Business Case: In an event-driven architecture, user data changes are captured via Change Data Capture (CDC) from the database. This table acts as a materialized stream (or buffer) of these events. It stores the `event_type` (INSERT, UPDATE, DELETE) and the `payload_json`. This allows downstream services (Analytics, Search Index) to maintain their own state without polling the main database.
-- KPIs: Event lag time, Throughput.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.user_event_stream (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    event_type VARCHAR(20) CHECK (event_type IN ('INSERT', 'UPDATE', 'DELETE')),
    payload_json JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_user_event_stream_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_event_stream IS 'Stores CDC events for user data synchronization.';

-- DB235: iam.access_denial_feedback
-- Description: User feedback on access denial (Is this an error?).
-- Business Case: Sometimes security blocks legitimate users (false positives). This table captures user feedback ("I should have access to this"). It links the `denied_action_id` to a flag `is_error`. Admins review this table to tune policies (e.g., "This Geo-fence is too tight"). It closes the loop between security enforcement and user experience.
-- KPIs: Feedback resolution time, False positive reduction.
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS iam.access_denial_feedback (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    denied_action_id UUID NOT NULL, -- Reference to access_logs
    is_error BOOLEAN NOT NULL, -- User claims it was a mistake
    explanation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_denial_feedback_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_denial_feedback IS 'Captures user feedback on incorrect access denials.';

-- DB236: iam.password_complexity_rules
-- Description: Detailed rules for password composition.
-- Business Case: Simple "length > 8" is often insufficient. This table allows for granular rules (`min_upper`, `min_digit`, `min_special`, `max_consecutive`). It allows enforcement of complex policies like "Must include 2 digits and 1 symbol, but no 3 consecutive characters". It supports `password_policies` (DB062) by providing the detailed logic execution.
-- KPIs: Rule complexity enforcement, Password strength score.
-- Feature Reference: F058
CREATE TABLE IF NOT EXISTS iam.password_complexity_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    min_upper INTEGER DEFAULT 0,
    min_digit INTEGER DEFAULT 0,
    min_special INTEGER DEFAULT 0,
    max_consecutive INTEGER,
    forbidden_chars TEXT,

    CONSTRAINT fk_pwd_complexity_policy FOREIGN KEY (policy_id) REFERENCES iam.password_policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.password_complexity_rules IS 'Defines granular logic for password complexity validation.';

-- DB237: iam.session_fixation_tokens
-- Description: Tokens used to prevent session fixation attacks.
-- Business Case: Session fixation attacks force a victim to use a known session ID. To prevent this, the system generates a random "fixation token" upon login and binds it to the session. This table stores the `token_id` and `old_token_hash`. The system validates this token on every request, ensuring that an attacker cannot simply steal a cookie to hijack a session.
-- KPIs: Validation overhead, Fixation attack prevention rate.
-- Feature Reference: F012
CREATE TABLE IF NOT EXISTS iam.session_fixation_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    old_token_hash VARCHAR(255), -- Optional: binding to previous session
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_fixation_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_fixation_tokens IS 'Stores anti-fixation tokens to bind session to a specific browser context.';

-- DB238: iam.ip_risk_scores
-- Description: Cached risk scores for IP addresses.
-- Business Case: Similar to DB059, but specifically for a dynamic score calculated over time. This table tracks the historical risk score of an IP address. An IP might be clean today but risky tomorrow. By tracking this temporal dimension, the system can differentiate between "Always Bad" IPs and "Currently Bad" IPs (e.g., a compromised residential IP), applying different remediation strategies.
-- KPIs: Score volatility, Risk accuracy.
-- Feature Reference: F063
CREATE TABLE IF NOT EXISTS iam.ip_risk_scores (
    ip_score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address INET NOT NULL,
    score NUMERIC(5,2) CHECK (score >= 0 AND score <= 100),
    category VARCHAR(50),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.ip_risk_scores IS 'Stores time-bound risk scores for IP addresses.';

-- DB239: iam.device_drift_detection
-- Description: Tracking changes in device hardware profile.
-- Business Case: Device fingerprinting works until the hardware changes (new RAM, OS update). This table tracks "drift"—the difference between the `observed_attr` (current) and `expected_attr` (baseline). If drift exceeds a threshold, it might indicate a VM clone or device swap. This allows the system to trigger a Step-Up challenge for the device (e.g., re-enter password).
-- KPIs: Drift detection sensitivity, False positive rate.
-- Feature Reference: F014
CREATE TABLE IF NOT EXISTS iam.device_drift_detection (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL,
    observed_attr JSONB NOT NULL,
    expected_attr JSONB NOT NULL,
    drift_score NUMERIC(3,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_device_drift_device FOREIGN KEY (device_id) REFERENCES iam.devices(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.device_drift_detection IS 'Tracks changes in device fingerprints to detect cloning or swaps.';

-- DB240: iam.backup_audit_trail
-- Description: Backup of immutable logs for disaster recovery.
-- Business Case: In the event of catastrophic database failure, we must restore the immutable log. This table stores a backup of the `access_logs` (DB009), likely in a compressed or binary format. It serves as the "gold copy" for disaster recovery, ensuring that even if the primary DB is corrupted, the security record survives.
-- KPIs: Backup consistency, Restoration success rate.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS iam.backup_audit_trail (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_batch_id VARCHAR(255) NOT NULL, -- Reference to chain or range
    backup_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    backup_data BYTEA, -- Compressed log data
    checksum_hash VARCHAR(255) -- Integrity check for the backup
);
COMMENT ON TABLE iam.backup_audit_trail IS 'Stores disaster recovery backups of the audit trail.';

-- DB241: iam.ml_model_features
-- Description: Feature set definitions used by ML models.
-- Business Case: Machine Learning models are only as good as their features. This table defines the feature set used by specific models (`model_id`). It lists the `feature_name` (e.g., "Login Time") and its `weight`. Changing this table allows data scientists to experiment with different feature sets (A/B testing) without deploying new model binaries.
-- KPIs: Feature importance score, Model accuracy.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.ml_model_features (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL, -- Reference to model version or ID
    feature_name VARCHAR(100) NOT NULL,
    weight NUMERIC(5,2) CHECK (weight >= 0 AND weight <= 1),
    description TEXT
);
COMMENT ON TABLE iam.ml_model_features IS 'Defines the feature set and weights for specific ML models.';

-- DB242: iam.ml_model_drift
-- Description: Tracking drift of ML model accuracy over time.
-- Business Case: Models degrade (drift) as user behavior changes (e.g., holiday traffic). This table tracks the `accuracy` and `f1_score` of models over time. If drift crosses a threshold, the system alerts data scientists to retrain the model. This ensures that the anomaly detection engine remains effective as the threat landscape evolves.
-- KPIs: Drift detection speed, Retraining frequency.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.ml_model_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,
    accuracy NUMERIC(3,2),
    f1_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.ml_model_drift IS 'Tracks the degradation of ML model performance over time.';

-- DB243: iam.knowledge_graph_updates
-- Description: Log of changes to the KG for eventual consistency.
-- Business Case: In distributed systems, the Knowledge Graph might be updated asynchronously. This table logs every change to an entity (`entity_id`, `change_type`). It serves as a source of truth for replaying updates to read replicas or search indices, ensuring that the KG is eventually consistent across all services.
-- KPIs: Replay latency, Update consistency.
-- Feature Reference: F122
CREATE TABLE IF NOT EXISTS iam.knowledge_graph_updates (
    update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    change_type VARCHAR(20) CHECK (change_type IN ('CREATE', 'UPDATE', 'DELETE')),
    data_snapshot JSONB NOT NULL, -- The state of the entity at change time
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_kg_updates_entity FOREIGN KEY (entity_id) REFERENCES iam.kg_entities(entity_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.knowledge_graph_updates IS 'Logs changes to the Knowledge Graph for consistency.';

-- DB244: iam.admin_console_sessions
-- Description: Sessions specifically within the isolated admin browser.
-- Business Case: Admins often use Remote Browser Isolation (DB147). This table tracks sessions *inside* that isolated browser environment. It links the `local_session_id` (PARI session) to the `iso_session_id` (Remote Browser ID). It helps in correlating admin actions taken in the secure environment with the user account in PARI.
-- KPIs: Isolation session duration, Correlation success.
-- Feature Reference: F147
CREATE TABLE IF NOT EXISTS iam.admin_console_sessions (
    console_session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    admin_id UUID NOT NULL,
    iso_session_id VARCHAR(255), -- ID from isolation provider
    host_ip INET,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_console_session_admin FOREIGN KEY (admin_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.admin_console_sessions IS 'Tracks sessions within the isolated admin browser environment.';

-- DB245: iam.secure_email_logs
-- Description: Logs of security-sensitive emails (OTP, Alerts).
-- Business Case: Sending OTPs or alerts via email is a critical security function. This table logs every email dispatched (`recipient`, `template_id`, `status`). It is essential for debugging delivery issues (e.g., "Did the OTP email send?") and for detecting abuse (e.g., "User requesting 100 OTPs in an hour").
-- KPIs: Delivery success rate, Template rendering error rate.
-- Feature Reference: F075
CREATE TABLE IF NOT EXISTS iam.secure_email_logs (
    email_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    recipient VARCHAR(255) NOT NULL,
    template_id VARCHAR(100) NOT NULL, -- e.g., OTP_TEMPLATE
    subject VARCHAR(255),
    sent_status VARCHAR(20) CHECK (sent_status IN ('QUEUED', 'SENT', 'FAILED', 'BOUNCED')),
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);
COMMENT ON TABLE iam.secure_email_logs IS 'Logs the dispatch of security-sensitive emails (OTP, Alerts).';

-- DB246: iam.captcha_challenges_v3
-- Description: Captcha generation and validation records (V3/Analytics).
-- Business Case: Distinct from DB050 (session) and DB127 (V2), this table focuses on the *analytics* of Captcha usage or a specific integration (V3). It tracks `solved` status and `response_time`. This data helps in tuning the difficulty of Captchas—too easy = bots pass, too hard = users fail.
-- KPIs: Solve rate, Bot vs Human classification accuracy.
-- Feature Reference: F127
CREATE TABLE IF NOT EXISTS iam.captcha_challenges_v3 (
    captcha_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID,
    solved BOOLEAN DEFAULT FALSE,
    provider VARCHAR(50), -- e.g., hCaptcha, Cloudflare
    difficulty_score INTEGER CHECK (difficulty_score >= 0 AND difficulty_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_captcha_v3_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.captcha_challenges_v3 IS 'Analytics and tracking for Captcha challenges.';

-- DB247: iam.magic_link_analytics
-- Description: Tracking of one-time magic link usage (V3/Analytics).
-- Business Case: Distinct from DB051/DB128, this table is the analytics warehouse for magic links. It aggregates metrics like `used_ip`, `time_to_click`, and `device_type`. This helps marketing/security teams understand if passwordless login is being adopted and if there are geographic anomalies in link clicking.
-- KPIs: Link conversion rate, Geographic consistency.
-- Feature Reference: F128
CREATE TABLE IF NOT EXISTS iam.magic_link_analytics (
    analytics_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    link_id UUID NOT NULL,
    clicked_ip INET,
    time_to_click_seconds INTEGER,
    user_agent_hash VARCHAR(255),

    CONSTRAINT fk_magic_analytics_link FOREIGN KEY (link_id) REFERENCES iam.magic_links(link_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.magic_link_analytics IS 'Analytics tracking for magic link passwordless authentication.';

-- DB248: iam.biometric_liveness_detailed
-- Description: Records of liveness detection challenges (V3/Detailed).
-- Business Case: An evolution of DB105. This table stores granular data points for liveness checks, such as specific `challenge_type` (e.g., "Blink", "Smile") and the raw `feedback_data`. This allows for deeper analysis into why specific liveness checks might be failing for certain demographics or devices, ensuring fairness and accuracy.
-- KPIs: Challenge success rate per type, False rejection analysis.
-- Feature Reference: F105
CREATE TABLE IF NOT EXISTS iam.biometric_liveness_detailed (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    challenge_type VARCHAR(50) NOT NULL,
    result BOOLEAN NOT NULL,
    confidence NUMERIC(5,2),
    feedback_data JSONB, -- Device specific logs
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_liveness_v3_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.biometric_liveness_detailed IS 'Detailed records and analytics for biometric liveness checks.';

-- DB249: iam.zero_knowledge_proofs
-- Description: ZKP verification data for privacy-preserving auth.
-- Business Case: Zero Knowledge Proofs allow a user to prove they know a secret (like a password) without revealing the secret itself. This table stores the `proof_json` and the verification status. It is foundational for privacy-preserving authentication where the server never handles the raw credential. This aligns with PARI's goal of minimizing the data-at-risk on the server side.
-- KPIs: Proof verification speed, ZKP generation latency.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS iam.zero_knowledge_proofs (
    zkp_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    proof_json JSONB NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verification_challenge_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_zkp_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.zero_knowledge_proofs IS 'Stores Zero Knowledge Proof verification data.';

-- DB250: iam.dynamic_salt_versions
-- Description: Versions of dynamic salts used for obfuscation.
-- Business Case: Enhancing DB110 (`hash_salts`), this table tracks versions of "Dynamic Salts". In some obfuscation schemes, the salt itself might change based on context or time. This table logs the `salt_value` and `active_from` period. It ensures that old hashes can still be verified (using the old salt) while new data uses the new salt, supporting rotation without breaking history.
-- KPIs: Salt rotation history, Re-hashing success.
-- Feature Reference: F110
CREATE TABLE IF NOT EXISTS iam.dynamic_salt_versions (
    salt_ver_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    salt_value VARCHAR(255) NOT NULL UNIQUE,
    active_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    active_until TIMESTAMP WITH TIME ZONE, -- Nullable implies currently active
    created_by UUID NOT NULL
);
COMMENT ON TABLE iam.dynamic_salt_versions IS 'Tracks versioning of dynamic salts for data obfuscation.';

-- ================================================================================
-- Indexes and Constraints for Part 5 Tables
-- ================================================================================

-- Knowledge Graph
CREATE INDEX IF NOT EXISTS idx_kg_entities_type ON iam.kg_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_kg_rel_source ON iam.kg_relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_kg_rel_target ON iam.kg_relationships(target_entity_id);

-- Biometrics & Telemetry (High Volume)
CREATE INDEX IF NOT EXISTS idx_keystroke_session ON iam.raw_keystroke_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_keystroke_timestamp ON iam.raw_keystroke_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_consent_grants_user ON iam.consent_grants(user_id);

-- Threat Intel
CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON iam.threat_intel_cache(value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON iam.threat_intel_cache(ioc_type);

-- Secrets & Escrow
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON iam.secret_versions(secret_id);
CREATE INDEX IF NOT EXISTS idx_dynamic_secrets_expiry ON iam.dynamic_secrets(expires_at);

-- Admin & Compliance
CREATE INDEX IF NOT EXISTS idx_admin_audit_review_batch ON iam.admin_audit_review(log_batch_id);
CREATE INDEX IF NOT EXISTS idx_comp_map_perm ON iam.compliance_mappings(perm_id);
CREATE INDEX IF NOT EXISTS idx_evidence_control ON iam.evidence_locker(control_id);

-- Anomalies & Logs
CREATE INDEX IF NOT EXISTS idx_session_anomalies_session ON iam.session_anomalies(session_id);
CREATE INDEX IF NOT EXISTS idx_smart_lockout_user ON iam.smart_lockout_history(user_id);
CREATE INDEX IF NOT EXISTS idx_shadow_it_pattern ON iam.shadow_it_patterns USING gin(tool_signature);

-- Monitoring & Analytics
CREATE INDEX IF NOT EXISTS idx_feature_metrics_flag ON iam.feature_metrics(flag_name);
CREATE INDEX IF NOT EXISTS idx_ml_drift_model ON iam.ml_model_drift(model_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_captcha_v3_session ON iam.captcha_challenges_v3(session_id);
CREATE INDEX IF NOT EXISTS idx_magic_analytics_link ON iam.magic_link_analytics(link_id);

-- Cache & Event Stream
CREATE INDEX IF NOT EXISTS idx_pairwise_cache_sector ON iam.pairwise_subject_cache(sector_id);
CREATE INDEX IF NOT EXISTS idx_user_event_stream_user ON iam.user_event_stream(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_kg_updates_entity ON iam.knowledge_graph_updates(entity_id, timestamp DESC);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 5 Tables
-- ================================================================================

ALTER TABLE iam.consent_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.quarantine_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.session_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.synthetic_monitoring ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.pairwise_subject_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_event_stream ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.magic_link_analytics ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.zero_knowledge_proofs ENABLE ROW LEVEL SECURITY;

-- Policy: Consent Grants (User can see own)
CREATE POLICY consent_grants_user_isolation ON iam.consent_grants
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Policy: Quarantine Activities (User can see own attempts? No, usually sensitive. Let's restrict to Admins.)
CREATE POLICY quarantine_activities_admin_only ON iam.quarantine_activities
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

-- Policy: Session Recordings (Admin can see all, User can see own?)
-- Assume Admin only for video logs.
CREATE POLICY session_recordings_admin_only ON iam.session_recordings
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

-- Policy: Synthetic Monitoring (Admins only)
CREATE POLICY synthetic_monitoring_admin_only ON iam.synthetic_monitoring
    FOR ALL
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

-- Policy: Pairwise Cache (Public read? No. Service access.)
CREATE POLICY pairwise_cache_service_only ON iam.pairwise_subject_cache
    FOR ALL
    USING (true); -- Usually accessed by backend service, not direct user SQL.

-- Policy: User Event Stream (Service/Analytics access)
CREATE POLICY user_event_stream_service_only ON iam.user_event_stream
    FOR ALL
    USING (true);

-- Policy: Magic Link Analytics (Admin/User isolation)
CREATE POLICY magic_analytics_user_isolation ON iam.magic_link_analytics
    FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM iam.magic_links ml
        JOIN iam.users u ON ml.user_id = u.user_id
        WHERE ml.link_id = iam.magic_link_analytics.link_id
        AND u.user_id = current_setting('app.current_user_id', true)::UUID
    ));

-- Policy: ZKP (User can see own proofs)
CREATE POLICY zkp_user_isolation ON iam.zero_knowledge_proofs
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- ================================================================================
-- Triggers for Part 5 Tables
-- ================================================================================

CREATE TRIGGER trg_kg_entities_update BEFORE UPDATE ON iam.kg_entities FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_role_mining_candidates_update BEFORE UPDATE ON iam.role_mining_candidates FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_smart_lockout_history_update BEFORE UPDATE ON iam.smart_lockout_history FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_shadow_it_patterns_update BEFORE UPDATE ON iam.shadow_it_patterns FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_ml_model_features_update BEFORE UPDATE ON iam.ml_model_features FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_dynamic_salt_versions_update BEFORE UPDATE ON iam.dynamic_salt_versions FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();


-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 6
-- Scope: Database Objects DB251 - DB350 (Tables - Extended & Future-Proofing)
-- Note: This section extrapolates beyond the initial 200 table list based on
-- deep IAM patterns, AI/ML Ops, Privacy Engineering, and Future-Proofing.
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB251 - DB350)
-- ================================================================================

-- DB251: iam.ai_model_registry
-- Description: Central registry for ML models used in security.
-- Business Case: As the platform relies heavily on AI for anomaly detection (F061) and risk scoring (F054), managing the lifecycle of these models becomes critical. This table acts as a Model Registry, storing metadata for every model version (e.g., `model_name`, `algorithm`, `training_data_hash`). It ensures that only approved models are deployed into production. It links to the "Governance" aspect of AI, preventing unauthorized "black box" models from making sensitive security decisions.
-- KPIs: Model deployment accuracy, Model registry coverage.
-- Feature Reference: F061 (AI Anomaly Detection)
CREATE TABLE IF NOT EXISTS iam.ai_model_registry (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL,
    algorithm VARCHAR(50) NOT NULL, -- e.g., ISOLATION_FOREST, LSTM
    model_path TEXT, -- Path to artifact in S3/Registry
    training_data_hash VARCHAR(255), -- Integrity check for training data
    is_approved BOOLEAN DEFAULT FALSE,
    approved_by UUID,
    deployed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.ai_model_registry IS 'Registry for ML models managing lifecycle and approval status.';

-- DB252: iam.training_job_logs
-- Description: Logs of ML training runs.
-- Business Case: Training AI models is resource-intensive. This table tracks the execution of training jobs (`job_id`, `status`). It records input parameters, output metrics (Accuracy, F1 Score), and duration. This historical data is vital for debugging model performance degradation ("Model Drift") and justifying compute costs. It allows Data Scientists to trace why a specific model version started behaving differently.
-- KPIs: Training job success rate, Resource utilization.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.training_job_logs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    initiated_by UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    hyperparameters_json JSONB,
    metrics_json JSONB, -- Accuracy, Precision, Recall
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_training_job_model FOREIGN KEY (model_id) REFERENCES iam.ai_model_registry(model_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.training_job_logs IS 'Stores execution logs and metrics for ML model training jobs.';

-- DB253: iam.feature_drift_alerts
-- Description: Alerts generated when input data distribution changes.
-- Business Case: Models fail when input data drifts (e.g., a pandemic changes login patterns). This table stores alerts generated by monitoring the statistical distribution of features (IP, Time, Device). It links to the specific `feature_name` that drifted. Early detection of drift allows the platform to trigger model retraining (DB252) or fallback to rule-based security before accuracy drops too low.
-- KPIs: Drift detection latency, False positive rate.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.feature_drift_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    drift_score NUMERIC(5,2),
    threshold_breach NUMERIC(5,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_feature_drift_model FOREIGN KEY (model_id) REFERENCES iam.ai_model_registry(model_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.feature_drift_alerts IS 'Stores alerts detecting statistical drift in ML input features.';

-- DB254: iam.policy_ab_testing
-- Description: A/B testing configuration for security policies.
-- Business Case: Rolling out a new ABAC policy (DB011) to all users is risky. This table manages A/B testing ("Canary Releases") for policies. It splits traffic (`traffic_percentage`) between `policy_id_a` (current) and `policy_id_b` (new). It tracks the `success_rate` (no unauthorized access) and `user_complaints`. This data-driven approach allows admins to validate that a new policy improves security without impacting user experience negatively.
-- KPIs: Test coverage, Statistical significance.
-- Feature Reference: F018
CREATE TABLE IF NOT EXISTS iam.policy_ab_testing (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_name VARCHAR(255) NOT NULL,
    policy_id_a UUID NOT NULL, -- Control
    policy_id_b UUID NOT NULL, -- Variant
    traffic_percentage INTEGER CHECK (traffic_percentage >= 0 AND traffic_percentage <= 100),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_ab_test_policy_a FOREIGN KEY (policy_id_a) REFERENCES iam.policies(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_ab_test_policy_b FOREIGN KEY (policy_id_b) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_ab_testing IS 'Manages A/B testing configuration for security policy rollouts.';

-- DB255: iam.blockchain_identity_ledger
-- Description: Immutable ledger for identity verification.
-- Business Case: For high-trust, cross-organizational scenarios (e.g., university to employer), we need an immutable proof of identity. This table conceptually represents a blockchain ledger (or its local cache) where identity records are hashed and chained. It stores the `transaction_hash` and `previous_hash`. Even if the internal DB is compromised, the public ledger (referenced here) proves that a credential was valid at a certain point in time. This is the ultimate "Proof of Existence".
-- KPIs: Ledger verification time, Immutable proof integrity.
-- Feature Reference: F094 (ZKP/Crypto)
CREATE TABLE IF NOT EXISTS iam.blockchain_identity_ledger (
    tx_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    previous_tx_hash VARCHAR(255),
    block_height BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bc_ledger_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.blockchain_identity_ledger IS 'Local cache/reference of identity records on an immutable blockchain ledger.';

-- DB256: iam.smart_contract_events
-- Description: Events emitted by identity smart contracts.
-- Business Case: Decentralized identities (DB141) often live on blockchains via Smart Contracts. This table logs events emitted by those contracts (e.g., `RoleGranted`, `PermissionRevoked`). It acts as a bridge between the off-chain PARI database and the on-chain state. By monitoring these events, PARI can trigger internal workflows (like sending an email) in response to an on-chain governance action.
-- KPIs: Event processing latency, Bridge reliability.
-- Feature Reference: F053 (Smart Contract Logic)
CREATE TABLE IF NOT EXISTS iam.smart_contract_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(255) NOT NULL,
    event_name VARCHAR(100) NOT NULL,
    transaction_hash VARCHAR(255) NOT NULL,
    payload_json JSONB,
    processed BOOLEAN DEFAULT FALSE,
    emitted_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.smart_contract_events IS 'Logs events from decentralized identity smart contracts.';

-- DB257: iam.software_bom
-- Description: Software Bill of Materials for IAM components.
-- Business Case: Supply chain attacks target CI/CD pipelines. This table stores the SBOM (Software Bill of Materials) for every deployed IAM microservice. It lists libraries (`library_name`, `version_hash`). If a vulnerability (CVE) is announced (e.g., Log4j), the system queries this table to identify exactly which services are at risk and need immediate patching, significantly reducing the Mean Time to Remediate (MTTR).
-- KPIs: Vulnerability scan speed, Component coverage.
-- Feature Reference: F136 (Logic Bomb/Security)
CREATE TABLE IF NOT EXISTS iam.software_bom (
    sbom_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    library_name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    hash_sha256 CHAR(64),
    license_type VARCHAR(50),
    is_vulnerable BOOLEAN DEFAULT FALSE,
    last_scanned TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.software_bom IS 'Stores Software Bill of Materials (SBOM) for IAM services.';

-- DB258: iam.vendor_scarity
-- Description: Deep scoring for 3rd party vendors.
-- Business Case: Beyond simple risk scores (DB013), this table stores granular "Scarity" ratings for vendors based on continuous monitoring. It factors in `security_posture` (CIM score), `financial_health`, `geopolitical_risk`, and `data_breach_history`. This score influences how tightly the system applies restrictions (e.g., requiring MFA every time vs. once a week) when accessing PARI data via that vendor's connection.
-- KPIs: Score accuracy, Vendor churn prediction.
-- Feature Reference: F109
CREATE TABLE IF NOT EXISTS iam.vendor_scarity (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL, -- Assuming external vendors table or generic ID
    scarity_score NUMERIC(3,2) CHECK (scarity_score >= 0 AND scarity_score <= 10),
    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    factors_json JSONB
);
COMMENT ON TABLE iam.vendor_scarity IS 'Stores detailed scarity/risk scores for third-party vendors.';

-- DB259: iam.helpdesk_tickets
-- Description: Linking auth issues to support tickets.
-- Business Case: Users call the helpdesk when they can't log in. This table links a support `ticket_id` (from external CRM like Zendesk) to IAM `sessions` or `users`. It allows support agents to see *exactly* why a login failed (referencing `failure_reason`) without having full admin access to the IAM logs. This bridges the gap between Operational Support and Security, improving user experience.
-- KPIs: Ticket resolution time, First Contact Resolution (FCR).
-- Feature Reference: F106
CREATE TABLE IF NOT EXISTS iam.helpdesk_tickets (
    ticket_id VARCHAR(100) PRIMARY KEY, -- External ID
    user_id UUID NOT NULL,
    issue_type VARCHAR(50) CHECK (issue_type IN ('LOGIN_FAIL', 'MFA_LOST', 'ACCOUNT_LOCKED', 'ACCESS_DENIED')),
    status VARCHAR(20),
    linked_session_id UUID,
    agent_id UUID, -- The helpdesk agent resolving it
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_helpdesk_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_helpdesk_session FOREIGN KEY (linked_session_id) REFERENCES iam.sessions(session_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.helpdesk_tickets IS 'Links IAM events to external helpdesk support tickets.';

-- DB260: iam.hr_lifecycle_events
-- Description: Detailed HR feed events for JIT access.
-- Business Case: "Joiner-Mover-Leaver" (JML) is the standard IAM workflow. This table stores detailed events from HR systems (e.g., "Promoted to Manager", "Transferred to EU"). It triggers automated workflows in DB001/DB010. For example, a "Leaver" event immediately revokes all roles, while a "Mover" event triggers a review of location-based access (Geo-fencing).
-- KPIs: Provisioning automation rate, Revocation speed.
-- Feature Reference: F101 (Automated Provisioning)
CREATE TABLE IF NOT EXISTS iam.hr_lifecycle_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id VARCHAR(100) NOT NULL, -- External HR ID
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('HIRE', 'TERMINATE', 'PROMOTE', 'TRANSFER', 'SUSPEND')),
    effective_date DATE NOT NULL,
    details_json JSONB, -- New salary, new dept, etc.
    processed BOOLEAN DEFAULT FALSE,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.hr_lifecycle_events IS 'Ingests and processes HR lifecycle events for automated access control.';

-- DB261: iam.billing_metrics
-- Description: IAM resource usage for billing.
-- Business Case: In a SaaS model, IAM resources (AuthN/AuthZ calls, stored logs) cost money. This table aggregates usage metrics (`mfa_checks`, `policy_evals`) per `tenant_id`. It enables the platform to bill tenants accurately based on consumption and to identify "noisy neighbors" impacting shared infrastructure, driving capacity planning.
-- KPIs: Cost per user, Resource margin.
-- Feature Reference: F016 (Access Analytics)
CREATE TABLE IF NOT EXISTS iam.billing_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    quantity BIGINT NOT NULL,
    unit_cost NUMERIC(10,4), -- Cost per unit
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.billing_metrics IS 'Aggregates IAM resource usage for accurate tenant billing.';

-- DB262: iam.sanctions_watchlist
-- Description: Real-time sanctions lists (OFAC, EU, UN).
-- Business Case: Compliance requires blocking individuals/entities on sanctions lists. This table acts as a high-speed cache for sanctions data. It is refreshed daily (or via stream). During login or transaction, the system checks user attributes (name, DOB, country) against this table. A hit triggers an immediate hard block and an internal SAR (Suspicious Activity Report). This is critical for AML/KYC compliance.
-- KPIs: List freshness, Block accuracy.
-- Feature Reference: F102 (Explicit Denies)
CREATE TABLE IF NOT EXISTS iam.sanctions_watchlist (
    watch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    list_name VARCHAR(50) NOT NULL, -- e.g., OFAC_SDN, EU_CONSOLIDATED
    entity_type VARCHAR(20) CHECK (entity_type IN ('INDIVIDUAL', 'ENTITY', 'VESSEL')),
    name VARCHAR(255) NOT NULL,
    alt_names TEXT[], -- Array of known aliases
    dob DATE,
    country CHAR(2),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.sanctions_watchlist IS 'High-performance cache of global sanctions lists for compliance screening.';

-- DB263: iam.cross_border_transfers
-- Description: Logs of data moving across borders.
-- Business Case: GDPR and other laws restrict transferring data out of specific jurisdictions. This table logs every instance where a user in Region A accesses data stored in Region B. It provides a definitive record for regulators to prove (or disprove) compliance with cross-border data transfer laws. It works in tandem with Geo-fencing (DB014).
-- KPIs: Transfer volume, Compliance incident count.
-- Feature Reference: F013 (Geo-Fencing)
CREATE TABLE IF NOT EXISTS iam.cross_border_transfers (
    transfer_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    user_country CHAR(2) NOT NULL,
    data_location_country CHAR(2) NOT NULL,
    data_sensitivity VARCHAR(20),
    transfer_size_bytes BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cross_border_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.cross_border_transfers IS 'Logs data access events that cross geopolitical borders.';

-- DB264: iam.advanced_bot_detection
-- Description: Canvas fingerprinting and behavioral bot detection.
-- Business Case: Bots are getting better at mimicking humans. This table stores results of advanced detection techniques like HTML5 Canvas fingerprinting, WebRTC leak detection, and mouse movement analysis. It captures a `bot_probability` score and `technique_used`. High scores result in immediate blocking or CAPTCHA challenges, staying ahead of automated credential stuffing attacks.
-- KPIs: Bot detection rate, False positive rate.
-- Feature Reference: F127 (CAPTCHA) / F061 (AI)
CREATE TABLE IF NOT EXISTS iam.advanced_bot_detection (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    technique VARCHAR(50) NOT NULL, -- CANVAS, WEBRTC, MOUSE_MOVE
    bot_probability NUMERIC(3,2) CHECK (bot_probability >= 0 AND bot_probability <= 1),
    details_json JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_adv_bot_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.advanced_bot_detection IS 'Stores results of advanced browser fingerprinting for bot detection.';

-- DB265: iam.phishing_simulation
-- Description: Internal phishing campaign results.
-- Business Case: Security teams run phishing simulations to train users. This table tracks which users "clicked" or "entered credentials" on simulated phishing sites linked to their IAM accounts. The results feed into `risk_scores` (DB028) and trigger mandatory security training (DB266). It turns user failures into learning opportunities, strengthening the "human firewall".
-- KPIs: Phishing click rate, Training completion rate.
-- Feature Reference: F125 (Admin Actions)
CREATE TABLE IF NOT EXISTS iam.phishing_simulation (
    campaign_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    template_id UUID NOT NULL,
    action VARCHAR(20) CHECK (action IN ('CLICKED_LINK', 'ENTERED_CREDENTIALS', 'REPORTED')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_phishing_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.phishing_simulation IS 'Tracks user performance in internal phishing simulation campaigns.';

-- DB266: iam.security_training_progress
-- Description: User training status and progress.
-- Business Case: Compliance often requires security awareness training. This table tracks user progress through training modules (`module_id`). It links `completion_percentage` to their ability to perform certain actions (e.g., cannot use Admin Console until training is 100% done). It ensures that the workforce is educated on security policies relevant to their access level.
-- KPIs: Training compliance rate, Knowledge retention.
-- Feature Reference: F055 (SOP/Documents)
CREATE TABLE IF NOT EXISTS iam.security_training_progress (
    progress_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    module_id UUID NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    score INTEGER CHECK (score >= 0 AND score <= 100),

    CONSTRAINT fk_training_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.security_training_progress IS 'Tracks user progress on mandatory security training modules.';

-- DB267: iam.iot_device_attestation
-- Description: Hardware root of trust for IoT.
-- Business Case: IoT devices (sensors, actuators) need identities. This table stores `attestation_certificates` that prove the device's hardware integrity (e.g., TPM chip). It links to a device identity (DB143). Before allowing an IoT device to send data (which might trigger payments), the system validates the attestation certificate against this table.
-- KPIs: Attestation validation speed, Rogue device detection.
-- Feature Reference: F086 (mTLS)
CREATE TABLE IF NOT EXISTS iam.iot_device_attestation (
    attestation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    machine_id UUID NOT NULL, -- Ref iam.machine_identity_management
    certificate_pem TEXT NOT NULL,
    manufacturer VARCHAR(100),
    hardware_version VARCHAR(50),
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_iot_machine FOREIGN KEY (machine_id) REFERENCES iam.machine_identity_management(machine_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.iot_device_attestation IS 'Stores hardware attestation certificates for IoT devices.';

-- DB268: iam.firmware_signatures
-- Description: Signed firmware hashes for IoT.
-- Business Case: IoT devices are vulnerable to firmware hacks. This table stores authorized `firmware_hashes` signed by the platform. When a device connects, it reports its firmware hash. If it doesn't match this table, the device is considered compromised and disconnected. This ensures the integrity of the physical endpoint in the IAM chain of trust.
-- KPIs: Firmware mismatch detection, Update compliance.
-- Feature Reference: F143 (Machine Identity)
CREATE TABLE IF NOT EXISTS iam.firmware_signatures (
    sig_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_model VARCHAR(100) NOT NULL,
    firmware_version VARCHAR(50) NOT NULL,
    hash_sha256 CHAR(64) NOT NULL,
    signing_key_id VARCHAR(50) NOT NULL,
    released_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.firmware_signatures IS 'Stores approved hashes for IoT device firmware.';

-- DB269: iam.edge_gateway_sync
-- Description: Status of IAM sync at edge.
-- Business Case: In edge computing (factories, ships), internet is unreliable. Edge gateways cache IAM policies locally. This table tracks the `last_sync_status` and `policy_version` at each `gateway_id`. It allows central Ops to see if a specific edge gateway is running outdated policies, which is a critical security risk in isolated environments.
-- KPIs: Sync latency, Version drift count.
-- Feature Reference: F032 (Offline Policy Evaluation)
CREATE TABLE IF NOT EXISTS iam.edge_gateway_sync (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gateway_id VARCHAR(100) NOT NULL,
    policy_version INTEGER NOT NULL,
    last_sync_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    sync_status VARCHAR(20) DEFAULT 'SUCCESS'
);
COMMENT ON TABLE iam.edge_gateway_sync IS 'Tracks synchronization status of IAM policies with edge gateways.';

-- DB270: iam.data_catalog_objects
-- Description: Cataloging specific data entities.
-- Business Case: ABAC requires knowing *what* data is. This table acts as a Data Catalog, registering high-value assets (`object_name`, `type`). It links these objects to classification labels (DB037). It provides the inventory required for the Policy Engine to answer "Does User X have permission for Object Y?".
-- KPIs: Catalog coverage, Object classification accuracy.
-- Feature Reference: F133 (Dynamic Data Labeling)
CREATE TABLE IF NOT EXISTS iam.data_catalog_objects (
    object_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    object_name VARCHAR(255) NOT NULL,
    object_type VARCHAR(50) NOT NULL CHECK (object_type IN ('TABLE', 'FILE', 'API', 'QUEUE')),
    owner_id UUID NOT NULL,
    location_uri TEXT,

    CONSTRAINT fk_catalog_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.data_catalog_objects IS 'Catalogs data assets for fine-grained ABAC targeting.';

-- DB271: iam.column_level_classifications
-- Description: Specific sensitivity per column.
-- Business Case: Security often exists at the column level (e.g., SSN vs. Name). This table stores classification (`sensitivity_level`) for specific columns (`table_name`, `column_name`). It feeds into the Dynamic Masking engine (DB015). This granularity allows masking just the SSN while displaying the name, optimizing utility vs. privacy.
-- KPIs: Column coverage, Masking enforcement.
-- Feature Reference: F007 (Column Level Masking)
CREATE TABLE IF NOT EXISTS iam.column_level_classifications (
    classification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    sensitivity VARCHAR(20) CHECK (sensitivity IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'PII')),
    masking_rule VARCHAR(100),

    CONSTRAINT uk_column_class UNIQUE (table_name, column_name)
);
COMMENT ON TABLE iam.column_level_classifications IS 'Stores sensitivity labels for individual database columns.';

-- DB272: iam.privacy_budgets
-- Description: GDPR "Right to be forgotten" budget tracking.
-- Business Case: Anonymization (adding noise) costs data utility. This table implements "Privacy Budgeting". It tracks how many queries have been run on a specific dataset (or user) using Differential Privacy (F083). Once the `budget_remaining` hits zero, the system must refuse further queries or delete the dataset, mathematically guaranteeing that an individual cannot be re-identified.
-- KPIs: Budget consumption rate, Data utility preservation.
-- Feature Reference: F083 (Inference Blocking)
CREATE TABLE IF NOT EXISTS iam.privacy_budgets (
    budget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id UUID NOT NULL, -- Data set or User ID
    epsilon_spent NUMERIC(10,6) DEFAULT 0, -- Epsilon is the privacy parameter
    epsilon_limit NUMERIC(10,6) NOT NULL,
    reset_date DATE
);
COMMENT ON TABLE iam.privacy_budgets IS 'Tracks Differential Privacy budget to prevent re-identification.';

-- DB273: iam.deletion_queue
-- Description: Queue for GDPR deletion requests.
-- Business Case: Deleting data across distributed systems (DB, backups, logs, analytics) is hard. This table manages the workflow for a "Right to be Forgotten" request. It tracks the `status` (PENDING, BACKUP_PURGED, LIVE_DELETED) across different subsystems. It ensures that deletion is thorough and provable, satisfying the strictest GDPR requirements.
-- KPIs: Deletion completion time, Subsystem coverage.
-- Feature Reference: F103 (Data Retention)
CREATE TABLE IF NOT EXISTS iam.deletion_queue (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    requested_by UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    subsystems_json JSONB, -- {"database": "DONE", "s3": "PENDING"}
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_del_queue_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_del_queue_requestor FOREIGN KEY (requested_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.deletion_queue IS 'Manages the workflow of GDPR deletion requests across subsystems.';

-- DB274: iam.data_lineage
-- Description: Traceability of data flow.
-- Business Case: To secure data, we must know where it flows. This table tracks `data_lineage` - how data moves from Source A through Transform B to Destination C. It links `access_logs` (DB009) together. If a leak is found, this lineage allows the system to trace back exactly which access event or user caused the data to reach the unauthorized destination.
-- KPIs: Lineage completeness, Traceback speed.
-- Feature Reference: F118 (Distributed Trace)
CREATE TABLE IF NOT EXISTS iam.data_lineage (
    lineage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trace_id UUID NOT NULL,
    source_table VARCHAR(100),
    operation VARCHAR(20),
    destination_table VARCHAR(100),
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.data_lineage IS 'Tracks the flow of data through the system for traceability.';

-- DB275: iam.dlp_policy_violations
-- Description: Logs of DLP triggers based on IAM tags.
-- Business Case: Data Loss Prevention (DLP) systems use IAM tags (DB040) to decide if data can leave the corporate network. This table logs violations—e.g., "User tried to email a 'RESTRICTED' file to Gmail". It provides context for Security Ops to distinguish between honest mistakes and malicious exfiltration attempts, directly correlating IAM classification with DLP action.
-- KPIs: Violation detection rate, False positive analysis.
-- Feature Reference: F133 (Data Labeling)
CREATE TABLE IF NOT EXISTS iam.dlp_policy_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    resource_id UUID NOT NULL,
    resource_classification VARCHAR(20),
    action_blocked VARCHAR(50), -- EMAIL_UPLOAD, USB_COPY
    dlp_rule_id VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dlp_violation_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.dlp_policy_violations IS 'Logs DLP incidents triggered by IAM data classification.';

-- DB276: iam.quantum_ready_keys
-- Description: Keys ready for post-quantum migration.
-- Business Case: "Harvest Now, Decrypt Later" is a real threat. This table stores `quantum_safe_public_keys`. The corresponding private keys are never used for encryption now, but are stored in escrow. When cryptographically agile algorithms (like Kyber) are standard, the system can switch to these pre-generated keys. This prepares the platform for Y2Q (Year to Quantum).
-- KPIs: Key availability, Crypto-agility score.
-- Feature Reference: F081 (Quantum Resistant)
CREATE TABLE IF NOT EXISTS iam.quantum_ready_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    algorithm VARCHAR(50) NOT NULL, -- e.g., CRYSTALS-KYBER
    public_key_pem TEXT NOT NULL,
    prepared_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.quantum_ready_keys IS 'Stores pre-generated post-quantum safe keys for future migration.';

-- DB277: iam.quantum_migration_plan
-- Description: Roadmap for crypto-agility.
-- Business Case: Migrating to post-quantum cryptography is complex. This table outlines the `migration_plan` for different assets. It identifies `legacy_systems` that cannot support new algorithms and defines workarounds or retirement dates. It provides project management oversight for the security team's transition to quantum-resistant infrastructure.
-- KPIs: Migration adherence, Risk mitigation coverage.
-- Feature Reference: F081
CREATE TABLE IF NOT EXISTS iam.quantum_migration_plan (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL,
    current_algo VARCHAR(50),
    target_algo VARCHAR(50),
    target_date DATE,
    status VARCHAR(20) DEFAULT 'PLANNED'
);
COMMENT ON TABLE iam.quantum_migration_plan IS 'Roadmap for migrating assets to post-quantum cryptography.';

-- DB278: iam.homomorphic_encryption_keys
-- Description: Keys for computing on encrypted data.
-- Business Case: Homomorphic Encryption allows processing data while it's still encrypted. This table manages the keys used for this. It enables third parties (e.g., analytics firms) to compute statistics on PARI data without ever seeing the raw data, solving the tension between data utility and absolute privacy.
-- KPIs: Key rotation, Compute accuracy over encrypted data.
-- Feature Reference: F117 (FLE)
CREATE TABLE IF NOT EXISTS iam.homomorphic_encryption_keys (
    he_key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id UUID NOT NULL,
    scheme VARCHAR(50) NOT NULL, -- e.g., BFV, CKKS
    public_param_json JSONB,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.homomorphic_encryption_keys IS 'Stores keys for Homomorphic Encryption contexts.';

-- DB279: iam.secure_multiparty_computation
-- Description: Inputs for MPC protocols.
-- Business Case: MPC allows multiple parties to compute a function on their inputs without revealing the inputs to each other. This table stores the input shares (`share_blob`) for specific MPC computations (e.g., Risk Score aggregation). It enables privacy-preserving analytics where no single entity holds the complete picture of the user's data.
-- KPIs: Compute latency, Share reconstruction integrity.
-- Feature Reference: F094 (ZKP)
CREATE TABLE IF NOT EXISTS iam.secure_multiparty_computation (
    mpc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    computation_id UUID NOT NULL,
    party_id UUID NOT NULL,
    share_blob BYTEA NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING'
);
COMMENT ON TABLE iam.secure_multiparty_computation IS 'Stores input shares for Secure Multi-Party Computation protocols.';

-- DB280: iam.zero_knowledge_range_proofs
-- Description: Proving data ranges without revealing data.
-- Business Case: To verify someone is an adult without knowing their exact age, or earns >$X without knowing salary, we use Zero Knowledge Range Proofs. This table stores the proof commitments and verification results. It allows for granular ABAC based on numerical ranges without the Policy Engine ever seeing the actual sensitive value.
-- KPIs: Proof generation time, Verification success.
-- Feature Reference: F094
CREATE TABLE IF NOT EXISTS iam.zero_knowledge_range_proofs (
    proof_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    attribute_name VARCHAR(100) NOT NULL, -- e.g., salary, age
    range_min INTEGER,
    range_max INTEGER,
    proof_blob BYTEA NOT NULL,
    verified BOOLEAN DEFAULT FALSE,

    CONSTRAINT fk_zk_range_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.zero_knowledge_range_proofs IS 'Stores range proofs for privacy-preserving attribute verification.';

-- DB281: iam.graphql_analytics
-- Description: Usage analytics for GraphQL API.
-- Business Case: GraphQL APIs are flexible but prone to abuse. This table logs analytics for GQL queries—`query_complexity`, `depth`, and `field_frequency`. It helps identify resource-intensive queries or potential "GraphQL DoS" attacks. It also informs product teams about which fields are unused and can be deprecated.
-- KPIs: Query latency, Resource consumption.
-- Feature Reference: F085 (GraphQL Depth Limiting)
CREATE TABLE IF NOT EXISTS iam.graphql_analytics (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash VARCHAR(255),
    complexity INTEGER,
    depth INTEGER,
    execution_time_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.graphql_analytics IS 'Stores performance and usage metrics for GraphQL queries.';

-- DB282: iam.graphql_complexity_mitigation
-- Description: Rules to limit query depth/complexity.
-- Business Case: Nested GraphQL queries can crash servers. This table stores mitigation rules (e.g., "Max Depth: 10", "Max Cost: 1000"). The GraphQL Engine consults this table at runtime to reject overly complex queries before they execute. This protects the availability of the IAM platform.
-- KPIs: Rejection rate (valid vs. invalid), Server health.
-- Feature Reference: F085
CREATE TABLE IF NOT EXISTS iam.graphql_complexity_mitigation (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_name VARCHAR(50), -- e.g., ANONYMOUS, AUTHENTICATED, ADMIN
    max_depth INTEGER,
    max_complexity INTEGER,
    max_cost INTEGER
);
COMMENT ON TABLE iam.graphql_complexity_mitigation IS 'Stores rules to limit GraphQL query complexity.';

-- DB283: iam.api_gateway_configs
-- Description: Configs for Kong/Apigee gateway.
-- Business Case: IAM policies often need to be enforced at the API Gateway level (before hitting the app). This table stores configuration snippets or references that are pushed to API Gateways (e.g., Kong plugins). It ensures that the Gateway configuration matches the central IAM policy definitions, maintaining consistency across the edge.
-- KPIs: Config sync status, Policy enforcement at edge.
-- Feature Reference: F098 (DoS Resilience)
CREATE TABLE IF NOT EXISTS iam.api_gateway_configs (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gateway_name VARCHAR(100) NOT NULL,
    policy_id UUID NOT NULL,
    config_json JSONB NOT NULL, -- Plugin specific config
    deployed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_api_gateway_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.api_gateway_configs IS 'Stores configurations for external API Gateway enforcement.';

-- DB284: iam.api_deprecation_schedule
-- Description: Scheduling API version removal.
-- Business Case: To clean up technical debt, old API versions must be deprecated. This table schedules the lifecycle of API versions (`version`, `deprecation_date`, `sunshine_date`). It allows the platform to warn users via headers (Alert: Deprecated) that they need to upgrade, ensuring a smooth transition and preventing sudden breakage of integrations.
-- KPIs: Sunset adherence, User migration rate.
-- Feature Reference: F024 (OAuth Scopes)
CREATE TABLE IF NOT EXISTS iam.api_deprecation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('ACTIVE', 'DEPRECATED', 'SUNSET')),
    deprecation_date DATE,
    sunshine_date DATE
);
COMMENT ON TABLE iam.api_deprecation_schedule IS 'Manages the lifecycle and deprecation of API versions.';

-- DB285: iam.partner_identities
-- Description: External partner identity verification.
-- Business Case: B2B flows involve verifying partners. This table stores verified identities of external partners (`partner_org`, `legal_entity_id`). It links to their federation IDs. This ensures that when a partner connects, we verify not just the user, but that they represent a verified legal entity, enforcing non-repudiation at the organizational level.
-- KPIs: Partner verification speed, Entity status monitoring.
-- Feature Reference: F091 (Federation)
CREATE TABLE IF NOT EXISTS iam.partner_identities (
    partner_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_name VARCHAR(255) NOT NULL,
    legal_entity_id VARCHAR(100),
    verification_status VARCHAR(20) DEFAULT 'PENDING',
    verified_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.partner_identities IS 'Stores verified identity details of external B2B partners.';

-- DB286: iam.digital_twin_identity
-- Description: Virtual representation of user identity.
-- Business Case: A "Digital Twin" aggregates all data points about a user into a virtual profile. This table stores the pointer to the Digital Twin model. It allows the ABAC engine to query not just static attributes, but the holistic view of the user (predicted intent, current activity, social graph) for more dynamic authorization.
-- KPIs: Twin synchronization, Prediction accuracy.
-- Feature Reference: F122 (Dependency Graph)
CREATE TABLE IF NOT EXISTS iam.digital_twin_identity (
    twin_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    twin_data_json JSONB, -- The dynamic twin representation
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_twin_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.digital_twin_identity IS 'Stores the virtual representation (Digital Twin) of a user identity.';

-- DB287: iam.metaverse_identity
-- Description: Avatar/3D credentials.
-- Business Case: Accessing metaverse environments requires 3D avatars. This table links a user to their avatar metadata (`asset_id`, `signature`). It ensures that the avatar presenting itself in the virtual world is indeed controlled by the authenticated PARI user, preventing "Avatar Impersonation" attacks.
-- KPIs: Avatar validation speed, Asset integrity.
-- Feature Reference: F149 (Adaptive UI)
CREATE TABLE IF NOT EXISTS iam.metaverse_identity (
    avatar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    virtual_world_id VARCHAR(100),
    avatar_asset_hash CHAR(64) NOT NULL,
    private_key_signature VARCHAR(255),

    CONSTRAINT fk_metaverse_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.metaverse_identity IS 'Links PARI identities to 3D avatars for metaverse access.';

-- DB288: iam.spatial_access_control
-- Description: AR/VR zone access logs.
-- Business Case: In AR/VR, access is location-based in 3D space. This table logs access to specific `spatial_zones` (coordinates, bounds). It enables policies like "Only allowed to enter the 'Server Room' zone if physically inside the building". It extends ABAC into the spatial domain.
-- KPIs: Zone entry accuracy, Spatial query performance.
-- Feature Reference: F014 (Device Trust/Geo)
CREATE TABLE IF NOT EXISTS iam.spatial_access_control (
    spatial_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    zone_id VARCHAR(100) NOT NULL,
    entry_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    exit_time TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_spatial_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.spatial_access_control IS 'Logs access to spatial zones in AR/VR environments.';

-- DB289: iam.attendance_integration
-- Description: Physical presence linking to digital auth.
-- Business Case: "Badge-in, Login-out". This table links physical access badge scans (from building security) to digital sessions. If a user is physically not in the building, but their digital account is active, it might indicate credential theft. This cross-referencing strengthens security for on-premise workers.
-- KPIs: Badge-Login correlation rate, Anomaly detection.
-- Feature Reference: F112 (Synthetic Monitoring)
CREATE TABLE IF NOT EXISTS iam.attendance_integration (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    badge_id VARCHAR(100) NOT NULL,
    door_location VARCHAR(100),
    scan_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attendance_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.attendance_integration IS 'Links physical badge scans to digital identity for verification.';

-- DB290: iam.carpool_entry_logs
-- Description: Carpooling (mobility) identity sharing.
-- Business Case: In corporate carpooling apps, employees share identities to verify ride status. This table logs the "share" of identity for a specific trip. It ensures that the privacy of the user's identity is respected (time-bound sharing) while allowing verification of green credentials (carpool status).
-- KPIs: Share expiration, Privacy adherence.
-- Feature Reference: F111 (Self Service Groups)
CREATE TABLE IF NOT EXISTS iam.carpool_entry_logs (
    trip_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    shared_with_user_id UUID,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_carpool_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.carpool_entry_logs IS 'Logs temporary identity sharing for corporate mobility programs.';

-- DB291: iam.sustainable_access_score
-- Description: Eco-impact of access (e.g. paperless).
-- Business Case: Security should support sustainability. This table tracks the "Green Score" of a user's access patterns—e.g., using digital signatures instead of paper, consolidating trips. It can be used to gamify secure behavior or report on the carbon footprint reduction achieved by the IAM platform.
-- KPIs: Carbon saved, Digital adoption rate.
-- Feature Reference: F116 (Role Catalog)
CREATE TABLE IF NOT EXISTS iam.sustainable_access_score (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    metric VARCHAR(100) NOT NULL, -- PAPER_SAVED, KWH_SAVED
    value NUMERIC(10,2),
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sust_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.sustainable_access_score IS 'Tracks environmental impact metrics related to access methods.';

-- DB292: iam.neurodata_access
-- Description: Brain-Computer Interface (BCI) data access.
-- Business Case: Future interfaces like Neuralink require handling neural data. This table logs access to "NeuroData" which is the ultimate biometric. Access to this data requires the highest level of consent and security (DB207, DB056). This table is the forefront of privacy rights for cognitive liberty.
-- KPIs: Consent verification, Access restriction.
-- Feature Reference: F072 (Biometrics)
CREATE TABLE IF NOT EXISTS iam.neurodata_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    data_chunk_id UUID NOT NULL,
    access_reason TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_neuro_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.neurodata_access IS 'Logs highly restricted access to neural/biometric data.';

-- DB293: iam.genomic_data_access
-- Description: Health data access rights.
-- Business Case: Genetic data is immutable and highly sensitive. This table tracks explicit access grants to genomic data, often used in personalized medicine or insurance. It requires explicit consent trails (DB148) and strict retention policies. The audit trail here is vital for genetic discrimination lawsuits.
-- KPIs: Access audit completeness, Consent linkage.
-- Feature Reference: F140 (PIA)
CREATE TABLE IF NOT EXISTS iam.genomic_data_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL, -- The data subject
    requester_id UUID NOT NULL, -- The doctor/researcher
    genomic_sequence_id UUID,
    purpose TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_genomic_subject FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_genomic_requester FOREIGN KEY (requester_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.genomic_data_access IS 'Tracks access to highly sensitive genomic data.';

-- DB294: iam.ethics_committee_reviews
-- Description: AI ethics reviews of access policies.
-- Business Case: AI can make biased decisions. An Ethics Committee must review high-impact AI policies. This table stores reviews, linking `policy_id` to `committee_feedback`. It ensures that "black box" AI decisions are not implemented without a human-in-the-loop check for fairness and bias.
-- KPIs: Review completion rate, Bias mitigation.
-- Feature Reference: F054 (Risk Scoring)
CREATE TABLE IF NOT EXISTS iam.ethics_committee_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    committee_id VARCHAR(100) NOT NULL,
    decision VARCHAR(20) CHECK (decision IN ('APPROVED', 'REJECTED', 'MODIFICATIONS_REQ')),
    feedback TEXT,
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ethics_policy FOREIGN KEY (policy_id) REFERENCES iam.policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.ethics_committee_reviews IS 'Stores ethics committee reviews for AI-driven policies.';

-- DB295: iam.algorithmic_transparency
-- Description: Explaining AI decisions to users.
-- Business Case: Users have a "Right to Explanation" for automated decisions. This table stores the explanations generated for the user (e.g., "Access denied because your location is new"). It links to the specific `decision_id` (DB009). Providing these explanations builds trust and helps users correct their behavior (e.g., "Go to office to access this").
-- KPIs: Explanation accuracy, User comprehension.
-- Feature Reference: F106 (Error Help Texts)
CREATE TABLE IF NOT EXISTS iam.algorithmic_transparency (
    explanation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    decision_id UUID NOT NULL,
    explanation_text TEXT NOT NULL,
    language VARCHAR(10),

    CONSTRAINT fk_transparency_decision FOREIGN KEY (decision_id) REFERENCES iam.access_logs(log_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.algorithmic_transparency IS 'Stores human-readable explanations for AI decisions.';

-- DB296: iam.fairness_audit_logs
-- Description: Checking for bias in access decisions.
-- Business Case: AI must be fair. This table stores the results of fairness audits. It queries logs (DB009) to detect if a specific demographic group is denied access at a statistically significantly higher rate than others. Detecting and logging these disparities allows the platform to retrain models and ensure equitable treatment.
-- KPIs: Disparity detection, Bias correction rate.
-- Feature Reference: F061 (AI Anomaly)
CREATE TABLE IF NOT EXISTS iam.fairness_audit_logs (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    demographic_group VARCHAR(50),
    denial_rate NUMERIC(5,2),
    benchmark_rate NUMERIC(5,2),
    disparity_score NUMERIC(5,2),
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.fairness_audit_logs IS 'Stores results of fairness audits on AI access decisions.';

-- DB297: iam.redressal_mechanisms
-- Description: User complaints on AI decisions.
-- Business Case: Users must be able to contest AI decisions. This table tracks redressal requests ("I think this is wrong"). It logs the `original_decision`, the `user_appeal`, and the `final_outcome` (overturned or upheld). It provides a structured channel for humans to override AI, feeding back into the training data.
-- KPIs: Appeal response time, Overturn rate.
-- Feature Reference: F106 (User Feedback)
CREATE TABLE IF NOT EXISTS iam.redressal_mechanisms (
    appeal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    original_log_id UUID NOT NULL,
    appeal_reason TEXT,
    reviewer_id UUID,
    outcome VARCHAR(20) CHECK (outcome IN ('UPHELD', 'OVERTURNED')),
    reviewed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_redressal_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_redressal_reviewer FOREIGN KEY (reviewer_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.redressal_mechanisms IS 'Tracks user appeals against automated access decisions.';

-- DB298: iam.collaborative_filtering_bubbles
-- Description: Checking if users are isolated in info.
-- Business Case: Algorithms can isolate users in "filter bubbles". This table attempts to map information access diversity. It analyzes if a user's access patterns are dangerously narrow, potentially preventing them from seeing critical security updates or diverse viewpoints required for their role.
-- KPIs: Diversity score, Bubble detection.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.collaborative_filtering_bubbles (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    diversity_index NUMERIC(5,2),
    bubble_detected BOOLEAN,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_cf_bubble_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.collaborative_filtering_bubbles IS 'Analyzes information diversity to detect filter bubbles.';

-- DB299: iam.information_overload_protection
-- Description: Limiting notification spam.
-- Business Case: Security alerts are important, but too many cause fatigue ("Alert Fatigue"). This table tracks the `notification_frequency` per user. It implements throttling or batching rules (e.g., "Don't notify user X of failed logins more than once per hour"). This ensures that alerts remain actionable and are not ignored.
-- KPIs: Notification read rate, User satisfaction.
-- Feature Reference: F075 (Notification Queue)
CREATE TABLE IF NOT EXISTS iam.information_overload_protection (
    user_id UUID NOT NULL,
    notification_type VARCHAR(50) NOT NULL,
    count INTEGER DEFAULT 0,
    last_sent_at TIMESTAMP WITH TIME ZONE,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,

    PRIMARY KEY (user_id, notification_type, window_start),
    CONSTRAINT kf_info_overload_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.information_overload_protection IS 'Manages notification frequency to prevent alert fatigue.';

-- DB300: iam.dark_web_monitoring
-- Description: Monitoring leaks on dark web.
-- Business Case: Credentials sometimes leak to the dark web. This table stores findings from dark web monitoring services (`source`, `leaked_credential_hash`). When a leak is found, the system triggers a forced password reset (DB121) or account lockout. This proactive measure secures accounts before attackers can widely exploit the leaked data.
-- KPIs: Detection speed, Leak coverage.
-- Feature Reference: F114 (APT Detection)
CREATE TABLE IF NOT EXISTS iam.dark_web_monitoring (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID, -- NULL if not matched yet
    credential_hash VARCHAR(255) NOT NULL,
    source_url TEXT,
    found_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_dark_web_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.dark_web_monitoring IS 'Stores findings from dark web credential monitoring.';

-- DB301: iam.breach_simulation_results
-- Description: Results of pen-test/breach sims.
-- Business Case: To test resilience, the platform runs breach simulations (Red Teaming). This table logs the results—what was accessed, what defenses held, what failed. It provides a "Scorecard" for the security posture, identifying gaps that automated monitoring might miss.
-- KPIs: Breach containment time, Defense effectiveness.
-- Feature Reference: F114 (Incident Response)
CREATE TABLE IF NOT EXISTS iam.breach_simulation_results (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(255) NOT NULL,
    compromised_assets JSONB,
    time_to_detection_min INTEGER,
    time_to_containment_min INTEGER,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.breach_simulation_results IS 'Stores results of breach and penetration simulations.';

-- DB302: iam.insider_threat_scorecards
-- Description: Monthly risk scorecards for employees.
-- Business Case: Insider threats are hard to detect. This table generates a monthly "Scorecard" for users based on DLP events, unusual access hours, and volume downloads. A trend upwards in the scorecard triggers a human review. It provides a quantifiable metric for HR/Legal regarding employee risk.
-- KPIs: Risk trend accuracy, Review trigger rate.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.insider_threat_scorecards (
    scorecard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    month DATE NOT NULL,
    risk_score NUMERIC(5,2),
    triggers TEXT[],
    reviewed BOOLEAN DEFAULT FALSE,

    CONSTRAINT kf_scorecard_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.insider_threat_scorecards IS 'Stores monthly risk scorecards for insider threat detection.';

-- DB303: iam.whistleblower_protection
-- Description: Secure channel identity management.
-- Business Case: Whistleblowers need anonymity. This table manages the "anonymized identity" used for whistleblower hotlines. It links the real `user_id` to a `pseudonymous_id` used for the report, ensuring that the system can facilitate the report without exposing the reporter to the review team initially.
-- KPIs: Anonymity preservation, Link accuracy.
-- Feature Reference: F094 (ZKP)
CREATE TABLE IF NOT EXISTS iam.whistleblower_protection (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    real_user_id UUID,
    pseudonymous_id UUID NOT NULL,
    encryption_key_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_whistle_user FOREIGN KEY (real_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.whistleblower_protection IS 'Manages pseudonymous identities for whistleblower protection.';

-- DB304: iam.journalistic_access
-- Description: Press/Gov access logs.
-- Business Case: Journalists or government auditors sometimes need access to sensitive data for investigation. This table logs this special access. It requires a `court_order_id` or similar authorization reference. It ensures that such high-stakes access is isolated and heavily audited, separate from standard user access.
-- KPIs: Authorization verification, Compliance adherence.
-- Feature Reference: F125 (Admin Actions)
CREATE TABLE IF NOT EXISTS iam.journalistic_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    legal_authorization_ref VARCHAR(255) NOT NULL, -- Court order ID, etc.
    data_accessed_summary TEXT,
    supervised_by UUID, -- Admin monitoring the session
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_journalistic_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.journalistic_access IS 'Logs special access granted for journalistic or legal investigation.';

-- DB305: iam.law_enforcement_requests
-- Description: Subpoena/access logs for LE.
-- Business Case: Law Enforcement (LE) agencies often request data. This table tracks these requests (`subpoena_id`, `requesting_agency`). It logs exactly what data was handed over. This is critical for the platform to maintain a transparent record of its cooperation with authorities, protecting both the users and the company.
-- KPIs: Request processing time, Data handed over accuracy.
-- Feature Reference: F060 (Compliance)
CREATE TABLE IF NOT EXISTS iam.law_enforcement_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    agency_name VARCHAR(255) NOT NULL,
    case_reference VARCHAR(255),
    data_provided JSONB,
    approved_by_legal BOOLEAN DEFAULT FALSE,
    fulfilled_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.law_enforcement_requests IS 'Tracks data access requests from law enforcement agencies.';

-- DB306: iam.data_fiduciary_logs
-- Description: Logs of data transfer between fiduciaries.
-- Business Case: When transferring data between banks or fiduciaries, we need a strict log. This table records the `chain_of_custody` for data packets. It proves that the data was handed from Entity A to Entity B securely and intact, which is a regulatory requirement in high-value financial transfers.
-- KPIs: Transfer integrity, Audit completeness.
-- Feature Reference: F094 (Audit Integrity)
CREATE TABLE IF NOT EXISTS iam.data_fiduciary_logs (
    transfer_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_packet_id UUID NOT NULL,
    from_entity VARCHAR(255) NOT NULL,
    to_entity VARCHAR(255) NOT NULL,
    hash_sha256 CHAR(64) NOT NULL,
    signed_by UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.data_fiduciary_logs IS 'Logs strict chain of custody for high-value data transfers.';

-- DB307: iam.regulation_change_impact
-- Description: Tracking impact of new laws.
-- Business Case: Laws change (e.g., CCPA, PDPA). This table tracks the impact analysis of new regulations on existing IAM policies. It maps `regulation_id` to `affected_policies`. It allows legal teams to instantly see which parts of the IAM system need configuration updates to remain compliant.
-- KPIs: Impact analysis speed, Remediation planning.
-- Feature Reference: F140 (PIA)
CREATE TABLE IF NOT EXISTS iam.regulation_change_impact (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_name VARCHAR(100) NOT NULL,
    effective_date DATE NOT NULL,
    affected_policy_count INTEGER,
    remediation_plan_json JSONB,
    status VARCHAR(20) DEFAULT 'PENDING_REVIEW'
);
COMMENT ON TABLE iam.regulation_change_impact IS 'Tracks impact of new regulations on existing IAM policies.';

-- DB308: iam.standard_bodies_mapping
-- Description: Mapping to ISO/NIST/etc.
-- Business Case: Different industries use different standards (NIST 800-53 vs ISO 27001). This table maps PARI internal controls (`control_id`) to multiple external standard IDs. This allows a single IAM configuration to generate compliance reports for multiple frameworks simultaneously, saving immense audit time.
-- KPIs: Mapping coverage, Report generation speed.
-- Feature Reference: F060 (Compliance)
CREATE TABLE IF NOT EXISTS iam.standard_bodies_mapping (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    internal_control_id VARCHAR(100) NOT NULL,
    standard_name VARCHAR(50) NOT NULL, -- e.g., NIST_800_53, ISO27001
    external_control_id VARCHAR(100) NOT NULL
);
COMMENT ON TABLE iam.standard_bodies_mapping IS 'Maps internal controls to multiple external compliance frameworks.';

-- DB309: iam.audit_committee_assignments
-- Description: Rotating auditors.
-- Business Case: To prevent "you scratch my back, I scratch yours", auditors must be rotated. This table manages the rotation schedule (`auditor_id`, `assigned_department`). It ensures that access reviews (DB018) are conducted by an independent auditor, satisfying SOX requirements for independence.
-- KPIs: Rotation adherence, Conflict detection.
-- Feature Reference: F124 (Access Certification)
CREATE TABLE IF NOT EXISTS iam.audit_committee_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,
    department_code VARCHAR(50) NOT NULL,
    quarter_start DATE NOT NULL,
    quarter_end DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    CONSTRAINT kf_audit_assign_auditor FOREIGN KEY (auditor_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.audit_committee_assignments IS 'Manages rotation of independent auditors for access reviews.';

-- DB310: iam.continuous_control_monitoring
-- Description: CCM metrics.
-- Business Case: GRC (Governance, Risk, Compliance) requires Continuous Control Monitoring (CCM). This table stores the test results for automated controls (e.g., "Is password expiry policy enforced?"). It provides a real-time dashboard of compliance health, replacing point-in-time audits.
-- KPIs: Control pass rate, Remediation time.
-- Feature Reference: F060
CREATE TABLE IF NOT EXISTS iam.continuous_control_monitoring (
    monitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,
    test_result VARCHAR(20) CHECK (test_result IN ('PASS', 'FAIL', 'WARN')),
    details TEXT,
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.continuous_control_monitoring IS 'Stores real-time status of automated security controls.';

-- DB311: iam.threat_hunting_queries
-- Description: Saved hunting queries.
-- Business Case: Threat hunters write SQL/Graph queries to find patterns. This table saves these `queries`. Sharing queries helps the community. It allows analysts to quickly re-run a successful hunt from last week or share it with a colleague, operationalizing threat hunting knowledge.
-- KPIs: Query reuse rate, Hunt success rate.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.threat_hunting_queries (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    query_text TEXT NOT NULL,
    author_id UUID NOT NULL,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_hunt_author FOREIGN KEY (author_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.threat_hunting_queries IS 'Library of saved queries used for threat hunting.';

-- DB312: iam.incident_escalation_matrix
-- Description: Who to call for what incident.
-- Business Case: During an incident, who do you call? This table defines the escalation matrix (`severity` -> `role` -> `contact_method`). It automates the notification process during incident response, ensuring no time is wasted looking up phone numbers for the "Crisis Manager".
-- KPIs: Escalation speed, Contact accuracy.
-- Feature Reference: F114 (Incident Response)
CREATE TABLE IF NOT EXISTS iam.incident_escalation_matrix (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    severity VARCHAR(20) NOT NULL,
    target_role_id UUID NOT NULL,
    contact_method VARCHAR(20) NOT NULL, -- EMAIL, SMS, PAGE
    time_to_escalate_min INTEGER,

    CONSTRAINT kf_escalation_role FOREIGN KEY (target_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.incident_escalation_matrix IS 'Defines escalation paths and contacts for security incidents.';

-- DB313: iam.crisis_communication_logs
-- Description: Comms during crisis.
-- Business Case: Communication failures kill crisis management. This table logs every communication sent during a crisis (`incident_id`, `channel`, `message`). It provides a clear timeline of who was told what and when, which is critical for post-mortem analysis and legal liability.
-- KPIs: Message delivery, Stakeholder coverage.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.crisis_communication_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    target_audience VARCHAR(100),
    channel VARCHAR(50),
    message_summary TEXT,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.crisis_communication_logs IS 'Logs all communications sent during security crises.';

-- DB314: iam.dr_plans
-- Description: Disaster Recovery plan steps.
-- Business Case: If the IAM system goes down, business stops. This table stores the step-by-step DR plan (`step_order`, `action`, `responsible_party`). It acts as a playbook for the Ops team to recover the IAM platform in the correct sequence, minimizing downtime and data loss.
-- KPIs: Plan execution accuracy, Recovery Time Objective (RTO) adherence.
-- Feature Reference: F019 (Break Glass)
CREATE TABLE IF NOT EXISTS iam.dr_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_name VARCHAR(100) NOT NULL, -- e.g., "Data Center Failure"
    step_order INTEGER NOT NULL,
    action TEXT NOT NULL,
    responsible_role_id UUID,
    estimated_duration_min INTEGER,

    CONSTRAINT kf_dr_plan_role FOREIGN KEY (responsible_role_id) REFERENCES iam.roles(role_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.dr_plans IS 'Stores the detailed steps of Disaster Recovery procedures.';

-- DB315: iam.dr_test_results
-- Description: DR test execution results.
-- Business Case: A DR plan is useless unless tested. This table logs the results of scheduled DR drills (`drill_id`). It records `actual_duration` vs `target` and any issues encountered. It proves to stakeholders that the organization is capable of recovering from a disaster.
-- KPIs: Drill success rate, RTO accuracy.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS iam.dr_test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    drill_id UUID NOT NULL,
    scenario_name VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    outcome VARCHAR(20) CHECK (outcome IN ('SUCCESS', 'PARTIAL', 'FAILURE')),
    lessons_learned TEXT
);
COMMENT ON TABLE iam.dr_test_results IS 'Stores execution results of Disaster Recovery drills.';

-- DB316: iam.bc_p_recovery_order
-- Description: Business Continuity Plan recovery order.
-- Business Case: Which apps come back online first? This table defines the priority list for restoring access to applications. It ensures that "Critical Infrastructure" apps get IAM services restored before "Internal Cafeteria Menu" apps, prioritizing business continuity during an outage.
-- KPIs: Recovery priority adherence.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS iam.bc_p_recovery_order (
    order_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    app_name VARCHAR(100) NOT NULL,
    business_criticality VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    recovery_tier INTEGER NOT NULL,
    dependencies TEXT[]
);
COMMENT ON TABLE iam.bc_p_recovery_order IS 'Defines the priority order for restoring application access.';

-- DB317: iam.single_points_of_failure
-- Description: Identifying SPOFs in IAM.
-- Business Case: Redundancy is key. This table identifies Single Points of Failure (SPOFs) in the IAM architecture (e.g., "This one server holds the root CA key"). It tracks `mitigation_status`. The goal is to keep this table empty by constantly engineering out SPOFs.
-- KPIs: SPOF count, Mitigation velocity.
-- Feature Reference: F113 (PKI)
CREATE TABLE IF NOT EXISTS iam.single_points_of_failure (
    spof_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(255) NOT NULL,
    risk_impact TEXT,
    mitigation_plan TEXT,
    resolved BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.single_points_of_failure IS 'Identifies and tracks single points of failure in IAM infrastructure.';

-- DB318: iam.resilience_metrics
-- Description: RTO/RPO tracking.
-- Business Case: Resilience is measured by RTO (Recovery Time Objective) and RPO (Recovery Point Objective). This table tracks actual performance of the IAM system against these targets during incidents. It provides data for executive reporting on system reliability and resilience investments.
-- KPIs: RTO attainment, RPO attainment.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS iam.resilience_metrics (
    incident_id UUID NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    target_rto_min INTEGER,
    actual_rto_min INTEGER,
    target_rpo_min INTEGER,
    data_loss_bytes BIGINT,
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.resilience_metrics IS 'Tracks RTO/RPO compliance for IAM services.';

-- DB319: iam.capacity_planning
-- Description: IAM resource forecasting.
-- Business Case: IAM scales with users. This table uses historical data to forecast future resource needs (`token_volume`, `storage_gb`). It ensures that the infrastructure is provisioned ahead of time (Autoscaling) to handle user growth or peak seasons (like Black Friday) without performance degradation.
-- KPIs: Forecast accuracy, Capacity utilization.
-- Feature Reference: F112 (Synthetic Monitoring)
CREATE TABLE IF NOT EXISTS iam.capacity_planning (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(50) NOT NULL,
    prediction_date DATE NOT NULL,
    predicted_value NUMERIC(15,2),
    actual_value NUMERIC(15,2),
    model_version VARCHAR(50)
);
COMMENT ON TABLE iam.capacity_planning IS 'Stores resource forecasts for IAM infrastructure scaling.';

-- DB320: iam.tenant_onboarding_checklist
-- Description: Checklist for new tenants.
-- Business Case: Onboarding a new tenant involves many steps (DNS setup, Identity Provider config, Policy import). This table tracks the `onboarding_checklist`. It ensures that no step is missed, guaranteeing that the new tenant's environment is secure and compliant from Day 1.
-- KPIs: Onboarding completion time, Missed step count.
-- Feature Reference: F033 (Tenant Config)
CREATE TABLE IF NOT EXISTS iam.tenant_onboarding_checklist (
    checklist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    task_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'IN_PROGRESS', 'DONE', 'BLOCKED')),
    assignee_id UUID,
    due_date DATE,

    CONSTRAINT kf_onboard_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE,
    CONSTRAINT kf_onboard_assignee FOREIGN KEY (assignee_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.tenant_onboarding_checklist IS 'Manages the checklist for new tenant onboarding.';

-- DB321: iam.tenant_offboarding_audit
-- Description: Audit of tenant exit.
-- Business Case: Offboarding (removing a tenant) is the highest security risk. This table audits the `offboarding_process`. It verifies that all data was deleted, backups purged, and access revoked. This legal-grade audit trail is required to ensure that residual data doesn't leak to the next tenant (multi-tenancy).
-- KPIs: Data sanitization verification, Process completeness.
-- Feature Reference: F103 (Data Retention)
CREATE TABLE IF NOT EXISTS iam.tenant_offboarding_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    task_description TEXT NOT NULL,
    verified_by UUID NOT NULL,
    verification_status VARCHAR(20) DEFAULT 'PENDING',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_offboard_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE,
    CONSTRAINT kf_offboard_verifier FOREIGN KEY (verified_by) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.tenant_offboarding_audit IS 'Audits the offboarding process to ensure complete data removal.';

-- DB322: iam.brand_safety_monitoring
-- Description: Monitoring brand misuse of IAM.
-- Business Case: Attackers might create phishing sites using your brand's logos (lookalike attacks). This table logs detected brand misuse incidents. It links to `digital_identity` protection teams. It helps the legal and security teams take down fraudulent sites that misuse the PARI brand identity to steal credentials.
-- KPIs: Takedown time, Detection rate.
-- Feature Reference: F126 (Branding)
CREATE TABLE IF NOT EXISTS iam.brand_safety_monitoring (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reported_url TEXT NOT NULL,
    brand_asset_type VARCHAR(50), -- LOGO, NAME, TRADEMARK
    status VARCHAR(20) DEFAULT 'REPORTED', -- REPORTED, VERIFIED, TAKEN_DOWN
    reported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.brand_safety_monitoring IS 'Tracks detected misuse of brand assets in phishing campaigns.';

-- DB323: iam.social_media_impersonation
-- Description: Detecting fake profiles.
-- Business Case: Impersonators create fake profiles on LinkedIn/Twitter to target employees. This table stores detected fake profiles (`profile_url`, `evidence`). It allows security teams to warn employees about "Spear Phishing" attempts using these identities. It is a proactive defense against social engineering.
-- KPIs: Profile takedown speed, User warning rate.
-- Feature Reference: F126
CREATE TABLE IF NOT EXISTS iam.social_media_impersonation (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    platform VARCHAR(50) NOT NULL,
    target_user_id UUID, -- The person being impersonated
    profile_url TEXT,
    evidence_json JSONB,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    CONSTRAINT kf_smi_target FOREIGN KEY (target_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.social_media_impersonation IS 'Stores detected fake social media profiles used for impersonation.';

-- DB324: iam.deepfake_detection_logs
-- Description: Audio/Video deepfake checks.
-- Business Case: AI can generate fake audio/video of CEOs authorizing transfers. This table stores the results of deepfake detection checks on incoming media files (e.g., voice instructions for a wire transfer). If `is_deepfake` is TRUE, the transaction is blocked. This is a cutting-edge defense against AI-powered fraud.
-- KPIs: Detection accuracy, False positive rate.
-- Feature Reference: F105 (Liveness) / F073 (Biometrics)
CREATE TABLE IF NOT EXISTS iam.deepfake_detection_logs (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_id UUID NOT NULL,
    file_type VARCHAR(20) CHECK (file_type IN ('AUDIO', 'VIDEO', 'IMAGE')),
    is_deepfake BOOLEAN NOT NULL,
    confidence_score NUMERIC(3,2),
    model_version VARCHAR(50),
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.deepfake_detection_logs IS 'Stores results of deepfake analysis on media files.';

-- DB325: iam.voice_spoofing_protection
-- Description: Voice anti-spoofing metadata.
-- Business Case: Voice spoofing (replay attacks, synthesis) is a threat. This table stores metadata for voice authentication challenges designed to detect spoofs (`challenge_type`, `anti_spoof_result`). It ensures that voice biometrics (DB186) remain secure even against high-quality TTS (Text-to-Speech) engines.
-- KPIs: Spoof detection rate, UX friction.
-- Feature Reference: F072
CREATE TABLE IF NOT EXISTS iam.voice_spoofing_protection (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    voice_id UUID NOT NULL,
    anti_spoof_feature VARCHAR(100) NOT NULL, -- LIVENESS, SPECTROGRAM
    result VARCHAR(20) CHECK (result IN ('GENUINE', 'SPOOF', 'INCONCLUSIVE')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_voice_spoof_voice FOREIGN KEY (voice_id) REFERENCES iam.voiceprints(voice_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.voice_spoofing_protection IS 'Stores results of anti-spoofing checks for voice authentication.';

-- DB326: iam.video_authentication
-- Description: Deepfake-resistant video auth.
-- Business Case: Video calls can be deepfaked. This table manages challenges for video authentication (`lip_sync_check`, `blink_check`). It ensures that the person on the video call is real and present, providing a higher assurance level than standard video calls for high-value transactions.
-- KPIs: Check pass rate, Detection resilience.
-- Feature Reference: F105
CREATE TABLE IF NOT EXISTS iam.video_authentication (
    auth_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    lip_sync_pass BOOLEAN,
    facial_liveness_pass BOOLEAN,
    depth_analysis_pass BOOLEAN,
    overall_result VARCHAR(20),

    CONSTRAINT kf_video_auth_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.video_authentication IS 'Stores multi-factor checks for video-based authentication.';

-- DB327: iam.gait_analysis
-- Description: Walking pattern analysis (continuous auth).
-- Business Case: Gait is a strong biometric. This table stores gait feature vectors derived from accelerometers in mobile phones/wearables. It allows for continuous authentication—if the user's gait suddenly changes (e.g., phone passed to someone else), the system can re-authenticate. It is passive and highly secure.
-- KPIs: Verification accuracy, Battery drain analysis.
-- Feature Reference: F073 (Keystroke/Biometric)
CREATE TABLE IF NOT EXISTS iam.gait_analysis (
    gait_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    feature_vector JSONB NOT NULL,
    device_id UUID NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_gait_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT kf_gait_device FOREIGN KEY (device_id) REFERENCES iam.devices(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.gait_analysis IS 'Stores gait biometric data for continuous authentication.';

-- DB328: iam.vein_matching
-- Description: Vein scan biometrics.
-- Business Case: Vein patterns are internal and extremely hard to spoof. This table stores vein scan templates (usually IR images). It provides one of the highest forms of biometric security suitable for access to ultra-secure areas (data centers, physical vaults).
-- KPIs: Match rate, Sensor availability.
-- Feature Reference: F072 (Liveness) / F105
CREATE TABLE IF NOT EXISTS iam.vein_matching (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    hand_or_finger VARCHAR(10) CHECK (hand_or_finger IN ('PALM', 'FINGER')),
    template_enc BYTEA NOT NULL,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_vein_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.vein_matching IS 'Stores vein scan biometric templates for high-security access.';

-- DB329: iam.dna_sequence_storage
-- Description: (Future/Extreme) DNA for access.
-- Business Case: In the far future, DNA might be used for ultimate identity verification. This table is a placeholder for DNA sequence snippets (Short Tandem Repeats - STRs). *Note: This requires extreme privacy and ethical oversight (DB294).*
-- KPIs: Sequence security, Ethical compliance.
-- Feature Reference: F293 (Genomic)
CREATE TABLE IF NOT EXISTS iam.dna_sequence_storage (
    dna_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    str_marker VARCHAR(255), -- Specific genetic marker used for ID only
    encrypted_sequence BYTEA NOT NULL,
    consent_id UUID NOT NULL, -- Link to explicit consent

    CONSTRAINT kf_dna_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.dna_sequence_storage IS '(Experimental) Stores specific genetic markers for identity verification.';

-- DB330: iam.emotion_recognition_auth
-- Description: Emotion-based auth trust.
-- Business Case: Stress or fear might indicate coercion. This table stores emotion recognition results derived from facial analysis during login. If "Fear" is detected, the system might trigger a silent alarm or block access, assuming the user might be forced to login by an attacker.
-- KPIs: Emotion classification accuracy, False alarm rate.
-- Feature Reference: F105 (Liveness)
CREATE TABLE IF NOT EXISTS iam.emotion_recognition_auth (
    emotion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    detected_emotion VARCHAR(50), -- NEUTRAL, FEAR, ANGER, STRESS
    confidence_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_emotion_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.emotion_recognition_auth IS 'Stores emotion analysis results to detect duress or coercion.';

-- DB331: iam.stress_level_adaptation
-- Description: Adapting auth based on stress.
-- Business Case: If a user is stressed (maybe due to a deadline), failing them repeatedly on CAPTCHA adds to the stress. This table tracks inferred `stress_levels` and modifies the challenge difficulty (e.g., make it easier temporarily). This balances security with user empathy during difficult life events.
-- KPIs: Adaptive difficulty accuracy, User sentiment.
-- Feature Reference: F127 (CAPTCHA) / F149 (Adaptive UI)
CREATE TABLE IF NOT EXISTS iam.stress_level_adaptation (
    adaptation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    inferred_stress VARCHAR(20) CHECK (inferred_stress IN ('LOW', 'MEDIUM', 'HIGH')),
    captcha_difficulty_reduction INTEGER DEFAULT 0,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_stress_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.stress_level_adaptation IS 'Stores adaptive auth adjustments based on user stress levels.';

-- DB332: iam.contextual_noise_cancellation
-- Description: Cancelling background noise for voice auth.
-- Business Case: Voice auth fails in noisy subways. This table stores `noise_profiles` for the user's environment. The system uses this profile to perform AI noise cancellation on the audio stream before processing the biometric template (DB186), significantly improving reliability.
-- KPIs: Success rate improvement, Profile learning speed.
-- Feature Reference: F072 (Voice Biometrics)
CREATE TABLE IF NOT EXISTS iam.contextual_noise_cancellation (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    environment_hash VARCHAR(255), -- Hash of background noise
    noise_model_data BYTEA,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_noise_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.contextual_noise_cancellation IS 'Stores noise profiles to enhance voice biometric accuracy.';

-- DB333: iam.multi_modal_fusion
-- Description: Combining Face+Voice+Keystroke.
-- Business Case: Single biometrics have failure points. Multi-modal fusion combines signals (e.g., Face + Voice). This table stores the `fusion_weights` and `fusion_logic`. It ensures that if one signal is weak (bad lighting for Face), the system can rely more heavily on the Voice signal, providing robust authentication.
-- KPIs: Fusion accuracy, Robustness index.
-- Feature Reference: F072 / F073
CREATE TABLE IF NOT EXISTS iam.multi_modal_fusion (
    fusion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    modalities_used TEXT[], -- FACE, VOICE, BEHAVIORAL
    fusion_algorithm VARCHAR(50),
    final_score NUMERIC(5,2),
    decision VARCHAR(10) -- ALLOW, DENY, CHALLENGE

    CONSTRAINT kf_fusion_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.multi_modal_fusion IS 'Stores results of combined multi-modal biometric authentication.';

-- DB334: iam.liveness_feedback_loop
-- Description: User feedback on liveness failure.
-- Business Case: Users get frustrated when liveness checks fail for no reason. This table captures user feedback ("I was blinking!"). It feeds back into the AI model (Retraining) to reduce false negatives, making the system smarter and less annoying.
-- KPIs: Feedback volume, Model improvement rate.
-- Feature Reference: F105 / F061
CREATE TABLE IF NOT EXISTS iam.liveness_feedback_loop (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    user_agreement BOOLEAN, -- User claims they are human
    reason TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_liveness_feedback_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.liveness_feedback_loop IS 'Captures user feedback to improve liveness detection AI.';

-- DB335: iam.privacy_enhancing_technologies
-- Description: Logs of PET usage (Diff privacy).
-- Business Case: Privacy Enhancing Technologies (PETs) like Differential Privacy must be logged. This table records when and where PETs were applied (`obfuscation_level`). It provides an audit trail proving that data was processed in a privacy-preserving manner, a requirement for GDPR compliance.
-- KPIs: PET coverage, Data utility vs. Privacy trade-off.
-- Feature Reference: F083 (Inference Blocking)
CREATE TABLE IF NOT EXISTS iam.privacy_enhancing_technologies (
    pet_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    operation_id UUID NOT NULL,
    pet_type VARCHAR(50) NOT NULL, -- DIFF_PRIVACY, HOMOMORPHIC_ENC
    parameters_json JSONB,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.privacy_enhancing_technologies IS 'Logs the application of Privacy Enhancing Technologies.';

-- DB336: iam.synthetic_data_generation
-- Description: Privacy-safe synthetic data for testing.
-- Business Case: Testing with production PII is illegal/risky. This table references `synthetic_datasets` generated to look like real data but containing no real PII. Developers and Data Scientists use this to test IAM features (DB132) without touching sensitive user data.
-- KPIs: Synthetic data quality, Production data protection.
-- Feature Reference: F132 (Test Case Generator)
CREATE TABLE IF NOT EXISTS iam.synthetic_data_generation (
    dataset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_schema_name VARCHAR(100), -- Real table structure
    generator_model_id VARCHAR(50),
    rows_generated BIGINT,
    privacy_budget_consumed NUMERIC(10,6),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.synthetic_data_generation IS 'Stores metadata for privacy-safe synthetic datasets.';

-- DB337: iam.federated_learning_nodes
-- Description: Nodes in federated ML.
-- Business Case: Centralizing ML data violates privacy. Federated Learning trains models on devices/nodes without moving data. This table registers the `participating_nodes`. It coordinates the training rounds, ensuring that no single node can influence the global model disproportionately.
-- KPIs: Node participation rate, Model convergence speed.
-- Feature Reference: F061 (AI)
CREATE TABLE IF NOT EXISTS iam.federated_learning_nodes (
    node_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    node_type VARCHAR(50) NOT NULL, -- MOBILE, DATA_CENTER
    trust_level NUMERIC(3,2),
    last_contact TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);
COMMENT ON TABLE iam.federated_learning_nodes IS 'Registers nodes participating in federated learning.';

-- DB338: iam.split_learning_shards
-- Description: Data shards for split learning.
-- Business Case: Similar to federated, but splitting data vertically by feature. This table tracks `data_shards`—who holds which subset of features. It ensures that no single entity has the complete feature vector, preserving privacy while allowing collaborative training.
-- KPIs: Shard integrity, Reassembly prevention.
-- Feature Reference: F061
CREATE TABLE IF NOT EXISTS iam.split_learning_shards (
    shard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_set_name VARCHAR(100) NOT NULL,
    holder_id UUID NOT NULL,
    encryption_key_id UUID,

    CONSTRAINT kf_split_holder FOREIGN KEY (holder_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.split_learning_shards IS 'Stores data shards for split learning protocols.';

-- DB339: iam.secure_aggregation
-- Description: Aggregating stats without raw data.
-- Business Case: We need analytics (e.g., "Average login time") without raw logs. This table stores `secure_aggregates`. It uses techniques like Multi-Party Computation (MPC) to allow calculating statistics across data silos where raw data is never exposed.
-- KPIs: Calculation accuracy, Privacy guarantee.
-- Feature Reference: F279 (MPC)
CREATE TABLE IF NOT EXISTS iam.secure_aggregation (
    agg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    contributing_shards TEXT[],
    result_value NUMERIC(15,2),
    computed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.secure_aggregation IS 'Stores results of privacy-preserving aggregate statistics.';

-- DB340: iam.secret_sharing_recovery
-- Description: Logs of secret sharing events.
-- Business Case: Sometimes secrets need to be shared securely between services. This table logs the `secret_sharing` event using a protocol like Shamir's Secret Sharing. It records who received shares, ensuring that the reconstruction of the master secret is traceable and authorized.
-- KPIs: Share distribution count, Reconstruction success.
-- Feature Reference: F210 (Key Escrow)
CREATE TABLE IF NOT EXISTS iam.secret_sharing_recovery (
    share_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    share_index INTEGER NOT NULL, -- e.g., Share 2 of 3
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_secret_share_recipient FOREIGN KEY (recipient_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.secret_sharing_recovery IS 'Logs the distribution of secret shares for recovery.';

-- DB341: iam.custodial_asset_tracking
-- Description: Tracking who holds what key.
-- Business Case: In a "Break Glass" scenario, we need to know who holds the keys to decrypt the system. This table tracks `custodial_assets`. It maps keys to `custodians` and their availability status. It is crucial for ensuring the keys are actually accessible during a disaster.
-- KPIs: Custodian availability, Asset recovery success.
-- Feature Reference: F019 (Break Glass)
CREATE TABLE IF NOT EXISTS iam.custodial_asset_tracking (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    custodian_id UUID NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- MASTER_KEY, HSM_TOKEN
    status VARCHAR(20) CHECK (status IN ('HELD', 'RELEASED', 'LOST')),
    location_description TEXT,

    CONSTRAINT kf_custodian_user FOREIGN KEY (custodian_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.custodial_asset_tracking IS 'Tracks the location and holders of critical security assets.';

-- DB342: iam.key_rotation_schedule
-- Description: Schedule for upcoming rotations.
-- Business Case: Keys must be rotated regularly. This table stores the `key_rotation_schedule`. It alerts administrators of upcoming rotations and automates the process where possible (e.g., for ephemeral keys). It ensures the platform stays ahead of cryptographic attacks and compliance deadlines.
-- KPIs: Rotation compliance, Missed rotations count.
-- Feature Reference: F089 (HSM) / F150 (E2E Keys)
CREATE TABLE IF NOT EXISTS iam.key_rotation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL,
    planned_rotation_date DATE NOT NULL,
    rotation_status VARCHAR(20) DEFAULT 'PENDING',
    completed_rotation_date DATE,

    CONSTRAINT kf_rotation_key FOREIGN KEY (key_id) REFERENCES iam.encryption_keys(key_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.key_rotation_schedule IS 'Schedules and tracks cryptographic key rotations.';

-- DB343: iam.crypto_inventory
-- Description: Inventory of all crypto assets.
-- Business Case: You can't protect what you don't know you have. This table is a centralized inventory of all crypto assets (Keys, Certificates, Secrets) across the platform. It tags assets with `criticality` and `owner`, providing a single pane of glass for crypto governance.
-- KPIs: Inventory completeness, Asset coverage.
-- Feature Reference: F089
CREATE TABLE IF NOT EXISTS iam.crypto_inventory (
    inventory_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_type VARCHAR(50) NOT NULL,
    asset_id UUID NOT NULL, -- Ref to specific table (cert, key)
    criticality VARCHAR(20),
    owner_id UUID,
    location VARCHAR(255), -- HSM, Vault, File

    CONSTRAINT kf_crypto_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.crypto_inventory IS 'Centralized inventory of all cryptographic assets.';

-- DB344: iam.quantum_resistance_audit
-- Description: Checking quantum-safe algorithms.
-- Business Case: Not all algorithms are quantum-safe. This table audits the usage of algorithms, flagging those that are vulnerable (e.g., RSA-2048). It provides a roadmap for migration to `quantum_ready_keys` (DB276).
-- KPIs: Vulnerable asset count, Migration progress.
-- Feature Reference: F081 (Quantum Resistant)
CREATE TABLE IF NOT EXISTS iam.quantum_resistance_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL,
    algorithm_name VARCHAR(50) NOT NULL,
    is_quantum_safe BOOLEAN NOT NULL,
    recommended_replacement VARCHAR(50),
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.quantum_resistance_audit IS 'Audits cryptographic assets for quantum resistance.';

-- DB345: iam.side_channel_analysis
-- Description: Detecting side-channel attacks on auth.
-- Business Case: Side-channel attacks infer secrets from timing, power, or sound. This table stores `telemetry_data` analyzed for anomalies. It is highly specialized, looking for patterns like specific timing delays in password comparisons. This ensures that the implementation of crypto/auth is theoretically sound and practically resistant.
-- KPIs: Anomaly detection rate, Telemetry volume.
-- Feature Reference: F094 (Integrity)
CREATE TABLE IF NOT EXISTS iam.side_channel_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    metric_type VARCHAR(50) NOT NULL, -- TIMING, CACHE, POWER
    anomaly_score NUMERIC(5,2),
    flagged BOOLEAN DEFAULT FALSE,

    CONSTRAINT kf_side_channel_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.side_channel_analysis IS 'Stores telemetry for detecting side-channel attacks.';

-- DB346: iam.fault_injection_results
-- Description: Results of chaos engineering tests.
-- Business Case: Chaos engineering intentionally breaks things to test resilience. This table stores `fault_injection_results` (e.g., "Simulated network packet loss"). It records how the IAM system responded (Did it fail open? Did it fail safe?). This data is invaluable for improving system robustness.
-- KPIs: Resilience score, Fault coverage.
-- Feature Reference: F019
CREATE TABLE IF NOT EXISTS iam.fault_injection_results (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    fault_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20),
    system_response VARCHAR(50), -- DEGRADED, UNAVAILABLE, STABLE
    recovery_time_seconds INTEGER,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.fault_injection_results IS 'Stores results of chaos engineering fault injection tests.';

-- DB347: iam.red_team_exercises
-- Description: Scheduling and results of Red Teaming.
-- Business Case: Red Teams simulate attacks. This table manages the `red_team_exercise`. It logs the `objective`, `rules_of_engagement` (ROE), and `final_score`. It allows the Blue Team (Defenders) to learn from the Red Team's successes, improving the overall security posture.
-- KPIs: Objective completion, Blue Team response time.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.red_team_exercises (
    exercise_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    start_date DATE,
    end_date DATE,
    roe_text TEXT,
    objectives_met JSONB,
    lessons_learned TEXT
);
COMMENT ON TABLE iam.red_team_exercises IS 'Manages Red Team security exercises and results.';

-- DB348: iam.purple_team_collaboration
-- Description: Blue/Red team collaboration logs.
-- Business Case: Purple Teaming is when Blue and Red work together. This table logs the collaboration (`shared_intel`, `joint_debrief`). It fosters a culture of security learning rather than just competition, accelerating the patching of vulnerabilities found during exercises.
-- KPIs: Collaboration depth, Vulnerability fix time.
-- Feature Reference: F347
CREATE TABLE IF NOT EXISTS iam.purple_team_collaboration (
    collab_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    exercise_id UUID NOT NULL,
    topic VARCHAR(255) NOT NULL,
    participants TEXT[],
    outcome TEXT,

    CONSTRAINT kf_purple_exercise FOREIGN KEY (exercise_id) REFERENCES iam.red_team_exercises(exercise_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.purple_team_collaboration IS 'Stores collaboration logs from Purple Team exercises.';

-- DB349: iam.future_proofing_registry
-- Description: Registry for experimental features.
-- Business Case: Innovation requires experimentation. This table is a registry for "experimental" features or "beta" algorithms that are not yet production ready. It flags these features clearly (`experimental_flag`) so that auditors know they are not compliant-grade yet, but are in testing.
-- KPIs: Experiment success rate, Promotion to production.
-- Feature Reference: F119 (Feature Flags)
CREATE TABLE IF NOT EXISTS iam.future_proofing_registry (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    risk_level VARCHAR(20), -- LOW, MEDIUM, HIGH
    target_production_date DATE,
    status VARCHAR(20) DEFAULT 'LAB'
);
COMMENT ON TABLE iam.future_proofing_registry IS 'Registry for experimental security features.';

-- DB350: iam.security_config_history
-- Description: Complete history of security config changes.
-- Business Case: To understand "How did we get here?", we need a complete history of all security config changes (not just policies, but settings). This table logs every change to `iam` config tables. It provides the ultimate audit trail for security governance, allowing for point-in-time restoration of configuration if needed.
-- KPIs: History completeness, Restoration speed.
-- Feature Reference: F104 (Collaborative Locks)
CREATE TABLE IF NOT EXISTS iam.security_config_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id UUID NOT NULL,
    operation VARCHAR(20) CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    old_value JSONB,
    new_value JSONB,
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.security_config_history IS 'Global audit trail for all configuration changes in IAM.';

-- ================================================================================
-- Indexes and Constraints for Part 6 Tables
-- ================================================================================
-- (A representative selection of critical indexes due to volume)
CREATE INDEX IF NOT EXISTS idx_ai_model_name ON iam.ai_model_registry(model_name);
CREATE INDEX IF NOT EXISTS idx_training_job_model ON iam.training_job_logs(model_id);
CREATE INDEX IF NOT EXISTS idx_ab_test_policy ON iam.policy_ab_testing(policy_id_b);
CREATE INDEX IF NOT EXISTS idx_bc_ledger_user ON iam.blockchain_identity_ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_helpdesk_user ON iam.helpdesk_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_hr_event_type ON iam.hr_lifecycle_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sanctions_name ON iam.sanctions_watchlist(name);
CREATE INDEX IF NOT EXISTS idx_column_class_table ON iam.column_level_classifications(table_name);
CREATE INDEX IF NOT EXISTS idx_quantum_ready_algo ON iam.quantum_ready_keys(algorithm);
CREATE INDEX IF NOT EXISTS idx_gql_analytics_hash ON iam.graphql_analytics(query_hash);
CREATE INDEX IF NOT EXISTS idx_ethics_policy ON iam.ethics_committee_reviews(policy_id);
CREATE INDEX IF NOT EXISTS idx_crisis_comm_incident ON iam.crisis_communication_logs(incident_id);
CREATE INDEX IF NOT EXISTS idx_dr_test_scenario ON iam.dr_test_results(scenario_name);
CREATE INDEX IF NOT EXISTS idx_brand_safety_status ON iam.brand_safety_monitoring(status);
CREATE INDEX IF NOT EXISTS idx_deepfake_file ON iam.deepfake_detection_logs(file_id);
CREATE INDEX IF NOT EXISTS idx_multi_modal_user ON iam.multi_modal_fusion(user_id);
CREATE INDEX IF NOT EXISTS idx_secret_share_recipient ON iam.secret_sharing_recovery(recipient_id);
CREATE INDEX IF NOT EXISTS idx_config_history_table ON iam.security_config_history(table_name, changed_at DESC);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 6 Tables
-- ================================================================================
ALTER TABLE iam.helpdesk_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.security_training_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.genomic_data_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.redressal_mechanisms ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.secret_sharing_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.crypto_inventory ENABLE ROW LEVEL SECURITY;

CREATE POLICY helpdesk_tickets_support ON iam.helpdesk_tickets
    FOR ALL
    USING (
        user_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE)
    );

CREATE POLICY training_progress_user_isolation ON iam.security_training_progress
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY genomic_access_subject_restriction ON iam.genomic_data_access
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID); -- Users see their own access logs

CREATE POLICY redressal_user_isolation ON iam.redressal_mechanisms
    FOR ALL
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY secret_share_recipient_isolation ON iam.secret_sharing_recovery
    FOR SELECT
    USING (recipient_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY crypto_inventory_owner_isolation ON iam.crypto_inventory
    FOR ALL
    USING (owner_id = current_setting('app.current_user_id', true)::UUID);

-- ================================================================================
-- Triggers for Part 6 Tables
-- ================================================================================
CREATE TRIGGER trg_ai_model_registry_update BEFORE UPDATE ON iam.ai_model_registry FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_hr_lifecycle_events_update BEFORE UPDATE ON iam.hr_lifecycle_events FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_billing_metrics_update BEFORE UPDATE ON iam.billing_metrics FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_metaverse_identity_update BEFORE UPDATE ON iam.metaverse_identity FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_insider_threat_scorecards_update BEFORE UPDATE ON iam.insider_threat_scorecards FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_dr_plans_update BEFORE UPDATE ON iam.dr_plans FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_crypto_inventory_update BEFORE UPDATE ON iam.crypto_inventory FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_key_rotation_schedule_update BEFORE UPDATE ON iam.key_rotation_schedule FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_future_proofing_registry_update BEFORE UPDATE ON iam.future_proofing_registry FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();


-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 7
-- Scope: Database Objects DB351 - DB450 (Tables)
-- Note: Continuation of exhaustive schema definition covering advanced biometrics,
-- Web3 integration, Legal/Compliance extensions, Fraud detection, and Operational Excellence.
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB351 - DB450)
-- ================================================================================

-- DB351: iam.heartbeat_biometrics
-- Description: Continuous authentication via cardiac signals.
-- Business Case: Wearables can detect heart rate signatures. This table stores `heart_rate_variability` (HRV) and other cardiac telemetry linked to a user. By matching the live HRV to the stored baseline, the system can perform continuous passive authentication (Am I at the keyboard?) without user interaction. This is extremely hard to spoof compared to passwords or even fingerprints.
-- KPIs: Baseline match accuracy, Battery impact of monitoring.
-- Feature Reference: F073 (Keystroke/Biometrics)
CREATE TABLE IF NOT EXISTS iam.heartbeat_biometrics (
    reading_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    device_id UUID NOT NULL, -- The wearable
    hrv_sample JSONB NOT NULL, -- Array of intervals
    baseline_id UUID, -- Reference to baseline profile
    anomaly_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_heartbeat_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_heartbeat_device FOREIGN KEY (device_id) REFERENCES iam.devices(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.heartbeat_biometrics IS 'Stores cardiac telemetry for continuous passive authentication.';

-- DB352: iam.brainwave_auth_data
-- Description: EEG data for intent verification.
-- Business Case: Brain-Computer Interfaces (BCI) like Neuralink or headsets can measure focus and intent. This table stores `eeg_features` extracted from raw signals. It can be used to verify if a user is genuinely authorizing a transaction ("Did they intend to click 'Approve'?"). This is the ultimate defense against "rubber hose" attacks where a user is coerced into authorizing actions.
-- KPIs: Intent classification accuracy, Signal noise reduction.
-- Feature Reference: F072 (Voice/Biometrics)
CREATE TABLE IF NOT EXISTS iam.brainwave_auth_data (
    eeg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    signal_vector JSONB NOT NULL, -- Processed features from raw EEG
    intent_confidence NUMERIC(3,2),
    session_id UUID NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_brainwave_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_brainwave_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.brainwave_auth_data IS 'Stores EEG features for verifying user intent during authorization.';

-- DB353: iam.social_graph_integrity
-- Description: Detecting social engineering via graph analysis.
-- Business Case: Attackers often try to befriend employees to gain trust. This table models the `social_graph` of the organization. When a connection request comes in, the system checks the graph integrity (e.g., "Does this person have mutual friends?" or "Is this profile structure typical of a bot?"). It acts as a graph-based firewall against social engineering.
-- KPIs: Fake profile detection rate, Graph traversal performance.
-- Feature Reference: F126 (Branding/Phishing)
CREATE TABLE IF NOT EXISTS iam.social_graph_integrity (
    graph_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_a_id UUID NOT NULL,
    user_b_id UUID NOT NULL, -- The connection
    relationship_type VARCHAR(50) CHECK (relationship_type IN ('COLLEAGUE', 'FRIEND', 'FAMILY', 'STRANGER')),
    trust_score NUMERIC(3,2),
    verified_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_social_user_a FOREIGN KEY (user_a_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_social_user_b FOREIGN KEY (user_b_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.social_graph_integrity IS 'Models organizational social graph to detect social engineering attempts.';

-- DB354: iam.supply_chain_access
-- Description: Vendor access to source code/CI/CD.
-- Business Case: Vendors need access to CI/CD pipelines. This table stores `access_tickets` specifically for supply chain access. It links to the `software_bom` (DB257) of the vendor. It ensures that when a vendor accesses the build server, the system records exactly which artifacts they could have touched, satisfying software supply chain security standards (SSDF).
-- KPIs: Access justification quality, Artifact traceability.
-- Feature Reference: F257 (SBOM)
CREATE TABLE IF NOT EXISTS iam.supply_chain_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,
    pipeline_id VARCHAR(100) NOT NULL, -- e.g., Jenkins Job ID
    artifacts_allowed TEXT[], -- List of libraries/modules
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_sc_vendor FOREIGN KEY (vendor_id) REFERENCES iam.vendor_scarity(vendor_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.supply_chain_access IS 'Grants vendors restricted access to CI/CD pipelines.';

-- DB355: iam.defi_wallet_connection
-- Description: Web3 wallet connection logs.
-- Business Case: Integrating with DeFi protocols requires Web3 wallet connections (Metamask). This table stores `wallet_addresses` linked to IAM user IDs. It verifies `signature_challenges` to prove ownership of the wallet. This bridges traditional IAM with decentralized identity, allowing users to sign transactions via their Web3 wallet under PARI policy control.
-- KPIs: Wallet connection success, Signature verification speed.
-- Feature Reference: F141 (Decentralized Tokens)
CREATE TABLE IF NOT EXISTS iam.defi_wallet_connection (
    connection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    wallet_address VARCHAR(255) NOT NULL,
    chain_id VARCHAR(50) NOT NULL, -- ETH, SOL, POL
    signature_payload TEXT,
    verified BOOLEAN DEFAULT FALSE,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_defi_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.defi_wallet_connection IS 'Links IAM users to Web3 cryptocurrency wallets.';

-- DB356: iam.smart_contract_interactions
-- Description: Audit logs of on-chain interactions.
-- Business Case: Transactions on blockchains are immutable but anonymous. This table links on-chain `transaction_hashes` to internal IAM users (`authorized_by`). It proves which internal user authorized a specific smart contract call (e.g., "Release Escrow"). It is essential for forensic accountability in blockchain operations.
-- KPIs: Chain reconciliation speed, Attribution accuracy.
-- Feature Reference: F053 (Smart Contracts)
CREATE TABLE IF NOT EXISTS iam.smart_contract_interactions (
    interaction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(255) NOT NULL,
    function_name VARCHAR(100) NOT NULL,
    transaction_hash CHAR(66) NOT NULL, -- 0x...
    authorized_by UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_sc_interaction_user FOREIGN KEY (authorized_by) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.smart_contract_interactions IS 'Audits on-chain smart contract interactions back to IAM users.';

-- DB357: iam.fraud_ring_detection
-- Description: Grouping fraudsters together.
-- Business Case: Fraud is often organized (rings). This table stores `cluster_ids` of users who are linked by shared attributes (IP, Device, Behavior). If one user in a ring is caught, the system flags all others for investigation. This graph-based approach is far more effective than treating fraud as isolated events.
-- KPIs: Cluster detection accuracy, Ring completeness.
-- Feature Reference: F149 (Fraud Alert Linking)
CREATE TABLE IF NOT EXISTS iam.fraud_ring_detection (
    ring_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cluster_vector JSONB NOT NULL, -- Mathematical representation of the ring
    confidence_score NUMERIC(3,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.fraud_ring_detection IS 'Stores detected clusters of users linked to fraud rings.';

-- DB358: iam.interactive_voice_response
-- Description: Vishing (Voice phishing) defense.
-- Business Case: Attackers use deepfakes to mimic executives (Vishing). This table analyzes incoming calls to executives. It compares the `voice_profile` against the known executive profile (DB186). A mismatch or "synthetic" flag triggers a warning to the recipient ("You are not talking to the CEO").
-- KPIs: Vishing detection speed, False rejection rate.
-- Feature Reference: F072 (Voice Biometrics)
CREATE TABLE IF NOT EXISTS iam.interactive_voice_response (
    call_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_user_id UUID NOT NULL,
    caller_voice_profile_id UUID, -- Matched profile from DB186
    risk_score NUMERIC(3,2),
    was_blocked BOOLEAN DEFAULT FALSE,
    call_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_ivr_target FOREIGN KEY (target_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.ivr IS 'Analyzes incoming calls to detect Vishing (voice phishing) attacks.';

-- DB359: iam.deepfake_audio_generation
-- Description: Tracking synthetic audio use.
-- Business Case: The platform itself might use TTS (Text-to-Speech) for accessibility. Attackers use TTS for fraud. This table logs all `synthetic_audio_generation` events (whether authorized or unauthorized). It allows the platform to distinguish between "Legitimate Notification" and "Fraudulent Call" by analyzing the audio fingerprints.
-- KPIs: Legitimate audio vs. Fraudulent audio ratio.
-- Feature Reference: F072 / F324
CREATE TABLE IF NOT EXISTS iam.deepfake_audio_generation (
    audio_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    generation_source VARCHAR(100) NOT NULL, -- INTERNAL_TTS, EXTERNAL_MODEL
    user_id UUID, -- Who requested it?
    audio_hash CHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_deepfake_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.deepfake_audio_generation IS 'Tracks generation of synthetic audio for fraud attribution.';

-- DB360: iam.synthetic_identities
-- Description: Managing honeytokens/honeypots.
-- Business Case: Honeytokens are fake credentials (or accounts) seeded in the network. When an attacker uses them, it triggers an alert. This table stores these `synthetic_identities` and their `seeding_location`. It creates a "tripwire" system that detects attackers early in the kill chain.
-- KPIs: Honeytoken hit rate, Deployment coverage.
-- Feature Reference: F112 (Synthetic Monitoring)
CREATE TABLE IF NOT EXISTS iam.synthetic_identities (
    synthetic_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(50) NOT NULL CHECK (type IN ('AWS_KEY', 'DB_CREDENTIAL', 'FAKE_USER')),
    seeded_in VARCHAR(100) NOT NULL, -- e.g., GitHub Repo, Code Comment
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.synthetic_identities IS 'Manages honeytokens for early breach detection.';

-- DB361: iam.honeypot_events
-- Description: Triggers when honeytokens are used.
-- Business Case: This table logs the `access_attempt` on a synthetic identity (DB360). Every hit is a confirmed security incident. It stores the `attacker_ip` and `attacker_useragent`. This data is pure gold for threat intelligence, allowing the platform to block the attacker immediately across all systems.
-- KPIs: Alert fidelity time, Attacker blocking success.
-- Feature Reference: F360 (Synthetic Identities)
CREATE TABLE IF NOT EXISTS iam.honeypot_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    synthetic_id UUID NOT NULL,
    attacker_ip INET,
    attacker_user_agent TEXT,
    request_payload JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_honeypot_synth FOREIGN KEY (synthetic_id) REFERENCES iam.synthetic_identities(synthetic_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.honeypot_events IS 'Logs alerts triggered by honeytoken usage.';

-- DB362: iam.session_watermarking
-- Description: Watermarking the UI stream.
-- Business Case: Preventing screen recording/sharing of sensitive admin consoles. This table tracks the `watermark_id` injected into the video stream sent to the user's browser. It contains a unique signature for the user and session. If a screenshot appears on the dark web, the watermark identifies the leaker instantly.
-- KPIs: Watermark decodeability, Performance overhead.
-- Feature Reference: F125 (Admin Actions) / F146 (Watermarking)
CREATE TABLE IF NOT EXISTS iam.session_watermarking (
    watermark_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    pattern_type VARCHAR(50) NOT NULL, -- OSCILLATING, TEXT_OVERLAY
    strength_level INTEGER CHECK (strength_level >= 1 AND strength_level <= 10),
    injected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_session_watermark_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_watermarking IS 'Manages UI stream watermarking for leak tracing.';

-- DB363: iam.document_access_watermarking
-- Description: Watermarking PDF/Doc downloads.
-- Business Case: Similar to session watermarking, but for static files. When a user downloads a report, a hidden watermark (e.g., steganography in the margins or font variations) is applied. This table stores the `watermark_signature` used. It protects high-value documents like financial audits or contracts from being leaked without attribution.
-- KPIs: Watermark robustness, Decode accuracy.
-- Feature Reference: F146 (Watermarking)
CREATE TABLE IF NOT EXISTS iam.document_access_watermarking (
    doc_watermark_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    document_id UUID NOT NULL, -- The file downloaded
    user_id UUID NOT NULL,
    watermark_text VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_doc_watermark_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.document_access_watermarking IS 'Tracks hidden watermarks applied to document downloads.';

-- DB364: iam.api_abuse_patterns
-- Description: Detecting scraping/scraping.
-- Business Case: Legitimate API usage differs from scraping. Scrapers often follow sequential IDs or make requests at perfectly regular intervals. This table stores `abuse_signatures` (e.g., "Sequential ID access", "High velocity scraping"). It helps the WAF (Web App Firewall) distinguish between a power user and a bot.
-- KPIs: Abuse detection rate, False positive reduction.
-- Feature Reference: F098 (DoS Resilience)
CREATE TABLE IF NOT EXISTS iam.api_abuse_patterns (
    pattern_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    pattern_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_api_abuse_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.api_abuse_patterns IS 'Logs detected patterns indicative of API scraping.';

-- DB365: iam.compliance_chatbot_history
-- Description: AI answering compliance questions.
-- Business Case: Employees ask questions like "Can I share this data?". This table logs the history of the Compliance Chatbot. It stores the `question`, the `retrieved_policy` (citations), and the `answer`. This conversational data is valuable for identifying gaps in documentation and training.
-- KPIs: Answer accuracy, Question volume trends.
-- Feature Reference: F060 (Compliance)
CREATE TABLE IF NOT EXISTS iam.compliance_chatbot_history (
    interaction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    question TEXT NOT NULL,
    matched_policies TEXT[], -- Citations
    confidence_score NUMERIC(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_chatbot_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.compliance_chatbot_history IS 'Stores AI compliance assistant interactions.';

-- DB366: iam.gdpr_data_subject_requests
-- Description: Managing DSARs.
-- Business Case: GDPR requires handling Data Subject Access Requests (DSARs) efficiently. This table tracks the workflow of a DSAR (Identify -> Locate -> Retrieve -> Deliver). It records the `dsar_type` (Access, Port, Erase) and `status`. It ensures the organization meets the 30-day deadline for response.
-- KPIs: Request response time, DSAR completion rate.
-- Feature Reference: F273 (Deletion Queue)
CREATE TABLE IF NOT EXISTS iam.gdpr_data_subject_requests (
    dsar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    request_type VARCHAR(20) CHECK (request_type IN ('ACCESS', 'PORT', 'ERASE', 'RECTIFY', 'RESTRICT')),
    status VARCHAR(20) DEFAULT 'PENDING',
    due_date DATE NOT NULL,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_dsar_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.gdpr_data_subject_requests IS 'Manages GDPR Data Subject Access Requests lifecycle.';

-- DB367: iam.right_to_be_forgotten_verification
-- Description: Double-checking deletion.
-- Business Case: Erasure is hard. This table stores the `verification_records` proving that data was actually deleted. It links to the DSAR (DB366) and contains cryptographic hashes of the "deleted" state (or a token from the secure delete service). It allows the company to prove "We really deleted it" in court.
-- KPIs: Verification completeness, Audit reliability.
-- Feature Reference: F103 (Data Retention)
CREATE TABLE IF NOT EXISTS iam.right_to_be_forgotten_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dsar_id UUID NOT NULL,
    system_name VARCHAR(100) NOT NULL, -- e.g., S3, Database, Backup
    deletion_token_hash VARCHAR(255),
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_rtbf_dsar FOREIGN KEY (dsar_id) REFERENCES iam.gdpr_data_subject_requests(dsar_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.right_to_be_forgotten_verification IS 'Stores proof of data deletion for Right to be Forgotten requests.';

-- DB368: iam.data_portability_logs
-- Description: Moving data out.
-- Business Case: GDPR Portability requires giving users their data in a machine-readable format. This table logs the generation and transfer of these `portability_packages`. It tracks the `file_format` (JSON, CSV) and `transfer_method` (Email, Secure Link). It provides an audit trail for where the data went.
-- KPIs: Package generation success, Transfer security.
-- Feature Reference: F366 (DSAR)
CREATE TABLE IF NOT EXISTS iam.data_portability_logs (
    export_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dsar_id UUID NOT NULL,
    file_url TEXT NOT NULL,
    file_format VARCHAR(20),
    transfer_method VARCHAR(50),
    downloaded_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_portability_dsar FOREIGN KEY (dsar_id) REFERENCES iam.gdpr_data_subject_requests(dsar_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.data_portability_logs IS 'Logs the export and transfer of data for portability requests.';

-- DB369: iam.algorithmic_transparency_reports
-- Description: Explainable AI reports.
-- Business Case: "Black box" AI is untrustworthy. This table stores generated `transparency_reports` explaining a specific decision (e.g., "Why was access denied?"). It breaks down the `feature_contributions` (Weight: Age, Weight: Location). It satisfies the user's "Right to Explanation".
-- KPIs: Report generation speed, Human readability score.
-- Feature Reference: F295 (Algorithmic Transparency)
CREATE TABLE IF NOT EXISTS iam.algorithmic_transparency_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    decision_id UUID NOT NULL, -- Ref access_logs or decision table
    explanation_summary TEXT,
    feature_importance_json JSONB,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_algo_transparency_decision FOREIGN KEY (decision_id) REFERENCES iam.access_logs(log_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.algorithmic_transparency_reports IS 'Stores detailed explanations for AI-driven decisions.';

-- DB370: iam.model_card_repository
-- Description: Standardized ML model cards.
-- Business Case: MLOps requires "Model Cards" (standardized documentation). This table stores the `model_card` content for every model. It details `training_data`, `limitations`, and `intended_use`. It ensures that models are not misused (e.g., using a fraud model for credit scoring).
-- KPIs: Documentation completeness, Card accuracy.
-- Feature Reference: F251 (AI Registry)
CREATE TABLE IF NOT EXISTS iam.model_card_repository (
    card_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    model_card_json JSONB NOT NULL, -- Structured data following Model Cards standard
    version VARCHAR(20),
    last_validated TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_model_card_model FOREIGN KEY (model_id) REFERENCES iam.ai_model_registry(model_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.model_card_repository IS 'Repository for standardized ML Model Cards.';

-- DB371: iam.data_quality_metrics
-- Description: Data lineage quality.
-- Business Case: AI is only as good as the data. This table tracks `data_quality` metrics (Completeness, Uniqueness, Validity) for datasets used in training or auth decisions. A drop in quality triggers an alert to Data Scientists to fix the pipeline.
-- KPIs: Data Quality Score, Anomaly detection in data.
-- Feature Reference: F252 (Training Logs)
CREATE TABLE IF NOT EXISTS iam.data_quality_metrics (
    quality_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id VARCHAR(100) NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    score NUMERIC(3,2),
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.data_quality_metrics IS 'Tracks quality metrics for training and operational data.';

-- DB372: iam.privacy_by_design_audit
-- Description: Checking compliance at design time.
-- Business Case: Fixing privacy after code is written is expensive. This table audits `design_documents` or `schema_changes` against privacy principles (Data Minimization, Purpose Limitation). It stores `audit_results` (Pass/Fail) before code is even written, ensuring "Privacy by Design".
-- KPIs: Design-stage defect reduction, Audit speed.
-- Feature Reference: F140 (PIA)
CREATE TABLE IF NOT EXISTS iam.privacy_by_design_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_id UUID NOT NULL,
    artifact_type VARCHAR(50), -- DB_SCHEMA, API_CONTRACT
    pbd_principle VARCHAR(100),
    status VARCHAR(20),
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.privacy_by_design_audit IS 'Audits design artifacts for Privacy by Design principles.';

-- DB373: iam.ethical_ai_constraints
-- Description: Hard constraints on AI behavior.
-- Business Case: AI must not discriminate. This table stores `ethical_constraints` (e.g., "Do not use Gender in risk scoring"). The AI Engine is hard-coded or configured to query this table and strip or flag restricted features during inference. It provides a governance layer over the raw AI model.
-- KPIs: Constraint adherence rate, Bias mitigation.
-- Feature Reference: F294 (Ethics Committee)
CREATE TABLE IF NOT EXISTS iam.ethical_ai_constraints (
    constraint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    constraint_name VARCHAR(255) NOT NULL,
    restricted_features TEXT[], -- List of attribute names
    model_scope VARCHAR(100), -- Which models this applies to
    active_from DATE,
    active_until DATE
);
COMMENT ON TABLE iam.ethical_ai_constraints IS 'Stores ethical hard-constraints for AI behavior.';

-- DB374: iam.user_sentiment_analysis
-- Description: Sentiment from support tickets/feedback.
-- Business Case: Understanding user sentiment about security. This table stores the results of NLP sentiment analysis performed on user feedback (tickets, surveys). A negative trend indicates a policy or UX problem (e.g., "MFA is too hard").
-- KPIs: Sentiment trend, Correlation with churn.
-- Feature Reference: F106 (User Feedback)
CREATE TABLE IF NOT EXISTS iam.user_sentiment_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_id UUID NOT NULL, -- Ticket ID or Survey ID
    sentiment_score NUMERIC(3,2), -- -1 (Negative) to 1 (Positive)
    key_phrases TEXT[],
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.user_sentiment_analysis IS 'Stores sentiment analysis of user feedback.';

-- DB375: iam.security_sentiment_index
-- Description: Gauging org culture.
-- Business Case: "People are the strongest firewall." This table aggregates sentiment into an Organization Index. It scores how employees feel about security (e.g., "Do they feel safe?" or "Is security seen as a blocker?"). This metric helps CISOs adjust culture programs.
-- KPIs: Security Culture Score, Participation rate.
-- Feature Reference: F286 (Security Training)
CREATE TABLE IF NOT EXISTS iam.security_sentiment_index (
    index_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    date DATE NOT NULL,
    department_code VARCHAR(50),
    score NUMERIC(3,2),
    sample_size INTEGER
);
COMMENT ON TABLE iam.security_sentiment_index IS 'Tracks organizational security culture sentiment over time.';

-- DB376: iam.phishing_campaign_metrics
-- Description: Analytics for user training.
-- Business Case: Running phishing simulations is useless without analytics. This table aggregates metrics: click rates, report rates, and susceptibility per department. It drives the curriculum (e.g., "Finance needs more training on CEO fraud").
-- KPIs: Click rate reduction, Report rate increase.
-- Feature Reference: F265 (Phishing Simulation)
CREATE TABLE IF NOT EXISTS iam.phishing_campaign_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_id UUID NOT NULL,
    department_code VARCHAR(50),
    click_rate NUMERIC(3,2),
    report_rate NUMERIC(3,2),
    susceptible_user_count INTEGER
);
COMMENT ON TABLE iam.phishing_campaign_metrics IS 'Aggregates metrics from phishing simulation campaigns.';

-- DB377: iam.security_awareness_scores
-- Description: KPIs for training programs.
-- Business Case: Tracking the "Security IQ" of the workforce. This table stores individual `awareness_scores` derived from training completion, phishing sim performance, and quiz results. It allows managers to identify security champions and those who need remediation.
-- KPIs: Average organization score, Improvement over time.
-- Feature Reference: F266 (Training Progress)
CREATE TABLE IF NOT EXISTS iam.security_awareness_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    quarter_date DATE NOT NULL,
    overall_score INTEGER CHECK (overall_score >= 0 AND overall_score <= 100),
    breakdown_json JSONB, -- {training: 10, phishing: 5}

    CONSTRAINT kf_awareness_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.security_awareness_scores IS 'Tracks security awareness scores for employees.';

-- DB378: iam.vulnerability_scanner_results
-- Description: SAST/DAST results.
-- Business Case: Security starts in code. This table stores results from Static (SAST) and Dynamic (DAST) Application Security Testing tools. It links `vulnerability_id` to the specific `git_commit_hash` or `deployment_id`. It ensures that known vulnerabilities are not deployed to production.
-- KPIs: Vulnerability fix time, Vulnerability density.
-- Feature Reference: F257 (SBOM)
CREATE TABLE IF NOT EXISTS iam.vulnerability_scanner_results (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cwe_id VARCHAR(20), -- Common Weakness Enumeration
    affected_component VARCHAR(255),
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, FIXED, IGNORED
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.vulnerability_scanner_results IS 'Stores findings from SAST/DAST scanners.';

-- DB379: iam.container_image_signatures
-- Description: DevSecOps.
-- Business Case: Container images must be signed. This table stores the `cosign_signature` (Sigstore) for every image deployed to the platform. The runtime verifies the signature against this table before executing the container. It prevents the supply chain attack of running a modified image.
-- KPIs: Image verification speed, Signature validity.
-- Feature Reference: F169 (x509 Certs)
CREATE TABLE IF NOT EXISTS iam.container_image_signatures (
    image_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    image_sha256 CHAR(64) NOT NULL,
    signature_payload TEXT NOT NULL,
    signed_by VARCHAR(255), -- Identity who signed
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.container_image_signatures IS 'Stores verified signatures for container images.';

-- DB380: iam.kubernetes_pod_access
-- Description: K8s IAM.
-- Business Case: Controlling access to Kubernetes pods. This table maps `users` or `service_accounts` to allowed K8s `namespaces`, `pods`, and `verbs` (get, list, create). It acts as the policy layer for the Kubernetes API Server integration with IAM.
-- KPIs: Access latency, Policy granularity.
-- Feature Reference: F031 (Zero Trust)
CREATE TABLE IF NOT EXISTS iam.kubernetes_pod_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subject_id UUID NOT NULL, -- User or Service Account
    namespace VARCHAR(100) NOT NULL,
    pod_name VARCHAR(100),
    verb VARCHAR(20) NOT NULL, -- get, list, create, delete
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.kubernetes_pod_access IS 'Defines RBAC policies for Kubernetes pods.';

-- DB381: iam.serverless_function_roles
-- Description: AWS Lambda/Azure Functions.
-- Business Case: Serverless functions need execution roles. This table maps `functions` (ARN or Name) to IAM execution roles. It includes `resource_constraints` (e.g., "Can only access S3 bucket X"). It enforces least privilege for ephemeral compute.
-- KPIs: Role binding speed, Constraint accuracy.
-- Feature Reference: F031 (Zero Trust)
CREATE TABLE IF NOT EXISTS iam.serverless_function_roles (
    binding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    function_identifier VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL,
    resource_constraints JSONB,
    environment VARCHAR(50) NOT NULL, -- PROD, STAGE, DEV

    CONSTRAINT kf_serverless_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.serverless_function_roles IS 'Maps IAM roles to serverless function executions.';

-- DB382: iam.service_mesh_policies
-- Description: Istio/Linkerd.
-- Business Case: Service Mesh (mTLS) controls traffic. This table stores authorization policies (`allow`, `deny`) between services in the mesh. It defines the topology (Service A -> Service B) and the conditions. It extends IAM into the infrastructure layer for East-West traffic.
-- KPIs: Policy distribution speed, Mesh security score.
-- Feature Reference: F031 (Zero Trust)
CREATE TABLE IF NOT EXISTS iam.service_mesh_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_service VARCHAR(100) NOT NULL,
    destination_service VARCHAR(100) NOT NULL,
    action VARCHAR(20) NOT NULL, -- ALLOW, DENY
    rules_json JSONB,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.service_mesh_policies IS 'Stores access policies for the Service Mesh.';

-- DB383: iam.api_gateway_rate_limit_sharding
-- Description: Distributed rate limiting.
-- Business Case: Global rate limits are easy to spoof. This table implements "sharded" rate limits, where a user's limit is distributed across multiple data centers or nodes. It tracks the `shard_key` and `counter`. This prevents sophisticated attacks where an attacker rotates through different edge nodes to bypass local limits.
-- KPIs: Sharding accuracy, Global enforcement effectiveness.
-- Feature Reference: F199 (Rate Limit Rules)
CREATE TABLE IF NOT EXISTS iam.api_gateway_rate_limit_sharding (
    shard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    count INTEGER DEFAULT 0,
    shard_key VARCHAR(100) NOT NULL
);
COMMENT ON TABLE iam.api_gateway_rate_limit_sharding IS 'Distributed counters for sharded rate limiting.';

-- DB384: iam.distributed_tracing_context
-- Description: Trace ID propagation.
-- Business Case: Debugging in microservices requires context. This table stores the `trace_context` (Trace ID, Span ID) for IAM calls. It links the incoming request to the downstream service calls, allowing engineers to visualize the full request tree for a single login attempt.
-- KPIs: Trace completeness, Context retention.
-- Feature Reference: F118 (Distributed Trace)
CREATE TABLE IF NOT EXISTS iam.distributed_tracing_context (
    trace_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_span_id UUID,
    service_name VARCHAR(100) NOT NULL,
    operation_name VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.distributed_tracing_context IS 'Stores distributed tracing spans for IAM operations.';

-- DB385: iam.chaos_engineering_events
-- Description: Monkey testing.
-- Business Case: To test resilience, we randomly kill pods or drop packets. This table logs `chaos_events`. It links the experiment ID to the `victim_service` and the `injection_type`. It correlates chaos events with IAM failovers to see if IAM is resilient.
-- KPIs: Recovery success rate, Failure blast radius.
-- Feature Reference: F346 (Fault Injection)
CREATE TABLE IF NOT EXISTS iam.chaos_engineering_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id UUID NOT NULL,
    victim_service VARCHAR(100) NOT NULL,
    injection_type VARCHAR(50) NOT NULL, -- POD_KILL, LATENCY, PACKET_LOSS
    outcome VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.chaos_engineering_events IS 'Logs chaos engineering experiments.';

-- DB386: iam.canary_deployment_metrics
-- Description: Feature rollout safety.
-- Business Case: Rolling out a new IAM version is risky. This table monitors `canary_metrics` (Error rates, Latency) for the canary group (1% of users) vs control group. If the canary group degrades, the system auto-rolls back. It ensures safety during deployment.
-- KPIs: Canary diff detection, Rollback success.
-- Feature Reference: F119 (Feature Flags)
CREATE TABLE IF NOT EXISTS iam.canary_deployment_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    is_canary BOOLEAN NOT NULL,
    error_rate NUMERIC(5,2),
    latency_p95_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.canary_deployment_metrics IS 'Compares metrics between canary and control groups.';

-- DB387: iam.blue_green_deployment_status
-- Description: Deployment state.
-- Business Case: Blue/Green deployments switch traffic instantly. This table tracks the `active_environment` (Blue or Green) and the `switch_status`. It prevents "split-brain" where traffic goes to both simultaneously, which would cause data consistency issues in auth decisions.
-- KPIs: Switch latency, Environment isolation.
-- Feature Reference: F346
CREATE TABLE IF NOT EXISTS iam.blue_green_deployment_status (
    status_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    environment VARCHAR(20) NOT NULL, -- BLUE, GREEN
    current_version VARCHAR(50) NOT NULL,
    is_live BOOLEAN DEFAULT FALSE,
    switched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.blue_green_deployment_status IS 'Tracks the state of Blue/Green deployments.';

-- DB388: iam.rollback_playbooks
-- Description: Automated rollback logic.
-- Business Case: If canary metrics fail, rollback must be instant. This table defines the `rollback_playbooks` (steps to revert). It is linked to the deployment ID. Automation executes this table's content if the decision to abort is made.
-- KPIs: Rollback execution time, Data loss prevention.
-- Feature Reference: F388
CREATE TABLE IF NOT EXISTS iam.rollback_playbooks (
    playbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    steps_json JSONB NOT NULL, -- List of CLI/API commands to revert
    tested_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.rollback_playbooks IS 'Defines automated rollback procedures.';

-- DB389: iam.feature_flag_dependency_graph
-- Description: Dependencies between flags.
-- Business Case: You can't enable "New MFA" if "Auth Service v2" is off. This table stores the `dependency_graph`. The deployment engine checks this table to ensure flags are enabled in the correct topological order, preventing runtime crashes.
-- KPIs: Dependency resolution accuracy.
-- Feature Reference: F119
CREATE TABLE IF NOT EXISTS iam.feature_flag_dependency_graph (
    dependency_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_flag VARCHAR(100) NOT NULL,
    child_flag VARCHAR(100) NOT NULL,
    constraint_type VARCHAR(20) DEFAULT 'REQUIRES' -- REQUIRES, EXCLUDES
);
COMMENT ON TABLE iam.feature_flag_dependency_graph IS 'Stores dependencies between feature flags.';

-- DB390: iam.experiment_variants
-- Description: A/B testing variants.
-- Business Case: Feature flags might have multiple variants (Variant A: UI Blue, Variant B: UI Red). This table defines the `variant_config`. It maps users to variants. It allows for granular A/B testing not just of "on/off" but of specific implementations.
-- KPIs: Variant engagement, Conversion rate.
-- Feature Reference: F254 (Policy A/B Testing)
CREATE TABLE IF NOT EXISTS iam.experiment_variants (
    variant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_name VARCHAR(100) NOT NULL,
    variant_name VARCHAR(50) NOT NULL,
    config_payload JSONB NOT NULL,
    traffic_percentage INTEGER DEFAULT 0
);
COMMENT ON TABLE iam.experiment_variants IS 'Defines variants for A/B testing experiments.';

-- DB391: iam.cohort_analysis_users
-- Description: Grouping users for behavior analysis.
-- Business Case: Comparing a user to "average" is misleading. This table assigns users to `cohorts` (e.g., "Mobile Heavy Users", "Desktop Admins"). Analytics are run per cohort, identifying behaviors specific to that group (e.g., Mobile users are more susceptible to SMS phishing).
-- KPIs: Cohort stability, Risk differentiation.
-- Feature Reference: F122 (Dependency Graph)
CREATE TABLE IF NOT EXISTS iam.cohort_analysis_users (
    cohort_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    cohort_name VARCHAR(100) NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_cohort_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.cohort_analysis_users IS 'Assigns users to behavioral cohorts for analysis.';

-- DB392: iam.user_lifetime_value
-- Description: Security ROI.
-- Business Case: Security costs money. This table calculates the `lifetime_value` of a user account (Revenue - Security Costs). It helps justify security investments for high-value users (e.g., "VIPs get hardware keys").
-- KPIs: Security ROI per user, High-Value user count.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.user_lifetime_value (
    ltv_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    total_revenue NUMERIC(15,2),
    security_cost NUMERIC(15,2),
    ltv_score NUMERIC(15,2),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_ltv_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_lifetime_value IS 'Calculates the Lifetime Value (LTV) considering security costs.';

-- DB393: iam.churn_prediction
-- Description: Predicting leaving users (risk).
-- Business Case: A user leaving is a risk (insider threat). This table stores `churn_probability` scores derived from activity patterns (decreased login, unusual data export). High risk users trigger offboarding workflows (DB321) or monitoring.
-- KPIs: Prediction accuracy, Churn reduction.
-- Feature Reference: F302 (Insider Threat)
CREATE TABLE IF NOT EXISTS iam.churn_prediction (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    probability NUMERIC(3,2),
    risk_factors TEXT[],
    predicted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_churn_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.churn_prediction IS 'Stores predictions of user churn (leaving the organization).';

-- DB394: iam.autoscaling_decisions
-- Description: Cloud resource scaling based on IAM load.
-- Business Case: IAM is a bottleneck. If load spikes, we must scale out. This table logs `autoscaling_events` (Scale Up/Down) driven by metrics (CPU, Auth Queue Depth). It links the event to the `cluster_size` change. It ensures IAM performance meets SLA.
-- KPIs: Scaling lag, Cost optimization.
-- Feature Reference: F349 (Capacity Planning)
CREATE TABLE IF NOT EXISTS iam.autoscaling_decisions (
    scale_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    direction VARCHAR(20) NOT NULL, -- UP, DOWN
    reason_metric VARCHAR(100), -- CPU, MEMORY, QUEUE_DEPTH
    previous_size INTEGER,
    new_size INTEGER,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.autoscaling_decisions IS 'Logs autoscaling events for IAM infrastructure.';

-- DB395: iam.cost_attribution_model
-- Description: Who pays for IAM?
-- Business Case: In a SaaS platform, tenants should pay for their usage. This table implements the `cost_attribution` model. It calculates costs based on `user_count`, `auth_requests`, and `storage_volume` per tenant. It drives the billing engine.
-- KPIs: Billing accuracy, Cost transparency.
-- Feature Reference: F261 (Billing Metrics)
CREATE TABLE IF NOT EXISTS iam.cost_attribution_model (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    auth_request_count BIGINT,
    compute_cost NUMERIC(10,2),
    storage_cost NUMERIC(10,2),
    total_cost NUMERIC(10,2),

    CONSTRAINT kf_cost_attr_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.cost_attribution_model IS 'Calculates IAM operational costs per tenant.';

-- DB396: iam.resource_quotas
-- Description: Tenant resource limits.
-- Business Case: Noisy neighbors affect everyone. This table enforces `resource_quotas` (Max Users, Max API Calls/sec) per tenant. It prevents one tenant from degrading the platform for others.
-- KPIs: Quota enforcement success, Resource utilization.
-- Feature Reference: F33 (Tenant Configs)
CREATE TABLE IF NOT EXISTS iam.resource_quotas (
    quota_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- USERS, AUTH_PER_SEC, STORAGE_GB
    limit_value BIGINT NOT NULL,
    is_hard_limit BOOLEAN DEFAULT FALSE,

    CONSTRAINT kf_quotas_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.resource_quotas IS 'Enforces resource usage limits per tenant.';

-- DB397: iam.billing_dispute_evidence
-- Description: Logs for billing disputes.
-- Business Case: Tenants might dispute bills. This table stores the `evidence` (raw logs, usage summaries) supporting a specific `invoice_id`. It allows the finance team to reconstruct the bill line-by-line to prove the charge.
-- KPIs: Dispute resolution time, Evidence completeness.
-- Feature Reference: F261 (Billing)
CREATE TABLE IF NOT EXISTS iam.billing_dispute_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    invoice_id UUID NOT NULL,
    evidence_type VARCHAR(50),
    reference_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.billing_dispute_evidence IS 'Stores evidence to support billing disputes.';

-- DB398: iam.financial_transaction_controls
-- Description: Reg G limits on transactions.
-- Business Case: IAM controls access to financial data. This table stores specific `transaction_controls` (e.g., "4-eye approval for >$1M"). It links IAM roles to these financial limits. It enforces segregation of duties (Maker/Checker) via IAM.
-- KPIs: Control enforcement rate, Approval workflow speed.
-- Feature Reference: F314 (Fiduciary Logs)
CREATE TABLE IF NOT EXISTS iam.financial_transaction_controls (
    control_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID NOT NULL,
    currency CHAR(3),
    limit_amount NUMERIC(15,2),
    approver_count INTEGER CHECK (approver_count >= 1), -- 0 = Self-approve
    requires_mfa BOOLEAN DEFAULT TRUE,

    CONSTRAINT kf_financial_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.financial_transaction_controls IS 'Enforces financial limits and approvals based on IAM role.';

-- DB399: iam.aml_screening_results
-- Description: Anti-Money Laundering.
-- Business Case: Before allowing a payout, IAM checks AML lists. This table stores the `screening_results`. It links the transaction to the `watchlist_hit`. If a hit is found, the transaction is blocked, even if the user is otherwise authenticated.
-- KPIs: Screening speed, Block accuracy.
-- Feature Reference: F262 (Sanctions Watchlist)
CREATE TABLE IF NOT EXISTS iam.aml_screening_results (
    screening_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    watchlist_hit BOOLEAN,
    matched_entity VARCHAR(255),
    screened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_aml_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.aml_screening_results IS 'Stores results of Anti-Money Laundering checks.';

-- DB400: iam.sanctions_list_updates
-- Description: History of OFAC updates.
-- Business Case: Sanctions lists change daily. This table logs the `delta` of updates (Added, Removed entries). It helps in auditing why a user was suddenly blocked yesterday ("They were added to OFAC").
-- KPIs: List update latency, Historical accuracy.
-- Feature Reference: F262
CREATE TABLE IF NOT EXISTS iam.sanctions_list_updates (
    update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    list_name VARCHAR(50) NOT NULL,
    update_type VARCHAR(20) NOT NULL, -- ADD, REMOVE
    entity_name VARCHAR(255),
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.sanctions_list_updates IS 'Tracks history of changes to sanctions lists.';

-- DB401: iam.travel_rule_compliance
-- Description: Business travel policy checks.
-- Business Case: Employees traveling to high-risk countries might have restricted access. This table logs `travel_rule_compliance`. It checks the itinerary against the risk map and adjusts IAM policies (e.g., requires physical token).
-- KPIs: Rule match accuracy, Policy adjustment speed.
-- Feature Reference: F269 (Trip)
CREATE TABLE IF NOT EXISTS iam.travel_rule_compliance (
    trip_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    destination_country CHAR(2),
    risk_level VARCHAR(20),
    policy_adjustment TEXT, -- "MFA Required"
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_travel_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.travel_rule_compliance IS 'Checks IAM policies against business travel itineraries.';

-- DB402: iam.expense_report_audits
-- Description: Auditing employee expenses.
-- Business Case: Expense reports are a source of fraud. This table links expense data (from ERP) to IAM users. It checks for anomalies (duplicate receipts, amounts over policy). It uses IAM context (user role, history) to automate approval.
-- KPIs: Fraud detection rate, Auto-approval rate.
-- Feature Reference: F398 (Financial Controls)
CREATE TABLE IF NOT EXISTS iam.expense_report_audits (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    total_amount NUMERIC(15,2),
    anomaly_flag BOOLEAN,
    approved_by VARCHAR(50), -- AUTO, MANAGER
    approved_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_expense_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.expense_report_audits IS 'Audits expense reports using IAM anomaly detection.';

-- DB403: iam.corporate_card_usage
-- Description: Monitoring card spend.
-- Business Case: Corporate cards are risky. This table logs `card_transactions`. It links to the IAM user authorized to hold the card. It can block cards in real-time if the user account is compromised or if the transaction violates policy (e.g., gambling site).
-- KPIs: Fraud block rate, Policy compliance.
-- Feature Reference: F398
CREATE TABLE IF NOT EXISTS iam.corporate_card_usage (
    tx_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    card_last4 CHAR(4),
    user_id UUID NOT NULL,
    merchant_name VARCHAR(100),
    amount NUMERIC(10,2),
    was_blocked BOOLEAN,

    CONSTRAINT kf_corp_card_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.corporate_card_usage IS 'Monitors and controls corporate card transactions via IAM.';

-- DB404: iam.procurement_card_controls
-- Description: Purchasing controls.
-- Business Case: Procurement (P2P) requires specific roles. This table links `procurement_cards` to IAM roles. It defines limits (Category A: up to $5000). It ensures that only authorized users can use the card for specific suppliers.
-- KPIs: Control adherence, Spend visibility.
-- Feature Reference: F398
CREATE TABLE IF NOT EXISTS iam.procurement_card_controls (
    control_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    card_number_masked VARCHAR(20),
    role_id UUID NOT NULL,
    allowed_categories TEXT[],
    monthly_limit NUMERIC(10,2),

    CONSTRAINT kf_proc_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.procurement_card_controls IS 'Enforces IAM controls on procurement cards.';

-- DB405: iam.vendor_performance_history
-- Description: Vendor reviews.
-- Business Case: Vendor performance affects supply chain risk. This table stores `performance_reviews` (Delivery time, Quality, Security). A low security score might trigger a ban on vendor access (DB354). It integrates IAM security with vendor management.
-- KPIs: Vendor reliability, Security posture score.
-- Feature Reference: F354 (Supply Chain Access)
CREATE TABLE IF NOT EXISTS iam.vendor_performance_history (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,
    reviewer_id UUID NOT NULL,
    security_score INTEGER CHECK (security_score >= 1 AND security_score <= 10),
    reliability_score INTEGER,
    review_period VARCHAR(20), -- Q1, Q2
    notes TEXT,

    CONSTRAINT kf_vendor_perf_vendor FOREIGN KEY (vendor_id) REFERENCES iam.vendor_scarity(vendor_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.vendor_performance_history IS 'Stores historical performance reviews for vendors.';

-- DB406: iam.contract_compliance_status
-- Description: Legal contract adherence.
-- Business Case: Contracts have SLAs and security clauses. This table tracks `contract_compliance`. It links vendors/users to contracts and checks if the access level granted in IAM matches what is allowed in the contract (e.g., Data Residency).
-- KPIs: Compliance violation count, Contract coverage.
-- Feature Reference: F420 (Contract Neg)
CREATE TABLE IF NOT EXISTS iam.contract_compliance_status (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID,
    user_id UUID,
    compliance_clause TEXT,
    status VARCHAR(20) CHECK (status IN ('COMPLIANT', 'BREACH', 'PENDING')),
    last_audited TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.contract_compliance_status IS 'Tracks adherence to legal contract security clauses.';

-- DB407: iam.insurance_policies
-- Description: Cyber insurance data.
-- Business Case: Organizations buy cyber insurance. This table stores the `insurance_policy` details (Coverage limits, Deductible). It links IAM incident data (DB192) to the policy. When an incident occurs, the system calculates if it's covered.
-- KPIs: Claim approval rate, Premium cost.
-- Feature Reference: F408 (Claims)
CREATE TABLE IF NOT EXISTS iam.insurance_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    insurer_name VARCHAR(255) NOT NULL,
    policy_number VARCHAR(100) NOT NULL,
    coverage_limit NUMERIC(15,2),
    deductible NUMERIC(15,2),
    active_from DATE NOT NULL,
    active_until DATE
);
COMMENT ON TABLE iam.insurance_policies IS 'Stores cyber insurance policy details.';

-- DB408: iam.claim_history
-- Description: Insurance claims (cyber breaches).
-- Business Case: Filing claims. This table stores the `claim_history`. It references the `incident_id` and the `policy_id`. It tracks the status (Submitted, Approved, Paid). It provides data for negotiating future premiums.
-- KPIs: Claim payout time, Incident severity.
-- Feature Reference: F309 (Breach Simulation)
CREATE TABLE IF NOT EXISTS iam.claim_history (
    claim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    incident_id UUID NOT NULL,
    claim_amount NUMERIC(15,2),
    status VARCHAR(20),
    settled_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_claim_policy FOREIGN KEY (policy_id) REFERENCES iam.insurance_policies(policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.claim_history IS 'Stores history of cyber insurance claims.';

-- DB409: iam.risk_assessment_reports
-- Description: Annual reports for insurers.
-- Business Case: Insurers require annual risk assessments. This table stores the generated `risk_assessment_report` (PDF/URL). It aggregates IAM metrics over the year (vulnerability counts, breaches). It is essential for maintaining insurance coverage.
-- KPIs: Report completeness, Risk score trends.
-- Feature Reference: F309
CREATE TABLE IF NOT EXISTS iam.risk_assessment_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    insurer_id VARCHAR(255),
    report_year INTEGER NOT NULL,
    overall_score VARCHAR(5), -- A, B, C, D, E
    report_url TEXT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.risk_assessment_reports IS 'Stores annual risk assessment reports for insurers.';

-- DB410: iam.legal_hold_notices
-- Description: Preserving data for lawsuits.
-- Business Case: When a lawsuit is filed, a "Legal Hold" prevents deletion of data. This table tracks `legal_holds`. It references the `case_id` and the `data_scope` (Users, Dates). The retention engine (DB103) must check this table before deleting anything.
-- KPIs: Hold compliance, Data preservation verification.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS iam.legal_hold_notices (
    hold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_name VARCHAR(255) NOT NULL,
    case_number VARCHAR(100),
    scope_criteria JSONB, -- Users matching this criteria
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    lifted_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.legal_hold_notices IS 'Preserves data from deletion due to legal requirements.';

-- DB411: iam.e_discovery_collections
-- Description: Legal search tools.
-- Business Case: Lawyers need to query data (eDiscovery). This table stores the `collection_criteria` and the `result_set_id` (link to S3). It ensures that lawyers only see data relevant to the case and that their access is heavily audited.
-- KPIs: Query speed, Access control enforcement.
-- Feature Reference: F410
CREATE TABLE IF NOT EXISTS iam.e_discovery_collections (
    collection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id VARCHAR(100) NOT NULL,
    requesting_lawyer_id UUID,
    search_criteria JSONB,
    result_set_size_gb NUMERIC(10,2),
    exported_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_ediscovery_lawyer FOREIGN KEY (requesting_lawyer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.e_discovery_collections IS 'Stores eDiscovery collection tasks for legal review.';

-- DB412: iam.forensic_images
-- Description: Screenshots/Video for court.
-- Business Case: Screenshots are vital evidence. This table stores `forensic_images` (Screenshots of the session, screen recordings). It links to the `session_id` or `incident_id`. It chains these images (hashing) to prove they haven't been altered.
-- KPIs: Image chain integrity, Retrieval speed.
-- Feature Reference: F125 (Session Recording)
CREATE TABLE IF NOT EXISTS iam.forensic_images (
    image_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    capture_type VARCHAR(20), -- SCREENSHOT, VIDEO_FRAME
    file_url TEXT,
    file_hash CHAR(64) NOT NULL,
    sequence_number INTEGER,
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.forensic_images IS 'Stores forensic screenshots and video frames for evidence.';

-- DB413: iam.chain_of_custody_evidence
-- Description: Unbroken evidence trail.
-- Business Case: In court, the defense will argue the chain of custody was broken. This table creates a `chain_record` for every piece of evidence. It logs who accessed it, when, and the `file_hash`. It proves that the evidence presented is exactly what was captured during the incident.
-- KPIs: Chain completeness, Audit reliability.
-- Feature Reference: F203 (Audit Chain)
CREATE TABLE IF NOT EXISTS iam.chain_of_custody_evidence (
    custody_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL,
    custodian_id UUID NOT NULL,
    action VARCHAR(20), -- COLLECTED, ACCESSED, COPIED
    file_hash CHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_custody_evidence FOREIGN KEY (evidence_id) REFERENCES iam.forensic_images(image_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.chain_of_custody_evidence IS 'Logs the chain of custody for forensic evidence.';

-- DB414: iam.witness_testimony_records
-- Description: Witness statements (digital).
-- Business Case: Internal witnesses (users who saw the event) give testimony. This table stores `witness_records`. It links the `user_id` (witness) to the `incident_id` and stores their `statement`. It is often recorded via voice-to-text or secure form.
-- KPIs: Statement capture rate, Integrity verification.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.witness_testimony_records (
    testimony_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,
    witness_id UUID NOT NULL,
    statement TEXT,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_witness_user FOREIGN KEY (witness_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.witness_testimony_records IS 'Stores digital testimony from incident witnesses.';

-- DB415: iam.legal_review_comments
-- Description: Counsel notes.
-- Business Case: Legal counsel reviews evidence. This table stores `legal_notes` on specific evidence items or the case in general. It is privileged communication but essential for building the case strategy.
-- KPIs: Review coverage, Note searchability.
-- Feature Reference: F410
CREATE TABLE IF NOT EXISTS iam.legal_review_comments (
    comment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id VARCHAR(100) NOT NULL,
    counsel_id UUID NOT NULL,
    note_text TEXT,
    commented_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_legal_counsel FOREIGN KEY (counsel_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.legal_review_comments IS 'Stores privileged notes from legal counsel.';

-- DB416: iam.regulation_versioning
-- Description: Versioning of GDPR/CCPA.
-- Business Case: Laws change (e.g., GDPR 2.0). This table stores the `regulation_version` and the `text` of the regulation. When compliance checks run, they reference this specific version to ensure accuracy against the current law.
-- KPIs: Version accuracy, Update compliance.
-- Feature Reference: F307 (Regulation Impact)
CREATE TABLE IF NOT EXISTS iam.regulation_versioning (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_name VARCHAR(100) NOT NULL,
    version_number VARCHAR(20) NOT NULL,
    effective_date DATE NOT NULL,
    full_text TEXT
);
COMMENT ON TABLE iam.regulation_versioning IS 'Stores versions of privacy/compliance regulations.';

-- DB417: iam.cross_jurisdiction_mapping
-- Description: Mapping data location to law.
-- Business Case: Different countries have different laws. This table maps `country_code` to the applicable `regulation_version_id` (DB416). It automates the decision of "Which law applies to this data access?".
-- KPIs: Mapping correctness, Coverage.
-- Feature Reference: F263 (Cross Border Transfers)
CREATE TABLE IF NOT EXISTS iam.cross_jurisdiction_mapping (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2) NOT NULL,
    regulation_id UUID NOT NULL,
    region_override VARCHAR(50), -- e.g., CALIFORNIA for US/CCPA
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_jurisdiction_reg FOREIGN KEY (regulation_id) REFERENCES iam.regulation_versioning(version_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.cross_jurisdiction_mapping IS 'Maps geographic locations to applicable regulations.';

-- DB418: iam.data_localization_verification
-- Description: Proving data is local.
-- Business Case: Data must stay in the EU. This table stores `verification_logs` that prove a specific piece of data is physically stored in the correct region. It records the `data_center_id` and the `verification_hash`.
-- KPIs: Verification success rate, Compliance proof.
-- Feature Reference: F417
CREATE TABLE IF NOT EXISTS iam.data_localization_verification (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_id UUID NOT NULL,
    target_country CHAR(2),
    data_center_id VARCHAR(100),
    is_local BOOLEAN NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.data_localization_verification IS 'Logs verification of data residency requirements.';

-- DB419: iam.standard_contractual_clauses
-- Description: Legal boilerplate.
-- Business Case: Contracts have standard clauses (DPAs, Indemnification). This table stores the `boilerplate_clauses`. The automated contract generator (linked to DB420) pulls these clauses and fills in the variables. It ensures legal consistency and reduces lawyer time.
-- KPIs: Clause usage, Legal risk mitigation.
-- Feature Reference: F420
CREATE TABLE IF NOT EXISTS iam.standard_contractual_clauses (
    clause_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    clause_name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL, -- DATA_PRIVACY, LIABILITY
    text_content TEXT NOT NULL,
    is_mandatory BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.standard_contractual_clauses IS 'Library of standard legal contractual clauses.';

-- DB420: iam.contract_negotiation_history
-- Description: AI assisting contracts.
-- Business Case: AI can analyze negotiation history to suggest terms. This table logs the `negotiation_history` (Clause proposed, Counter-offer). It helps the legal AI learn optimal starting positions for contracts (e.g., Start at X cap, settle at Y).
-- KPIs: AI suggestion acceptance, Deal closure speed.
-- Feature Reference: F419
CREATE TABLE IF NOT EXISTS iam.contract_negotiation_history (
    negotiation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID,
    clause_id UUID NOT NULL,
    proposed_value TEXT,
    accepted_value TEXT,
    outcome VARCHAR(20), -- ACCEPTED, REJECTED, NEGOTIATED
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_negot_vendor FOREIGN KEY (vendor_id) REFERENCES iam.vendor_scarity(vendor_id) ON DELETE SET NULL,
    CONSTRAINT kf_negot_clause FOREIGN KEY (clause_id) REFERENCES iam.standard_contractual_clauses(clause_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.contract_negotiation_history IS 'Stores AI-assisted contract negotiation events.';

-- DB421: iam.ip_breach_compromise_monitor
-- Description: Database of credentials found in leaks.
-- Business Case: Many users reuse passwords. This table acts as a local cache of credentials found in public breaches (e.g., Collection #1). It allows the system to proactively force resets for users who have "appeared" in a leak, preventing account takeover.
-- KPIs: Breach ingestion rate, Match accuracy.
-- Feature Reference: F121 (Password Breach)
CREATE TABLE IF NOT EXISTS iam.ip_breach_compromise_monitor (
    breach_entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username_hash VARCHAR(255) NOT NULL, -- Hash of username
    password_hash VARCHAR(255) NOT NULL, -- Hash of password
    source_breach VARCHAR(255),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.ip_breach_compromise_monitor IS 'Cache of credentials found in public breaches.';

-- DB422: iam.domain_reputation_monitor
-- Description: Malicious domains.
-- Business Case: Phishing comes from malicious domains. This table stores a `reputation_score` for domains. It blocks access to these domains or flags emails arriving from them. It updates dynamically based on intelligence feeds.
-- KPIs: Reputation lag, Block rate.
-- Feature Reference: F208 (Threat Intel)
CREATE TABLE IF NOT EXISTS iam.domain_reputation_monitor (
    domain_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    reputation_score INTEGER CHECK (reputation_score >= 0 AND reputation_score <= 100),
    category VARCHAR(50), -- PHISHING, MALWARE, BOTNET
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.domain_reputation_monitor IS 'Tracks reputation scores of internet domains.';

-- DB423: iam.credential_stuffing_attempts
-- Description: Database of credentials found in leaks.
-- Business Case: Duplicate logic check. This table logs specific `credential_stuffing` attempts (User A tries password X, User B tries password X). It helps identify the "password spray" attack where attackers try one password against many users.
-- KPIs: Spray detection accuracy, Attack block rate.
-- Feature Reference: F421
CREATE TABLE IF NOT EXISTS iam.credential_stuffing_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_user_id UUID,
    ip_address INET NOT NULL,
    password_hash VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_stuffing_user FOREIGN KEY (target_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.credential_stuffing_attempts IS 'Logs attempts to stuff credentials into login forms.';

-- DB424: iam.account_takeover_indicators
-- Description: Heuristics for ATO.
-- Business Case: ATO (Account Takeover) has subtle signs. This table stores `indicator_logs` (e.g., "Success login immediately after failed MFA"). These heuristics trigger step-up authentication or account lockouts to stop the takeover.
-- KPIs: Detection sensitivity, False positive rate.
-- Feature Reference: F302
CREATE TABLE IF NOT EXISTS iam.account_takeover_indicators (
    indicator_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    session_id UUID,
    indicator_type VARCHAR(100) NOT NULL, -- MFA_BYPASS, IMPOSSIBLE_TRAVEL
    severity VARCHAR(20),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_ato_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT kf_ato_session FOREIGN KEY (session_id) REFERENCES iam.sessions(session_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.account_takeover_indicators IS 'Stores heuristics indicating Account Takeover (ATO).';

-- DB425: iam.session_anomaly_scores
-- Description: Rolling average of anomaly.
-- Business Case: A single anomaly might be a blip. This table tracks the `rolling_average_anomaly_score` for a user. It smooths out noise. A sustained high score triggers intervention, while a single blip might be ignored.
-- KPIs: Signal-to-noise ratio, Detection threshold tuning.
-- Feature Reference: F218 (Session Anomalies)
CREATE TABLE IF NOT EXISTS iam.session_anomaly_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL,
    average_score NUMERIC(3,2),
    peak_score NUMERIC(3,2),

    CONSTRAINT kf_session_anomaly_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.session_anomaly_scores IS 'Aggregates session anomaly scores into rolling averages.';

-- DB426: iam.user_behavior_graph
-- Description: Graph of user actions.
-- Business Case: Users have patterns (A always follows B). This table stores the `behavior_graph` (Nodes=Actions, Edges=Transitions). It detects deviations from the norm graph (e.g., User A usually goes to Admin -> Settings, but today went Admin -> Logs -> Export).
-- KPIs: Graph divergence detection, Pattern match speed.
-- Feature Reference: F122 (Knowledge Graph)
CREATE TABLE IF NOT EXISTS iam.user_behavior_graph (
    graph_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    source_node VARCHAR(100),
    target_node VARCHAR(100),
    transition_probability NUMERIC(3,2),
    last_observed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_behavior_graph_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_behavior_graph IS 'Stores the graph of user behavior transitions.';

-- DB427: iam.peer_group_analysis_history
-- Description: Historical peer comparison.
-- Business Case: Am I the outlier? This table stores the `peer_group_comparison` history. It compares a user's access pattern to their peer group. Being an outlier (e.g., accessing files no one else does) is a strong risk signal.
-- KPIs: Outlier detection rate, Group definition accuracy.
-- Feature Reference: F028 (Peer Group)
CREATE TABLE IF NOT EXISTS iam.peer_group_analysis_history (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    peer_group_id VARCHAR(100) NOT NULL,
    deviation_score NUMERIC(3,2),
    compared_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_peer_analysis_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.peer_group_analysis_history IS 'Stores history of peer group behavior comparisons.';

-- DB428: iam.dynamic_risk_thresholds
-- Description: Changing thresholds based on global threat level.
-- Business Case: During a major global attack (e.g., Log4j), thresholds should be lowered (be stricter). This table stores `dynamic_thresholds` keyed by `threat_level_code`. When the threat level rises, the system applies stricter rules from this table.
-- KPIs: Threshold adaptation speed, False positive management.
-- Feature Reference: F054 (Risk Scoring)
CREATE TABLE IF NOT EXISTS iam.dynamic_risk_thresholds (
    threshold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_level_code VARCHAR(20) NOT NULL, -- GREEN, YELLOW, ORANGE, RED
    mfa_required BOOLEAN DEFAULT TRUE,
    max_login_attempts INTEGER,
    anomaly_threshold_score NUMERIC(3,2)
);
COMMENT ON TABLE iam.dynamic_risk_thresholds IS 'Stores dynamic security thresholds based on global threat level.';

-- DB429: iam.access_request_routing
-- Description: Routing approval requests.
-- Business Case: Complex approvals need routing logic (Who approves this?). This table defines the `routing_rules`. It maps `request_type` to the `approver_group`. It ensures the JIT request lands in the right inbox (Manager, Security, Legal).
-- KPIs: Routing accuracy, Approval latency.
-- Feature Reference: F011 (JIT Workflow)
CREATE TABLE IF NOT EXISTS iam.access_request_routing (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(100),
    role_id UUID,
    approver_group_id VARCHAR(100),
    fallback_approver_id UUID, -- If group is empty

    CONSTRAINT kf_route_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.access_request_routing IS 'Defines routing logic for approval requests.';

-- DB430: iam.delegation_limits
-- Description: Limits on delegation.
-- Business Case: Delegation (F066) shouldn't be infinite. This table defines `delegation_limits` (e.g., "Cannot delegate to contractors", "Max duration 24 hours"). The JIT engine enforces these limits automatically.
-- KPIs: Limit enforcement success, Policy adherence.
-- Feature Reference: F066 (Delegation)
CREATE TABLE IF NOT EXISTS iam.delegation_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    delegator_role_id UUID NOT NULL,
    target_role_constraint VARCHAR(100), -- NONE, NO_CONTRACTOR
    max_duration_hours INTEGER,
    requires_approval BOOLEAN DEFAULT TRUE,

    CONSTRAINT kf_del_limit_delegator FOREIGN KEY (delegator_role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.delegation_limits IS 'Enforces constraints on privilege delegation.';

-- DB431: iam.privilege_usage_analytics
-- Description: Who uses what privilege.
-- Business Case: Least Privilege requires pruning unused rights. This table aggregates `privilege_usage` (How many times was Role X used?). It allows admins to identify "Zombie roles" that haven't been used in 6 months and safely remove them.
-- KPIs: Usage coverage, Revocation safety.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.privilege_usage_analytics (
    analytic_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_id UUID,
    permission_id UUID,
    usage_count BIGINT DEFAULT 0,
    last_used TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_priv_usage_role FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    CONSTRAINT kf_priv_usage_perm FOREIGN KEY (permission_id) REFERENCES iam.permissions(perm_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.privilege_usage_analytics IS 'Aggregates usage stats for roles and permissions.';

-- DB432: iam.admin_activity_dashboard
-- Description: Data for dashboards.
-- Business Case: Security dashboards need real-time data. This table acts as a materialized store for dashboard metrics (Active sessions, Failed logins, Pending approvals). It optimizes the queries for the UI, preventing dashboard load from hitting transactional tables.
-- KPIs: Dashboard refresh rate, Data freshness.
-- Feature Reference: F016
CREATE TABLE IF NOT EXISTS iam.admin_activity_dashboard (
    metric_name VARCHAR(100) PRIMARY KEY,
    value BIGINT,
    value2 NUMERIC(10,2), -- For rates/percentages
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.admin_activity_dashboard IS 'Optimized store for dashboard metrics.';

-- DB433: iam.security_incident_taxonomy
-- Description: Categorizing incidents.
-- Business Case: You can't manage what you don't classify. This table defines the `taxonomy` of incidents (Phishing, Malware, Insider). Every incident (DB192) is mapped here. It allows for detailed reporting (e.g., "We had 5 Phishing incidents this month").
-- KPIs: Classification accuracy, Reporting granularity.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.security_incident_taxonomy (
    tax_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    category VARCHAR(50) NOT NULL, -- THREAT_TYPE
    subcategory VARCHAR(100) NOT NULL, -- PHISHING_CREDS
    severity_mapping VARCHAR(20),
    description TEXT
);
COMMENT ON TABLE iam.security_incident_taxonomy IS 'Defines the taxonomy for classifying security incidents.';

-- DB434: iam.incident_lessons_learned
-- Description: Knowledge base.
-- Business Case: Don't make the same mistake twice. This table stores `lessons_learned` from post-mortems. It links to the incident and the `action_item` (e.g., "Implement MFA for VPN"). It drives the roadmap for future security improvements.
-- KPIs: Lesson implementation rate, Incident recurrence.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.incident_lessons_learned (
    lesson_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID,
    description TEXT NOT NULL,
    assigned_to UUID, -- Who fixes it
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED
    due_date DATE,

    CONSTRAINT kf_lessons_incident FOREIGN KEY (incident_id) REFERENCES iam.risk_events(event_id) ON DELETE SET NULL,
    CONSTRAINT kf_lessons_assigned FOREIGN KEY (assigned_to) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.incident_lessons_learned IS 'Stores remediation items from security incidents.';

-- DB435: iam.playbook_effectiveness
-- Description: Did the playbook work?
-- Business Case: Are our runbooks actually solving incidents? This table tracks `playbook_effectiveness`. It compares metrics (MTTD - Mean Time to Detect) before and after playbook execution. It proves the ROI of automation.
-- KPIs: MTTR reduction, Playbook success rate.
-- Feature Reference: F195 (Playbooks)
CREATE TABLE IF NOT EXISTS iam.playbook_effectiveness (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_id UUID NOT NULL,
    incident_id UUID,
    mttd_before_seconds INTEGER,
    mttd_after_seconds INTEGER,
    success BOOLEAN,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_playbook_effectiveness_pb FOREIGN KEY (playbook_id) REFERENCES iam.playbooks(playbook_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.playbook_effectiveness IS 'Measures the effectiveness of security playbooks.';

-- DB436: iam.soar_runbooks
-- Description: Security Orchestration Automation runbooks.
-- Business Case: SOAR (Security Orchestration, Automation and Response) connects tools. This table stores the `runbook_definition` for SOAR. It defines the steps (Isolate endpoint, Block IP, Ticket). It automates the response to complex attacks.
-- KPIs: Automation coverage, Execution fidelity.
-- Feature Reference: F114
CREATE TABLE IF NOT EXISTS iam.soar_runbooks (
    runbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_platform VARCHAR(100), -- CISCO, FORTINET, AWS
    actions_json JSONB NOT NULL, -- Orchestration steps
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.soar_runbooks IS 'Stores SOAR runbooks for automated response.';

-- DB437: iam.threat_intel_feeds
-- Description: Ingesting IoC feeds.
-- Business Case: Threat intel comes from many sources. This table manages the `subscription` to these feeds. It stores the `feed_url`, `format` (STIX, TAXII), and `last_pull_status`. It ensures the platform is consuming the latest threat data.
-- KPIs: Feed uptime, Ingestion latency.
-- Feature Reference: F208 (Threat Intel)
CREATE TABLE IF NOT EXISTS iam.threat_intel_feeds (
    feed_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_name VARCHAR(100) NOT NULL,
    feed_url TEXT NOT NULL,
    format VARCHAR(20), -- STIX, JSON, CSV
    api_key_enc BYTEA, -- Encrypted key if needed
    last_successful_pull TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.threat_intel_feeds IS 'Manages subscriptions to threat intelligence feeds.';

-- DB438: iam.indicator_of_compromise
-- Description: Specific IoC management.
-- Business Case: This table acts as the master list for Indicators of Compromise (IoC). It stores the `ioc_value` (Hash, IP, Domain), the `type`, and the `source_feed`. It is the high-speed table checked by auth systems.
-- KPIs: IoC validity, False positive rate.
-- Feature Reference: F208
CREATE TABLE IF NOT EXISTS iam.indicator_of_compromise (
    ioc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ioc_value VARCHAR(255) NOT NULL,
    ioc_type VARCHAR(20) NOT NULL,
    confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
    source_feed_id UUID,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_ioc_feed FOREIGN KEY (source_feed_id) REFERENCES iam.threat_intel_feeds(feed_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.indicator_of_compromise IS 'Master list of Indicators of Compromise.';

-- DB439: iam.attack_surface_analysis
-- Description: What is exposed?
-- Business Case: Knowing what you have is step 1 of defense. This table stores the `attack_surface` (Internet-facing IPs, API endpoints, Open Ports). It monitors changes. A new port opening triggers a security review.
-- KPIs: Surface visibility, Change detection speed.
-- Feature Reference: F257 (SBOM)
CREATE TABLE IF NOT EXISTS iam.attack_surface_analysis (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_type VARCHAR(50) NOT NULL, -- IP, DOMAIN, API_ENDPOINT
    identifier VARCHAR(255) NOT NULL,
    exposure_score INTEGER CHECK (exposure_score >= 0 AND exposure_score <= 100),
    first_discovered TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.attack_surface_analysis IS 'Catalogs and scores the external attack surface.';

-- DB440: iam.vulnerability_exposure_matrix
-- Description: Linking vulns to assets.
-- Business Case: Does CVE-2021-44228 affect us? This table maps `cve_id` to internal `assets` (DB257). It calculates the `exploitability_score`. It prioritizes patching based on actual exposure in the environment, not just CVSS score.
-- KPIs: Exposure calculation speed, Patch prioritization accuracy.
-- Feature Reference: F378 (Vuln Scanner)
CREATE TABLE IF NOT EXISTS iam.vulnerability_exposure_matrix (
    matrix_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    asset_id UUID NOT NULL,
    exploitability_score NUMERIC(3,2),
    patch_deadline DATE,

    CONSTRAINT fk_vuln_asset FOREIGN KEY (asset_id) REFERENCES iam.software_bom(bom_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.vulnerability_exposure_matrix IS 'Links vulnerabilities to assets with exploitability scores.';

-- DB441: iam.patch_management_queue
-- Description: Patches ready to apply.
-- Business Case: Patching windows need scheduling. This table stores the `patch_queue`. It tracks `target_asset`, `patch_version`, and `scheduled_window`. It integrates with deployment tools to apply the patch when ready.
-- KPIs: Patch compliance, Window adherence.
-- Feature Reference: F378
CREATE TABLE IF NOT EXISTS iam.patch_management_queue (
    queue_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id VARCHAR(50) NOT NULL,
    target_asset_id UUID NOT NULL,
    patch_version VARCHAR(50),
    scheduled_start TIMESTAMP WITH TIME ZONE,
    scheduled_end TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'PENDING',

    CONSTRAINT kf_patch_asset FOREIGN KEY (target_asset_id) REFERENCES iam.software_bom(bom_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.patch_management_queue IS 'Schedules and tracks vulnerability patching jobs.';

-- DB442: iam.configuration_drift_detection
-- Description: Config changed without approval?
-- Business Case: Uncontrolled config changes are dangerous. This table stores the `current_config_hash` of critical resources (AWS S3 Buckets, IAM Roles). It compares it against the `approved_config_hash`. Any drift triggers an alert.
-- KPIs: Drift detection time, Auto-remediation rate.
-- Feature Reference: F122 (Knowledge Graph)
CREATE TABLE IF NOT EXISTS iam.configuration_drift_detection (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(255) NOT NULL,
    approved_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL,
    is_drifted BOOLEAN DEFAULT FALSE,
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.configuration_drift_detection IS 'Detects unauthorized changes in configuration.';

-- DB443: iam.backup_verification_jobs
-- Description: Did backups work?
-- Business Case: Backups are useless if they can't be restored. This table manages `backup_verification_jobs`. It schedules a random restore of a backup to a sandbox environment to verify data integrity. It ensures confidence in disaster recovery.
-- KPIs: Verification success rate, Restore reliability.
-- Feature Reference: F313 (Backups)
CREATE TABLE IF NOT EXISTS iam.backup_verification_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'RUNNING',
    restore_size_bytes BIGINT,
    integrity_check BOOLEAN,
    verified_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.backup_verification_jobs IS 'Manages scheduled verification of backup integrity.';

-- DB444: iam.restore_test_results
-- Description: Testing restores.
-- Business Case: Detailed results of the verification job (DB443). This table stores the `test_logs`. If a test fails, it identifies which file/object is corrupt. This allows the ops team to fix the backup chain immediately.
-- KPIs: Failure resolution time, Backup health score.
-- Feature Reference: F443
CREATE TABLE IF NOT EXISTS iam.restore_test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    job_id UUID NOT NULL,
    object_path TEXT,
    checksum_status VARCHAR(20), -- MATCH, MISMATCH
    error_message TEXT,

    CONSTRAINT kf_restore_job FOREIGN KEY (job_id) REFERENCES iam.backup_verification_jobs(job_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.restore_test_results IS 'Stores granular results of backup restore tests.';

-- DB445: iam.archive_retrieval_requests
-- Description: Pulling data from deep storage.
-- Business Case: Old data is in Glacier/S3 Deep Archive. Retrieving it takes time. This table tracks `retrieval_requests`. It calculates the `eta` and manages the `status`. It notifies the user when the data is ready.
-- KPIs: Retrieval time estimation accuracy, Request completion.
-- Feature Reference: F078 (Archived Logs)
CREATE TABLE IF NOT EXISTS iam.archive_retrieval_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    archive_id UUID NOT NULL,
    user_id UUID NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    available_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, READY, EXPIRED
    download_url TEXT,

    CONSTRAINT kf_archive_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.archive_retrieval_requests IS 'Manages the slow retrieval of archived data.';

-- DB446: iam.data_lifecycle_states
-- Description: Active/Archived/Deleted state tracking.
-- Business Case: Data moves through states (Active -> Archived -> Deleted). This table tracks the `lifecycle_state` of data assets. It is the "Source of Truth" for a user's data status when handling DSARs (Right to Erase).
-- KPIs: State transition latency, Retention compliance.
-- Feature Reference: F103 (Retention)
CREATE TABLE IF NOT EXISTS iam.data_lifecycle_states (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_type VARCHAR(50) NOT NULL, -- USER_DATA, LOGS, KEYS
    asset_id VARCHAR(255) NOT NULL,
    current_state VARCHAR(20) NOT NULL CHECK (current_state IN ('ACTIVE', 'ARCHIVED', 'DELETED')),
    state_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.data_lifecycle_states IS 'Tracks the lifecycle state of data assets.';

-- DB447: iam.storage_optimization_recommendations
-- Description: AI suggesting archiving.
-- Business Case: Storing active data in expensive S3 is wasteful. This table stores `optimization_recommendations` generated by AI (e.g., "Table X hasn't been queried in 90 days"). It triggers a move to Glacier. It optimizes storage costs automatically.
-- KPIs: Recommendation accuracy, Cost savings realized.
-- Feature Reference: F103
CREATE TABLE IF NOT EXISTS iam.storage_optimization_recommendations (
    recommendation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_resource_id VARCHAR(255) NOT NULL,
    suggested_action VARCHAR(50), -- ARCHIVE, COMPRESS, DELETE
    estimated_savings NUMERIC(10,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.storage_optimization_recommendations IS 'Stores AI-generated recommendations for data storage.';

-- DB448: iam.query_performance_logs
-- Description: Slow IAM queries.
-- Business Case: Performance is critical. This table logs `query_performance`, specifically slow queries (>1s). It captures the `query_plan_hash` and `execution_time`. It helps DBAs optimize the IAM schema (e.g., missing indexes).
-- KPIs: P95 Latency, Slow query trend.
-- Feature Reference: F348 (DB Health)
CREATE TABLE IF NOT EXISTS iam.query_performance_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_signature TEXT NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    rows_examined BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.query_performance_logs IS 'Logs performance metrics for IAM database queries.';

-- DB449: iam.database_connection_pool_metrics
-- Description: DB health.
-- Business Case: Running out of connections is fatal. This table tracks `pool_metrics` (Active, Idle, Waiting). It monitors the health of the connection pool to the IAM database. Alerts are sent if usage > 80%.
-- KPIs: Pool utilization, Connection wait time.
-- Feature Reference: F348
CREATE TABLE IF NOT EXISTS iam.database_connection_pool_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,
    active_connections INTEGER,
    idle_connections INTEGER,
    waiting_connections INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.database_connection_pool_metrics IS 'Tracks health of database connection pools.';

-- DB450: iam.system_health_heartbeat
-- Description: "I'm alive" status.
-- Business Case: Is the IAM system up? This table stores the latest `heartbeat` from every microservice. It includes the `service_name`, `version`, and `status`. If a heartbeat stops, it triggers an alert.
-- KPIs: Uptime percentage, Heartbeat latency.
-- Feature Reference: F112 (Synthetic Monitoring)
CREATE TABLE IF NOT EXISTS iam.system_health_heartbeat (
    service_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'OK',
    last_beat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.system_health_heartbeat IS 'Stores heartbeat status of IAM system components.';

-- ================================================================================
-- Indexes and Constraints for Part 7 Tables
-- ================================================================================

-- Biometrics & Fraud
CREATE INDEX IF NOT EXISTS idx_heartbeat_device ON iam.heartbeat_biometrics(device_id);
CREATE INDEX IF NOT EXISTS idx_brainwave_session ON iam.brainwave_auth_data(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_user_a ON iam.social_graph_integrity(user_a_id);
CREATE INDEX IF NOT EXISTS idx_fraud_ring_created ON iam.fraud_ring_detection(detected_at);
CREATE INDEX IF NOT EXISTS idx_deepfake_audio_type ON iam.deepfake_audio_generation(generation_source);

-- Security & Honeytokens
CREATE INDEX IF NOT EXISTS idx_honeypot_synth ON iam.honeypot_events(synthetic_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_attacker ON iam.honeypot_events(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_watermark_session ON iam.session_watermarking(session_id);
CREATE INDEX IF NOT EXISTS idx_api_abuse_user ON iam.api_abuse_patterns(user_id);

-- Compliance & Legal
CREATE INDEX IF NOT EXISTS idx_dsar_status ON iam.gdpr_data_subject_requests(status);
CREATE INDEX IF NOT EXISTS idx_rtbf_dsar ON iam.right_to_be_forgotten_verification(dsar_id);
CREATE INDEX IF NOT EXISTS idx_legal_hold_case ON iam.legal_hold_notices(case_name);
CREATE INDEX IF NOT EXISTS idx_e_discovery_case ON iam.e_discovery_collections(case_id);
CREATE INDEX IF NOT EXISTS idx_forensic_incident ON iam.forensic_images(incident_id);

-- Infrastructure & DevSecOps
CREATE INDEX IF NOT EXISTS idx_k8s_subject ON iam.kubernetes_pod_access(subject_id);
CREATE INDEX IF NOT EXISTS idx_serverless_identifier ON iam.serverless_function_roles(function_identifier);
CREATE INDEX IF NOT EXISTS idx_autoscale_direction ON iam.autoscaling_decisions(direction);
CREATE INDEX IF NOT EXISTS idx_sig_image_hash ON iam.container_image_signatures(image_sha256);
CREATE INDEX IF NOT EXISTS idx_vuln_target ON iam.vulnerability_scanner_results(affected_component);

-- Analytics & Audit
CREATE INDEX IF NOT EXISTS idx_churn_user ON iam.churn_prediction(user_id);
CREATE INDEX IF NOT EXISTS idx_ato_user ON iam.account_takeover_indicators(user_id);
CREATE INDEX IF NOT EXISTS idx_lesson_incident ON iam.incident_lessons_learned(incident_id);
CREATE INDEX IF NOT EXISTS idx_playbook_effectiveness_pb ON iam.playbook_effectiveness(playbook_id);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 7 Tables
-- ================================================================================

ALTER TABLE iam.gdpr_data_subject_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.expense_report_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.corporate_card_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.vendor_performance_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.witness_testimony_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.e_discovery_collections ENABLE ROW LEVEL SECURITY;

CREATE POLICY dsar_user_isolation ON iam.gdpr_data_subject_requests
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY expense_audit_isolation ON iam.expense_report_audits
    FOR SELECT
    USING (
        user_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.user_roles ur JOIN iam.roles r ON r.role_name = 'FINANCE_AUDITOR' WHERE ur.user_id = current_setting('app.current_user_id', true)::UUID)
    );

CREATE POLICY corporate_card_user_isolation ON iam.corporate_card_usage
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY vendor_perf_admin_only ON iam.vendor_performance_history
    FOR ALL
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

CREATE POLICY witness_user_isolation ON iam.witness_testimony_records
    FOR SELECT
    USING (witness_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY e_discovery_lawyer_isolation ON iam.e_discovery_collections
    FOR ALL
    USING (requesting_lawyer_id = current_setting('app.current_user_id', true)::UUID);

-- ================================================================================
-- Triggers for Part 7 Tables
-- ================================================================================

CREATE TRIGGER trg_heartbeat_update BEFORE UPDATE ON iam.heartbeat_biometrics FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_churn_update BEFORE UPDATE ON iam.churn_prediction FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_cost_attr_update BEFORE UPDATE ON iam.cost_attribution_model FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_forensic_capture BEFORE INSERT ON iam.forensic_images FOR EACH ROW EXECUTE PROCEDURE iam.fn_audit_log_access(); -- Assuming log helper exists
CREATE TRIGGER trg_ioc_feed_update BEFORE UPDATE ON iam.threat_intel_feeds FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_system_heartbeat_update BEFORE INSERT ON iam.system_health_heartbeat FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_dsar_update BEFORE UPDATE ON iam.gdpr_data_subject_requests FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_legal_hold_update BEFORE UPDATE ON iam.legal_hold_notices FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();




-- ================================================================================
-- MODULE M09: GRANULAR ACCESS CONTROL (RBAC + ABAC)
-- Database Schema Definition - PART 8
-- Scope: Database Objects DB451 - DB550 (Tables)
-- Note: Part 8 completes the 550-table scope, focusing on IoT/Edge Access,
-- Gamification, Developer Experience, Sustainability, Post-Quantum readiness,
-- and Advanced Operational Intelligence.
-- ================================================================================

-- ================================================================================
-- DDL Statements (Tables DB451 - DB550)
-- ================================================================================

-- DB451: iam.iot_device_inventory
-- Description: Master inventory of all IoT devices in the PARI ecosystem.
-- Business Case: Managing IoT (sensors, controllers) at scale requires a centralized inventory. This table stores every device's `hardware_id`, `type`, and `firmware_version`. It serves as the master reference for IoT identities (DB143). Without this, provisioning access for a smart meter or a door lock would be chaotic. It ensures that every physical endpoint requesting access is known, authorized, and tracked.
-- KPIs: Inventory accuracy, Firmware version compliance.
-- Feature Reference: F143 (Machine Identity)
CREATE TABLE IF NOT EXISTS iam.iot_device_inventory (
    device_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hardware_serial VARCHAR(100) NOT NULL UNIQUE,
    device_type VARCHAR(50) NOT NULL, -- e.g., SMART_METER, LOCK_CONTROLLER, SENSOR
    manufacturer VARCHAR(100),
    model_name VARCHAR(100),
    firmware_version VARCHAR(50),
    provisioning_status VARCHAR(20) DEFAULT 'PENDING', -- PROVISIONED, RETIRED
    owner_id UUID, -- Department or Person responsible
    last_seen_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_iot_owner FOREIGN KEY (owner_id) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.iot_device_inventory IS 'Master inventory of all physical and virtual IoT devices.';

-- DB452: iam.iot_certificates
-- Description: X.509 certificates for IoT devices.
-- Business Case: IoT devices often use X.509s for mutual TLS (mTLS). This table stores the `certificate_pem` linked to the `device_id`. It tracks the `certificate_authority` and expiration. This ensures that if a device is compromised, its certificate can be immediately revoked, cutting it off from the secure mesh without impacting other devices.
-- KPIs: Certificate expiration rate, Revocation speed.
-- Feature Reference: F143 (Machine Identity)
CREATE TABLE IF NOT EXISTS iam.iot_certificates (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_id UUID NOT NULL,
    certificate_pem TEXT NOT NULL,
    issued_by VARCHAR(100), -- The internal CA or vendor
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, REVOKED
    fingerprint_sha256 CHAR(64),

    CONSTRAINT fk_iot_cert_device FOREIGN KEY (device_id) REFERENCES iam.iot_device_inventory(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.iot_certificates IS 'Stores X.509 certificates for IoT device authentication.';

-- DB453: iam.physical_access_logs
-- Description: Logs of physical access events (Badges, Bio).
-- Business Case: Bridging the gap between digital identity and physical access. This table logs when a badge is swiped or a biometric is scanned at a door. It links the `credential_id` (Badge ID) to the `user_id`. This creates a unified audit trail where you can see "User X logged in at 9:00 (IP)" AND "User X entered Building A at 9:05 (Door)", detecting impossible travel in the physical world.
-- KPIs: Log ingestion volume, Latency.
-- Feature Reference: F289 (Attendence Integration)
CREATE TABLE IF NOT EXISTS iam.physical_access_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    device_id UUID, -- The reader (Door Lock)
    credential_id VARCHAR(100) NOT NULL,
    access_result VARCHAR(20), -- GRANTED, DENIED
    location_id VARCHAR(100), -- e.g., "Building A", "Lobby"
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_phys_access_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_phys_access_device FOREIGN KEY (device_id) REFERENCES iam.iot_device_inventory(device_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.physical_access_logs IS 'Logs physical access events like badge swipes.';

-- DB454: iam.badge_reader_status
-- Description: Health monitoring of physical access readers.
-- Business Case: If a badge reader goes offline or is tampered with, security is compromised. This table stores the `health_status` and `battery_level` of readers. It allows the system to trigger maintenance alerts and automatically adjust physical access policies (e.g., "Require manual PIN at this door if reader camera is offline").
-- KPIs: Reader uptime, Alert sensitivity.
-- Feature Reference: F269 (Edge Gateway Sync)
CREATE TABLE IF NOT EXISTS iam.badge_reader_status (
    reader_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    location_id VARCHAR(100) NOT NULL,
    device_type VARCHAR(50), -- RFID, NFC, BIOMETRIC
    is_online BOOLEAN DEFAULT FALSE,
    battery_level INTEGER CHECK (battery_level >= 0 AND battery_level <= 100),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    tamper_alert BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.badge_reader_status IS 'Stores the health and status of physical badge readers.';

-- DB455: iam.location_beacons
-- Description: Indoor positioning beacons for location auth.
-- Business Case: For granular physical access (e.g., Server Room A only), we need to know *exactly* where a user is. This table maps `beacon_id` (UUID, MAC) to a physical location. If a user's detected beacons match the `required_beacons` for a resource, access is granted. It enables "Location-Aware" physical security.
-- KPIs: Beacon density, Detection accuracy.
-- Feature Reference: F288 (Spatial Access)
CREATE TABLE IF NOT EXISTS iam.location_beacons (
    beacon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    uuid_namespace VARCHAR(100) NOT NULL,
    major_id VARCHAR(50),
    minor_id INTEGER CHECK (minor_id >= 0 AND minor_id <= 65535),
    floor INTEGER,
    zone_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.location_beacons IS 'Defines the location of Bluetooth Low Energy (BLE) beacons.';

-- DB456: iam.smart_lock_audit
-- Description: Audit trail of smart lock events.
-- Business Case: Smart locks log every unlock event. This table captures `unlock_method` (App, Badge, Pin) and `duration`. It helps answer questions like "Who unlocked the server room door last Tuesday?" and detects anomalies like an unlock happening when the office is closed for holidays.
-- KPIs: Event coverage, Retrieval speed.
-- Feature Reference: F453 (Physical Access Logs)
CREATE TABLE IF NOT EXISTS iam.smart_lock_audit (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    lock_id UUID NOT NULL,
    user_id UUID,
    unlock_method VARCHAR(50), -- APP, BIOMETRIC, PHYSICAL_KEY
    access_granted BOOLEAN NOT NULL,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.smart_lock_audit IS 'Stores granular logs for smart lock/unlock events.';

-- DB457: iam.elevator_access_logs
-- Description: Floor access tracking via elevators.
-- Business Case: Not all users have access to all floors. This table logs `access_granted_to_floor`. It enforces policies like "Interns can only access Floors 1-3". By tracking the request, the system can prevent elevator buttons from lighting up to restricted floors for unauthorized users.
-- KPIs: Policy enforcement rate, Hardware integration lag.
-- Feature Reference: F014 (Device Trust)
CREATE TABLE IF NOT EXISTS iam.elevator_access_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    elevator_controller_id UUID NOT NULL,
    requested_floor INTEGER NOT NULL,
    access_granted BOOLEAN NOT NULL,
    reason TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.elevator_access_logs IS 'Logs and controls elevator access based on floor permissions.';

-- DB458: iam.printer_encryption_keys
-- Description: Keys for secure badge printing.
-- Business Case: Blank badges are a security risk. This table stores encryption keys used by on-site badge printers. When a badge is printed, the data is encrypted using a key from this table before being sent to the printer. Rotation of these keys is critical to prevent unauthorized badge cloning.
-- KPIs: Key rotation frequency, Printer encryption success.
-- Feature Reference: F089 (HSM)
CREATE TABLE IF NOT EXISTS iam.printer_encryption_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    printer_id VARCHAR(100) NOT NULL,
    algorithm VARCHAR(50) DEFAULT 'AES-256',
    public_key TEXT NOT NULL,
    private_key_enc BYTEA NOT NULL,
    active_from TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.printer_encryption_keys IS 'Stores encryption keys for secure badge printing systems.';

-- DB459: iam.visitor_management
-- Description: Temporary access for non-employees.
-- Business Case: Visitors (Contractors, Interviewees) need temporary access. This table stores `visitor_passes` linked to a `sponsor_user`. It sets `valid_from` and `valid_until` windows. It ensures that visitor badges automatically expire and stop working at the end of the visit, maintaining high security for transient personnel.
-- KPIs: Sponsor coverage rate, Expiration enforcement.
-- Feature Reference: F101 (Automated Provisioning)
CREATE TABLE IF NOT EXISTS iam.visitor_management (
    visitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    sponsor_user_id UUID NOT NULL,
    company_name VARCHAR(255),
    photo_url TEXT,
    access_level VARCHAR(100), -- e.g., "Lobby Only"
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    CONSTRAINT fk_visitor_sponsor FOREIGN KEY (sponsor_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.visitor_management IS 'Manages temporary visitor access and credentials.';

-- DB460: iam.physical_security_zones
-- Description: Mapping of zones to access rules.
-- Business Case: Large campuses have zones with varying security levels (Public, Secure, Confidential). This table defines these zones and maps them to required access levels. It links to location beacons (DB455) to enforce context-aware policies like "You cannot be in the 'Server Room' unless you have a physical escort."
-- KPIs: Zone mapping completeness, Enforcement accuracy.
-- Feature Reference: F013 (Geo-Fencing)
CREATE TABLE IF NOT EXISTS iam.physical_security_zones (
    zone_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    zone_name VARCHAR(100) NOT NULL,
    security_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    parent_zone_id UUID,
    description TEXT,

    CONSTRAINT fk_zone_parent FOREIGN KEY (parent_zone_id) REFERENCES iam.physical_security_zones(zone_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.physical_security_zones IS 'Defines hierarchical security zones within physical facilities.';

-- DB461: iam.security_badges
-- Description: Gamification achievements for security.
-- Business Case: Gamification improves security culture. This table stores `badges` (achievements) like "2FA Champion" or "Phish Fisher". Users earn these by completing actions. It drives positive reinforcement for behaviors that are usually ignored (like reporting a phishing email), turning security into a game.
-- KPIs: Badge issuance rate, User engagement metrics.
-- Feature Reference: F149 (Adaptive UI)
CREATE TABLE IF NOT EXISTS iam.security_badges (
    badge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    badge_type VARCHAR(50) NOT NULL, -- e.g., MULTI_FACTOR_ENABLER
    title VARCHAR(100),
    icon_url TEXT,
    earned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_badge_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.security_badges IS 'Stores gamification badges/achievements for users.';

-- DB462: iam.leaderboard
-- Description: Global ranking of security scores.
-- Business Case: Competition drives performance. This table stores a snapshot of user `security_scores` to create a `leaderboard`. It refreshes weekly or monthly. It ranks users against their peers, fostering a competitive environment where users want to improve their security posture to climb the ranks.
-- KPIs: Rank calculation speed, Participation rate.
-- Feature Reference: F291 (Sustainable Access)
CREATE TABLE IF NOT EXISTS iam.leaderboard (
    leaderboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    user_id UUID NOT NULL,
    score NUMERIC(10,2) NOT NULL,
    rank INTEGER NOT NULL,

    CONSTRAINT fk_leaderboard_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT uk_leaderboard_period UNIQUE (period_start, period_end, user_id)
);
COMMENT ON TABLE iam.leaderboard IS 'Stores snapshots of user security scores for ranking.';

-- DB463: iam.security_challenges
-- Description: Active gamified campaigns.
-- Business Case: To address specific threats, launch a challenge (e.g., "Enable MFA Week"). This table defines the `challenge_details` and tracks participation. It logs who joined and their progress. It aligns the entire workforce towards specific security goals through gamified competition.
-- KPIs: Challenge completion rate, Target achievement.
-- Feature Reference: F265 (Phishing Simulation)
CREATE TABLE IF NOT EXISTS iam.security_challenges (
    challenge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    target_audience VARCHAR(50), -- ALL, DEPARTMENT
    participation_count INTEGER DEFAULT 0,
    success_rate NUMERIC(3,2)
);
COMMENT ON TABLE iam.security_challenges IS 'Defines security gamification challenges and campaigns.';

-- DB464: iam.points_redemption
-- Description: Redeeming points for rewards.
-- Business Case: Badges are nice, but rewards are better. This table tracks `points_redemption`. Users earn points by taking security actions (Badges) and redeem them here for real rewards (Gift cards, Time off). It provides a tangible ROI for the user's engagement with security.
-- KPIs: Redemption rate, Cost per point.
-- Feature Reference: F461 (Security Badges)
CREATE TABLE IF NOT EXISTS iam.points_redemption (
    redemption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    reward_name VARCHAR(255) NOT NULL,
    points_cost INTEGER NOT NULL,
    redeemed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_redemption_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.points_redemption IS 'Tracks redemption of security gamification points for rewards.';

-- DB465: iam.team_statistics
-- Description: Aggregated scores per team/department.
-- Business Case: Gamification shouldn't be individual-only. This table aggregates stats (Average Security Score, Training Completion) by `team_id`. It allows managers to see "How is my department doing?" and fosters collective responsibility for security culture.
-- KPIs: Team engagement, Score improvement.
-- Feature Reference: F462 (Leaderboard)
CREATE TABLE IF NOT EXISTS iam.team_statistics (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_id UUID NOT NULL, -- Could link to a Department table
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    avg_security_score NUMERIC(5,2),
    total_badges_earned INTEGER,
    members_count INTEGER
);
COMMENT ON TABLE iam.team_statistics IS 'Stores aggregated gamification statistics for teams.';

-- DB466: iam.gamification_events
-- Description: Logs of point-earning actions.
-- Business Case: Every time a user does something good (MFA enable, Phish report), they earn points. This table logs these `events`. It links to the `user_id`, `action_type`, and `points_awarded`. This is the transaction ledger that drives the security economy.
-- KPIs: Event volume, Point distribution.
-- Feature Reference: F461
CREATE TABLE IF NOT EXISTS iam.gamification_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- MFA_ENABLED, REPORTED_PHISH
    points_earned INTEGER NOT NULL,
    context_json JSONB,
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_gamification_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.gamification_events IS 'Logs events where users earn gamification points.';

-- DB467: iam.badge_awards
-- Description: Visual flair for profiles.
-- Description: Gamification boosts status. This table stores `badge_awards` (virtual medals, shields) that appear on user profiles. It links to `user_id` and `challenge_id` (optional). These visual indicators signal to peers that a user is a security champion, reinforcing positive social pressure.
-- KPIs: Award distribution, Display count.
-- Feature Reference: F461
CREATE TABLE IF NOT EXISTS iam.badge_awards (
    award_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    award_name VARCHAR(100) NOT NULL,
    image_url TEXT,
    awarded_for_reason TEXT,
    awarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_awards_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.badge_awards IS 'Stores visual awards earned by users.';

-- DB468: iam.streaks
-- Description: Counters for consecutive secure actions.
-- Business Case: Consistency matters. This table tracks `streaks` (e.g., "30 days without a phishing click"). It logs the `streak_type`, `current_count`, and `last_reset_at`. Breaking a streak (clicking a phish) usually triggers a penalty or loss of points, making the streak valuable to the user.
-- KPIs: Longest streak, Reset frequency.
-- Feature Reference: F461
CREATE TABLE IF NOT EXISTS iam.streaks (
    streak_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    streak_type VARCHAR(50) NOT NULL, -- LOGIN_STREAK, NO_PHISH_CLICK
    current_count INTEGER DEFAULT 0,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT kf_streaks_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.streaks IS 'Tracks consecutive days or actions without security incidents.';

-- DB469: iam.quest_progress
-- Description: Journeys or multi-step tasks.
-- Business Case: Complex learning paths are "Quests" (e.g., "The Path to Security Hero"). This table tracks a user's progress through a `quest_template`. It records which `steps` have been completed (Step 1: Change Password, Step 2: Enable MFA). It keeps users engaged over long periods.
-- KPIs: Quest completion rate, Step abandonment rate.
-- Feature Reference: F461
CREATE TABLE IF NOT EXISTS iam.quest_progress (
    progress_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    quest_id UUID NOT NULL, -- Reference to quest template
    step_id INTEGER NOT NULL,
    step_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETE
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_quest_progress_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.quest_progress IS 'Tracks user progress through security learning quests.';

-- DB470: iam.training_level
-- Description: XP/Level based on engagement.
-- Business Case: To make gamification sticky, we use RPG elements (XP, Levels). This table stores the user's `current_level` and `current_xp`. Leveling up unlocks new permissions (e.g., cosmetic changes in app) and status, keeping users engaged for the long term.
-- KPIs: Level distribution, XP inflation rate.
-- Feature Reference: F461
CREATE TABLE IF NOT EXISTS iam.training_level (
    level_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    current_level INTEGER DEFAULT 1,
    current_xp BIGINT DEFAULT 0,
    last_leveled_up_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_level_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.training_level IS 'Stores user XP and Level in the gamification system.';

-- DB471: iam.api_sandbox_keys
-- Description: Dev keys for testing environments.
-- Business Case: Developers need to test IAM APIs in Sandboxes. This table stores sandbox-specific `api_keys`. These keys are heavily rate-limited and segregated from production keys. They allow devs to build integrations without risking production data or hitting production limits.
-- KPIs: Key turnover rate, Sandbox availability.
-- Feature Reference: F476 (Playground Deployment)
CREATE TABLE IF NOT EXISTS iam.api_sandbox_keys (
    sandbox_key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    environment VARCHAR(20) NOT NULL CHECK (environment IN ('DEV', 'STAGE', 'QA')),
    rate_limit INTEGER NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT kf_sandbox_dev FOREIGN KEY (developer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.api_sandbox_keys IS 'Stores API keys strictly for developer sandbox environments.';

-- DB472: iam.developer_onboarding
-- Description: Tracking dev education/provisioning.
-- Business Case: New devs need access but also education. This table tracks the `onboarding_checklist` for developers (e.g., "Read Secure Coding Guide", "Sign NDA"). It links to `developer_id`. It ensures that a dev cannot deploy to production until they have completed their security training and key generation.
-- KPIs: Onboarding time, Checklist completion.
-- Feature Reference: F101 (Automated Provisioning)
CREATE TABLE IF NOT EXISTS iam.developer_onboarding (
    onboarding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    task_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_dev_onboard_user FOREIGN KEY (developer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.developer_onboarding IS 'Tracks onboarding tasks for new developers.';

-- DB473: iam.api_usage_quotas
-- Description: Limits for developer accounts.
-- Business Case: Developers can write runaway code (infinite loops). This table defines `usage_quotas` for dev accounts (e.g., "Max 1000 API calls/hour"). It protects the IAM platform from accidental DDoS caused by bad code in dev sandboxes.
-- KPIs: Quota enforcement accuracy, Over-limit alerts.
-- Feature Reference: F123 (Rate Limit Rules)
CREATE TABLE IF NOT EXISTS iam.api_usage_quotas (
    quota_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    resource_path VARCHAR(255) NOT NULL, -- /v1/users
    limit_per_window INTEGER NOT NULL,
    window_minutes INTEGER NOT NULL,

    CONSTRAINT kf_dev_quota_user FOREIGN KEY (developer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.api_usage_quotas IS 'Defines usage quotas for developer accounts to prevent abuse.';

-- DB474: iam.sandbox_logs
-- Description: Audit logs for sandbox activity.
-- Business Case: Sandbox activity is still security-sensitive (test data might be real-looking). This table logs `sandbox_events`. It tracks which API endpoint was hit, by which `developer_id`, with what `request_payload`. It helps debug integration issues and detects if devs are testing against production endpoints (shadow IT).
-- KPIs: Log retention, Event classification.
-- Feature Reference: F043 (Shadow IT Discovery)
CREATE TABLE IF NOT EXISTS iam.sandbox_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    method VARCHAR(10) NOT NULL, -- GET, POST, PUT
    path VARCHAR(255) NOT NULL,
    status_code INTEGER,
    latency_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_sandbox_log_dev FOREIGN KEY (developer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.sandbox_logs IS 'Stores audit logs for developer sandbox activity.';

-- DB475: iam.rate_limit_buckets
-- Description: Token bucket algorithm state.
-- Business Case: Rate limiting needs an algorithm. Token Bucket is a popular choice. This table stores the `bucket_tokens` and `last_refill_time` for a specific user. It allows the API Gateway to check the bucket, subtract a token, and allow the request without hitting a database for every single request (high performance).
-- KPIs: Bucket accuracy, Refill latency.
-- Feature Reference: F098 (DoS Resilience)
CREATE TABLE IF NOT EXISTS iam.rate_limit_buckets (
    bucket_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    tokens_remaining INTEGER DEFAULT 0,
    last_refill TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    window_size_seconds INTEGER NOT NULL,

    CONSTRAINT kf_bucket_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.rate_limit_buckets IS 'Stores the state of Token Bucket rate limiters.';

-- DB476: iam.playground_deployment
-- Description: ephemeral test environments.
-- Business Case: Developers need to test full flows (User -> Register -> MFA). This table manages `playground_deployment` configs. It provisions a temporary subdomain (e.g., `dev-123.pari.net`) and sets up the auth database state for that environment, which can be torn down later.
-- KPIs: Deployment speed, Environment isolation.
-- Feature Reference: F471 (Sandbox Keys)
CREATE TABLE IF NOT EXISTS iam.playground_deployment (
    deployment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    environment_url VARCHAR(255) NOT NULL,
    db_schema_version VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_playground_dev FOREIGN KEY (developer_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.playground_deployment IS 'Manages ephemeral playground deployments for testing.';

-- DB477: iam.documentation_access
-- Description: Tracking who read sensitive docs.
-- Business Case: API documentation (Swagger, PDFs) for sensitive features (Admin APIs) should be restricted. This table logs access to documentation artifacts. It ensures that only authorized developers can view documentation for high-privilege endpoints, reducing the risk of exploit knowledge leakage.
-- KPIs: Document coverage, Access authorization rate.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.documentation_access (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    doc_id VARCHAR(100) NOT NULL,
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_docs_access_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.documentation_access IS 'Logs access to sensitive API documentation.';

-- DB478: iam.code_example_usage
-- Description: Copy-paste metrics for code samples.
-- Business Case: Developers love code snippets. This table tracks usage of `code_snippets` from the dev portal. It helps identify which code examples are most popular or misunderstood, guiding technical writers to improve documentation and prevent common integration bugs.
-- KPIs: Snippet usage rank, Copy success.
-- Feature Reference: F477 (Documentation)
CREATE TABLE IF NOT EXISTS iam.code_example_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snippet_id VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL,
    lang VARCHAR(20) NOT NULL, -- PYTHON, JAVASCRIPT
    copied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_code_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.code_example_usage IS 'Tracks usage of code examples provided in the dev portal.';

-- DB479: iam.debug_token_management
-- Description: Long-lived tokens for debugging.
-- Business Case: Debugging production auth is hard (short-lived tokens). This table manages `debug_tokens` which have extended TTL (e.g., 24 hours). They are strictly controlled, require privileged access to generate, and are audited heavily. They allow deep debugging without constantly re-authing.
-- KPIs: Token session duration, Revocation audit.
-- Feature Reference: F154 (Access Tokens)
CREATE TABLE IF NOT EXISTS iam.debug_token_management (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    authorized_by UUID NOT NULL,
    target_user_id UUID NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_debug_auth_by FOREIGN KEY (authorized_by) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT kf_debug_target_user FOREIGN KEY (target_user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.debug_token_management IS 'Stores extended-duration tokens for production debugging.';

-- DB480: iam.developer_feedback
-- Description: Feedback on APIs/Docs.
-- Business Case: Developers are the primary customers of the IAM API. This table captures their `feedback` (Bugs, UX issues, Feature Requests). It links to specific `api_version` or `doc_id`. This feedback loop is essential for prioritizing the product roadmap for the IAM platform itself.
-- KPIs: Feedback volume, Response time.
-- Feature Reference: F106 (User Feedback)
CREATE TABLE IF NOT EXISTS iam.developer_feedback (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    category VARCHAR(50) NOT NULL, -- BUG, FEATURE, DOCS
    content TEXT NOT NULL,
    api_version VARCHAR(20),
    status VARCHAR(20) DEFAULT 'OPEN',
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_dev_feedback_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.developer_feedback IS 'Captures developer feedback on APIs and documentation.';

-- DB481: iam.event_bus_messages
-- Description: Audit logs of Event Bus (Kafka/Pulsar) messages.
-- Business Case: IAM events must be shared with other systems (Analytics, Billing). This table stores the `message_id` and `payload` published to the Event Bus. It acts as a buffer or audit trail ensuring that every event published can be traced back to the original context, crucial for distributed system debugging.
-- KPIs: Message throughput, Ordering guarantee.
-- Feature Reference: F234 (CDC/User Event Stream)
CREATE TABLE IF NOT EXISTS iam.event_bus_messages (
    message_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(100) NOT NULL,
    partition_key VARCHAR(255) NOT NULL,
    offset BIGINT NOT NULL,
    payload_json JSONB,
    published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.event_bus_messages IS 'Logs messages published to the Event Bus.';

-- DB482: iam.dead_letter_queue
-- Description: Failed event processing.
-- Business Case: Sometimes downstream services are down. This table stores `dead_letter` messages that failed to process. It stores the `original_payload` and `error_reason`. It ensures that we don't lose critical security events (like "User Locked") just because a report server was temporarily down.
-- KPIs: Queue size, Re-processing success rate.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.dead_letter_queue (
    dead_letter_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_topic VARCHAR(100) NOT NULL,
    payload_json JSONB NOT NULL,
    failure_reason TEXT NOT NULL,
    retry_count INTEGER DEFAULT 0,
    enqueued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.dead_letter_queue IS 'Stores messages that failed to be processed by subscribers.';

-- DB483: iam.subscription_management
-- Description: Pub/Sub subscription state.
-- Business Case: Services subscribe to event topics. This table manages `subscriptions`. It links a `subscriber_id` to `topics`. It allows the IAM platform to push config updates or revocations to services instantly via Pub/Sub, rather than relying on polling.
-- KPIs: Subscription latency, Consistency.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.subscription_management (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subscriber_id VARCHAR(100) NOT NULL,
    topic_name VARCHAR(100) NOT NULL,
    qos_level INTEGER DEFAULT 1,
    last_confirmed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.subscription_management IS 'Manages Pub/Sub subscriptions to event topics.';

-- DB484: iam.webhook_delivery_status
-- Description: Detailed logs of webhook attempts.
-- Business Case: Webhooks (DB097) are tricky (Network issues). This table stores detailed `delivery_attempts`. It tracks `http_status_code`, `latency`, and `retry_count`. It provides the granular reliability data needed to tune the webhook service for external partners.
-- KPIs: Delivery success rate, Average latency.
-- Feature Reference: F097 (Webhooks)
CREATE TABLE IF NOT EXISTS iam.webhook_delivery_status (
    delivery_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    webhook_id UUID NOT NULL,
    event_payload_hash VARCHAR(255) NOT NULL,
    response_code INTEGER,
    latency_ms INTEGER,
    attempt_number INTEGER NOT NULL,
    delivered_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_webhook_delivery_hook FOREIGN KEY (webhook_id) REFERENCES iam.webhooks(hook_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.webhook_delivery_status IS 'Stores the status and retries for webhook deliveries.';

-- DB485: iam.event_replay_requests
-- Description: Re-processing past events.
-- Business Case: "Oops, the logic for blocking users was wrong". This table manages `replay_requests`. It identifies a range of events (from DB009 or Event Bus) and schedules a re-run. It allows for correcting mistakes in automated decisions (e.g., fixing false positives) by replaying the context.
-- KPIs: Replay accuracy, Conflict detection.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.event_replay_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_range_start TIMESTAMP WITH TIME ZONE NOT NULL,
    event_range_end TIMESTAMP WITH TIME ZONE NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    requested_by UUID NOT NULL,
    replayed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_replay_requestor FOREIGN KEY (requested_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.event_replay_requests IS 'Manages requests to replay historical events through the system.';

-- DB486: iam.schema_registry
-- Description: Evolution of data schemas.
-- Business Case: Databases evolve. This table registers `schema_versions` for all data products. It maps `version_hash` to `definition`. Consumers (API readers, Analytics) check this table to understand if the data structure (e.g., "User object") has changed and requires a code update.
-- KPIs: Version compatibility, Registration latency.
-- Feature Reference: F487 (Message Transformations)
CREATE TABLE IF NOT EXISTS iam.schema_registry (
    schema_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    product_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,
    schema_definition JSONB NOT NULL,
    introduced_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deprecated_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.schema_registry IS 'Registry for schema versions of different data products.';

-- DB487: iam.message_transformations
-- Description: Converting event formats.
-- Business Case: Producer A sends JSON, Consumer B needs Avro. This table stores `transformation_rules`. It defines input format, output format, and `mapping_logic`. The event bus engine applies this logic to make systems interoperable without code changes in the producers/consumers.
-- KPIs: Transformation success rate, Latency overhead.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.message_transformations (
    transform_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    input_format VARCHAR(50) NOT NULL,
    output_format VARCHAR(50) NOT NULL,
    mapping_logic JSONB NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
COMMENT ON TABLE iam.message_transformations IS 'Defines rules to transform messages between different formats.';

-- DB488: iam.idempotency_keys
-- Description: Ensuring exactly-once processing.
-- Business Case: Re-processing messages (Replay) can cause duplicate actions (e.g., "Welcome email sent twice"). This table stores `idempotency_keys` (hash of user_id + event_id). The system checks this table before processing. If the key exists, the message is skipped. This ensures consistency even during retries.
-- KPIs: Duplicate detection rate, Storage usage.
-- Feature Reference: F485 (Event Replay)
CREATE TABLE IF NOT EXISTS iam.idempotency_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.idempotency_keys IS 'Stores keys to ensure exactly-once message processing.';

-- DB489: iam.confluent_state
-- Description: Global ordering for streams.
-- Business Case: Kafka topics need a Confluent state. This table caches the `confluent_state` (Offsets) for consumer groups. It allows the system to resume consumption from exactly where it left off, even after a crash or upgrade, ensuring zero data loss.
-- KPIs: State synchronization time, Commit latency.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.confluent_state (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(100) NOT NULL,
    consumer_group VARCHAR(100) NOT NULL,
    partition INTEGER NOT NULL,
    offset BIGINT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.confluent_state IS 'Caches the consumption state (offsets) for Kafka topics.';

-- DB490: iam.consumer_lag_metrics
-- Description: Monitoring consumer health.
-- Business Case: Lag indicates if consumers are too slow. This table stores `consumer_lag` metrics. It alerts if a consumer falls behind the producer significantly (e.g., "Audit logs are piling up"). This allows the platform to scale consumers horizontally to keep up with security event volume.
-- KPIs: Lag trend, Scale-up time.
-- Feature Reference: F481 (Event Bus)
CREATE TABLE IF NOT EXISTS iam.consumer_lag_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(100) NOT NULL,
    consumer_group VARCHAR(100) NOT NULL,
    lag_offset BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.consumer_lag_metrics IS 'Tracks how far behind consumers are from the latest event.';

-- DB491: iam.edge_device_registration
-- Description: Registering Edge nodes.
-- Business Case: In Edge computing, edge routers/fog nodes run local IAM logic. This table registers these `edge_devices`. It links to a `deployment_id`. The central system pushes policies (DB497) to these devices, ensuring consistent policy enforcement at the edge even if the WAN link is down.
-- KPIs: Device registration count, Sync health.
-- Feature Reference: F269 (Edge Gateway Sync)
CREATE TABLE IF NOT EXISTS iam.edge_device_registration (
    device_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_name VARCHAR(100) NOT NULL,
    edge_type VARCHAR(50) NOT NULL, -- ROUTER, GATEWAY, IOT_HUB
    hardware_spec JSONB,
    last_sync_timestamp TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'ONLINE'
);
COMMENT ON TABLE iam.edge_device_registration IS 'Registers edge computing devices in the IAM network.';

-- DB492: iam.fog_compute_policies
-- Description: Local policies for fog nodes.
-- Business Case: Fog nodes need to react instantly (<1ms). They cannot query the cloud DB. This table stores lightweight `local_policies` that are pushed to the edge. The edge engine enforces these policies locally for latency-sensitive operations (factory access).
-- KPIs: Policy deployment latency, Local enforcement accuracy.
-- Feature Reference: F491 (Edge Device)
CREATE TABLE IF NOT EXISTS iam.fog_compute_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    policy_scope JSONB NOT NULL, -- Local context (e.g., Line 1 only)
    version INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT kf_fog_policy_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.fog_compute_policies IS 'Defines local access policies for Fog/Edge nodes.';

-- DB493: iam.edge_sync_logs
-- Description: Audit of syncs to edge.
-- Business Case: Syncing policies to edge devices must be audited. This table logs every `sync_event` (Update, Delete). It records success/failure and `bytes_transferred`. It helps debug issues where an edge device might be applying policies incorrectly due to sync failures.
-- KPIs: Sync success rate, Bandwidth usage.
-- Feature Reference: F269 (Edge Gateway Sync)
CREATE TABLE IF NOT EXISTS iam.edge_sync_logs (
    sync_log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    action VARCHAR(20) NOT NULL, -- PUSH, FETCH, VERIFY
    status VARCHAR(20),
    message TEXT,
    sync_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_edge_sync_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.edge_sync_logs IS 'Logs synchronization events between cloud and edge devices.';

-- DB494: iam.disconnected_mode_auth
-- Description: Handling auth without WAN.
-- Business Case: If the WAN link dies, edge nodes must still allow auth (or deny it). This table stores `disconnected_mode_configs`. It determines if a device can "Fail Open" (allow cached users only) or "Fail Closed" (total denial) during isolation.
-- KPIs: Availability in disconnected mode, Security posture.
-- Feature Reference: F002 (Offline Tokens)
CREATE TABLE IF NOT EXISTS iam.disconnected_mode_auth (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    mode VARCHAR(20) NOT NULL CHECK (mode IN ('FAIL_OPEN', 'FAIL_CLOSED', 'CACHED_ONLY')),
    cached_user_limit INTEGER,
    enabled_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_disc_auth_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.disconnected_mode_auth IS 'Defines behavior during WAN disconnection.';

-- DB495: iam.edge_health_heartbeat
-- Description: Pings from edge devices.
-- Business Case: We need to know if an edge node is alive. This table stores `heartbeat` pings. It tracks `cpu_usage`, `memory_usage`, and `latency`. A missed heartbeat triggers an alert and potentially pushes a "shut down" command to the device if it's behaving erratically.
-- KPIs: Heartbeat latency, Device uptime.
-- Feature Reference: F450 (System Health)
CREATE TABLE IF NOT EXISTS iam.edge_health_heartbeat (
    heartbeat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    sequence_number BIGINT NOT NULL,
    cpu_usage NUMERIC(3,2),
    memory_usage INTEGER,
    uptime_seconds BIGINT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_edge_hb_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.edge_health_heartbeat IS 'Stores health telemetry from edge devices.';

-- DB496: iam.cache_invalidationation_requests
-- Description: Forcing edge nodes to clear cache.
-- Business Case: When a policy changes, cached data on the edge is stale. This table stores `invalidation_requests`. It broadcasts a command to edge nodes to clear their policy cache. It ensures that a revocation takes effect instantly, even on edge devices.
-- KPIs: Invalidation broadcast speed, Acknowledgment rate.
-- Feature Reference: F497 (Policy Backlog)
CREATE TABLE IF NOT EXISTS iam.cache_invalidationation_requests (
    invalidation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    target_edge_type VARCHAR(50), -- ALL, ROUTERS, SPECIFIC_ID
    reason VARCHAR(255),
    broadcast_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledgements_count INTEGER DEFAULT 0
);
COMMENT ON TABLE iam.cache_invalidationation_requests IS 'Manages cache invalidation signals sent to edge nodes.';

-- DB497: iam.policy_update_backlog
-- Description: Syncing updates when edge is offline.
-- Business Case: Edge devices can be offline for days. This table stores a `backlog` of policy updates waiting for the device to come online. When the device reconnects, it pulls updates from this table. This ensures eventual consistency without requiring constant connectivity.
-- KPIs: Backlog size, Recovery time.
-- Feature Reference: F493 (Edge Sync Logs)
CREATE TABLE IF NOT EXISTS iam.policy_update_backlog (
    backlog_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    operation VARCHAR(20) NOT NULL, -- CREATE, UPDATE, DELETE
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    synced_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_backlog_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.policy_update_backlog IS 'Queues policy updates for devices currently offline.';

-- DB498: iam.local_event_journal
-- Description: Store and forward for edge nodes.
-- Business Case: Edge nodes must store events locally. This table represents the `journal` on the edge. It stores events (Access Log) locally until they can be forwarded to the cloud. It provides resiliency for logging and ensures the audit trail is never lost due to network blips.
-- KPIs: Journal storage usage, Forward success rate.
-- Feature Reference: F493 (Edge Sync Logs)
CREATE TABLE IF NOT EXISTS iam.local_event_journal (
    journal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    event_category VARCHAR(50) NOT NULL, -- AUTH, AUDIT, CONFIG
    event_json JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    forwarded_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_journal_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.local_event_journal IS 'Stores events locally on edge devices before cloud sync.';

-- DB499: iam.bandwidth_optimization
-- Description: Compressing events for low-bandwidth links.
-- Business Case: Edge links (Satellite, 4G) are expensive. This table stores `bandwidth_profiles`. It determines which events should be compressed or aggregated before sending. It optimizes the cost and speed of syncing from edge to cloud.
-- KPIs: Data compression ratio, Cost savings.
-- Feature Reference: F498 (Local Journal)
CREATE TABLE IF NOT EXISTS iam.bandwidth_optimization (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    edge_device_id UUID NOT NULL,
    data_type VARCHAR(50) NOT NULL,
    compression_algorithm VARCHAR(50), -- ZSTD, GZIP, SNAPPY
    estimated_compression_ratio NUMERIC(3,2),

    CONSTRAINT kf_bandwidth_device FOREIGN KEY (edge_device_id) REFERENCES iam.edge_device_registration(device_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.bandwidth_optimization IS 'Configures compression strategies for edge-to-cloud sync.';

-- DB500: iam.edge_location_estimates
-- Description: Triangulation / Location Estimates.
-- Business Case: Edge devices might lack GPS. This table stores `location_estimates` (e.g., "Device A is near Device B"). It allows the system to infer location based on network topology (e.g., "If connected to Switch X, user is in Building A").
-- KPIs: Estimation accuracy, Update frequency.
-- Feature Reference: F013 (Geo-Fencing)
CREATE TABLE IF NOT EXISTS iam.edge_location_estimates (
    estimate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_identifier VARCHAR(255) NOT NULL, -- Edge Node
    estimated_zone VARCHAR(100),
    confidence NUMERIC(3,2),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.edge_location_estimates IS 'Stores inferred location estimates for edge devices.';

-- DB501: iam.executive_dashboards
-- Description: Pre-calculated KPIs for C-Suite.
-- Business Case: Executives don't need raw logs. This table stores aggregated `executive_metrics` (e.g., "Critical Vulnerabilities Open", "Compliance Score", "Weekly Incidents"). It refreshes hourly, providing a high-level view of security posture for decision-makers without overwhelming them with data.
-- KPIs: Dashboard refresh latency, Metric accuracy.
-- Feature Reference: F432 (Dashboard)
CREATE TABLE IF NOT EXISTS iam.executive_dashboards (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(15,2),
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    trend_direction VARCHAR(10) -- UP, DOWN, STABLE
);
COMMENT ON TABLE iam.executive_dashboards IS 'Stores aggregated metrics for executive dashboards.';

-- DB502: iam.compliance_visualizations
-- Description: Data structures for visual graphs.
-- Business Case: Visuals are key for communicating risk. This table stores `graph_data` (Nodes, Edges) for compliance visualizations (e.g., "Who has access to GDPR data?"). It allows the frontend to render interactive topology maps for auditors.
-- KPIs: Render performance, Data freshness.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.compliance_visualizations (
    viz_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    viz_name VARCHAR(255) NOT NULL,
    graph_structure JSONB NOT NULL,
    snapshot_date DATE NOT NULL,
    created_by UUID NOT NULL,

    CONSTRAINT kf_viz_user FOREIGN KEY (created_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.compliance_visualizations IS 'Stores snapshot data for compliance graphs.';

-- DB503: iam.security_posture_scoring
-- Description: Organizational maturity score.
-- Business Case: How secure is the org? This table stores the calculated `security_posture_score`. It aggregates hundreds of metrics (Vulns, Training, Incidents) into a single score (0-1000). It provides a benchmark for maturity levels (CMMI levels) and tracks improvement over quarters.
-- KPIs: Score stability, Improvement velocity.
-- Feature Reference: F501 (Exec Dashboards)
CREATE TABLE IF NOT EXISTS iam.security_posture_scoring (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    score_period VARCHAR(20) NOT NULL, -- Q1, Q2, Q3, Q4
    overall_score INTEGER NOT NULL,
    people_score INTEGER,
    process_score INTEGER,
    technology_score INTEGER,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.security_posture_scoring IS 'Stores organizational security maturity scores.';

-- DB504: iam.risk_velocity
-- Description: Speed of change in risk profile.
-- Business Case: Static risk scores hide trends. This table tracks `risk_velocity` (Rate of change). A sudden spike in user risk (e.g., rapid permission gain) is a high-velocity event indicating potential compromise. It focuses on the *movement* of risk rather than just the current level.
-- KPIs: Velocity calculation accuracy, Alert frequency.
-- Feature Reference: F054 (Risk Scores)
CREATE TABLE IF NOT EXISTS iam.risk_velocity (
    velocity_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    risk_delta NUMERIC(5,2), -- Change in score
    time_window_minutes INTEGER NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_velocity_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.risk_velocity IS 'Tracks the rate of change in user risk scores.';

-- DB505: iam.threat_landscape
-- Description: Mapping external threats to internal posture.
-- Business Case: You are only as safe as the environment. This table links `external_threats` (e.g., "Active Ransomware in region") to internal `mitigation_status`. It helps executives visualize "What is coming for us?" and whether we are prepared.
-- KPIs: Threat intel freshness, Mitigation coverage.
-- Feature Reference: F208 (Threat Intel)
CREATE TABLE IF NOT EXISTS iam.threat_landscape (
    threat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_region VARCHAR(100),
    internal_impact_score NUMERIC(5,2),
    mitigation_plan TEXT,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.threat_landscape IS 'Maps external cyber threats to internal mitigation status.';

-- DB506: iam.forensic_queries
-- Description: Saved search queries for investigations.
-- Business Case: Forensic analysts run the same queries often. This table stores `saved_queries`. It allows analysts to quickly reload a complex filter (e.g., "All Admin access attempts from IP Range X in last 30 days") without rebuilding the query. It improves investigation efficiency.
-- KPIs: Query reuse count, Execution time reduction.
-- Feature Reference: F311 (Threat Hunting)
CREATE TABLE IF NOT EXISTS iam.forensic_queries (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    query_definition JSONB NOT NULL,
    last_run_at TIMESTAMP WITH TIME ZONE,
    result_count BIGINT,

    CONSTRAINT kf_forensic_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.forensic_queries IS 'Stores saved search queries for forensic investigations.';

-- DB507: iam.audit_trail_queries
-- Description: specialized queries for compliance.
-- Business Case: Auditors need specific views of the audit trail. This table stores `compliance_queries`. Examples include "Show me all data exports approved by User X". It automates the retrieval of evidence for audits, significantly reducing the cost of manual inspection.
-- KPIs: Query complexity, Result export speed.
-- Feature Reference: F015 (Audit Logs)
CREATE TABLE IF NOT EXISTS iam.audit_trail_queries (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID NOT NULL, -- Link to compliance report
    query_description TEXT,
    query_sql TEXT NOT NULL,
    execution_time_ms INTEGER,
    returned_row_count BIGINT,
    created_by UUID NOT NULL,

    CONSTRAINT kf_audit_query_report FOREIGN KEY (report_id) REFERENCES iam.compliance_reports(report_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.audit_trail_queries IS 'Stores specialized queries used to generate compliance reports.';

-- DB508: iam.report_subscriptions
-- Description: Scheduled report emails.
-- Business Case: Executives and Managers need regular reports. This table manages `report_subscriptions`. It links `user_id` to a `report_template`. The scheduler runs the query and emails the result. It ensures proactive visibility without manual intervention.
-- KPIs: Delivery success rate, Schedule adherence.
-- Feature Reference: F060 (Compliance)
CREATE TABLE IF NOT EXISTS iam.report_subscriptions (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    report_id UUID NOT NULL,
    frequency VARCHAR(20) NOT NULL, -- DAILY, WEEKLY, MONTHLY
    day_of_week INTEGER,
    next_run_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT kf_sub_user FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE,
    CONSTRAINT kf_sub_report FOREIGN KEY (report_id) REFERENCES iam.compliance_reports(report_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.report_subscriptions IS 'Manages automatic subscriptions to security reports.';

-- DB509: iam.custom_report_templates
-- Description: User-defined reports.
-- Business Case: Standard reports don't fit all needs. This table stores `custom_report_templates`. Users define their own SQL/parameters. It allows for niche reporting (e.g., "Show me logins from 'Building B' on Weekends") tailored to specific roles or projects.
-- KPIs: Template usage count, Report generation time.
-- Feature Reference: F060 (Compliance)
CREATE TABLE IF NOT EXISTS iam.custom_report_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    sql_query TEXT NOT NULL,
    parameters_json JSONB,
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_custom_report_user FOREIGN KEY (created_by) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.custom_report_templates IS 'Stores user-defined report templates for ad-hoc analysis.';

-- DB510: iam.data_warehouse_exports
-- Description: ETL jobs to data warehouse.
-- Business Case: Deep analytics require a Data Warehouse. This table manages `etl_jobs`. It extracts data from IAM transaction tables to the DW. It tracks `volume`, `success_rate`, and `duration`. It ensures the data warehouse is up-to-date for long-term trend analysis.
-- KPIs: ETL freshness, Error rate.
-- Feature Reference: F016 (Access Stats)
CREATE TABLE IF NOT EXISTS iam.data_warehouse_exports (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    start_timestamp TIMESTAMP WITH TIME ZONE,
    end_timestamp TIMESTAMP WITH TIME ZONE,
    rows_exported BIGINT,
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, COMPLETED, FAILED
    error_message TEXT
);
COMMENT ON TABLE iam.data_warehouse_exports IS 'Tracks ETL job exports to the data warehouse.';

-- DB521: iam.auth_energy_metrics
-- Description: Joules of energy per auth event.
-- Business Case: Even digital operations consume energy. This table estimates the `energy_consumed` (Joules) for different auth methods. It compares Password (low cost) vs. Biometric (higher cost). It allows the platform to optimize for "Green Auth" modes.
-- KPIs: Energy per auth, Cost per transaction.
-- Feature Reference: F523 (Carbon Footprint)
CREATE TABLE IF NOT EXISTS iam.auth_energy_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auth_method VARCHAR(50) NOT NULL,
    estimated_joules NUMERIC(10,2),
    cpu_cycles_estimate BIGINT,
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.auth_energy_metrics IS 'Stores energy consumption metrics for authentication methods.';

-- DB522: iam.green_auth_methods
-- Description: Prioritizing low-carbon methods.
-- Business Case: Not all auth is equal. This table ranks `auth_methods` by their `green_score`. The system can prompt users to use a "Greener" method (like local biometrics) if they are in a region with high carbon intensity, reducing the cloud compute footprint of auth checks.
-- KPIs: Green adoption rate, Carbon reduction.
-- Feature Reference: F521 (Auth Energy)
CREATE TABLE IF NOT EXISTS iam.green_auth_methods (
    method_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    method_name VARCHAR(50) NOT NULL,
    carbon_intensity_index NUMERIC(3,2), -- Lower is better
    estimated_cost_per_auth NUMERIC(10,4),
    is_preferred BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.green_auth_methods IS 'Ranks authentication methods by their environmental impact.';

-- DB523: iam.carbon_footprint_tracking
-- Description: Total carbon footprint of IAM.
-- Business Case: Calculating the total carbon cost of the IAM platform. This table aggregates `carbon_footprint` per `service` or `tenant`. It sums up energy from Auth, DB, and API components. It supports Corporate Social Responsibility (CSR) reporting.
-- KPIs: Footprint accuracy, Reduction goal adherence.
-- Feature Reference: F522 (Green Auth)
CREATE TABLE IF NOT EXISTS iam.carbon_footprint_tracking (
    footprint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    total_co2_kg NUMERIC(15,2),
    offset_credits_purchased NUMERIC(15,2),
    net_footprint NUMERIC(15,2),

    CONSTRAINT kf_carbon_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.carbon_footprint_tracking IS 'Tracks the carbon footprint of IAM operations.';

-- DB524: iam.renewable_energy_certificates
-- Description: Proving green energy usage.
-- Business Case: "Green" needs proof. This table stores `energy_certificates` from the cloud provider. It proves that the infrastructure used for a specific period was powered by renewables. It allows tenants to claim carbon credits (DB523 offset).
-- KPIs: Certificate validity, Coverage percentage.
-- Feature Reference: F523
CREATE TABLE IF NOT EXISTS iam.renewable_energy_certificates (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider VARCHAR(100) NOT NULL,
    region VARCHAR(100),
    energy_source_type VARCHAR(50) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    certificate_url TEXT
);
COMMENT ON TABLE iam.renewable_energy_certificates IS 'Stores Renewable Energy Certificates (RECs) for verification.';

-- DB525: iam.hardware_efficiency_ratings
-- Description: Efficiency of underlying hardware.
-- Business Case: Newer hardware is more efficient. This table stores `efficiency_ratings` for servers/CPUs (Performance per Watt). The IAM system can schedule jobs to run during periods when the grid is "greener" or on more efficient hardware instances to optimize the carbon/energy ratio of IAM operations.
-- KPIs: Rating accuracy, Cost per Watt.
-- Feature Reference: F521 (Auth Energy)
CREATE TABLE IF NOT EXISTS iam.hardware_efficiency_ratings (
    rating_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hardware_sku VARCHAR(100) NOT NULL,
    performance_per_watt NUMERIC(10,2),
    efficiency_grade VARCHAR(20), -- A+, A, B, C, D-
    last_benchmarked TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.hardware_efficiency_ratings IS 'Stores power efficiency ratings for hardware.';

-- DB526: iam.digital_cleanup_jobs
-- Description: Deleting useless data to save energy.
-- Business Case: Storing data costs energy (E-waste). This table manages `cleanup_jobs` that archive or delete old data (e.g., logs from 5 years ago). By actively managing storage, the platform reduces the energy required to cool the data centers and spin up drives.
-- KPIs: Data volume reduction, Energy saved (kWh).
-- Feature Reference: F103 (Data Retention)
CREATE TABLE IF NOT EXISTS iam.digital_cleanup_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    cleanup_criteria JSONB NOT NULL,
    data_volume_gb_before NUMERIC(10,2),
    data_volume_gb_after NUMERIC(10,2),
    energy_saved_est_kwh NUMERIC(15,2),
    status VARCHAR(20) DEFAULT 'SCHEDULED',
    executed_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.digital_cleanup_jobs IS 'Schedules jobs to delete obsolete data to save energy.';

-- DB527: iam.sustainability_dashboard_data
-- Description: KPIs for sustainability.
-- Business Case: Green KPIs are becoming key business metrics. This table stores `sustainability_metrics` (PUE Reduction, Renewable %). It powers the Green Dashboard for the CTO/Operations team to demonstrate compliance with environmental goals.
-- KPIs: Dashboard uptime, Real-time data accuracy.
-- Feature Reference: F523 (Carbon Footprint)
CREATE TABLE IF NOT EXISTS iam.sustainability_dashboard_data (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(15,2),
    unit VARCHAR(50), -- kWh, CO2e, Percentage
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.sustainability_dashboard_data IS 'Stores metrics for the sustainability dashboard.';

-- DB528: iam.e_waste_monitoring
-- Description: Reducing power from idle resources.
-- Business Case: Idle CPUs still consume power. This table monitors `e_waste` (Idle resources). It identifies resources (DB connections, API servers) that are provisioned but unused, allowing automated downscaling to save energy.
-- KPIs: Idle time detection speed, Savings realized.
-- Feature Reference: F526 (Digital Cleanup)
CREATE TABLE IF NOT EXISTS iam.e_waste_monitoring (
    monitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- DATABASE_SERVER, COMPUTE_INSTANCE
    resource_id VARCHAR(255) NOT NULL,
    idle_duration_seconds BIGINT,
    wastage_watts_estimate NUMERIC(10,2),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.e_waste_monitoring IS 'Monitors idle resources to identify energy waste.';

-- DB529: iam.lifecycle_energy_cost
-- Description: Cost of running IAM over time.
-- Business Case: ESG reporting requires Total Cost of Ownership. This table tracks the `lifecycle_energy_cost` of the IAM platform. It aggregates the energy cost of running the platform for each tenant, associating carbon output with financial spend.
-- KPIs: Cost attribution accuracy, Budget variance.
-- Feature Reference: F523 (Carbon Footprint)
CREATE TABLE IF NOT EXISTS iam.lifecycle_energy_cost (
    cost_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    total_kwh_used NUMERIC(15,2),
    energy_cost_currency NUMERIC(15,2),
    carbon_tax_paid NUMERIC(15,2),

    CONSTRAINT kf_lifecycle_cost_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.lifecycle_energy_cost IS 'Tracks the energy cost of running IAM operations.';

-- DB530: iam.green_compliance_audit
-- Description: Auditing green claims.
-- Business Case: Green claims must be verified. This table stores `green_compliance_audit` records. It validates that the purchased renewable credits (DB523) match the actual energy usage. It prevents "Greenwashing" by ensuring claims are backed by math and certificates.
-- KPIs: Audit success rate, Certificate verification.
-- Feature Reference: F524 (Renewable Certs)
CREATE TABLE IF NOT EXISTS iam.green_compliance_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_id UUID NOT NULL,
    audit_year INTEGER NOT NULL,
    green_score NUMERIC(5,2),
    credits_purchased BIGINT,
    credits_used BIGINT,
    findings TEXT,
    audited_by UUID NOT NULL,
    audited_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_green_audit_tenant FOREIGN KEY (tenant_id) REFERENCES iam.tenant_configs(tenant_id) ON DELETE CASCADE,
    CONSTRAINT kf_green_auditor FOREIGN KEY (audited_by) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.green_compliance_audit IS 'Audits environmental compliance and carbon credit usage.';

-- DB531: iam.hybrid_encryption_keys
-- Description: Combining Classical + Post-Quantum.
-- Business Case: Transitioning to PQC takes time. This table manages `hybrid_encryption`. It encrypts data using both a classical algorithm (for now) and a PQC algorithm (for later) in a dual-envelope format. It ensures that data is secure today and ready for the future without re-encrypting everything immediately.
-- KPIs: Key derivation success, Performance overhead.
-- Feature Reference: F534 (Algorithm Transition)
CREATE TABLE IF NOT EXISTS iam.hybrid_encryption_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_id UUID NOT NULL, -- Reference to protected data
    classical_key_id VARCHAR(100), -- Reference to IAM Encryption Keys
    pqc_key_id VARCHAR(100), -- Reference to Quantum Keys
    encapsulation_format VARCHAR(50), -- HYBRID, FOWARD_SECURE
    transition_date DATE,

    CONSTRAINT kf_hybrid_data FOREIGN KEY (data_id) REFERENCES iam.data_catalog_objects(object_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.hybrid_encryption_keys IS 'Manages keys for hybrid encryption (Classical + Quantum).';

-- DB532: iam.lattice_based_signatures
-- Description: Lattice cryptography (Kyber/Dilithium) keys.
-- Business Case: Lattice-based crypto (Kyber-718) is a primary candidate for PQC. This table stores `lattice_keys`. It links them to specific data categories. These keys are large and require special handling, distinct from standard RSA keys.
-- KPIs: Key generation latency, Signature verification speed.
-- Feature Reference: F081 (Quantum Resistant)
CREATE TABLE IF NOT EXISTS iam.lattice_based_signatures (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    algorithm_name VARCHAR(50) NOT NULL, -- KYBER718, DILITHIUM5
    key_size_bits INTEGER,
    public_key_pem TEXT NOT NULL,
    private_key_enc BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.lattice_based_signatures IS 'Stores Lattice-based (Post-Quantum) cryptographic keys.';

-- DB533: iam.quantum_key_escrow
-- Description: Splitting quantum keys.
-- Business Case: Quantum keys are powerful; if stolen, they decrypt everything. This table implements Shamir's Secret Sharing for Quantum keys. It stores `shards` of the master key. Accessing the master key requires combining these shards. It ensures that a single point of compromise doesn't reveal the key.
-- KPIs: Shard reconstruction success, Access latency.
-- Feature Reference: F210 (Key Escrow)
CREATE TABLE IF NOT EXISTS iam.quantum_key_escrow (
    shard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    master_key_id VARCHAR(100) NOT NULL,
    shard_number INTEGER NOT NULL CHECK (shard_number > 0),
    shard_holder_id UUID NOT NULL, -- The custodian
    shard_hash VARCHAR(255) NOT NULL,

    CONSTRAINT kf_qk_holder FOREIGN KEY (shard_holder_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.quantum_key_escrow IS 'Stores Shamir secret shards for Quantum keys.';

-- DB534: iam.algorithm_transition_plan
-- Description: Roadmap to PQC.
-- Business Case: You can't switch to PQC overnight. This table defines the `transition_plan`. It maps `data_owner` -> `target_algorith` (e.g., "HR Data -> Dilithium5") and sets the `migration_date`. It orchestrates a gradual, risk-managed migration path to quantum-safe algorithms.
-- KPIs: Plan adherence, Migration completion rate.
-- Feature Reference: F537 (PQC Roadmap)
CREATE TABLE IF NOT EXISTS iam.algorithm_transition_plan (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_owner VARCHAR(255) NOT NULL,
    target_pqc_algorithm VARCHAR(50) NOT NULL,
    current_algorithm VARCHAR(50) NOT NULL,
    readiness_score INTEGER CHECK (readiness_score >= 0 AND readiness_score <= 100),
    scheduled_migration_date DATE,
    completed_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE iam.algorithm_transition_plan IS 'Tracks the transition plan from Classical to Post-Quantum algorithms.';

-- DB535: iam.crypto_agility_score
-- Description: Readiness for Quantum threats.
-- Business Case: "Harvest Now, Decrypt Later" is a threat. This table calculates a `crypto_agility_score` (0-100). It factors in algorithm age, key length, and exposure. A low score implies vulnerability to quantum attacks (Store-and-decrypt), prompting immediate rotation.
-- KPIs: Score calculation frequency, Threat coverage.
-- Feature Reference: F540 (Quantum Readiness)
CREATE TABLE IF NOT EXISTS iam.crypto_agility_score (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL, -- Could be key_id or generic asset
    algorithm_type VARCHAR(50) NOT NULL,
    key_length_bits INTEGER,
    score NUMERIC(3,2),
    last_assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.crypto_agility_score IS 'Scores cryptographic assets on their resistance to quantum attacks.';

-- DB536: iam.post_quantum_simulation
-- Description: Simulating quantum attacks.
-- Business Case: Is our RSA-2048 already broken? This table stores results of `post_quantum_simulations`. It runs quantum algorithms (theoretically or on real hardware) against stored public keys. It identifies vulnerabilities (e.g., "Key Y can be factored in 5 mins").
-- KPIs: Simulation coverage, Time-to-crack.
-- Feature Reference: F081 (Quantum Resistant)
CREATE TABLE IF NOT EXISTS iam.post_quantum_simulation (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_key_id UUID NOT NULL,
    simulation_type VARCHAR(50) NOT NULL, -- SHOR, VARIENT_OPTIMAL
    outcome VARCHAR(20) NOT NULL, -- SECURE, COMPROMISED
    estimated_compute_time_hours NUMERIC(10,2),
    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.post_quantum_simulation IS 'Stores results of post-quantum cryptanalysis simulations.';

-- DB537: iam.quantum_safe_roadmap
-- Description: Milestones for Y2Q readiness.
-- Business Case: Y2Q (Year to Quantum) is estimated 2030, but preparation starts now. This table tracks `roadmap_milestones` (e.g., "Generate PQC Keys", "Update TLS"). It ensures the organization is not scrambling at the last minute.
-- KPIs: Milestone completion %, Budget variance.
-- Feature Reference: F534 (Transition Plan)
CREATE TABLE IF NOT EXISTS iam.quantum_safe_roadmap (
    milestone_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    milestone_name VARCHAR(255) NOT NULL,
    target_year INTEGER, -- e.g., 2025, 2028
    description TEXT,
    status VARCHAR(20) DEFAULT 'PLANNED', -- PLANNED, IN_PROGRESS, COMPLETED
    completed_at TIMESTAMP WITH TIME ZONE,
    owner_id UUID
);
COMMENT ON TABLE iam.quantum_safe_roadmap IS 'Tracks the roadmap for Y2Q readiness milestones.';

-- DB538: iam.key_derivation_functions
-- Description: PQC key derivation logic.
-- Business Case: PQC keys often change state. This table stores `derivation_logic`. It links a `parent_seed` to derived public keys. It ensures that if the parent seed needs to be rotated, all derived keys can be updated deterministically without regenerating user keys for every single user.
-- KPIs: Derivation speed, Key consistency.
-- Feature Reference: F539 (Lattice Keys)
CREATE TABLE IF NOT EXISTS iam.key_derivation_functions (
    derivation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_seed_id VARCHAR(100) NOT NULL,
    public_key_id UUID NOT NULL,
    derivation_path VARCHAR(50) NOT NULL, -- HKDF, SSSA
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_derivation_key FOREIGN KEY (public_key_id) REFERENCES iam.jwks_keys(kid) ON DELETE CASCADE
);
COMMENT ON TABLE iam.key_derivation_functions IS 'Stores logic for deriving child keys from parent seeds.';

-- DB539: iam.lattice_key_shards
-- Description: Fragments of lattice keys.
-- Business Case: Managing the pieces of a key. This table stores the `shards` of a lattice key. It links to the `derivation_function` (DB538). By managing the shards, we can rotate individual pieces of the key if one component is suspected of compromise.
-- KPIs: Shard availability, Rotation success.
-- Feature Reference: F538
CREATE TABLE IF NOT EXISTS iam.lattice_key_shards (
    shard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    lattice_key_id UUID NOT NULL,
    shard_index INTEGER NOT NULL,
    shard_value_enc BYTEA NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    CONSTRAINT kf_lattice_shard_key FOREIGN KEY (lattice_key_id) REFERENCES iam.lattice_based_signatures(key_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.lattice_key_shards IS 'Stores the components of lattice-based keys.';

-- DB540: iam.quantum_readiness_audit
-- Description: Independent verification of readiness.
-- Business Case: Self-assessment is bias. This table stores `quantum_readiness_audit` reports generated by external auditors. It validates the claims made by the internal Crypto Agility Score (F535) and identifies gaps in the preparation strategy.
-- KPIs: Audit findings count, Gap remediation rate.
-- Feature Reference: F535 (Crypto Agility)
CREATE TABLE IF NOT EXISTS iam.quantum_readiness_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_entity VARCHAR(100) NOT NULL,
    audit_year INTEGER NOT NULL,
    internal_score INTEGER CHECK (internal_score >= 0 AND internal_score <= 100),
    auditor_score INTEGER CHECK (auditor_score >= 0 AND auditor_score <= 100),
    critical_findings TEXT,
    signed_report_url TEXT,

    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.quantum_readiness_audit IS 'Stores external audit results on quantum readiness.';

-- DB541: iam.sre_maturity_model
-- Description: Level of process maturity (SRE).
-- Business Case: Good processes scale better. This table maps the organization's `sre_maturity_level` (1-5) to specific `capabilities`. It tracks if we are "Initial", "Repeatable", "Optimizing", "Managed" or "Optimizing". It drives continuous improvement in security operations.
-- KPIs: Level progression, Capability gaps.
-- Feature Reference: F549 (Operational Risk)
CREATE TABLE IF NOT EXISTS iam.sre_maturity_model (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    level_name VARCHAR(100) NOT NULL,
    level_number INTEGER UNIQUE NOT NULL,
    required_capabilities TEXT[],
    current_compliance BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.sre_maturity_model IS 'Defines the maturity model for Security Operations (SRE).';

-- DB542: iam.incident_mean_time_to_resolve
-- Description: MTTR analysis per incident type.
-- Business Case: MTTR (Mean Time To Resolve) is a key SLO/KPI. This table stores `mttr_data` aggregated by `incident_type` (Phishing, Malware). It analyzes historical data to identify bottlenecks (e.g., "Phishing takes 10 days to resolve because email team is slow"). It focuses resources on the worst offenders.
-- KPIs: MTTR trend, Resolution bottleneck identification.
-- Feature Reference: F313 (Backup Logs)
CREATE TABLE IF NOT EXISTS iam.incident_mean_time_to_resolve (
    mttr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_type VARCHAR(50) NOT NULL,
    avg_time_to_resolve_hours NUMERIC(10,2),
    median_time_to_resolve_hours NUMERIC(10,2),
    sample_size INTEGER, -- N incidents
    period_start DATE NOT NULL,
    period_end DATE NOT NULL
);
COMMENT ON TABLE iam.incident_mean_time_to_resolve IS 'Stores Mean Time To Resolve (MTTR) metrics for incidents.';

-- DB543: iam.change_failure_rollbacks
-- Description: Rollback logs for bad changes.
-- Business Case: Automation can go wrong (e.g., a bad policy deployment). This table logs `change_failure` incidents and their `rollbacks`. It captures the `bad_commit_id` and the `rollback_commit_id`. It helps learn why the change failed and prevents the same mistake from happening twice.
-- KPIs: Rollback speed, Failure classification.
-- Feature Reference: F388 (Rollback Playbooks)
CREATE TABLE IF NOT EXISTS iam.change_failure_rollbacks (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(100) NOT NULL, -- SERVICE, DATABASE, CONFIG
    bad_commit_hash VARCHAR(255),
    rollback_commit_hash VARCHAR(255),
    root_cause VARCHAR(255),
    performed_by UUID,
    rollback_duration_seconds INTEGER,

    CONSTRAINT kf_rollback_performer FOREIGN KEY (performed_by) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.change_failure_rollbacks IS 'Logs details of failed changes and subsequent rollbacks.';

-- DB544: iam.slo_detection
-- Description: Service Level Objectives monitoring.
-- Business Case: Security operations must meet SLOs (99.9% uptime). This table stores `slo_violations`. It tracks violations (downtime, latency spike) and triggers alerts. It ensures that the platform stays within the contractual boundaries agreed upon with customers.
-- KPIs: Uptime percentage, Violation duration.
-- Feature Reference: F450 (System Capacity)
CREATE TABLE IF NOT EXISTS iam.slo_detection (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    slo_target_percentage NUMERIC(3,2) NOT NULL,
    actual_percentage NUMERIC(3,2),
    violation_duration_seconds INTEGER,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.slo_detection IS 'Stores records of SLO (Service Level Objective) violations.';

-- DB545: iam.runbook_scheduling_conflicts
-- Description: Collision in resource reservation.
-- Business Case: Multiple playbooks might need the same resource (e.g., "Stop the DB"). This table detects `scheduling_conflicts`. It prevents two automated runbooks from trying to lock the same resource at the same time, which would cause race conditions or lockups.
-- KPIs: Conflict detection accuracy, Resolution time.
-- Feature Reference: F195 (Playbooks)
CREATE TABLE IF NOT EXISTS iam.runbook_scheduling_conflicts (
    conflict_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_id_a UUID NOT NULL,
    playbook_id_b UUID NOT NULL,
    resource_id VARCHAR(255),
    conflict_time TIMESTAMP WITH TIME ZONE NOT NULL,
    resolved BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE iam.runbook_scheduling_conflicts IS 'Detects scheduling conflicts between automation runbooks.';

-- DB546: iam.ai_model_monitoring_dash
-- Description: Health of AI models.
-- Business Case: AI models drift or decay. This table stores `monitoring_metrics` for deployed models (F0251). It tracks `prediction_accuracy`, `data_drift_score`, and `latency`. If the model health drops below a threshold, it alerts data scientists to retrain or rollback.
-- KPIs: Model health score, Alert frequency.
-- Feature Reference: F061 (AI Anomaly)
CREATE TABLE IF NOT EXISTS iam.ai_model_monitoring_dash (
    dashboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(15,2),
    threshold_red NUMERIC(15,2),
    threshold_yellow NUMERIC(15,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_ai_monitor_model FOREIGN KEY (model_id) REFERENCES iam.ai_model_registry(model_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.ai_model_monitoring_dash IS 'Stores metrics for monitoring AI model health and performance.';

-- DB547: iam.on_call_rotation_schedule
-- Description: Rotating access for support.
-- Business Case: Support On-Call teams often have persistent access to user data. This table manages `on_call_rotation_schedule`. It cycles permissions among support staff to ensure no single person holds access indefinitely, reducing the risk of insider threats within the support team.
-- KPIs: Rotation adherence, Coverage gap percentage.
-- Feature Reference: F310 (Rotation Schedule)
CREATE TABLE IF NOT EXISTS iam.on_call_rotation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    support_team_id UUID NOT NULL,
    target_resource VARCHAR(255),
    current_holder_id UUID,
    rotation_frequency_days INTEGER NOT NULL,
    next_rotation_date DATE NOT NULL,

    CONSTRAINT kf_on_call_holder FOREIGN KEY (current_holder_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.on_call_rotation_schedule IS 'Manages periodic rotation of access for On-Call support staff.';

-- DB548: iam.process_mining_tasks
-- Description: Finding gaps in coverage.
-- Business Case: Processes are complex and have gaps. This table stores `process_mining_tasks`. It identifies potential risks (e.g., "Single point of failure in password reset") based on process analysis. It provides a roadmap for tightening security operations and reducing risk.
-- KPIs: Task completion rate, Risk reduction.
-- Feature Reference: F541 (SRE Maturity)
CREATE TABLE IF NOT EXISTS iam.process_mining_tasks (
    task_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    process_name VARCHAR(255) NOT NULL,
    risk_description TEXT,
    likelihood_score NUMERIC(3,2), -- Probability of exploitation
    remediation_priority VARCHAR(20), -- CRITICAL, HIGH, MEDIUM, LOW
    status VARCHAR(20) DEFAULT 'IDENTIFIED', -- IDENTIFIED, IN_PROGRESS, RESOLVED
    assigned_to UUID,

    CONSTRAINT kf_pm_assigned_to FOREIGN KEY (assigned_to) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.process_mining_tasks IS 'Stores tasks resulting from process mining for risk mitigation.';

-- DB549: iam.operational_risk_register
-- Description: Central risk ledger for Ops.
-- Business Case: Operational risks are often siloed. This table acts as a single `risk_register` for all ops risks. It assigns a `risk_owner` and `status`. It ensures that every identified risk is tracked to completion, preventing the "we knew about it but forgot to fix" problem.
-- KPIs: Open risk count, Average time to close.
-- Feature Reference: F541 (SRE Maturity)
CREATE TABLE IF NOT EXISTS iam.operational_risk_register (
    risk_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_name VARCHAR(255) NOT NULL,
    category VARCHAR(50),
    likelihood NUMERIC(3,2),
    impact NUMERIC(3,2),
    risk_owner UUID NOT NULL,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, MITIGATING, CLOSED, ACCEPTED
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT kf_ops_risk_owner FOREIGN KEY (risk_owner) REFERENCES iam.users(user_id) ON DELETE SET NULL
);
COMMENT ON TABLE iam.operational_risk_register IS 'Central ledger for tracking operational security risks.';

-- DB550: iam.system_capacity_plans
-- Description: Future growth requirements.
-- Business Case: IAM must scale for growth. This table stores `capacity_plans`. It projects future `user_growth`, `storage_needs`, and `bandwidth` based on business roadmaps. It triggers infrastructure provisioning (e.g., "Buy more DB storage") 3 months before it runs out.
-- KPIs: Forecast accuracy, Capacity lead time.
-- Feature Reference: F541 (SRE Maturity)
CREATE TABLE IF NOT EXISTS iam.system_capacity_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    plan_name VARCHAR(255) NOT NULL,
    projected_users BIGINT NOT NULL,
    projected_storage_gb NUMERIC(20,2),
    projected_bandwidth_mbps NUMERIC(20, 2),
    planning_horizon VARCHAR(20) NOT NULL, -- 6 MONTHS, 1 YEAR
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.system_capacity_plans IS 'Stores capacity plans for future system growth.';

-- ================================================================================
-- Indexes and Constraints for Part 8 Tables
-- ================================================================================
-- IoT & Physical
CREATE INDEX IF NOT EXISTS idx_iot_device_hw_serial ON iam.iot_device_inventory(hardware_serial);
CREATE INDEX IF NOT EXISTS idx_phys_access_log_user ON iam.physical_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_badge_reader_status ON iam.badge_reader_status(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_smart_lock_user ON iam.smart_lock_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_visitor_sponsor ON iam.visitor_management(sponsor_id);
CREATE INDEX IF NOT EXISTS idx_zone_parent ON iam.physical_security_zones(parent_zone_id);

-- Gamification
CREATE INDEX IF NOT EXISTS idx_leaderboard_period ON iam.leaderboard(period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_challenge_participants ON iam.security_challenges(target_audience);
CREATE INDEX IF NOT EXISTS idx_team_stats_team ON iam.team_statistics(team_id, period_start);
CREATE INDEX IF NOT EXISTS idx_events_user ON iam.gamification_events(user_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_quest_progress_user ON iam.quest_progress(user_id);

-- Sandbox & Integration
CREATE INDEX IF NOT EXISTS idx_sandbox_keys_dev ON iam.api_sandbox_keys(developer_id);
CREATE INDEX IF NOT EXISTS idx_dev_onboard_user ON iam.developer_onboarding(developer_id);
CREATE INDEX IF NOT EXISTS id_usage_quotas_user ON iam.api_usage_quotas(developer_id);
CREATE INDEX IF NOT EXISTS idx_buckets_user ON iam.rate_limit_buckets(user_id);
CREATE INDEX IF NOT EXISTS idempotency_hash ON iam.idempotency_keys(key_hash);
CREATE INDEX IF NOT EXISTS kf_conf_state_topic_offset ON iam.confluent_state(topic_name, partition, offset);
CREATE INDEX IF NOT EXISTS kf_letter_queue_topic ON iam.dead_letter_queue(original_topic);

-- Edge & Fog
CREATE INDEX IF NOT EXISTS kf_fog_policy_device ON iam.fog_compute_policies(edge_device_id, is_active);
CREATE INDEX IF NOT EXISTS kf_sync_edge_device ON iam.edge_sync_logs(edge_device_id, sync_timestamp);
CREATE INDEX IF NOT EXISTS kf_journal_device_created ON iam.local_event_journal(edge_device_id, created_at);
CREATE INDEX IF NOT EXISTS kf_bandwidth_device ON iam.bandwidth_optimization(edge_device_identifier);
CREATE INDEX IF NOT EXISTS kf_estimate_device ON iam.edge_location_estimates(device_identifier, last_seen);

-- Analytics & Reporting
CREATE INDEX IF NOT EXISTS kf_forensic_user ON iam.forensic_queries(user_id);
CREATE INDEX IF NOT EXISTS kf_audit_query_report ON iam.audit_trail_queries(report_id);
CREATE INDEX IF NOT EXISTS kf_sub_user_report ON iam.report_subscriptions(user_id, next_run_at);
CREATE INDEX IF NOT EXISTS kf_custom_report_user ON iam.custom_report_templates(created_by);
CREATE INDEX IF NOT EXISTS kf_etl_table_end ON iam.data_warehouse_exports(table_name, status);

-- Sustainability
CREATE INDEX IF NOT EXISTS kf_energy_method_name ON iam.auth_energy_metrics(auth_method);
CREATE INDEX IF NOT EXISTS kf_footprint_tenant ON iam.carbon_footprint_tracking(tenant_id, period_start);
CREATE INDEX IF NOT EXISTS kf_green_cert_region ON iam.renewable_energy_certificates(region);
CREATE INDEX IF NOT EXISTS kf_lifecycle_tenant ON iam.lifecycle_energy_cost(tenant_id, period_start);

-- Quantum & Advanced Crypto
CREATE INDEX IF NOT EXISTS kf_hybrid_data ON iam.hybrid_encryption_keys(data_id);
CREATE INDEX IF NOT EXISTS kf_pqc_key ON iam.lattice_based_signatures(key_size_bits);
CREATE INDEX IF NOT EXISTS kf_qk_shard_master ON iam.quantum_key_escrow(master_key_id);
CREATE INDEX IF NOT EXISTS kf_transition_data_owner ON iam.algorithm_transition_plan(data_owner, scheduled_migration_date);
CREATE INDEX IF NOT EXISTS kf_derivation_key ON iam.key_derivation_functions(parent_seed_id);

-- Operations (Ops)
CREATE INDEX IF NOT EXISTS kf_slo_conflict_time ON iam.runbook_scheduling_conflicts(conflict_time);
CREATE INDEX IF NOT EXISTS kf_ai_monitor_model_metric ON iam.ai_model_monitoring_dash(model_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS kf_schedule_next_rot ON iam.on_call_rotation_schedule(next_rotation_date);
CREATE INDEX IF EXISTS kf_mining_task_owner ON iam.process_mining_tasks(assigned_to);
CREATE INDEX IF NOT EXISTS kf_risk_owner_status ON iam.operational_risk_register(risk_owner, status);
CREATE INDEX IF NOT EXISTS kf_capacity_horizon ON iam.system_capacity_plans(planning_horizon, created_at);

-- ================================================================================
-- Row Level Security (RLS) Policies for Part 8 Tables
-- ================================================================================

ALTER TABLE iam.iot_device_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.api_sandbox_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.forensic_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.custom_report_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.ai_model_monitoring_dash ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.on_call_rotation_schedule ENABLE ROW LEVEL SECURITY;

CREATE POLICY iot_device_admin_only ON iam.iot_device_inventory
    FOR ALL
    USING (EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID AND is_super_user = TRUE));

CREATE POLICY sandbox_keys_owner_isolation ON iam.api_sandbox_keys
    FOR ALL
    USING (developer_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY forensic_queries_owner_isolation ON iam.forensic_queries
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY custom_template_owner_isolation ON iam.custom_report_templates
    FOR ALL
    USING (created_by = current_setting('app.current_user_id', true)::UUID);

CREATE POLICY ai_monitor_readonly_for_ops ON iam.ai_model_monitoring_dash
    FOR SELECT
    USING (
        EXISTS (SELECT 1 FROM iam.users WHERE user_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.roles r JOIN iam.user_roles ur ON r.role_id = ur.role_id WHERE r.role_name = 'SECURITY_ENGINEER')
    );

CREATE POLICY oncall_rotation_access_isolation ON iam.on_call_rotation_schedule
    FOR ALL
    USING (
        current_holder_id = current_setting('app.current_user_id', true)::UUID
        OR EXISTS (SELECT 1 FROM iam.user_roles ur JOIN iam.roles r ON r.role_id = ur.role_id WHERE r.role_name = 'SUPPORT_MANAGER')
    );

-- ================================================================================
-- Triggers for Part 8 Tables
-- ================================================================================
CREATE TRIGGER trg_iot_device_update BEFORE UPDATE ON iam.iot_device_inventory FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_iot_cert_update BEFORE UPDATE ON iam.iot_certificates FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_badge_reader_update BEFORE UPDATE ON iam.badge_reader_status FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_smart_lock_audit_update BEFORE UPDATE ON iam.smart_lock_audit FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_visitor_expire_check BEFORE INSERT OR UPDATE ON iam.visitor_management FOR EACH ROW EXECUTE FUNCTION iam.check_expiry_date();
CREATE TRIGGER trg_leaderboard_update BEFORE UPDATE ON iam.leaderboard FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_sandbox_keys_update BEFORE UPDATE ON IAM.api_sandbox_keys FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_dev_onboarding_update BEFORE UPDATE ON iam.developer_onboarding FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER trg_sandbox_logs_update BEFORE UPDATE ON iam.sandbox_logs FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_buckets_update BEFORE UPDATE ON iam.rate_limit_buckets FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_replay_update BEFORE UPDATE ON iam.dead_letter_queue FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_sub_sync_update BEFORE UPDATE ON iam.subscription_management FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_state_update BEFORE UPDATE ON iam.confluent_state FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_delivery_update BEFORE UPDATE ON iam.webhook_delivery_status FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_replay_req_update BEFORE UPDATE ON iam.event_replay_requests FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_fog_policy_update BEFORE UPDATE ON iam.fog_compute_policies FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_edge_sync_update BEFORE UPDATE ON iam.edge_sync_logs FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_journal_insert BEFORE INSERT ON iam.local_event_journal FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_bandwidth_update BEFORE UPDATE ON iam.bandwidth_optimization FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_estimate_update BEFORE UPDATE ON iam.edge_location_estimates FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_viz_update BEFORE UPDATE ON iam.compliance_visualizations FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_score_update BEFORE UPDATE ON iam.security_posture_scoring FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_velocity_update BEFORE UPDATE ON iam.risk_velocity FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_threat_update BEFORE UPDATE ON iam.threat_landscape FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_forensic_query_update BEFORE UPDATE ON iam.forensic_queries FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_audit_query_insert BEFORE INSERT ON iam.audit_trail_queries FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_report_sub_update BEFORE UPDATE ON iam.report_subscriptions FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_custom_report_update BEFORE UPDATE ON iam.custom_report_templates FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_warehouse_update BEFORE UPDATE ON iam.data_warehouse_exports FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_auth_energy_update BEFORE UPDATE ON iam.auth_energy_metrics FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_green_score_update BEFORE UPDATE ON iam.green_auth_methods FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_footprint_update BEFORE UPDATE ON iam.carbon_footprint_tracking FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_green_cert_update BEFORE UPDATE ON iam.renewable_energy_certificates FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_lifecycle_cost_update BEFORE UPDATE ON iam.lifecycle_energy_cost FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_green_audit_update BEFORE UPDATE ON iam.green_compliance_audit FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_hybrid_key_update BEFORE UPDATE ON iam.hybrid_encryption_keys FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_lattice_key_update BEFORE UPDATE ON iam.lattice_based_signatures FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_qk_escrow_update BEFORE UPDATE ON iam.quantum_key_escrow FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_transition_plan_update BEFORE UPDATE ON iam.algorithm_transition_plan FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_derivation_func_update BEFORE UPDATE ON iam.key_derivation_functions FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_lattice_shard_update BEFORE UPDATE ON iam.lattice_key_shards FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_q_audit_update BEFORE UPDATE ON iam.quantum_readiness_audit FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_sre_model_update BEFORE UPDATE ON iam.sre_maturity_model FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_mttr_update BEFORE UPDATE ON iam.incident_mean_time_to_resolve FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_rollback_update BEFORE UPDATE ON iam.change_failure_rollbacks FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_slo_conflict_insert BEFORE INSERT OR UPDATE ON iam.runbook_scheduling_conflicts FOR EACH ROW EXECUTE FUNCTION iam.detect_scheduling_conflicts();
CREATE TRIGGER kf_ai_monitor_update BEFORE UPDATE ON iam.ai_model_monitoring FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_on_call_schedule_update BEFORE UPDATE ON iam.on_call_rotation_schedule FOR EACH ROW EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_mining_task_update BEFORE UPDATE ON iam.process_mining_tasks FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_ops_risk_update BEFORE UPDATE ON iam.operational_risk_register FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();
CREATE TRIGGER kf_capacity_plan_update BEFORE UPDATE ON iam.system_capacity_plans FOR EACH ROW EXISTS EXECUTE FUNCTION iam.update_modified_column();

-- Helper function for Conflict Detection (Referenced in Trigger)
CREATE OR REPLACE FUNCTION iam.detect_scheduling_conflicts()
RETURNS TRIGGER AS $$ BEGIN
    -- Check for conflicts with the same resource
    IF NEW.conflict_time IS NOT NULL AND NEW.status = 'PENDING' THEN
        PERFORM INSERT INTO iam.runbook_scheduling_conflicts (conflict_time, resource_id, status, detected_at)
        VALUES (uuid_generate_v4(), NEW.resource_id, 'CONFLICT', NOW());
        RAISE NOTICE 'Scheduling conflict detected for resource %', NEW.resource_id;
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;
