-- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Database Schema Definition Script
-- ==========================================================================================================
-- Description:
-- This script defines the database schema for Module M23, which serves as the enterprise-grade interface
-- between the open-source ecosystem and the regulated PARI payment infrastructure. It implements a
-- CMMI Level 5 governed contribution hub, managing the entire SDLC governance for external contributions.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- 1. Schema Creation
-- --------------------------------------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS m23_governance AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA m23_governance IS 'Governance hub for FOSS contributions, CI/CD pipelines, and community management for PARI.';

-- --------------------------------------------------------------------------------------------------------
-- 2. Extensions
-- --------------------------------------------------------------------------------------------------------

-- Extension: pgcrypto
-- Purpose: Provides cryptographic functions for hashing, PGP encryption, and UUID generation.
-- Use Case: Securely storing contributor PGP keys, hashing API tokens, and generating UUIDs.
CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA public;
COMMENT ON EXTENSION pgcrypto IS 'Cryptographic functions for PARI governance security.';

-- Extension: pg_trgm
-- Purpose: Provides trigraph matching for fuzzy string searching.
-- Use Case: Searching issues, PRs, and contributors based on similarity.
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public;
COMMENT ON EXTENSION pg_trgm IS 'Fuzzy string matching for contributor and issue search.';

-- Extension: btree_gin
-- Purpose: Allows GIN indexes to handle B-tree equivalent data types.
-- Use Case: Composite indexes involving JSONB and scalar types.
CREATE EXTENSION IF NOT EXISTS btree_gin SCHEMA public;
COMMENT ON EXTENSION btree_gin IS 'Enables GIN indexes for scalar types used in composite governance queries.';

-- Extension: ltree
-- Purpose: Handles tree-like structures (labels).
-- Use Case: Managing hierarchical dependency trees and file structures.
CREATE EXTENSION IF NOT EXISTS ltree SCHEMA public;
COMMENT ON EXTENSION ltree IS 'Label tree for hierarchical dependency and file path management.';

-- 2.a List of Database Objects to Implement (Scanned Rows 1-50)
-- Tables: contributors, contributor_organizations, organizations, repositories, pull_requests, commits, ci_pipeline_runs, ci_jobs, test_results, code_coverage_metrics, sast_findings, sca_dependencies, sca_vulnerabilities, license_compliance_results, approved_licenses, db_migration_scripts, db_schema_validation, secret_scans, approvals, review_comments, issue_references, architecture_decision_records, performance_benchmarks, build_artifacts, sbom_entries, container_images, image_vulnerabilities, dependency_pins, api_spec_changes, breaking_changes, changelog_entries, labels, pr_labels, milestones, pr_milestones, badges, contributor_badges, bounties, bounty_claims, preview_environments, quality_gates, gate_results, sentiment_analysis, spam_reports, technical_debt_tags, documentation_updates, access_control_policies, fuzz_test_results, merge_queue.
-- Enumerated Types: contributor_role, pr_state, pipeline_status, job_status, test_status, severity_level, license_compliance_status, migration_check_type, approval_state, sentiment_score, gate_operator, bounty_status, pr_label_color.

-- --------------------------------------------------------------------------------------------------------
-- 3. Enums
-- --------------------------------------------------------------------------------------------------------

-- Enum: contributor_role
-- Description: Defines the various roles a contributor can play within the ecosystem.
CREATE TYPE m23_governance.contributor_role AS ENUM ('INDIVIDUAL', 'CORPORATE', 'MAINTAINER', 'BOT', 'AUDITOR');
COMMENT ON TYPE m23_governance.contributor_role IS 'Roles defining the access level and nature of the contributor.';

-- Enum: pr_state
-- Description: States of a Pull Request.
CREATE TYPE m23_governance.pr_state AS ENUM ('OPEN', 'CLOSED', 'MERGED', 'DRAFT');
COMMENT ON TYPE m23_governance.pr_state IS 'Lifecycle states for Pull Requests.';

-- Enum: pipeline_status
-- Description: Status of a CI/CD Pipeline run.
CREATE TYPE m23_governance.pipeline_status AS ENUM ('QUEUED', 'RUNNING', 'SUCCESS', 'FAILURE', 'CANCELLED', 'PENDING');
COMMENT ON TYPE m23_governance.pipeline_status IS 'Status tracking for CI orchestration.';

-- Enum: job_status
-- Description: Status of individual jobs within a pipeline.
CREATE TYPE m23_governance.job_status AS ENUM ('QUEUED', 'RUNNING', 'SUCCESS', 'FAILURE', 'SKIPPED');
COMMENT ON TYPE m23_governance.job_status IS 'Granular status for CI jobs.';

-- Enum: test_status
-- Description: Outcome of a unit or integration test.
CREATE TYPE m23_governance.test_status AS ENUM ('PASS', 'FAIL', 'SKIP', 'ERROR');
COMMENT ON TYPE m23_governance.test_status IS 'Results for automated test execution.';

-- Enum: severity_level
-- Description: Severity rating for security findings.
CREATE TYPE m23_governance.severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
COMMENT ON TYPE m23_governance.severity_level IS 'Standardized severity ratings for vulnerabilities.';

-- Enum: license_compliance_status
-- Description: Compliance state of a dependency license.
CREATE TYPE m23_governance.license_compliance_status AS ENUM ('APPROVED', 'PROHIBITED', 'REVIEW_REQUIRED');
COMMENT ON TYPE m23_governance.license_compliance_status IS 'Legal standing of dependency licenses.';

-- Enum: migration_check_type
-- Description: Types of validation performed on SQL migrations.
CREATE TYPE m23_governance.migration_check_type AS ENUM ('IDEMPOTENCY', 'SYNTAX', 'PERFORMANCE', 'RLS_POLICY');
COMMENT ON TYPE m23_governance.migration_check_type IS 'Categories of database migration validation.';

-- Enum: approval_state
-- Description: State of a code review approval.
CREATE TYPE m23_governance.approval_state AS ENUM ('APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED');
COMMENT ON TYPE m23_governance.approval_state IS 'Review outcomes for Pull Requests.';

-- Enum: sentiment_score
-- Description: Categorization of comment sentiment.
CREATE TYPE m23_governance.sentiment_category AS ENUM ('POSITIVE', 'NEUTRAL', 'NEGATIVE', 'TOXIC');
COMMENT ON TYPE m23_governance.sentiment_category IS 'Community health sentiment classification.';

-- Enum: gate_operator
-- Description: Comparison operators for quality gates.
CREATE TYPE m23_governance.gate_operator AS ENUM ('GREATER_THAN', 'LESS_THAN', 'EQUALS', 'NOT_EQUALS');
COMMENT ON TYPE m23_governance.gate_operator IS 'Logic operators for quality metrics evaluation.';

-- Enum: bounty_status
-- Description: Status of a financial bounty.
CREATE TYPE m23_governance.bounty_status AS ENUM ('OPEN', 'CLAIMED', 'PAID', 'EXPIRED', 'REJECTED');
COMMENT ON TYPE m23_governance.bounty_status IS 'Lifecycle state for bug bounties.';

-- Enum: currency_code
-- Description: Supported currencies for bounties.
CREATE TYPE m23_governance.currency_code AS ENUM ('USD', 'EUR', 'GBP', 'BTC', 'ETH');
COMMENT ON TYPE m23_governance.currency_code IS 'Supported currencies for financial incentives.';

-- --------------------------------------------------------------------------------------------------------
-- 4. DDL Statements (Tables 1-50)
-- --------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Table: 01 - contributors
-- Description: Stores profile, identity, and reputation information for FOSS developers.
-- Business Case: Centralizing contributor identity is essential for legal traceability (DCO/CLA),
-- reputation management, and access control. It allows the system to distinguish between trusted
-- committers and first-time contributors, applying appropriate governance gates. This table
-- supports the gamification strategy to encourage high-quality participation.
-- KPIs: 1. Active Contributor Growth Rate, 2. Reputation Score Distribution, 3. CLA Signing Rate,
-- 4. Corporate vs. Individual Ratio, 5. Contributor Retention Rate.
-- Feature Reference: 15, 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributors (
    -- Primary Key
    contributor_id BIGSERIAL PRIMARY KEY,

    -- Identification
    github_handle VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    pgp_key_fingerprint CHAR(49), -- 40 hex chars + spaces
    display_name VARCHAR(255),
    avatar_url TEXT,

    -- Classification
    role m23_governance.contributor_role NOT NULL DEFAULT 'INDIVIDUAL',
    is_corporate BOOLEAN DEFAULT FALSE,

    -- Reputation & Trust
    reputation_score NUMERIC(5,2) DEFAULT 0.00 CHECK (reputation_score >= 0 AND reputation_score <= 100),
    trust_level INTEGER DEFAULT 1 CHECK (trust_level BETWEEN 1 AND 5),
    total_prs_merged INTEGER DEFAULT 0,
    total_commits INTEGER DEFAULT 0,

    -- Location & Info
    country_code CHAR(2),
    timezone VARCHAR(50),
    bio TEXT,

    -- Legal & Compliance
    cla_signed_at TIMESTAMP WITH TIME ZONE,
    dco_enforced BOOLEAN DEFAULT TRUE,
    tax_id VARCHAR(50), -- For bounties

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    suspension_reason TEXT,

    -- Audit & System
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT uq_contributors_email UNIQUE (email),
    CONSTRAINT uq_contributors_handle UNIQUE (github_handle),
    CONSTRAINT chk_contributors_pgp_format CHECK (pgp_key_fingerprint ~ '^[A-F0-9 ]+$')
);

COMMENT ON TABLE m23_governance.contributors IS 'Master registry for all developers interacting with the PARI ecosystem.';
COMMENT ON COLUMN m23_governance.contributors.reputation_score IS 'Calculated score based on code quality, review speed, and test coverage.';
COMMENT ON COLUMN m23_governance.contributors.pgp_key_fingerprint IS 'Fingerprint for verifying commit signatures (DCO).';

------------------------------------------------------------------------------------------------
-- Table: 02 - contributor_organizations
-- Description: Links contributors to companies/organizations for CLA purposes.
-- Business Case: Many contributions are made on behalf of corporations. This junction table ensures
-- that the legal entity (Company) has signed the Corporate CLA, protecting PARI from IP litigation.
-- It allows tracking of which organizations are actively participating in the ecosystem.
-- KPIs: 1. Corporate Partner Engagement, 2. CLA Coverage Rate, 3. Contributions per Organization,
-- 4. Onboarding Time for Partners, 5. Partner Retention.
-- Feature Reference: 3
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_organizations (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    organization_id INTEGER NOT NULL,

    -- Relationship Details
    role VARCHAR(50) DEFAULT 'EMPLOYEE', -- EMPLOYEE, CONTRACTOR, AFFILIATE
    cla_text TEXT, -- Store specific CLA version text signed
    signed_cla_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_primary BOOLEAN DEFAULT FALSE, -- Primary affiliation for payments/bounties

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Keys & Constraints
    CONSTRAINT pk_contributor_orgs PRIMARY KEY (contributor_id, organization_id),
    CONSTRAINT fk_co_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id) ON DELETE CASCADE,
    CONSTRAINT fk_co_organization FOREIGN KEY (organization_id) REFERENCES m23_governance.organizations(organization_id) ON DELETE CASCADE
);

COMMENT ON TABLE m23_governance.contributor_organizations IS 'Junction table mapping contributors to their corporate affiliations for legal coverage.';

------------------------------------------------------------------------------------------------
-- Table: 03 - organizations
-- Description: List of partner organizations participating in the ecosystem.
-- Business Case: Manages the entities that sign the master CLA. It tracks domains for automated
-- email verification (e.g., checking if an email matches the org domain) and maintains contact
-- points for legal and engineering liaison.
-- KPIs: 1. Total Active Organizations, 2. Contribution Volume per Org, 3. Domain Verification Success,
-- 4. Average Time to Sign CLA, 5. Organization churn rate.
-- Feature Reference: 3
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.organizations (
    -- Primary Key
    organization_id SERIAL PRIMARY KEY,

    -- Identity
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    domain VARCHAR(255) NOT NULL, -- e.g., "example.com"
    logo_url TEXT,

    -- Legal & Contact
    cla_text TEXT, -- The master CLA text
    contact_email VARCHAR(255) NOT NULL,
    legal_representative_name VARCHAR(255),

    -- Status
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.organizations IS 'Registry of corporate entities contributing to the PARI project.';

------------------------------------------------------------------------------------------------
-- Table: 04 - repositories
-- Description: Metadata for the various PARI repositories (core, wallet, docs).
-- Business Case: PARI is a monorepo or multi-repo project. This table centralizes configuration
-- for branch protection rules, default CI pipelines, and visibility settings. It allows M23 to
-- apply governance policies consistently across different codebases (e.g., stricter rules for
-- 'core' vs 'docs').
-- KPIs: 1. Repository Health Score, 2. Active Branch Count, 3. Issue Resolution Time per Repo,
-- 4. Stars/Forks Growth, 5. Default Branch Compliance.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.repositories (
    -- Primary Key
    repo_id SERIAL PRIMARY KEY,

    -- Identity
    name VARCHAR(255) NOT NULL, -- e.g., "pari-core", "pari-wallet"
    description TEXT,
    external_id BIGINT, -- GitHub/GitLab Repo ID
    scm_provider VARCHAR(50) DEFAULT 'github', -- github, gitlab, bitbucket

    -- Configuration
    default_branch VARCHAR(100) DEFAULT 'main',
    visibility VARCHAR(20) CHECK (visibility IN ('PUBLIC', 'PRIVATE', 'INTERNAL')),
    is_archived BOOLEAN DEFAULT FALSE,

    -- Governance Hooks
    requires_cla BOOLEAN DEFAULT TRUE,
    requires_dco BOOLEAN DEFAULT TRUE,
    auto_merge_enabled BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.repositories IS 'Configuration metadata for source code repositories under governance.';

------------------------------------------------------------------------------------------------
-- Table: 05 - pull_requests
-- Description: Core entity tracking all submitted Pull Requests.
-- Business Case: The central unit of work in M23. Tracks the lifecycle of a contribution from
-- draft to merge. Critical for MTTR (Mean Time To Resolve) analysis and identifying bottlenecks
-- in the review process. It links code changes to CI runs, security scans, and approvals.
-- KPIs: 1. Mean Time to Merge (MTTM), 2. PR Merge Rate, 3. Time to First Review,
-- 4. PR Abandonment Rate, 5. Reopen Rate.
-- Feature Reference: 2, 160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pull_requests (
    -- Primary Key
    pr_id BIGSERIAL PRIMARY KEY,

    -- Foreign Keys
    repo_id INTEGER NOT NULL,
    contributor_id BIGINT NOT NULL,

    -- Identification
    number INTEGER NOT NULL, -- The PR number from SCM
    title VARCHAR(255) NOT NULL,
    description TEXT,
    state m23_governance.pr_state NOT NULL DEFAULT 'OPEN',

    -- Branching
    target_branch VARCHAR(100) NOT NULL,
    source_branch VARCHAR(100) NOT NULL,
    commit_sha_base CHAR(40), -- The commit SHA of the base branch
    commit_sha_head CHAR(40), -- The commit SHA of the PR head

    -- Metadata
    is_draft BOOLEAN DEFAULT FALSE,
    mergeable BOOLEAN, -- Calculated by SCM
    merged_by BIGINT,
    merged_commit_sha CHAR(40),

    -- Timestamps
    opened_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,
    merged_at TIMESTAMP WITH TIME ZONE,

    -- Analysis
    changed_files INTEGER DEFAULT 0,
    additions INTEGER DEFAULT 0,
    deletions INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_pr_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id),
    CONSTRAINT fk_pr_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT uq_repo_number UNIQUE (repo_id, number)
);

COMMENT ON TABLE m23_governance.pull_requests IS 'Primary tracking entity for all code contributions.';
CREATE INDEX idx_pr_repo_state ON m23_governance.pull_requests(repo_id, state);
CREATE INDEX idx_pr_contributor ON m23_governance.pull_requests(contributor_id);

------------------------------------------------------------------------------------------------
-- Table: 06 - commits
-- Description: Links commits to PRs for traceability and DCO validation.
-- Business Case: Ensures every line of code is attributable to a specific individual and agreement.
-- This table stores the cryptographic signature of commits to enforce the DCO (Signed-off-by).
-- It enables granular blame-tracking and security forensics.
-- KPIs: 1. DCO Compliance Rate, 2. Signed Commit Percentage, 3. Average Commits per PR,
-- 4. Commit Message Format Compliance, 5. Malicious Commit Detection Rate.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.commits (
    -- Primary Key
    commit_sha CHAR(40) PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    author_id BIGINT,
    committer_id BIGINT,

    -- Details
    message TEXT NOT NULL,
    signed_off BOOLEAN DEFAULT FALSE, -- DCO Check
    signature_verified BOOLEAN,
    signer_key_id VARCHAR(255),

    -- Timestamps
    committed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    authored_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_commit_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_commit_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.commits IS 'Granular tracking of code changes with legal verification.';

------------------------------------------------------------------------------------------------
-- Table: 07 - ci_pipeline_runs
-- Description: Tracks the execution of CI pipelines for a specific commit/PR.
-- Business Case: Provides a high-level view of the health of a contribution. Allows correlation of
-- build failures with specific code changes. Critical for monitoring CI infrastructure performance
-- and identifying flaky tests or resource bottlenecks.
-- KPIs: 1. Pipeline Success Rate, 2. Average Pipeline Duration, 3. Queue Time,
-- 4. Infrastructure Cost per Run, 5. Flaky Test Detection Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ci_pipeline_runs (
    -- Primary Key
    run_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    commit_sha CHAR(40) NOT NULL,

    -- Execution
    pipeline_name VARCHAR(255) DEFAULT 'default',
    status m23_governance.pipeline_status NOT NULL DEFAULT 'QUEUED',
    conclusion VARCHAR(50), -- SUCCESS, FAILURE, NEUTRAL

    -- Metrics
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,
    queue_duration_ms INTEGER,

    -- Environment
    runner_type VARCHAR(50), -- e.g., 'linux-large', 'gpu'
    triggered_by VARCHAR(100), -- 'web', 'api', 'schedule'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_pipeline_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_pipeline_commit FOREIGN KEY (commit_sha) REFERENCES m23_governance.commits(commit_sha)
);

CREATE INDEX idx_pipeline_pr ON m23_governance.ci_pipeline_runs(pr_id, status);
COMMENT ON TABLE m23_governance.ci_pipeline_runs IS 'Orchestration tracking for CI/CD workflows.';

------------------------------------------------------------------------------------------------
-- Table: 08 - ci_jobs
-- Description: Individual jobs within a pipeline run (e.g., test, lint, build).
-- Business Case: Breaks down the pipeline into actionable units. If a pipeline fails, this table
-- identifies exactly which step (e.g., 'security-scan' or 'unit-test') failed, allowing developers
-- to fix specific issues without re-running expensive steps.
-- KPIs: 1. Job Failure Rate by Type, 2. Average Job Duration, 3. Cache Hit Ratio,
-- 4. Parallelism Efficiency, 5. Retry Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ci_jobs (
    -- Primary Key
    job_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Execution
    job_name VARCHAR(255) NOT NULL, -- e.g., 'lint-go', 'test-unit'
    status m23_governance.job_status NOT NULL DEFAULT 'QUEUED',

    -- Details
    log_url TEXT,
    log_file_path TEXT, -- Internal storage path
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,

    -- Dependencies
    depends_on BIGINT[], -- Array of job_ids this job waits for

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_job_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

COMMENT ON TABLE m23_governance.ci_jobs IS 'Detailed breakdown of CI pipeline execution steps.';

------------------------------------------------------------------------------------------------
-- Table: 09 - test_results
-- Description: Detailed results of unit and integration tests.
-- Business Case: Essential for maintaining the 95% coverage gate. Stores individual test case
-- outcomes to allow developers to see exactly which tests failed and why (error_message).
-- Enables historical analysis of test flakiness.
-- KPIs: 1. Test Pass Rate, 2. Test Execution Time, 3. Flaky Test Frequency,
-- 4. Coverage Percentage (derived), 5. Failure Bucket Analysis.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.test_results (
    -- Primary Key
    test_id BIGSERIAL PRIMARY KEY,

    -- Linking
    job_id BIGINT NOT NULL,

    -- Details
    suite_name VARCHAR(255) NOT NULL, -- e.g., 'payment.core'
    test_name VARCHAR(500) NOT NULL,
    status m23_governance.test_status NOT NULL,

    -- Metrics
    duration_ms NUMERIC(10,3),
    error_message TEXT,
    stack_trace TEXT,

    -- Metadata
    file_path VARCHAR(1000),
    line_number INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_test_job FOREIGN KEY (job_id) REFERENCES m23_governance.ci_jobs(job_id)
);

CREATE INDEX idx_test_job_status ON m23_governance.test_results(job_id, status);
COMMENT ON TABLE m23_governance.test_results IS 'Granular test execution data for quality assurance.';

------------------------------------------------------------------------------------------------
-- Table: 10 - code_coverage_metrics
-- Description: Stores coverage reports per commit.
-- Business Case: Enforces the quality gate of >95% coverage. Tracks how a specific PR impacts
-- the overall codebase health. Allows visualization of which files or directories are losing coverage.
-- KPIs: 1. Line Coverage Percentage, 2. Branch Coverage Percentage, 3. New Code Coverage,
-- 4. Coverage Drift, 5. Uncovered Complex Files.
-- Feature Reference: 9
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_coverage_metrics (
    -- Primary Key
    coverage_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    commit_sha CHAR(40) NOT NULL,

    -- Metrics
    line_coverage_pct NUMERIC(5,2) CHECK (line_coverage_pct BETWEEN 0 AND 100),
    branch_coverage_pct NUMERIC(5,2) CHECK (branch_coverage_pct BETWEEN 0 AND 100),
    lines_covered INTEGER,
    lines_total INTEGER,
    functions_covered INTEGER,
    functions_total INTEGER,

    -- Detailed Report (JSONB)
    report_jsonb JSONB, -- Detailed breakdown by file

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_coverage_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.code_coverage_metrics IS 'Aggregated code quality metrics for gating.';

------------------------------------------------------------------------------------------------
-- Table: 11 - sast_findings
-- Description: Static Analysis security findings.
-- Business Case: Identifies security vulnerabilities (SQL Injection, XSS) in code before it is
-- merged. Critical for "Shift Left" security. Mapping findings to CWE IDs allows for standardized
-- risk assessment and tracking of recurring issues.
-- KPIs: 1. Time to Fix Critical Vulnerabilities, 2. Vulnerability Density, 3. False Positive Rate,
-- 4. SAST Tool Coverage, 5. Reoccurring Vulnerability Patterns.
-- Feature Reference: 4
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sast_findings (
    -- Primary Key
    finding_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Analysis Details
    tool_name VARCHAR(50) NOT NULL, -- e.g., 'SonarQube', 'Semgrep'
    severity m23_governance.severity_level NOT NULL,
    cwe_id VARCHAR(10), -- Common Weakness Enumeration
    rule_id VARCHAR(100), -- Tool specific rule ID

    -- Location
    file_path VARCHAR(1000) NOT NULL,
    line_number INTEGER,
    code_snippet TEXT,

    -- Description
    description TEXT NOT NULL,
    fingerprint VARCHAR(64), -- To deduplicate identical findings

    -- Status
    is_false_positive BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, FIXED, IGNORED

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_sast_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_sast_pr_severity ON m23_governance.sast_findings(pr_id, severity);
COMMENT ON TABLE m23_governance.sast_findings IS 'Security vulnerabilities detected by static analysis tools.';

------------------------------------------------------------------------------------------------
-- Table: 12 - sca_dependencies
-- Description: Dependency inventory scanned for a specific build.
-- Business Case: Manages the Supply Chain. Lists every library used in a build to check against
-- vulnerability databases. Ensures that no unwanted or unapproved dependencies slip into production.
-- KPIs: 1. Dependency Count, 2. Outdated Dependency Rate, 3. License Compliance Rate,
-- 4. Unapproved Dependency Block Rate, 5. Transitive Dependency Depth.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sca_dependencies (
    -- Primary Key
    dep_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Package Details
    package_name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL, -- npm, maven, go, cargo, pip
    manager VARCHAR(50), -- yarn, mvn, go modules

    -- Licensing
    license_spdx VARCHAR(50), -- SPDX Identifier
    license_name VARCHAR(255),

    -- Integrity
    checksum_sha256 CHAR(64),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_dep_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

CREATE INDEX idx_sca_run ON m23_governance.sca_dependencies(run_id);
COMMENT ON TABLE m23_governance.sca_dependencies IS 'Inventory of third-party libraries used in the build.';

------------------------------------------------------------------------------------------------
-- Table: 13 - sca_vulnerabilities
-- Description: CVEs found in dependencies.
-- Business Case: Detects known security flaws in third-party code (e.g., Log4Shell). Critical
-- for preventing supply chain attacks. Links to the specific version of the dependency to ensure
-- accuracy.
-- KPIs: 1. CVE Remediation Time, 2. Critical CVE Count, 3. Affected Packages,
-- 4. Patch Availability Rate, 5. Transitive Vulnerability Impact.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sca_vulnerabilities (
    -- Primary Key
    vuln_id BIGSERIAL PRIMARY KEY,

    -- Linking
    dep_id BIGINT NOT NULL,

    -- Vulnerability Details
    cve_id VARCHAR(20) NOT NULL,
    severity m23_governance.severity_level NOT NULL,
    cvss_score NUMERIC(3,1),
    vector_string VARCHAR(100),

    -- Remediation
    fixed_in_version VARCHAR(100),

    -- Reference
    advisory_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_vuln_dep FOREIGN KEY (dep_id) REFERENCES m23_governance.sca_dependencies(dep_id)
);

CREATE INDEX idx_vuln_dep ON m23_governance.sca_vulnerabilities(dep_id);
COMMENT ON TABLE m23_governance.sca_vulnerabilities IS 'Known security vulnerabilities in third-party dependencies.';

------------------------------------------------------------------------------------------------
-- Table: 14 - license_compliance_results
-- Description: Results of license scanning (e.g., GPLv2 vs AGPLv3+).
-- Business Case: Prevents IP contamination. PARI is AGPLv3+; integrating GPL-incompatible code or
-- copyleft licenses that force proprietary closure of PARI extensions must be flagged.
-- Automates the legal review process.
-- KPIs: 1. License Policy Violation Rate, 2. License Identification Accuracy,
-- 3. Time to Review Non-Standard Licenses, 4. Approved Library Percentage.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.license_compliance_results (
    -- Primary Key
    check_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,
    dependency_id BIGINT,

    -- License Info
    license_id INTEGER,
    spdx_id VARCHAR(50),
    license_name VARCHAR(255),

    -- Verdict
    compliance_status m23_governance.license_compliance_status NOT NULL,
    justification TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_license_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

COMMENT ON TABLE m23_governance.license_compliance_results IS 'Legal compliance status of software licenses.';

------------------------------------------------------------------------------------------------
-- Table: 15 - approved_licenses
-- Description: Whitelist of allowed open-source licenses.
-- Business Case: The master list of licenses legally approved for use within PARI. Maintained by
-- the Legal team. Used by the SCA engine to automatically reject PRs containing forbidden licenses.
-- KPIs: 1. List Update Frequency, 2. Usage Distribution of Approved Licenses,
-- 3. Exception Request Volume.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.approved_licenses (
    -- Primary Key
    license_id SERIAL PRIMARY KEY,

    -- Identification
    spdx_id VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,

    -- Usage Constraints
    can_use_in_commercial BOOLEAN DEFAULT TRUE,
    can_redistribute BOOLEAN DEFAULT TRUE,
    requires_source_distribution BOOLEAN, -- Copyleft
    is_compatible_with_agplv3 BOOLEAN, -- Specific PARI requirement

    -- Text
    license_text TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.approved_licenses IS 'Master whitelist of legally permitted open-source licenses.';

------------------------------------------------------------------------------------------------
-- Table: 16 - db_migration_scripts
-- Description: Tracks SQL migration scripts submitted in PRs.
-- Business Case: Database changes are high-risk. This table tracks which PR introduced which
-- schema change, ensuring that every migration has been reviewed for idempotency and performance.
-- KPIs: 1. Migration Failure Rate, 2. Rollback Success Rate, 3. Average Migration Execution Time,
-- 4. Destructive Change Count, 5. Migration Review Coverage.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.db_migration_scripts (
    -- Primary Key
    migration_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Script Details
    script_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    checksum CHAR(64) NOT NULL, -- SHA256 of the script content

    -- Analysis
    is_idempotent BOOLEAN DEFAULT FALSE,
    is_destructive BOOLEAN DEFAULT FALSE,
    estimated_impact_rows BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_migration_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.db_migration_scripts IS 'Tracking of DDL/DML changes to the core database schema.';

------------------------------------------------------------------------------------------------
-- Table: 17 - db_schema_validation
-- Description: Results of automated DB schema checks.
-- Business Case: Stores the output of automated linters/checkers that ensure SQL scripts meet
-- PARI standards (ANSI compliance, no SELECT *, naming conventions). Prevents technical debt in
-- the data layer.
-- KPIs: 1. SQL Linter Pass Rate, 2. Naming Convention Violation Rate, 3. Performance Warning Count.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.db_schema_validation (
    -- Primary Key
    validation_id BIGSERIAL PRIMARY KEY,

    -- Linking
    migration_id BIGINT NOT NULL,

    -- Checks
    check_type m23_governance.migration_check_type NOT NULL,
    passed BOOLEAN NOT NULL,
    error_message TEXT,
    line_number INTEGER,
    code_context TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_validation_migration FOREIGN KEY (migration_id) REFERENCES m23_governance.db_migration_scripts(migration_id)
);

COMMENT ON TABLE m23_governance.db_schema_validation IS 'Results of automated SQL quality and safety checks.';

------------------------------------------------------------------------------------------------
-- Table: 18 - secret_scans
-- Description: Results of secret scanning on the repository.
-- Business Case: Prevents credential leakage (the #1 cause of account takeover). Scans code diffs
-- for high-entropy strings that look like API keys, passwords, or certificates.
-- Auto-rejects PRs containing secrets.
-- KPIs: 1. Secret Leak Incident Rate, 2. False Positive Rate, 3. Time to Revoke Leaked Secrets,
-- 4. Scan Execution Time.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.secret_scans (
    -- Primary Key
    scan_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Detection
    file_path TEXT NOT NULL,
    secret_type VARCHAR(50) NOT NULL, -- AWS Key, JWT, Password
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    secret_hash CHAR(64), -- Hash of the detected secret

    -- Status
    is_whitelisted BOOLEAN DEFAULT FALSE, -- Test keys might be allowed
    verified BOOLEAN, -- If API verified the secret is active

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_scan_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_scan_pr ON m23_governance.secret_scans(pr_id);
COMMENT ON TABLE m23_governance.secret_scans IS 'Detection of potential leaked credentials in code changes.';

------------------------------------------------------------------------------------------------
-- Table: 19 - approvals
-- Description: Tracks code reviews and approvals.
-- Business Case: Enforces the "4-eyes principle" or required review counts. Tracks which
-- committers have approved a PR for merge. Essential for auditing who authorized code entry into
-- the core ledger.
-- KPIs: 1. Review Turnaround Time, 2. Reviewer Participation Distribution, 3. Approval Thoroughness,
-- 4. Stale Review Rate.
-- Feature Reference: 66
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.approvals (
    -- Primary Key
    approval_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    reviewer_id BIGINT NOT NULL,

    -- State
    state m23_governance.approval_state NOT NULL,
    commit_sha CHAR(40), -- The specific commit this approval applies to

    -- Content
    body TEXT,

    -- Timestamps
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    dismissed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_approval_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_approval_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_approval_pr ON m23_governance.approvals(pr_id, state);
COMMENT ON TABLE m23_governance.approvals IS 'Formal review decisions governing merge eligibility.';

------------------------------------------------------------------------------------------------
-- Table: 20 - review_comments
-- Description: Detailed comments made during code review.
-- Business Case: Facilitates the knowledge transfer and quality improvement process. Stores
-- the line-by-line feedback. Also used for sentiment analysis (Table 43) to detect toxic behavior.
-- KPIs: 1. Comment Resolution Time, 2. Constructive Feedback Ratio, 3. Toxic Comment Rate.
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.review_comments (
    -- Primary Key
    comment_id BIGSERIAL PRIMARY KEY,

    -- Linking
    approval_id BIGINT,
    pr_id BIGINT NOT NULL,
    author_id BIGINT NOT NULL,

    -- Position
    file_path TEXT,
    line_number INTEGER,

    -- Content
    body TEXT NOT NULL,
    diff_hunk TEXT, -- The specific code block being discussed

    -- Sentiment (Auto-populated)
    sentiment_score NUMERIC(3,2) CHECK (sentiment_score BETWEEN -1.0 AND 1.0),
    sentiment_category m23_governance.sentiment_category,

    -- Status
    is_resolved BOOLEAN DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_comment_approval FOREIGN KEY (approval_id) REFERENCES m23_governance.approvals(approval_id),
    CONSTRAINT fk_comment_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_comment_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.review_comments IS 'Line-by-line discussion and feedback on proposed code changes.';

------------------------------------------------------------------------------------------------
-- Table: 21 - issue_references
-- Description: Links PRs to Jira/GitHub issues.
-- Business Case: Ensures traceability. Every PR should solve a defined requirement or bug.
-- Allows Product Management to roadmap effectively by seeing which issues are being addressed in
-- the current development cycle.
-- KPIs: 1. PR-to-Issue Linkage Rate, 2. Issue Resolution Velocity, 3. Scope Creep Detection.
-- Feature Reference: 160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.issue_references (
    -- Composite Primary Key
    pr_id BIGINT NOT NULL,
    issue_id VARCHAR(100) NOT NULL, -- Can be external ID

    -- Metadata
    issue_tracker VARCHAR(50) DEFAULT 'github', -- github, jira, azure-devops
    issue_type VARCHAR(50), -- BUG, FEATURE, IMPROVEMENT

    -- Constraints
    CONSTRAINT pk_pr_issue PRIMARY KEY (pr_id, issue_id),
    CONSTRAINT fk_ref_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.issue_references IS 'Traceability linkage between code changes and product requirements.';

------------------------------------------------------------------------------------------------
-- Table: 22 - architecture_decision_records
-- Description: Stores metadata for ADRs linked to PRs.
-- Business Case: Significant design changes must be documented. This table enforces that for
-- complex PRs, an ADR exists and is linked. Maintains architectural history and intent.
-- KPIs: 1. ADR Coverage for Major Changes, 2. ADR Obsolescence Rate, 3. Design Review Participation.
-- Feature Reference: 10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.architecture_decision_records (
    -- Primary Key
    adr_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT,

    -- Details
    title VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'PROPOSED', -- PROPOSED, ACCEPTED, SUPERSEDED
    url TEXT, -- Link to the ADR document (usually Markdown in repo)
    context TEXT,
    decision TEXT,
    consequences TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_adr_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.architecture_decision_records IS 'Metadata tracking for significant architectural design decisions.';

------------------------------------------------------------------------------------------------
-- Table: 23 - performance_benchmarks
-- Description: Stores benchmark results for PR comparisons.
-- Business Case: PARI handles high-throughput payments. This table ensures that a "performance
-- regression" does not slip in. Compares metrics (latency, throughput) of the PR head against
-- the base branch.
-- KPIs: 1. Performance Regression Count, 2. Benchmark Stability, 3. Transaction Throughput,
-- 4. Latency Percentiles (p50, p99).
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.performance_benchmarks (
    -- Primary Key
    benchmark_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Scenario
    scenario_name VARCHAR(255) NOT NULL, -- e.g., "ISO20022_Payment_Parse"

    -- Metrics
    value NUMERIC(20,5) NOT NULL, -- e.g., duration in ms
    unit VARCHAR(20) NOT NULL, -- ms, ops/sec, bytes
    baseline_value NUMERIC(20,5), -- The value from the base branch
    diff_pct NUMERIC(5,2), -- Percentage change

    -- Result
    is_regression BOOLEAN DEFAULT FALSE,
    is_improvement BOOLEAN DEFAULT FALSE,
    threshold_pct NUMERIC(5,2), -- The allowed variance

    -- Environment
    runner_hardware VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_bench_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_bench_pr ON m23_governance.performance_benchmarks(pr_id);
COMMENT ON TABLE m23_governance.performance_benchmarks IS 'Performance metrics to prevent degradation in payment processing speed.';

------------------------------------------------------------------------------------------------
-- Table: 24 - build_artifacts
-- Description: Metadata for artifacts generated by CI.
-- Business Case: Tracks the output of the build process (binaries, Docker images, SBOMs).
-- Essential for traceability—knowing exactly which binary artifact is deployed to production.
-- KPIs: 1. Artifact Storage Size, 2. Build Success Rate, 3. Artifact Retention Compliance.
-- Feature Reference: 58
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.build_artifacts (
    -- Primary Key
    artifact_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Details
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- BINARY, DOCKER_IMAGE, SBOM, JAR
    size_bytes BIGINT,

    -- Integrity
    checksum_sha256 CHAR(64) NOT NULL,
    signed_signature TEXT, -- Sigstore/Cosign signature

    -- Location
    storage_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_artifact_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

COMMENT ON TABLE m23_governance.build_artifacts IS 'Immutable inventory of build outputs for deployment and auditing.';

------------------------------------------------------------------------------------------------
-- Table: 25 - sbom_entries
-- Description: Software Bill of Materials entries.
-- Business Case: Compliance requirement (e.g., US Cybersecurity Executive Order). Lists every
-- component, library, and module in the delivered software. Enables rapid response to new CVEs.
-- KPIs: 1. SBOM Generation Accuracy, 2. Vulnerability Scan Match Rate, 3. Component Completeness.
-- Feature Reference: 48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sbom_entries (
    -- Primary Key
    entry_id BIGSERIAL PRIMARY KEY,

    -- Linking
    artifact_id BIGINT NOT NULL,

    -- Component
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    supplier VARCHAR(255),
    download_location TEXT,
    license_concluded VARCHAR(50),
    checksum_sha256 CHAR(64),

    -- Hierarchy
    is_dependency BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_sbom_artifact FOREIGN KEY (artifact_id) REFERENCES m23_governance.build_artifacts(artifact_id)
);

CREATE INDEX idx_sbom_artifact ON m23_governance.sbom_entries(artifact_id);
COMMENT ON TABLE m23_governance.sbom_entries IS 'Detailed Software Bill of Materials for compliance and supply chain security.';

------------------------------------------------------------------------------------------------
-- Table: 26 - container_images
-- Description: Docker image metadata.
-- Business Case: PARI runs on containerized infrastructure. This table tracks the specific image
-- digests built and deployed, ensuring reproducibility and preventing image drift.
-- KPIs: 1. Image Size Reduction, 2. Base Image Freshness, 3. Layer Count Optimization.
-- Feature Reference: 18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.container_images (
    -- Primary Key
    image_id BIGSERIAL PRIMARY KEY,

    -- Linking
    artifact_id BIGINT NOT NULL,

    -- Image Details
    registry VARCHAR(100) NOT NULL,
    repo VARCHAR(255) NOT NULL,
    tag VARCHAR(100) NOT NULL,
    digest CHAR(71) NOT NULL, -- sha256:...
    layers_count INTEGER,
    size_bytes BIGINT,

    -- Security
    base_image_digest CHAR(71),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_image_artifact FOREIGN KEY (artifact_id) REFERENCES m23_governance.build_artifacts(artifact_id),
    CONSTRAINT uq_image_digest UNIQUE (registry, repo, digest)
);

COMMENT ON TABLE m23_governance.container_images IS 'Metadata for containerized deployment units.';

------------------------------------------------------------------------------------------------
-- Table: 27 - image_vulnerabilities
-- Description: CVEs found in Docker layers.
-- Business Case: Runtime security. Checks the OS layer (Alpine/Debian) for vulnerabilities, not
-- just the application code. Critical for preventing host escape or container takeover.
-- KPIs: 1. Image CVE Count, 2. OS Patch Compliance, 3. Base Image Update Frequency.
-- Feature Reference: 59
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.image_vulnerabilities (
    -- Primary Key
    img_vuln_id BIGSERIAL PRIMARY KEY,

    -- Linking
    image_id BIGINT NOT NULL,

    -- Vulnerability
    cve_id VARCHAR(20) NOT NULL,
    package_name VARCHAR(255),
    severity m23_governance.severity_level NOT NULL,
    fixed_in_version VARCHAR(100),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_img_vuln_image FOREIGN KEY (image_id) REFERENCES m23_governance.container_images(image_id)
);

COMMENT ON TABLE m23_governance.image_vulnerabilities IS 'Security findings within the container operating system layers.';

------------------------------------------------------------------------------------------------
-- Table: 28 - dependency_pins
-- Description: Tracks lock files (package-lock.json) to ensure pinning.
-- Business Case: Ensures reproducible builds. Prevents a dependency from changing mid-day
-- (e.g., a library author deleting a version) which could break production builds.
-- KPIs: 1. Lock File Coverage, 2. Reproducible Build Success Rate.
-- Feature Reference: 12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_pins (
    -- Primary Key
    pin_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Lock File
    file_name VARCHAR(255) NOT NULL, -- package-lock.json, go.sum
    dependency_name VARCHAR(255) NOT NULL,
    expected_version VARCHAR(100) NOT NULL,
    ecosystem VARCHAR(50),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_pin_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

COMMENT ON TABLE m23_governance.dependency_pins IS 'Verification of strict version pinning in dependency manifests.';

------------------------------------------------------------------------------------------------
-- Table: 29 - api_spec_changes
-- Description: Tracks changes to OpenAPI specs.
-- Business Case: API contracts are sacred. This table detects changes to the OpenAPI/Swagger
-- definition, flagging breaking changes that would crash banking clients or wallet integrations.
-- KPIs: 1. Breaking Change Detection Rate, 2. API Spec Accuracy, 3. Documentation Lag.
-- Feature Reference: 17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_spec_changes (
    -- Primary Key
    spec_change_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Change Details
    endpoint_path TEXT NOT NULL,
    method VARCHAR(10) NOT NULL, -- GET, POST, PUT, DELETE
    change_type VARCHAR(50) NOT NULL, -- ADDED, REMOVED, MODIFIED
    property_changed VARCHAR(255), -- e.g., 'response.200.schema'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_spec_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.api_spec_changes IS 'Audit trail of modifications to API contracts.';

------------------------------------------------------------------------------------------------
-- Table: 30 - breaking_changes
-- Description: Logs detected breaking changes.
-- Business Case: A subset of API spec changes, but specifically for *breaking* changes.
-- These require explicit approval from a "API Architect" before merge, ensuring backwards
-- compatibility for banks.
-- KPIs: 1. Breaking Change Frequency, 2. Breaking Change Approval Time, 3. Client Integration Failure Rate.
-- Feature Reference: 17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.breaking_changes (
    -- Primary Key
    break_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    description TEXT NOT NULL,
    severity m23_governance.severity_level NOT NULL DEFAULT 'HIGH',
    component_affected VARCHAR(255),

    -- Status
    is_approved BOOLEAN, -- Explicit waiver required
    approver_id BIGINT,
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_break_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_break_approver FOREIGN KEY (approver_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.breaking_changes IS 'Critical log of backwards-incompatible modifications requiring high-level approval.';

------------------------------------------------------------------------------------------------
-- Table: 31 - changelog_entries
-- Description: Changelog updates required for PRs.
-- Business Case: Transparency. Ensures that every merged PR contributes to the CHANGELOG,
-- facilitating release notes generation for downstream consumers.
-- KPIs: 1. Changelog Coverage, 2. Release Note Automation Accuracy.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.changelog_entries (
    -- Primary Key
    changelog_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Entry Details
    version VARCHAR(50), -- e.g. v1.2.3
    change_type VARCHAR(20) CHECK (change_type IN ('ADDED', 'CHANGED', 'DEPRECATED', 'REMOVED', 'FIXED', 'SECURITY')),
    description TEXT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_changelog_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.changelog_entries IS 'Structured data for automated release note generation.';

------------------------------------------------------------------------------------------------
-- Table: 32 - labels
-- Description: Definition of PR labels.
-- Business Case: Categorizes PRs for filtering and routing (e.g., 'bug', 'enhancement',
-- 'documentation'). Used for automation triggers.
-- KPIs: 1. Label Usage Consistency, 2. Triage Efficiency.
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.labels (
    -- Primary Key
    label_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(100) NOT NULL UNIQUE,
    color CHAR(7) NOT NULL, -- Hex code
    description TEXT,

    -- Scope
    scope VARCHAR(50) DEFAULT 'GLOBAL', -- GLOBAL, repo specific

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.labels IS 'Master list of categorization tags for Pull Requests.';

------------------------------------------------------------------------------------------------
-- Table: 33 - pr_labels
-- Description: Junction for PR labels.
-- Business Case: Many-to-many relationship implementation. Allows a PR to have multiple tags
-- (e.g., 'security' and 'database').
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_labels (
    pr_id BIGINT NOT NULL,
    label_id INTEGER NOT NULL,

    -- Audit
    labeled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    labeled_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT pk_pr_labels PRIMARY KEY (pr_id, label_id),
    CONSTRAINT fk_prl_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id) ON DELETE CASCADE,
    CONSTRAINT fk_prl_label FOREIGN KEY (label_id) REFERENCES m23_governance.labels(label_id)
);

------------------------------------------------------------------------------------------------
-- Table: 34 - milestones
-- Description: Project milestones for releases.
-- Business Case: Time-boxing development. Organizes PRs into specific releases (e.g., "Q1 2024
-- Banking Compliance Update").
-- KPIs: 1. Milestone Completion Rate, 2. On-Time Release Delivery.
-- Feature Reference: 54
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.milestones (
    -- Primary Key
    milestone_id SERIAL PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    state VARCHAR(20) DEFAULT 'OPEN', -- OPEN, CLOSED
    due_date TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.milestones IS 'Time-based grouping for releases and project tracking.';

------------------------------------------------------------------------------------------------
-- Table: 35 - pr_milestones
-- Description: Links PRs to milestones.
-- Business Case: Associates work with a delivery target.
-- Feature Reference: 54
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_milestones (
    pr_id BIGINT NOT NULL,
    milestone_id INTEGER NOT NULL,

    -- Constraints
    CONSTRAINT pk_pr_milestones PRIMARY KEY (pr_id, milestone_id),
    CONSTRAINT fk_prm_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_prm_milestone FOREIGN KEY (milestone_id) REFERENCES m23_governance.milestones(milestone_id)
);

------------------------------------------------------------------------------------------------
-- Table: 36 - badges
-- Description: Gamification badges.
-- Business Case: Encourages contributions. Awards visual status (e.g., "Bug Hunter") to
-- contributors, fostering community engagement.
-- KPIs: 1. Badge Earned Count, 2. Contributor Retention vs. Badges.
-- Feature Reference: 69
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.badges (
    -- Primary Key
    badge_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon_url TEXT,
    criteria JSONB, -- Stored logic for awarding (e.g., {"commits": 100})

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.badges IS 'Achievements definition for community gamification.';

------------------------------------------------------------------------------------------------
-- Table: 37 - contributor_badges
-- Description: Links badges to contributors.
-- Business Case: Records which contributors have earned which awards.
-- Feature Reference: 69
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_badges (
    contributor_id BIGINT NOT NULL,
    badge_id INTEGER NOT NULL,

    awarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    awarded_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT pk_contributor_badges PRIMARY KEY (contributor_id, badge_id),
    CONSTRAINT fk_cb_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_cb_badge FOREIGN KEY (badge_id) REFERENCES m23_governance.badges(badge_id)
);

------------------------------------------------------------------------------------------------
-- Table: 38 - bounties
-- Description: Monetary rewards for issues.
-- Business Case: Incentivizes critical bug fixes or feature development, especially for security
-- vulnerabilities.
-- KPIs: 1. Bounty Payout Time, 2. Bounty Engagement Rate.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.bounties (
    -- Primary Key
    bounty_id SERIAL PRIMARY KEY,

    -- Issue
    issue_id VARCHAR(100) NOT NULL UNIQUE, -- External ID

    -- Financials
    amount NUMERIC(15,2) NOT NULL,
    currency m23_governance.currency_code NOT NULL DEFAULT 'USD',

    -- Status
    status m23_governance.bounty_status NOT NULL DEFAULT 'OPEN',

    -- Details
    description TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.bounties IS 'Financial incentives for critical community contributions.';

------------------------------------------------------------------------------------------------
-- Table: 39 - bounty_claims
-- Description: Links PRs to bounty claims.
-- Business Case: Ties the specific code fix to the reward payment.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.bounty_claims (
    -- Primary Key
    bounty_id INTEGER NOT NULL,
    pr_id BIGINT NOT NULL,

    -- Claim
    claimed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    paid_at TIMESTAMP WITH TIME ZONE,
    transaction_hash VARCHAR(255), -- Blockchain or Bank Reference

    -- Constraints
    CONSTRAINT pk_bounty_claims PRIMARY KEY (bounty_id, pr_id),
    CONSTRAINT fk_claim_bounty FOREIGN KEY (bounty_id) REFERENCES m23_governance.bounties(bounty_id),
    CONSTRAINT fk_claim_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

------------------------------------------------------------------------------------------------
-- Table: 40 - preview_environments
-- Description: Tracks ephemeral preview deployments.
-- Business Case: Allows stakeholders (Product Managers, Designers) to interact with a live version
-- of the PR before merging, improving feedback quality.
-- KPIs: 1. Environment Spin-up Time, 2. Environment Utilization Rate.
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.preview_environments (
    -- Primary Key
    env_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Access
    url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, STOPPED, ERROR

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Auto-termination

    -- Infrastructure
    namespace VARCHAR(100),
    cluster_id VARCHAR(100),

    -- Constraints
    CONSTRAINT fk_preview_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.preview_environments IS 'Ephemeral deployments for live verification of Pull Requests.';

------------------------------------------------------------------------------------------------
-- Table: 41 - quality_gates
-- Description: Definition of quality rules.
-- Business Case: The "Threshold" logic. Defines what constitutes a "pass" for the system.
-- (e.g., Coverage must be > 95).
-- KPIs: 1. Gate Stability, 2. False Positive Rejection Rate.
-- Feature Reference: 9
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.quality_gates (
    -- Primary Key
    gate_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(255) NOT NULL UNIQUE,
    metric_type VARCHAR(100) NOT NULL, -- code_coverage, sast_critical_count
    operator m23_governance.gate_operator NOT NULL,
    threshold_value NUMERIC(20,5) NOT NULL,

    -- Scope
    applies_to VARCHAR(50) DEFAULT 'ALL', -- ALL, CORE, WALLET

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.quality_gates IS 'Configurable threshold definitions for automated merge blocking.';

------------------------------------------------------------------------------------------------
-- Table: 42 - gate_results
-- Description: Results of quality gate evaluation.
-- Business Case: The evaluation log. Stores the actual value vs the threshold for a specific run.
-- Provides debuggability for why a PR was blocked.
-- Feature Reference: 9
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.gate_results (
    -- Primary Key
    result_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,
    gate_id INTEGER NOT NULL,

    -- Evaluation
    passed BOOLEAN NOT NULL,
    actual_value NUMERIC(20,5),

    -- Audit
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_gate_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id),
    CONSTRAINT fk_gate_def FOREIGN KEY (gate_id) REFERENCES m23_governance.quality_gates(gate_id)
);

CREATE INDEX idx_gate_run ON m23_governance.gate_results(run_id, passed);
COMMENT ON TABLE m23_governance.gate_results IS 'Historical record of quality rule evaluations per build.';

------------------------------------------------------------------------------------------------
-- Table: 43 - sentiment_analysis
-- Description: Stores sentiment of PR comments.
-- Business Case: Community health monitoring. Automatically flags toxic comments for moderator
-- intervention, maintaining a welcoming environment.
-- KPIs: 1. Toxic Comment Reduction Rate, 2. Moderator Intervention Efficiency.
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sentiment_analysis (
    -- Primary Key
    sentiment_id BIGSERIAL PRIMARY KEY,

    -- Linking
    comment_id BIGINT NOT NULL,

    -- Analysis
    score NUMERIC(3,2), -- Magnitude -1.0 to 1.0
    magnitude NUMERIC(3,2), -- Strength of emotion
    category m23_governance.sentiment_category,

    -- Audit
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50),

    -- Constraints
    CONSTRAINT fk_sentiment_comment FOREIGN KEY (comment_id) REFERENCES m23_governance.review_comments(comment_id)
);

COMMENT ON TABLE m23_governance.sentiment_analysis IS 'AI-driven analysis of community interaction tone.';

------------------------------------------------------------------------------------------------
-- Table: 44 - spam_reports
-- Description: Reports on spam or malicious contributions.
-- Business Case: Self-moderation tool. Allows trusted users to flag spam PRs or issues for automated
-- cleanup or human review.
-- KPIs: 1. Spam Detection Accuracy, 2. False Positive Spam Rate.
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spam_reports (
    -- Primary Key
    report_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT,
    reporter_id BIGINT NOT NULL,

    -- Details
    reason TEXT NOT NULL,
    spam_type VARCHAR(50), -- BOT, MALICIOUS, IRRELEVANT

    -- Status
    reviewed_at TIMESTAMP WITH TIME ZONE,
    action_taken VARCHAR(50), -- DISMISSED, BANNED_USER, DELETED

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_spam_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_spam_reporter FOREIGN KEY (reporter_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.spam_reports IS 'Community-driven moderation reports.';

------------------------------------------------------------------------------------------------
-- Table: 45 - technical_debt_tags
-- Description: Tags PRs that introduce debt.
-- Business Case: Making the invisible visible. Explicitly tracks when a PR takes a shortcut
-- (e.g., "TODO: refactor") to ensure it is paid back later.
-- KPIs: 1. Technical Debt Ratio, 2. Debt Paydown Velocity.
-- Feature Reference: 39
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.technical_debt_tags (
    -- Primary Key
    debt_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Debt Details
    description TEXT NOT NULL,
    file_path VARCHAR(1000),
    estimated_hours NUMERIC(5,2),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),

    -- Status
    is_paid BOOLEAN DEFAULT FALSE,
    paid_in_pr_id BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_debt_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.technical_debt_tags IS 'Tracking mechanism for code quality shortcuts.';

------------------------------------------------------------------------------------------------
-- Table: 46 - documentation_updates
-- Description: Tracks documentation file changes.
-- Business Case: Ensures code and documentation evolve together. Can block merges if code changes
-- are significant but docs are untouched.
-- KPIs: 1. Doc-to-Code Change Ratio, 2. Doc Readability Score.
-- Feature Reference: 19
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.documentation_updates (
    -- Primary Key
    doc_update_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path TEXT NOT NULL,
    words_added INTEGER,
    words_removed INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_doc_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.documentation_updates IS 'Quantification of documentation maintenance effort.';

------------------------------------------------------------------------------------------------
-- Table: 47 - access_control_policies
-- Description: Stores OPA/Rego policy metadata for PR checks.
-- Business Case: "Policy-as-Code". Ensures that infrastructure or authorization changes are
-- validated against defined security policies before merge.
-- KPIs: 1. Policy Coverage, 2. Policy Violation Rate.
-- Feature Reference: 37
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.access_control_policies (
    -- Primary Key
    policy_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL UNIQUE,
    rego_path TEXT NOT NULL, -- Path to policy in repo
    description TEXT,

    -- Validation
    last_checked_at TIMESTAMP WITH TIME ZONE,
    is_valid BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.access_control_policies IS 'Registry of security policies enforced via code review.';

------------------------------------------------------------------------------------------------
-- Table: 48 - fuzz_test_results
-- Description: Results of fuzzing campaigns.
-- Business Case: Deep security testing. Fuzzing throws random data at inputs to find memory
-- corruption or panic bugs that standard tests miss. Critical for crypto libraries.
-- KPIs: 1. Code Coverage (Fuzz), 2. Unique Crashes Found, 3. Stability Duration.
-- Feature Reference: 26
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.fuzz_test_results (
    -- Primary Key
    fuzz_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Execution
    target_binary VARCHAR(255) NOT NULL,
    execution_time_sec INTEGER NOT NULL,

    -- Results
    unique_crashes INTEGER DEFAULT 0,
    edge_cov NUMERIC(5,2), -- Edge coverage percentage
    corpus_size BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_fuzz_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.fuzz_test_results IS 'Results of chaos-engineering style input fuzzing.';

------------------------------------------------------------------------------------------------
-- Table: 49 - merge_queue
-- Description: Queue for serializing merges.
-- Business Case: Prevents merge conflicts in trunk-based development. Ensures that PRs are merged
-- one by one after passing all tests on the exact tip of the branch.
-- KPIs: 1. Queue Wait Time, 2. Merge Conflict Rate.
-- Feature Reference: 22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.merge_queue (
    -- Primary Key
    queue_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL UNIQUE,

    -- Queue State
    position INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, MERGING, FAILED, COMPLETED

    -- Audit
    enqueued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_queue_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.merge_queue IS 'Controls the serialization of merges to the main branch.';

-- --------------------------------------------------------------------------------------------------------
-- 5. Stored Procedures and Triggers (for Tables 1-49)
-- --------------------------------------------------------------------------------------------------------

-- Trigger Function: Updated At
CREATE OR REPLACE FUNCTION m23_governance.trigger_set_updated_at()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    IF NEW.updated_by IS NULL THEN
        NEW.updated_by = current_setting('app.current_user_id', true)::UUID;
    END IF;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;

-- Apply Trigger to Tables 1-49 (Skipping junction tables or those without updated_at)
CREATE TRIGGER trg_contributors_updated_at BEFORE UPDATE ON m23_governance.contributors
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_organizations_updated_at BEFORE UPDATE ON m23_governance.organizations
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_repositories_updated_at BEFORE UPDATE ON m23_governance.repositories
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_pull_requests_updated_at BEFORE UPDATE ON m23_governance.pull_requests
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_approved_licenses_updated_at BEFORE UPDATE ON m23_governance.approved_licenses
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_adr_updated_at BEFORE UPDATE ON m23_governance.architecture_decision_records
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_review_comments_updated_at BEFORE UPDATE ON m23_governance.review_comments
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_bounties_updated_at BEFORE UPDATE ON m23_governance.bounties
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_quality_gates_updated_at BEFORE UPDATE ON m23_governance.quality_gates
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_access_control_policies_updated_at BEFORE UPDATE ON m23_governance.access_control_policies
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

-- Row Level Security (RLS) Example for Contributors
ALTER TABLE m23_governance.contributors ENABLE ROW LEVEL SECURITY;

CREATE POLICY contributor_isolation_policy ON m23_governance.contributors
    FOR ALL
    USING (
        contributor_id = (
            SELECT contributor_id
            FROM m23_governance.contributors c
            JOIN m23_governance.contributor_organizations co ON c.contributor_id = co.contributor_id
            WHERE c.email = current_setting('app.current_user_email', true)
        )
        OR current_setting('app.is_admin', true)::BOOLEAN
    );

-- --------------------------------------------------------------------------------------------------------
-- 6. Materialized Views (Tables 1-49)
-- --------------------------------------------------------------------------------------------------------

-- View: Dashboard Summary
CREATE MATERIALIZED VIEW m23_governance.mv_pr_dashboard AS
SELECT
    r.name as repo_name,
    pr.state,
    COUNT(*) as pr_count,
    AVG(EXTRACT(EPOCH FROM (COALESCE(pr.closed_at, CURRENT_TIMESTAMP) - pr.opened_at))/3600) as avg_age_hours
FROM m23_governance.pull_requests pr
JOIN m23_governance.repositories r ON pr.repo_id = r.repo_id
GROUP BY r.name, pr.state
WITH DATA;

CREATE UNIQUE INDEX uq_mv_pr_dashboard ON m23_governance.mv_pr_dashboard(repo_name, state);

COMMENT ON MATERIALIZED VIEW m23_governance.mv_dashboard IS 'Aggregated summary of PR velocity by repository and state.';

-- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 2: Database Objects Tables 051-100
-- ==========================================================================================================
-- Description:
-- This script continues the definition of the database schema for Module M23, covering database
-- objects 51 through 100 as defined in the comprehensive feature matrix. This section focuses on
-- branching strategies, code ownership, community management, statistics, audit trails, and
-- advanced security metrics.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 51 - branch_protection_rules
-- Description: Rules applied to git branches to prevent unauthorized merges or deletions.
-- Business Case: Critical for maintaining the integrity of the `main` and `release` branches.
-- These rules enforce peer reviews, status checks (CI/CD), and restrictions on who can push,
-- mitigating the risk of unauthorized code injection or accidental breaking changes.
-- KPIs: 1. Rule Compliance Rate, 2. Unauthorized Push Attempts, 3. Forced Override Frequency.
-- Feature Reference: 32
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.branch_protection_rules (
    -- Primary Key
    rule_id SERIAL PRIMARY KEY,

    -- Linking
    repo_id INTEGER NOT NULL,

    -- Scope
    branch_pattern VARCHAR(255) NOT NULL, -- e.g., "main", "release/*"

    -- Enforcement Settings
    requires_approvals BOOLEAN DEFAULT TRUE,
    required_approving_review_count INTEGER DEFAULT 1,
    dismiss_stale_reviews BOOLEAN DEFAULT TRUE,
    requires_code_owner_reviews BOOLEAN DEFAULT TRUE,
    requires_status_checks BOOLEAN DEFAULT TRUE,
    requires_strict_status_checks BOOLEAN DEFAULT FALSE, -- Requires PR to be up to date
    requires_linear_history BOOLEAN DEFAULT TRUE,
    allows_force_pushes BOOLEAN DEFAULT FALSE,
    allows_deletions BOOLEAN DEFAULT FALSE,
    restricts_pushes BOOLEAN DEFAULT FALSE, -- If true, only specific teams/users can push
    push_allowance_list VARCHAR(255)[], -- Array of team/user slugs

    -- Contexts
    required_status_check_contexts VARCHAR(100)[], -- e.g., '{ci/circleci, security/scan}'

    -- Locking
    lock_branch BOOLEAN DEFAULT FALSE, -- Read-only mode (often used during releases)
    lock_reason TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_bp_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.branch_protection_rules IS 'Governance rules preventing unauthorized modification of critical git branches.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 52 - contributor_stats_daily
-- Description: Daily aggregation stats for contributors.
-- Business Case: Provides a time-series view of contributor engagement. Essential for generating
-- leaderboards, identifying burnout (drop in activity), and recognizing top contributors automatically.
-- KPIs: 1. Daily Active Contributors (DAC), 2. Average Commits per Contributor, 3. Churn Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_stats_daily (
    -- Composite Primary Key
    stat_id BIGSERIAL PRIMARY KEY,
    contributor_id BIGINT NOT NULL,
    date DATE NOT NULL,

    -- Metrics
    commits_made INTEGER DEFAULT 0,
    prs_opened INTEGER DEFAULT 0,
    prs_reviewed INTEGER DEFAULT 0,
    reviews_completed INTEGER DEFAULT 0,
    comments_added INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_contributor_stats UNIQUE (contributor_id, date),
    CONSTRAINT fk_stats_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_contrib_stats_date ON m23_governance.contributor_stats_daily(date DESC);
COMMENT ON TABLE m23_governance.contributor_stats_daily IS 'Aggregated daily metrics for contributor performance analytics.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 53 - repo_stats_daily
-- Description: Daily aggregation stats for repositories.
-- Business Case: Tracks the health and growth of the project over time. Used in executive
-- dashboards to visualize adoption (stars/forks) and activity volume (issues/PRs).
-- KPIs: 1. Star Growth Velocity, 2. Issue Resolution Rate, 3. Fork/Star Ratio.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.repo_stats_daily (
    -- Composite Primary Key
    repo_stat_id BIGSERIAL PRIMARY KEY,
    repo_id INTEGER NOT NULL,
    date DATE NOT NULL,

    -- Metrics
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    watchers INTEGER DEFAULT 0,
    issues_open INTEGER DEFAULT 0,
    pr_open INTEGER DEFAULT 0,
    pr_merged INTEGER DEFAULT 0,
    commits_count INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_repo_stats UNIQUE (repo_id, date),
    CONSTRAINT fk_repo_stats_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.repo_stats_daily IS 'Daily health and popularity metrics for source code repositories.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 54 - audit_trail
-- Description: Immutable log of significant governance events.
-- Business Case: Essential for CMMI Level 5 traceability and regulatory compliance (GDPR/PSD2).
-- Provides a forensic record of who changed what (settings, permissions, merges) and when.
-- Once written, rows must never be deleted or updated.
-- KPIs: 1. Audit Log Completeness, 2. Event Retrieval Latency, 3. Immutable Record Integrity.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.audit_trail (
    -- Primary Key
    event_id BIGSERIAL PRIMARY KEY,

    -- Event Details
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    actor_type VARCHAR(50) NOT NULL, -- USER, SYSTEM, BOT
    actor_id VARCHAR(255) NOT NULL, -- ID of the actor
    action_type VARCHAR(100) NOT NULL, -- CREATE, UPDATE, DELETE, MERGE, BLOCK
    resource_type VARCHAR(100) NOT NULL, -- PR, REPO, POLICY, USER
    resource_id VARCHAR(255) NOT NULL,

    -- Context
    details_json JSONB, -- Additional context like old_value, new_value, ip_address
    ip_address INET,
    user_agent TEXT,

    -- Result
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT
);

COMMENT ON TABLE m23_governance.audit_trail IS 'Immutable, tamper-evident log of all governance actions for forensic analysis.';
CREATE INDEX idx_audit_timestamp ON m23_governance.audit_trail(timestamp DESC);

-- --------------------------------------------------------------------------------------------------------
-- Table: 55 - webhooks
-- Description: External webhook endpoints for notifications.
-- Business Case: Enables integration with external tools (Slack, Jira, PagerDuty). When specific
-- events occur (PR merged, build failed), M23 notifies these endpoints to keep stakeholders
-- informed automatically.
-- KPIs: 1. Webhook Delivery Success Rate, 2. Endpoint Response Time.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.webhooks (
    -- Primary Key
    webhook_id SERIAL PRIMARY KEY,

    -- Target
    url TEXT NOT NULL,
    secret VARCHAR(255), -- HMAC secret for validation

    -- Configuration
    events VARCHAR(50)[] NOT NULL, -- e.g., {pull_request, push, deployment}
    content_type VARCHAR(50) DEFAULT 'application/json',
    is_active BOOLEAN DEFAULT TRUE,
    insecure_ssl BOOLEAN DEFAULT FALSE, -- For testing only

    -- Metadata
    description TEXT,
    owner_id BIGINT, -- Contributor who owns this webhook

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT fk_webhook_owner FOREIGN KEY (owner_id) REFERENCES m23_governance.contributors(contributor_id)
);

-- Trigger for webhooks
CREATE TRIGGER trg_webhooks_updated_at BEFORE UPDATE ON m23_governance.webhooks
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.webhooks IS 'Configuration for external event-driven notifications.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 56 - webhook_deliveries
-- Description: Logs of webhook delivery attempts.
-- Business Case: Tracks the success/failure of notifications sent to external systems. Crucial
-- for debugging integration failures (e.g., Slack down, Jira API limit reached). Supports retry logic.
-- KPIs: 1. Successful Delivery Rate, 2. Retry Frequency, 3. Average Latency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.webhook_deliveries (
    -- Primary Key
    delivery_id BIGSERIAL PRIMARY KEY,

    -- Linking
    webhook_id INTEGER NOT NULL,

    -- Request
    event_type VARCHAR(50) NOT NULL,
    payload_json JSONB,
    request_headers JSONB,

    -- Response
    response_status INTEGER,
    response_body TEXT,
    response_headers JSONB,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SUCCESS, FAILED, RETRYING
    attempts INTEGER DEFAULT 1,
    last_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Duration
    duration_ms INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_whd_webhook FOREIGN KEY (webhook_id) REFERENCES m23_governance.webhooks(webhook_id)
);

CREATE INDEX idx_whd_webhook_status ON m23_governance.webhook_deliveries(webhook_id, status);
COMMENT ON TABLE m23_governance.webhook_deliveries IS 'Delivery log and retry queue for external webhook notifications.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 57 - project_settings
-- Description: Global module settings.
-- Business Case: Centralized configuration for the M23 module. Stores feature flags (e.g.,
-- enable_cooloff_period, enforce_gamification) without requiring code redeployments.
-- KPIs: 1. Configuration Change Frequency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.project_settings (
    -- Composite Primary Key
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    value_type VARCHAR(20) DEFAULT 'STRING', -- STRING, INTEGER, BOOLEAN, JSON
    description TEXT,

    -- Access Control
    is_public BOOLEAN DEFAULT FALSE, -- Can clients read this?
    is_readonly BOOLEAN DEFAULT FALSE,

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

CREATE TRIGGER trg_project_settings_updated_at BEFORE UPDATE ON m23_governance.project_settings
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.project_settings IS 'Global key-value store for module configuration and feature flags.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 58 - security_advisories
-- Description: Published security advisories for vulnerabilities.
-- Business Case: Official communication channel for security issues found in the PARI ecosystem.
-- Coordinates with CVE databases. Ensures downstream consumers (banks) are aware of risks.
-- KPIs: 1. Time to Disclosure (MTTD), 2. Advisory Accuracy.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.security_advisories (
    -- Primary Key
    advisory_id SERIAL PRIMARY KEY,

    -- Identification
    cve_id VARCHAR(20), -- External CVE ID
    ghsa_id VARCHAR(50), -- GitHub Security Advisory ID
    summary TEXT NOT NULL,
    description TEXT,

    -- Severity
    severity m23_governance.severity_level NOT NULL,
    cvss_vector VARCHAR(100),
    cvss_score NUMERIC(3,1),

    -- Lifecycle
    published_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    withdrawn_at TIMESTAMP WITH TIME ZONE,

    -- References
    identifiers JSONB, -- Array of {type, value}
    references JSONB, -- Array of URLs

    -- Audit
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

CREATE TRIGGER trg_advisories_updated_at BEFORE UPDATE ON m23_governance.security_advisories
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.security_advisories IS 'Official records of security vulnerabilities and their remediation status.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 59 - dependency_licenses
-- Description: Junction table for dependencies and licenses.
-- Business Case: Dependencies can have multiple licenses (e.g., MIT AND Apache). This table
-- resolves the many-to-many relationship to ensure accurate compliance checking.
-- KPIs: 1. Multi-license Detection Accuracy.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_licenses (
    -- Composite Primary Key
    dep_id BIGINT NOT NULL,
    license_id INTEGER NOT NULL,

    -- Constraints
    CONSTRAINT pk_dep_licenses PRIMARY KEY (dep_id, license_id),
    CONSTRAINT fk_dl_dep FOREIGN KEY (dep_id) REFERENCES m23_governance.sca_dependencies(dep_id),
    CONSTRAINT fk_dl_license FOREIGN KEY (license_id) REFERENCES m23_governance.approved_licenses(license_id)
);

COMMENT ON TABLE m23_governance.dependency_licenses IS 'Resolves many-to-many relationship between software packages and their licenses.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 60 - i18n_strings
-- Description: Stores UI strings for translation checks.
-- Business Case: PARI serves a global market. This table tracks all user-facing strings to ensure
-- no hardcoded text exists and that all languages are updated simultaneously.
-- KPIs: 1. Translation Coverage per Locale, 2. Missing String Count.
-- Feature Reference: 40
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.i18n_strings (
    -- Primary Key
    string_id SERIAL PRIMARY KEY,

    -- Details
    key VARCHAR(255) NOT NULL UNIQUE, -- e.g., "nav.home"
    source_text TEXT NOT NULL, -- English (en_US)
    context TEXT, -- Usage context for translators
    is_plural BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.i18n_strings IS 'Master repository of translatable strings for the UI.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 61 - pr_i18n_files
-- Description: Tracks i18n files modified in a PR.
-- Business Case: Ensures that code changes impacting the UI are accompanied by updates to translation
-- files. Prevents "missing translation" errors in production.
-- KPIs: 1. UI Change to Translation File Ratio.
-- Feature Reference: 40
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_i18n_files (
    -- Composite Primary Key
    pr_id BIGINT NOT NULL,
    language_code CHAR(5) NOT NULL, -- e.g., en_US, de_DE, fr_FR
    file_path TEXT NOT NULL,

    -- Changes
    strings_added INTEGER DEFAULT 0,
    strings_removed INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_pr_i18n UNIQUE (pr_id, language_code, file_path),
    CONSTRAINT fk_i18n_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.pr_i18n_files IS 'Tracks localization file changes within Pull Requests.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 62 - accessibility_reports
-- Description: Results of a11y scans (e.g., AXE core).
-- Business Case: Ensures PARI is usable by everyone, including those with disabilities (WCAG 2.1).
-- Detects missing alt tags, poor contrast, and keyboard navigation issues.
-- KPIs: 1. WCAG Compliance Score, 2. Accessibility Debt, 3. Critical A11y Violations.
-- Feature Reference: 41
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.accessibility_reports (
    -- Primary Key
    report_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    url TEXT, -- The URL tested (if available)
    tool_name VARCHAR(50) DEFAULT 'axe-core',
    violation_count INTEGER DEFAULT 0,
    incomplete_count INTEGER DEFAULT 0,

    -- Data
    results_jsonb JSONB, -- Detailed violation nodes

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_a11y_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.accessibility_reports IS 'Automated accessibility compliance scan results.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 63 - visual_regression_results
-- Description: Stores diff images for UI changes.
-- Business Case: Prevents unintended UI layout shifts. Compares screenshots of the "base" vs
-- "head" code to catch pixel-perfect regressions before they reach users.
-- KPIs: 1. Visual Diff Detection Rate, 2. False Positive Rate.
-- Feature Reference: 91
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.visual_regression_results (
    -- Primary Key
    vr_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Comparison
    screenshot_name VARCHAR(255) NOT NULL,
    baseline_url TEXT,
    diff_url TEXT,
    actual_url TEXT,

    -- Metrics
    diff_percentage NUMERIC(5,2),
    has_diff BOOLEAN DEFAULT FALSE,
    pixel_diff_count BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_vr_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.visual_regression_results IS 'Stores screenshot comparisons to detect visual UI regressions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 64 - bundle_sizes
-- Description: JS bundle size metrics.
-- Business Case: Performance optimization. Ensures new dependencies don't bloat the wallet JS,
-- keeping load times fast for mobile users on slow networks.
-- KPIs: 1. Bundle Size Growth Rate, 2. Gzipped Size Limit Compliance.
-- Feature Reference: 92
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.bundle_sizes (
    -- Primary Key
    bundle_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Metrics
    bundle_name VARCHAR(255) NOT NULL,
    size_bytes BIGINT NOT NULL,
    gzip_bytes BIGINT NOT NULL,
    size_delta_bytes BIGINT, -- Change from baseline

    -- Compliance
    exceeds_limit BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_bundle_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.bundle_sizes IS 'Tracks JavaScript bundle size to maintain wallet performance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 65 - code_complexity_metrics
-- Description: Cyclomatic complexity per file.
-- Business Case: High complexity leads to bugs. This table flags files that are becoming too
-- difficult to maintain or test, prompting refactoring.
-- KPIs: 1. Average Cyclomatic Complexity, 2. Complex File Count.
-- Feature Reference: 30
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_complexity_metrics (
    -- Primary Key
    metric_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path TEXT NOT NULL,
    complexity_score INTEGER NOT NULL, -- McCabe's score
    function_count INTEGER,
    class_count INTEGER,
    lines_of_code INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_complexity_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.code_complexity_metrics IS 'Stores code complexity analysis results to maintain software maintainability.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 66 - code_duplication_records
-- Description: Duplication detection results.
-- Business Case: DRY (Don't Repeat Yourself). Code duplication bloats the codebase and creates
-- maintenance burden (fixing a bug requires fixing it in multiple places).
-- KPIs: 1. Duplication Percentage, 2. Total Duplicated Lines.
-- Feature Reference: 38
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_duplication_records (
    -- Primary Key
    dup_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path_a TEXT NOT NULL,
    file_path_b TEXT NOT NULL,
    lines_duplicated INTEGER,
    start_line_a INTEGER,
    start_line_b INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_dup_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.code_duplication_records IS 'Identifies copy-pasted code blocks to reduce technical debt.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 67 - dead_code_records
-- Description: Detected unused code.
-- Business Case: Dead code is confusing to developers and increases the attack surface. Removing
-- it simplifies the codebase.
-- KPIs: 1. Dead Code Elimination Rate.
-- Feature Reference: 27
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dead_code_records (
    -- Primary Key
    dead_code_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path TEXT NOT NULL,
    symbol_name VARCHAR(255), -- Function/Variable name
    symbol_type VARCHAR(50), -- FUNCTION, CLASS, VARIABLE
    language VARCHAR(50),

    -- Confidence
    last_accessed_estimate DATE, -- When it was last used (or never)

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_dead_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.dead_code_records IS 'Flags unused code segments for removal to keep the codebase clean.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 68 - test_impact_map
-- Description: Maps source files to test files.
-- Business Case: Optimization. Instead of running the full test suite (hours), only run tests
-- relevant to the files changed in the PR. Dramatically speeds up feedback loops.
-- KPIs: 1. Test Execution Time Reduction, 2. Coverage of Selected Tests.
-- Feature Reference: 34
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.test_impact_map (
    -- Primary Key
    source_file TEXT NOT NULL, -- e.g., "src/core/payment.go"
    test_file TEXT NOT NULL,   -- e.g., "tests/core/payment_test.go"

    -- Scoring
    confidence NUMERIC(3,2) DEFAULT 1.00, -- How certain we are this test covers this source

    -- Audit
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_test_impact UNIQUE (source_file, test_file)
);

COMMENT ON TABLE m23_governance.test_impact_map IS 'Maps source code to unit tests to enable smart, selective test execution.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 69 - performance_regression_alerts
-- Description: Alerts for slow-downs.
-- Business Case: Instant notification when a PR degrades performance beyond a set threshold
-- (e.g., latency > 5%). Allows for immediate rollback or investigation.
-- KPIs: 1. Alert Latency, 2. True Positive Rate.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.performance_regression_alerts (
    -- Primary Key
    alert_id BIGSERIAL PRIMARY KEY,

    -- Linking
    benchmark_id BIGINT NOT NULL,
    pr_id BIGINT NOT NULL,

    -- Alert Details
    threshold_exceeded NUMERIC(5,2),
    actual_value NUMERIC(20,5),
    severity m23_governance.severity_level,

    -- Status
    alert_sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by BIGINT,

    -- Audit
    acknowledged_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_alert_bench FOREIGN KEY (benchmark_id) REFERENCES m23_governance.performance_benchmarks(benchmark_id),
    CONSTRAINT fk_alert_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_alert_user FOREIGN KEY (acknowledged_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.performance_regression_alerts IS 'Notifications triggered by significant performance degradation in benchmarks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 70 - threat_models
-- Description: Links PRs to threat model updates.
-- Business Case: Security by design. When code handling auth, crypto, or PII changes, the threat
-- model must be updated. This table ensures that linkage is enforced.
-- KPIs: 1. Threat Model Currency, 2. Security Review Coverage for Auth Changes.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.threat_models (
    -- Primary Key
    threat_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    model_file_path TEXT NOT NULL, -- Path to threat model diagram/doc in repo
    review_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, CHANGES_REQUESTED

    -- Review
    reviewer_id BIGINT,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_threat_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_threat_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.threat_models IS 'Tracks updates to threat modeling documentation for security-sensitive code.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 71 - pgp_keys
-- Description: Stores public PGP keys for contributors.
-- Business Case: Essential for DCO enforcement and release signing. Allows the system to verify
-- that a commit was made by the owner of the email address associated with the key.
-- KPIs: 1. Key Validity Coverage, 2. Expired Key Rate.
-- Feature Reference: 121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pgp_keys (
    -- Primary Key
    key_id SERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,

    -- Key Details
    key_id_long VARCHAR(255) NOT NULL, -- Full fingerprint
    key_data TEXT NOT NULL, -- ASCII armored public key
    key_bits INTEGER,
    algorithm VARCHAR(50), -- RSA, ECC

    -- Expiry
    expiry_date DATE,
    is_expired BOOLEAN DEFAULT FALSE,
    is_revoked BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_pgp_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT uq_pgp_long_id UNIQUE (key_id_long)
);

COMMENT ON TABLE m23_governance.pgp_keys IS 'Repository of contributor public keys for cryptographic verification.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 72 - commit_signatures
-- Description: Verification of git commit signatures.
-- Business Case: Automated validation of code provenance. Did this person actually write this code?
-- Crucial for supply chain security (e.g., verifying the build agent itself hasn't been compromised).
-- KPIs: 1. Verified Commit Percentage, 2. Signature Verification Success Rate.
-- Feature Reference: 57
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.commit_signatures (
    -- Primary Key
    commit_sha CHAR(40) PRIMARY KEY,

    -- Verification
    signature_valid BOOLEAN NOT NULL,
    signer_key_id INTEGER, -- References pgp_keys
    signed_at TIMESTAMP WITH TIME ZONE,
    signer_name VARCHAR(255),

    -- Key Details (Snapshot)
    key_fingerprint CHAR(40),
    payload TEXT,

    -- Constraints
    CONSTRAINT fk_sig_key FOREIGN KEY (signer_key_id) REFERENCES m23_governance.pgp_keys(key_id)
);

COMMENT ON TABLE m23_governance.commit_signatures IS 'Cryptographic verification results of git commit signatures.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 73 - zksnark_proofs
-- Description: Metadata for ZK-SNARK circuits in PRs.
-- Business Case: PARI uses Zero-Knowledge proofs for privacy. Compiling these circuits is expensive.
-- This table verifies the validity and metrics (proving time, size) of submitted circuits.
-- KPIs: 1. Circuit Compilation Success Rate, 2. Proving Time per Circuit.
-- Feature Reference: 47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.zksnark_proofs (
    -- Primary Key
    circuit_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Circuit Details
    circuit_name VARCHAR(255) NOT NULL,
    circuit_type VARCHAR(50), -- groth16, plonk

    -- Metrics
    r1cs_size BIGINT, -- Rank-1 Constraint System size
    proving_time_ms INTEGER,
    verification_time_ms INTEGER,
    public_inputs_count INTEGER,
    circuit_hash CHAR(64),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_zk_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.zksnark_proofs IS 'Metadata for Zero-Knowledge circuits used in privacy-preserving transactions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 74 - kubernetes_manifests
-- Description: List of K8s manifests in PR.
-- Business Case: Infrastructure as Code (IaC) governance. Ensures that K8s deployments are secure,
-- resource-limited, and follow naming conventions before being applied to clusters.
-- KPIs: 1. Manifest Linter Pass Rate, 2. Resource Limit Compliance.
-- Feature Reference: 21
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.kubernetes_manifests (
    -- Primary Key
    manifest_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path TEXT NOT NULL,
    kind VARCHAR(50) NOT NULL, -- Deployment, Service, ConfigMap
    name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100),

    -- Analysis
    has_resource_limits BOOLEAN,
    has_healthcheck BOOLEAN,
    linter_status VARCHAR(20),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_k8s_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.kubernetes_manifests IS 'Inventory and validation of Kubernetes deployment definitions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 75 - helm_charts
-- Description: Helm chart metadata.
-- Business Case: Packaging for K8s. Ensures Chart.yaml values are valid, versioning is correct,
-- and dependencies are pinned.
-- KPIs: 1. Helm Lint Success Rate.
-- Feature Reference: 111
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.helm_charts (
    -- Primary Key
    chart_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    chart_name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL, -- SemVer
    app_version VARCHAR(50),
    description TEXT,

    -- Validation
    lint_status VARCHAR(20),
    lint_errors TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_helm_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.helm_charts IS 'Metadata for Helm packages used in deployment automation.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 76 - terraform_plans
-- Description: Terraform plan summaries.
-- Business Case: Cloud infrastructure governance. Detects accidental deletion of resources or
-- unauthorized increases in cost/spend.
-- KPIs: 1. Cost Change Detected, 2. Resource Destruction Count.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.terraform_plans (
    -- Primary Key
    plan_id SERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Changes
    resource_additions INTEGER DEFAULT 0,
    resource_changes INTEGER DEFAULT 0,
    resource_deletions INTEGER DEFAULT 0,

    -- Cost Estimate
    monthly_cost_delta NUMERIC(10,2),

    -- Security Check
    security_scan_passed BOOLEAN,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT kf_tf_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.terraform_plans IS 'Summarizes infrastructure changes proposed by Terraform configurations.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 77 - license_text_history
-- Description: Versioning of LICENSE files.
-- Business Case: Legal compliance. The license text is a legal document. Changes to it must be
-- tracked with effective dates to know which terms apply to which code version.
-- KPIs: 1. License Version Count.
-- Feature Reference: 153
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.license_text_history (
    -- Primary Key
    license_hist_id SERIAL PRIMARY KEY,

    -- Linking
    repo_id INTEGER NOT NULL,

    -- Content
    content_text TEXT NOT NULL,
    hash CHAR(64) NOT NULL,

    -- Lifecycle
    effective_date DATE NOT NULL,
    expiry_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_license_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.license_text_history IS 'Historical versioning of project license files for legal auditability.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 78 - contributor_avatars
-- Description: Profile pictures.
-- Business Case: Personalization and visual identification in the community dashboard.
-- Often references Gravatar or S3 URLs.
-- KPIs: N/A
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_avatars (
    -- Primary Key (Uses contributor_id)
    contributor_id BIGINT PRIMARY KEY,

    -- Details
    image_url TEXT NOT NULL,
    is_gravatar BOOLEAN DEFAULT TRUE,
    etag VARCHAR(100), -- Cache identifier

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_avatar_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE TRIGGER trg_avatars_updated_at BEFORE UPDATE ON m23_governance.contributor_avatars
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.contributor_avatars IS 'Stores avatar URLs for community profiles.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 79 - email_notifications
-- Description: Notification preferences.
-- Business Case: User experience. Avoids spam by letting contributors opt-in/out of specific
-- notification types (e.g., "Mention me", "My PR is merged").
-- KPIs: 1. Opt-in Rate, 2. Email Unsubscribe Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.email_notifications (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    notification_type VARCHAR(50) NOT NULL, -- PR_MERGED, PR_COMMENT, ISSUE_ASSIGNED

    -- Preference
    enabled BOOLEAN DEFAULT TRUE,

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT pk_email_prefs UNIQUE (contributor_id, notification_type),
    CONSTRAINT fk_email_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.email_notifications IS 'Per-user granular email notification settings.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 80 - spam_filter_rules
-- Description: Rules to auto-reject spam.
-- Business Case: Community hygiene. Automatically closes PRs that match known spam patterns
-- (e.g., "Fix typo for $10"), reducing moderation load.
-- KPIs: 1. Spam Detection Accuracy, 2. False Positive Rate.
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spam_filter_rules (
    -- Primary Key
    rule_id SERIAL PRIMARY KEY,

    -- Rule Definition
    pattern_type VARCHAR(20) NOT NULL, -- REGEX, KEYWORD, DOMAIN
    pattern_value TEXT NOT NULL,
    action VARCHAR(20) NOT NULL, -- CLOSE, LABEL, HIDE

    -- Effectiveness
    hit_count INTEGER DEFAULT 0,
    last_hit_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.spam_filter_rules IS 'Heuristic rules for automatic filtering of low-quality or malicious contributions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 81 - api_deprecation_schedule
-- Description: Tracks deprecated APIs for warnings.
-- Business Case: Lifecycle management. Allows clients (banks) to gracefully migrate off old APIs
-- before they are removed.
-- KPIs: 1. Deprecated API Adoption Decline, 2. Migration Success Rate.
-- Feature Reference: 61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_deprecation_schedule (
    -- Primary Key
    api_endpoint VARCHAR(255) PRIMARY KEY, -- e.g., GET /v1/legacy/payment

    -- Dates
    deprecation_date DATE NOT NULL,
    removal_date DATE NOT NULL,
    sunset_date DATE,

    -- Migration
    replacement_endpoint VARCHAR(255),
    migration_guide_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.api_deprecation_schedule IS 'Schedule for phasing out older API versions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 82 - feature_flags
-- Description: Configuration for feature toggles.
-- Business Case: Continuous Deployment. Allows merging code that is "off" by default, enabling it
-- for specific users or percentages gradually (canary releases).
-- KPIs: 1. Feature Flag Count, 2. Stale Flag Count.
-- Feature Reference: 76
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.feature_flags (
    -- Primary Key
    flag_name VARCHAR(255) PRIMARY KEY,

    -- Configuration
    description TEXT,
    enabled_percent NUMERIC(5,2) DEFAULT 0.00 CHECK (enabled_percent BETWEEN 0 AND 100),
    whitelisted_users BIGINT[], -- Array of contributor IDs
    whitelisted_teams INTEGER[], -- Array of team IDs

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_for_pr_id BIGINT, -- Link to PR that introduced the flag

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

CREATE TRIGGER trg_ff_updated_at BEFORE UPDATE ON m23_governance.feature_flags
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.feature_flags IS 'Runtime toggles for enabling/disabling features without deployment.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 83 - release_notes
-- Description: Drafted release notes.
-- Business Case: Communication. Aggregates changelogs into a coherent summary for end-users and
-- developers for each release version.
-- KPIs: 1. Release Note Completeness, 2. Time to Publish Release.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.release_notes (
    -- Primary Key
    note_id SERIAL PRIMARY KEY,

    -- Version
    version VARCHAR(50) NOT NULL, -- SemVer

    -- Content
    content TEXT,
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, PUBLISHED

    -- Metadata
    period_start DATE,
    period_end DATE,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.release_notes IS 'Drafted and published release notes for software versions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 84 - dependency_update_automations
-- Description: Tracks Dependabot/Renovate PRs.
-- Business Case: Security hygiene. Automated bots that submit PRs to update dependencies. This
-- table separates automated noise from human contributions.
-- KPIs: 1. Auto-Merge Success Rate, 2. Dependency Freshness.
-- Feature Reference: 12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_update_automations (
    -- Primary Key
    update_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Dependency
    package_name VARCHAR(255) NOT NULL,
    package_manager VARCHAR(50) NOT NULL,
    old_version VARCHAR(100),
    new_version VARCHAR(100),

    -- Source
    bot_name VARCHAR(50) DEFAULT 'dependabot', -- renovate, dependabot

    -- Constraints
    CONSTRAINT fk_dep_update_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.dependency_update_automations IS 'Tracks automated dependency update submissions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 85 - merge_conflicts
-- Description: Logs detected merge conflicts.
-- Business Case: Workflow optimization. Identifying frequently conflicting branches allows teams to
-- adjust their branching strategies or coordinate better.
-- KPIs: 1. Conflict Frequency per File, 2. Time to Resolve Conflict.
-- Feature Reference: 22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.merge_conflicts (
    -- Primary Key
    conflict_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    file_path TEXT NOT NULL,
    conflicting_branch VARCHAR(100),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN DEFAULT FALSE,

    -- Constraints
    CONSTRAINT fk_conflict_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.merge_conflicts IS 'Records merge conflicts to identify high-friction files.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 86 - lock_files
-- Description: Content hash of lock files to detect changes.
-- Business Case: Ensures reproducibility. By hashing the lock file, we can detect if a dependency
-- tree has changed, even if the package.json hasn't (e.g., transitive updates).
-- KPIs: 1. Lock File Stability.
-- Feature Reference: 12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.lock_files (
    -- Primary Key
    lock_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- File
    file_name VARCHAR(255) NOT NULL, -- package-lock.json, Cargo.lock
    content_hash CHAR(64) NOT NULL,
    file_size_bytes BIGINT,

    -- Constraints
    CONSTRAINT fk_lock_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.lock_files IS 'Hashes of dependency lock files to detect drift.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 87 - discussion_threads
-- Description: Top-level discussions (not PRs).
-- Business Case: Community collaboration. Provides a forum for RFCs (Request for Comments), Q&A,
-- and general design discussions that don't fit into the PR workflow.
-- KPIs: 1. Discussion Engagement, 2. Time to First Response.
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.discussion_threads (
    -- Primary Key
    thread_id BIGSERIAL PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    category VARCHAR(50), -- ANNOUNCEMENT, Q&A, RFC
    is_pinned BOOLEAN DEFAULT FALSE,
    is_locked BOOLEAN DEFAULT FALSE,

    -- Author
    author_id BIGINT NOT NULL,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_thread_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.discussion_threads IS 'Forum for community discussions and RFCs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 88 - thread_comments
-- Description: Comments in discussion threads.
-- Business Case: Enables threaded conversation on RFCs and announcements.
-- KPIs: N/A
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.thread_comments (
    -- Primary Key
    comment_id BIGSERIAL PRIMARY KEY,

    -- Linking
    thread_id BIGINT NOT NULL,
    parent_comment_id BIGINT, -- For nested replies

    -- Content
    author_id BIGINT NOT NULL,
    body TEXT NOT NULL,

    -- Sentiment
    sentiment_score NUMERIC(3,2),
    sentiment_category m23_governance.sentiment_category,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_thread_comment_thread FOREIGN KEY (thread_id) REFERENCES m23_governance.discussion_threads(thread_id),
    CONSTRAINT fk_thread_comment_parent FOREIGN KEY (parent_comment_id) REFERENCES m23_governance.thread_comments(comment_id),
    CONSTRAINT fk_thread_comment_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.thread_comments IS 'Comments within community discussion threads.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 89 - wiki_pages
-- Description: Documentation wiki revisions.
-- Business Case: Knowledge management. Collaborative documentation editing. Stores every version
-- to allow reverting vandalism or mistakes.
-- KPIs: 1. Doc Page Count, 2. Edit Frequency.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.wiki_pages (
    -- Primary Key
    page_id SERIAL PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE, -- URL-friendly title
    content TEXT,

    -- Status
    is_locked BOOLEAN DEFAULT FALSE,
    is_deprecated BOOLEAN DEFAULT FALSE,

    -- Timestamps
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT, -- Contributor ID (Referencing contributors)

    -- Constraints
    CONSTRAINT fk_wiki_contributor FOREIGN KEY (updated_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.wiki_pages IS 'Collaborative documentation pages.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 90 - protected_branches
-- Description: Explicit list of protected branches.
-- Business Case: Granular security control. While `branch_protection_rules` uses patterns, this
-- table defines explicit branches (like `main` or `v1.0`) that must never be deleted.
-- KPIs: 1. Protected Branch Coverage.
-- Feature Reference: 32
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.protected_branches (
    -- Composite Primary Key
    repo_id INTEGER NOT NULL,
    branch_name VARCHAR(255) NOT NULL,

    -- Configuration
    allow_force_pushes BOOLEAN DEFAULT FALSE,
    allow_deletions BOOLEAN DEFAULT FALSE,
    enforce_admins BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_protected_branches UNIQUE (repo_id, branch_name),
    CONSTRAINT fk_protected_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.protected_branches IS 'Explicit list of branches with restricted modification permissions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 91 - required_signatures
-- Description: Branches requiring signatures.
-- Business Case: High-security branch protection. Requires every commit to be cryptographically
-- signed (PGP) to be accepted into the branch.
-- KPIs: 1. Signature Enforcement Compliance.
-- Feature Reference: 121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.required_signatures (
    -- Composite Primary Key
    repo_id INTEGER NOT NULL,
    branch_pattern VARCHAR(255) NOT NULL,

    -- Configuration
    require_signature BOOLEAN DEFAULT TRUE,
    allowed_signers VARCHAR(255)[], -- Array of fingerprints or emails

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_req_sigs UNIQUE (repo_id, branch_pattern),
    CONSTRAINT fk_sigs_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.required_signatures IS 'Enforces cryptographic signing requirements for specific branches.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 92 - static_analysis_rules
-- Description: Custom rules for SAST tools.
-- Business Case: Tailoring security tools to PARI's specific architecture. Allows security engineers
-- to write custom checks (e.g., "Don't use old crypto") that standard tools might miss.
-- KPIs: 1. Custom Rule Count, 2. Custom Rule Trigger Rate.
-- Feature Reference: 4
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.static_analysis_rules (
    -- Primary Key
    rule_id SERIAL PRIMARY KEY,

    -- Definition
    tool VARCHAR(50) NOT NULL, -- semgrep, sonarqube
    rule_key VARCHAR(100) NOT NULL,
    severity m23_governance.severity_level NOT NULL,
    description TEXT,

    -- Code
    rule_definition TEXT, -- The actual query/pattern

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.static_analysis_rules IS 'Custom security rules configured for static analysis tools.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 93 - whitelisted_secrets
-- Description: Secrets that are allowed (e.g., test samples).
-- Business Case: Reducing noise. Sometimes test files contain fake keys (e.g., `abcd1234`). This
-- list tells the secret scanner to ignore specific known patterns.
-- KPIs: 1. False Positive Reduction.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.whitelisted_secrets (
    -- Primary Key
    secret_pattern VARCHAR(255) PRIMARY KEY,

    -- Reason
    reason TEXT NOT NULL,
    scope VARCHAR(50) DEFAULT 'GLOBAL', -- GLOBAL, REPO

    -- Audit
    added_by BIGINT NOT NULL,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.whitelisted_secrets IS 'Patterns of secrets that are permitted (e.g., known test values).';

-- --------------------------------------------------------------------------------------------------------
-- Table: 94 - deployment_rollback_history
-- Description: History of rollbacks triggered by bad PRs.
-- Business Case: Reliability tracking. If a PR causes a prod outage and a rollback occurs, this
-- table records it for post-mortem analysis.
-- KPIs: 1. Rollback Frequency, 2. Time to Recovery (MTTR).
-- Feature Reference: 73
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.deployment_rollback_history (
    -- Primary Key
    rollback_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    deployment_id BIGINT NOT NULL,

    -- Details
    reason TEXT NOT NULL,
    rollback_sha CHAR(40),
    triggered_by BIGINT,

    -- Audit
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_rollback_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.deployment_rollback_history IS 'Logs of production rollbacks linked to specific Pull Requests.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 95 - onboarding_checklists
-- Description: Checklist items for new contributors.
-- Business Case: Reduces friction. Guides new contributors through the setup process (CLA, Keys,
-- Local Env) to ensure they can start working quickly.
-- KPIs: 1. Onboarding Completion Rate, 2. Time to First Commit.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.onboarding_checklists (
    -- Primary Key
    item_id SERIAL PRIMARY KEY,

    -- Content
    description TEXT NOT NULL,
    link_url TEXT,
    order_index INTEGER NOT NULL,

    -- Category
    category VARCHAR(50), -- LEGAL, TECH, COMMUNITY
    is_required BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.onboarding_checklists IS 'Standardized onboarding tasks for new community members.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 96 - contributor_progress
-- Description: Tracking completion of onboarding.
-- Business Case: Gamification and support tracking. See where contributors are stuck in onboarding
-- to offer help.
-- KPIs: 1. Step Drop-off Points.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_progress (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    item_id INTEGER NOT NULL,

    -- Status
    completed_at TIMESTAMP WITH TIME ZONE,
    is_skipped BOOLEAN DEFAULT FALSE,

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_contributor_progress UNIQUE (contributor_id, item_id),
    CONSTRAINT fk_prog_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_prog_item FOREIGN KEY (item_id) REFERENCES m23_governance.onboarding_checklists(item_id)
);

COMMENT ON TABLE m23_governance.contributor_progress IS 'Tracks individual progress through the onboarding checklist.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 97 - mentorship_pairs
-- Description: Pairs new contributors with mentors.
-- Business Case: Knowledge transfer. Improves retention by giving new members a human contact.
-- KPIs: 1. Mentee Retention Rate, 2. Mentor Availability.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.mentorship_pairs (
    -- Composite Primary Key
    mentor_id BIGINT NOT NULL,
    mentee_id BIGINT NOT NULL,

    -- Lifecycle
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, PAUSED, ENDED

    -- Audit
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    -- Constraints
    CONSTRAINT pk_mentorship UNIQUE (mentor_id, mentee_id),
    CONSTRAINT fk_mentor FOREIGN KEY (mentor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_mentee FOREIGN KEY (mentee_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.mentorship_pairs IS 'Links mentors with mentees for community support.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 98 - community_events
-- Description: Hackathons or contribution sprints.
-- Business Case: Boosts engagement. Organizes time-boxed events to focus on specific areas
-- (e.g., "Documentation Week").
-- KPIs: 1. Event Participation Rate, 2. PRs Generated per Event.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.community_events (
    -- Primary Key
    event_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(50), -- HACKATHON, SPRINT, WORKSHOP

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.community_events IS 'Organizes contribution events and hackathons.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 99 - event_contributions
-- Description: Links PRs to community events.
-- Business Case: Metrics generation. Counts how many contributions were made during a specific event.
-- KPIs: 1. Contribution Volume per Event.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.event_contributions (
    -- Composite Primary Key
    pr_id BIGINT NOT NULL,
    event_id INTEGER NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_event_contrib UNIQUE (pr_id, event_id),
    CONSTRAINT fk_ev_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_ev_event FOREIGN KEY (event_id) REFERENCES m23_governance.community_events(event_id)
);

COMMENT ON TABLE m23_governance.event_contributions IS 'Associates Pull Requests with specific community events.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 100 - documentation_search_index
-- Description: Full text search index for docs.
-- Business Case: Discoverability. Enables fast, accurate search across all documentation files.
-- KPIs: 1. Search Latency, 2. Search Result Relevance.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.documentation_search_index (
    -- Primary Key
    doc_id SERIAL PRIMARY KEY,

    -- Content
    file_path TEXT NOT NULL,
    title TEXT,
    content_text TEXT,
    content_vector tsvector, -- Pre-calculated vector for fast search

    -- Metadata
    repo_id INTEGER,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_search_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

-- Index for full text search
CREATE INDEX idx_docs_search_vector ON m23_governance.documentation_search_index USING GIN(content_vector);
COMMENT ON TABLE m23_governance.documentation_search_index IS 'Optimized index for full-text search across documentation.';

-- Triggers for Part 2 Tables
-- Apply Updated At triggers to remaining tables that support it
CREATE TRIGGER trg_pr_labels_updated_at BEFORE UPDATE ON m23_governance.pr_labels
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();


    -- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 3: Database Objects Tables 101-150
-- ==========================================================================================================
-- Description:
-- This script continues the definition of the database schema for Module M23, covering database
-- objects 101 through 150. This section focuses on advanced PostgreSQL governance, dependency
-- intelligence, security remediation playbooks, web headers, CORS, API authentication, rate limiting,
-- cryptographic hygiene, and content validation.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 101 - dependency_submissions
-- Description: Vulnerabilities submitted by contributors.
-- Business Case: Crowdsourced security intelligence. Allows the community to report vulnerabilities
-- in dependencies that might not yet be in the official CVE database, enhancing proactive security.
-- KPIs: 1. Valid Submission Rate, 2. Time to CVE Publication, 3. Community Engagement in Security.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_submissions (
    -- Primary Key
    submission_id BIGSERIAL PRIMARY KEY,

    -- Contributor
    contributor_id BIGINT NOT NULL,

    -- Vulnerability Details
    description TEXT NOT NULL,
    affected_package VARCHAR(255) NOT NULL,
    affected_version VARCHAR(100) NOT NULL,
    proof_of_concept TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING_REVIEW', -- PENDING_REVIEW, VERIFIED, REJECTED, SUBMITTED_TO_CNA
    cve_id_assigned VARCHAR(20),

    -- Metadata
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_by BIGINT,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    internal_notes TEXT

    -- Constraints
    ,CONSTRAINT fk_sub_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_sub_reviewer FOREIGN KEY (reviewed_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.dependency_submissions IS 'Community-reported security vulnerabilities in upstream dependencies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 102 - pg_hba_rules
-- Description: Mock object for Postgres Host-Based Authentication checks in CI.
-- Business Case: In CI environments, we validate configuration files. This table stores the expected
-- state of pg_hba.conf rules to validate that new connections are only allowed from secure sources
-- (e.g., application servers, not public IPs).
-- KPIs: 1. Configuration Drift Detection, 2. Security Compliance Score.
-- Feature Reference: 43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pg_hba_rules (
    -- Primary Key
    rule_id SERIAL PRIMARY KEY,

    -- Rule Definition
    database VARCHAR(100) NOT NULL,
    user_name VARCHAR(100) NOT NULL,
    address VARCHAR(100), -- CIDR or 'samehost'
    method VARCHAR(20) NOT NULL, -- scram-sha-256, cert, reject

    -- Environment
    environment VARCHAR(20) NOT NULL, -- DEV, STAGING, PROD
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.pg_hba_rules IS 'Expected configuration for PostgreSQL host-based authentication rules.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 103 - row_level_security_policies
-- Description: Stores RLS policy metadata for validation.
-- Business Case: Critical for multi-tenant PARI deployment. This table tracks the required RLS
-- policies on sensitive tables (e.g., wallet_balances) to ensure tenant data isolation is enforced
-- in the database layer, not just application code.
-- KPIs: 1. RLS Policy Coverage, 2. Policy Bypass Attempt Detection.
-- Feature Reference: 25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.row_level_security_policies (
    -- Primary Key
    policy_id SERIAL PRIMARY KEY,

    -- Target
    table_schema VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    policy_name VARCHAR(100) NOT NULL,

    -- Definition
    command VARCHAR(10), -- ALL, SELECT, INSERT, UPDATE, DELETE
    using_expr TEXT, -- The SQL expression for the USING clause
    with_check_expr TEXT, -- The SQL expression for the WITH CHECK clause

    -- Validation
    is_enforced BOOLEAN DEFAULT TRUE,
    last_validated_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    CONSTRAINT uq_rls_table_policy UNIQUE (table_schema, table_name, policy_name)
);

COMMENT ON TABLE m23_governance.row_level_security_policies IS 'Governance registry for database-enforced tenant isolation policies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 104 - query_plans
-- Description: Stored EXPLAIN ANALYZE results for PRs.
-- Business Case: Performance regression detection. Stores the execution plan of queries modified
-- in a PR to detect if changes have introduced full table scans or inefficient joins compared
-- to the baseline.
-- KPIs: 1. Query Plan Cost Delta, 2. Buffer Cache Hit Ratio.
-- Feature Reference: 74
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.query_plans (
    -- Primary Key
    plan_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Query Details
    query_hash CHAR(32) NOT NULL, -- MD5 hash of the normalized query
    plan_json JSONB NOT NULL, -- The structured EXPLAIN output
    total_cost NUMERIC(20,5),
    total_time_ms NUMERIC(10,3),

    -- Comparison
    baseline_plan_id BIGINT, -- Reference to the plan before the change
    cost_delta_pct NUMERIC(5,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_plan_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_plans_query_hash ON m23_governance.query_plans(query_hash);
COMMENT ON TABLE m23_governance.query_plans IS 'Execution plans for SQL queries to detect performance regressions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 105 - index_usage_stats
-- Description: Statistics on index usage from CI env.
-- Business Case: Ensures indexes added in PRs are actually being used by the query planner, or
-- identifying indexes that are redundant and never scanned.
-- KPIs: 1. Index Scan Ratio, 2. Unused Index Count.
-- Feature Reference: 74
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.index_usage_stats (
    -- Primary Key
    index_id SERIAL PRIMARY KEY,

    -- Target
    table_name VARCHAR(255) NOT NULL,
    index_name VARCHAR(255) NOT NULL,
    indexrelid BIGINT, -- OID of the index

    -- Usage Metrics (Snapshot from pg_stat_user_indexes)
    idx_scan BIGINT,
    idx_tup_read BIGINT,
    idx_tup_fetch BIGINT,

    -- Size
    index_size_bytes BIGINT,

    -- Context
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    environment VARCHAR(20) -- CI, STAGING
);

COMMENT ON TABLE m23_governance.index_usage_stats IS 'Usage statistics to validate the necessity and efficiency of database indexes.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 106 - lock_wait_stats
-- Description: Lock wait statistics from load tests.
-- Business Case: PARI is a high-concurrency system. This table tracks lock contention during load
-- tests to ensure a PR doesn't introduce deadlocks or long waits that would freeze payments.
-- KPIs: 1. Average Lock Wait Time, 2. Deadlock Count.
-- Feature Reference: 75
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.lock_wait_stats (
    -- Primary Key
    wait_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Lock Details
    relation VARCHAR(255) NOT NULL, -- Table name
    mode VARCHAR(50) NOT NULL, -- AccessShareLock, ExclusiveLock
    wait_time_ms NUMERIC(10,3),
    blocked_query TEXT,
    blocking_query TEXT,

    -- Audit
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lock_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.lock_wait_stats IS 'Captures lock contention data to prevent concurrency bottlenecks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 107 - pg_stat_statements
-- Description: Aggregated query statistics for performance reviews.
-- Business Case: Centralized performance monitoring. Aggregates execution statistics for
-- normalized queries to identify the "Top 10 Slowest Queries" introduced in a PR.
-- KPIs: 1. Total Execution Time, 2. Mean Execution Time, 3. Calls Count.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pg_stat_statements (
    -- Composite Key
    queryid BIGINT NOT NULL,
    pr_id BIGINT NOT NULL,

    -- Metrics (Snapshot from pg_stat_statements extension)
    calls BIGINT,
    total_time_ms NUMERIC(20,3),
    mean_time_ms NUMERIC(10,3),
    max_time_ms NUMERIC(10,3),
    rows BIGINT,
    shared_blks_hit BIGINT,
    shared_blks_read BIGINT,

    -- Audit
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_pg_stat UNIQUE (queryid, pr_id, captured_at),
    CONSTRAINT fk_pg_stat_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.pg_stat_statements IS 'Aggregated performance metrics for SQL queries executed during testing.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 108 - partition_schemes
-- Description: Metadata on table partitioning strategies.
-- Business Case: PARI handles massive transaction volumes. This table ensures that PRs adding
-- partitioning to tables follow the correct strategy (e.g., Hash by merchant_id for even distribution).
-- KPIs: 1. Partition Pruning Efficiency, 2. Data Skew Ratio.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.partition_schemes (
    -- Primary Key
    table_name VARCHAR(255) PRIMARY KEY,

    -- Strategy
    partition_key VARCHAR(100) NOT NULL, -- e.g., 'created_at' or 'merchant_id'
    strategy VARCHAR(20) NOT NULL, -- RANGE, LIST, HASH

    -- Details
    partition_interval VARCHAR(100), -- e.g., '1 month', '10'
    default_partition_name VARCHAR(100), -- e.g., 'transactions_default'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.partition_schemes IS 'Defines the partitioning logic for large-scale database tables.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 109 - enum_types
-- Description: Registry of PostgreSQL ENUM types.
-- Business Case: Tracking schema changes. Ensures that changes to ENUMs (which can be destructive
-- in Postgres) are reviewed and tracked in M23 before merge.
-- KPIs: 1. ENUM Modification Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.enum_types (
    -- Primary Key
    type_name VARCHAR(255) PRIMARY KEY,

    -- Details
    labels_array TEXT[] NOT NULL, -- Array of allowed values
    is_user_defined BOOLEAN DEFAULT TRUE,

    -- Audit
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.enum_types IS 'Registry of enumerated data types used in the database schema.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 110 - composite_types
-- Description: Registry of PostgreSQL composite types.
-- Business Case: Custom types (structs) improve data integrity but add complexity. This table
-- tracks their definition to ensure they are documented and reviewed.
-- KPIs: 1. Composite Type Usage Count.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.composite_types (
    -- Primary Key
    type_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    attributes_json JSONB NOT NULL, -- List of {name, type} pairs

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.composite_types IS 'Registry of complex composite data structures in PostgreSQL.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 111 - extension_versions
-- Description: Allowed Postgres extensions and versions.
-- Business Case: Security and compliance. Only approved extensions (e.g., `pgcrypto`) can be installed.
-- This prevents developers from installing insecure or unverified C-extensions.
-- KPIs: 1. Extension Compliance Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.extension_versions (
    -- Primary Key
    extname VARCHAR(100) PRIMARY KEY,

    -- Versions
    default_version VARCHAR(50),
    installed_version VARCHAR(50),

    -- Policy
    is_allowed BOOLEAN DEFAULT TRUE,
    requires_superuser BOOLEAN DEFAULT FALSE,
    justification TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.extension_versions IS 'Whitelist of permitted PostgreSQL extensions and their versions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 112 - foreign_key_constraints
-- Description: List of FK constraints for validation.
-- Business Case: Data integrity. Tracks FKs to ensure referential integrity is maintained and
-- cascading deletes are intentional. Validates new FKs in PRs.
-- KPIs: 1. FK Validation Success Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.foreign_key_constraints (
    -- Primary Key
    constraint_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    table_name VARCHAR(255) NOT NULL,
    column_names TEXT[] NOT NULL,
    referenced_table VARCHAR(255) NOT NULL,
    referenced_columns TEXT[] NOT NULL,

    -- Configuration
    on_delete_action VARCHAR(20), -- CASCADE, RESTRICT, SET NULL, NO ACTION
    on_update_action VARCHAR(20),
    is_deferrable BOOLEAN DEFAULT FALSE,
    is_deferred BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.foreign_key_constraints IS 'Registry of foreign key constraints to enforce data relationships.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 113 - check_constraints
-- Description: List of CHECK constraints for validation.
-- Business Case: Logic enforcement at the DB level. Ensures business rules (e.g., balances >= 0)
-- cannot be bypassed by application bugs.
-- KPIs: 1. Constraint Violation Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.check_constraints (
    -- Primary Key
    constraint_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    table_name VARCHAR(255) NOT NULL,
    check_clause TEXT NOT NULL, -- The boolean expression
    description TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.check_constraints IS 'Registry of logic validation rules on table columns.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 114 - exclusion_constraints
-- Description: List of exclusion constraints.
-- Business Case: Preventing overlaps. Used for ranges (time ranges, spatial data) to ensure no
-- double booking or overlapping sessions.
-- KPIs: 1. Exclusion Violation Count.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.exclusion_constraints (
    -- Primary Key
    constraint_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    table_name VARCHAR(255) NOT NULL,
    index_predicate TEXT, -- The WHERE clause
    definition TEXT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.exclusion_constraints IS 'Registry of constraints preventing range overlaps.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 115 - trigger_definitions
-- Description: Metadata on triggers.
-- Business Case: Automation tracking. Ensures triggers (e.g., for audit logging) are reviewed
-- for performance impact (triggers fire on every row).
-- KPIs: 1. Trigger Execution Time, 2. Trigger Failure Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.trigger_definitions (
    -- Primary Key
    trigger_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    table_name VARCHAR(255) NOT NULL,
    action_timing VARCHAR(10) NOT NULL, -- BEFORE, AFTER, INSTEAD OF
    event_manipulation VARCHAR(20) NOT NULL, -- INSERT, UPDATE, DELETE, TRUNCATE
    function_name VARCHAR(255) NOT NULL,

    -- Metadata
    is_constraint BOOLEAN DEFAULT FALSE,
    is_deferrable BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.trigger_definitions IS 'Registry of database event triggers.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 116 - view_definitions
-- Description: SQL definitions of views.
-- Business Case: Virtualization layer. Tracks views used for reporting or security abstraction.
-- Ensures changes to views don't break downstream consumers.
-- KPIs: 1. View Complexity, 2. View Usage Count.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.view_definitions (
    -- Primary Key
    view_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    definition_sql TEXT NOT NULL,
    schema_name VARCHAR(100) NOT NULL,

    -- Security
    is_security_barrier BOOLEAN DEFAULT FALSE,

    -- Audit
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.view_definitions IS 'Registry of SQL view definitions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 117 - materialized_view_definitions
-- Description: Definitions of materialized views.
-- Business Case: Performance caching. Tracks MVs used to pre-compute expensive joins.
-- Monitors refresh schedules and data staleness.
-- KPIs: 1. Refresh Duration, 2. Data Staleness.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.materialized_view_definitions (
    -- Primary Key
    matview_name VARCHAR(255) PRIMARY KEY,

    -- Definition
    definition_sql TEXT NOT NULL,
    schema_name VARCHAR(100) NOT NULL,

    -- Audit
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.materialized_view_definitions IS 'Registry of materialized view definitions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 118 - refresh_policies
-- Description: Refresh schedules for MVs.
-- Business Case: Automation. Defines when materialized views should be refreshed to keep data
-- current without overloading the database during peak hours.
-- KPIs: 1. Schedule Adherence.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.refresh_policies (
    -- Primary Key
    matview_name VARCHAR(255) PRIMARY KEY,

    -- Policy
    schedule_cron VARCHAR(100) NOT NULL, -- Cron expression
    concurrent_refreshes BOOLEAN DEFAULT FALSE,
    start_time TIME,

    -- Constraints
    CONSTRAINT fk_refresh_mv FOREIGN KEY (matview_name) REFERENCES m23_governance.materialized_view_definitions(matview_name) ON DELETE CASCADE
);

COMMENT ON TABLE m23_governance.refresh_policies IS 'Schedules for refreshing materialized views.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 119 - table_privileges
-- Description: Expected privileges for tables.
-- Business Case: Least Privilege Enforcement. Ensures that the CI system validates that
-- the `web_anon` role doesn't have `SELECT` on `users` table, etc.
-- KPIs: 1. Privilege Drift Count.
-- Feature Reference: 43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.table_privileges (
    -- Composite Primary Key
    table_name VARCHAR(255) NOT NULL,
    grantee VARCHAR(100) NOT NULL,

    -- Privileges
    privileges_array VARCHAR(50)[] NOT NULL, -- {SELECT, INSERT, UPDATE}
    is_grantable BOOLEAN DEFAULT FALSE,

    -- Environment
    environment VARCHAR(20) NOT NULL,

    CONSTRAINT pk_table_privs UNIQUE (table_name, grantee, environment)
);

COMMENT ON TABLE m23_governance.table_privileges IS 'Expected access control lists for database tables.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 120 - schema_migrations_version
-- Description: Tracks current schema version.
-- Business Case: Idempotency. Ensures migration scripts run only once and in the correct order.
-- Critical for preventing schema corruption.
-- KPIs: 1. Migration Idempotency Success Rate.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.schema_migrations_version (
    -- Primary Key
    version VARCHAR(255) PRIMARY KEY,

    -- Status
    dirty BOOLEAN DEFAULT FALSE, -- True if the last migration failed mid-way
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Execution
    execution_time_ms INTEGER,
    success BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.schema_migrations_version IS 'Tracks the state of the database schema migration history.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 121 - spdx_documents
-- Description: Full SPDX documents generated.
-- Business Case: Legal Requirement. Generates the full SBOM document in SPDX format for regulatory
-- submission and auditing.
-- KPIs: 1. SBOM Generation Success Rate.
-- Feature Reference: 48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spdx_documents (
    -- Primary Key
    doc_id SERIAL PRIMARY KEY,

    -- Linking
    artifact_id BIGINT NOT NULL,

    -- Document Meta
    spdx_version VARCHAR(20) NOT NULL, -- SPDX-2.3
    data_license VARCHAR(50) NOT NULL, -- CC0-1.0
    spdx_id VARCHAR(255) NOT NULL, -- Document identifier
    document_name VARCHAR(255) NOT NULL,
    document_namespace TEXT NOT NULL,

    -- Creation
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_spdx_artifact FOREIGN KEY (artifact_id) REFERENCES m23_governance.build_artifacts(artifact_id)
);

COMMENT ON TABLE m23_governance.spdx_documents IS 'Header information for generated Software Bill of Materials (SBOM) documents.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 122 - spdx_packages
-- Description: Packages within SPDX docs.
-- Business Case: Component breakdown. Lists every software component (library, module) included
-- in the build.
-- KPIs: 1. Component Count.
-- Feature Reference: 48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spdx_packages (
    -- Primary Key
    pkg_id SERIAL PRIMARY KEY,

    -- Linking
    doc_id INTEGER NOT NULL,

    -- Package Details
    spdx_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    download_location TEXT,
    files_analyzed INTEGER DEFAULT 0,
    verification_code TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_spdx_pkg_doc FOREIGN KEY (doc_id) REFERENCES m23_governance.spdx_documents(doc_id)
);

COMMENT ON TABLE m23_governance.spdx_packages IS 'Detailed list of packages in an SBOM.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 123 - spdx_files
-- Description: Files verified within SPDX.
-- Business Case: Granular tracking. Lists individual source files and their checksums to verify
-- integrity of the supply chain.
-- KPIs: 1. File Verification Count.
-- Feature Reference: 48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spdx_files (
    -- Primary Key
    file_id SERIAL PRIMARY KEY,

    -- Linking
    pkg_id INTEGER NOT NULL,

    -- File Details
    spdx_id VARCHAR(255) NOT NULL,
    filename TEXT NOT NULL,
    file_types TEXT[], -- e.g., {text/x-c, application/json}
    checksum_sha1 CHAR(40),
    checksum_sha256 CHAR(64),
    license_concluded VARCHAR(50),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_spdx_file_pkg FOREIGN KEY (pkg_id) REFERENCES m23_governance.spdx_packages(pkg_id)
);

COMMENT ON TABLE m23_governance.spdx_files IS 'List of individual files contained within an SPDX package.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 124 - spdx_relationships
-- Description: Relationships between SPDX elements.
-- Business Case: Dependency mapping. Defines how components relate (e.g., DEPENDS_ON, PATCH_FOR,
-- CONTAINED_BY). Critical for understanding the supply chain graph.
-- KPIs: 1. Dependency Graph Depth.
-- Feature Reference: 48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.spdx_relationships (
    -- Primary Key
    rel_id SERIAL PRIMARY KEY,

    -- Linking
    spdx_doc_id INTEGER NOT NULL,

    -- Relationship
    element VARCHAR(255) NOT NULL, -- SPDX ID ref
    related_element VARCHAR(255) NOT NULL, -- SPDX ID ref
    relationship_type VARCHAR(50) NOT NULL, -- DEPENDS_ON, DESCRIBES, PATCH_FOR

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_spdx_rel_doc FOREIGN KEY (spdx_doc_id) REFERENCES m23_governance.spdx_documents(doc_id)
);

COMMENT ON TABLE m23_governance.spdx_relationships IS 'Defines the relationships between SPDX elements (packages, files).';

-- --------------------------------------------------------------------------------------------------------
-- Table: 125 - vulnerability_intelligence
-- Description: Aggregated vulnerability data feeds.
-- Business Case: Threat Intelligence. Aggregates CVE data from multiple sources (NVD, OSV, GitHub
-- Advisory Database) to provide a unified view of threats.
-- KPIs: 1. Feed Sync Latency.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.vulnerability_intelligence (
    -- Primary Key
    cve_id VARCHAR(20) PRIMARY KEY,

    -- Details
    description TEXT,
    published_date DATE,
    modified_date DATE,
    severity m23_governance.severity_level,
    cvss_score_v3 NUMERIC(3,1),
    assigner_org VARCHAR(255),

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.vulnerability_intelligence IS 'Centralized database of known security vulnerabilities.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 126 - cpe_matches
-- Description: CPE identifiers for vulnerabilities.
-- Business Case: Product identification. Maps CVEs to CPE (Common Platform Enumeration) strings to
-- identify exactly which software versions are affected (e.g., Apache httpd 2.4.49).
-- KPIs: 1. Match Accuracy.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cpe_matches (
    -- Primary Key
    match_id BIGSERIAL PRIMARY KEY,

    -- Linking
    cve_id VARCHAR(20) NOT NULL,

    -- Match Details
    cpe_string VARCHAR(255) NOT NULL, -- e.g., cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    cpe_name VARCHAR(255), -- Human readable part
    is_vulnerable BOOLEAN DEFAULT TRUE,

    -- Constraints
    CONSTRAINT fk_cpe_cve FOREIGN KEY (cve_id) REFERENCES m23_governance.vulnerability_intelligence(cve_id)
);

COMMENT ON TABLE m23_governance.cpe_matches IS 'Maps CVEs to specific software product versions using CPE strings.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 127 - remediation_playbooks
-- Description: Playbooks for common vulnerability fixes.
-- Business Case: Automated response speed. Provides pre-written code patches or configuration
-- changes for common CVEs (e.g., Log4j settings) to reduce time-to-patch.
-- KPIs: 1. Playbook Execution Success Rate.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.remediation_playbooks (
    -- Primary Key
    playbook_id SERIAL PRIMARY KEY,

    -- Target
    cve_pattern VARCHAR(50) NOT NULL, -- Pattern matching or specific CVE ID

    -- Remediation
    instructions_jsonb JSONB NOT NULL, -- {steps: [], patch_content: ""}
    language VARCHAR(50), -- Python, Go, Dockerfile
    severity_scope VARCHAR(20), -- Which severity this applies to

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    tested_environment VARCHAR(20) -- dev, staging
);

COMMENT ON TABLE m23_governance.remediation_playbooks IS 'Automated fix instructions for common security vulnerabilities.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 128 - security_headers
-- Description: Required security headers for web components.
-- Business Case: Browser security enforcement. Mandates headers like HSTS, X-Frame-Options to prevent
-- clickjacking, MITM, and other browser-based attacks.
-- KPIs: 1. Header Coverage Rate.
-- Feature Reference: 138
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.security_headers (
    -- Primary Key
    header_name VARCHAR(50) PRIMARY KEY,

    -- Configuration
    required_value TEXT NOT NULL,
    description TEXT,
    apply_to VARCHAR(50) DEFAULT 'ALL', -- ALL, WEB, WALLET, ADMIN

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.security_headers IS 'Definition of mandatory HTTP security headers for web applications.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 129 - csp_directives
-- Description: Content Security Policy directives.
-- Business Case: XSS mitigation. Defines a whitelist of sources for scripts, styles, and images,
-- preventing the loading of malicious content.
-- KPIs: 1. CSP Violation Count.
-- Feature Reference: 137
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.csp_directives (
    -- Primary Key
    directive_name VARCHAR(50) PRIMARY KEY, -- script-src, img-src, default-src

    -- Configuration
    sources_array TEXT[] NOT NULL, -- {'self', 'https://api.pari.org', 'https://cdn.trusted.com'}
    is_enabled BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.csp_directives IS 'Defines the Content Security Policy whitelist for external resources.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 130 - permission_policies
-- Description: Feature policy permissions.
-- Business Case: Device feature control. Controls access to sensitive browser features like Geolocation,
-- Camera, or Microphone.
-- KPIs: 1. Policy Violation Count.
-- Feature Reference: 142
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.permission_policies (
    -- Primary Key
    feature_name VARCHAR(50) PRIMARY KEY, -- geolocation, camera, microphone

    -- Configuration
    allow_list TEXT[] NOT NULL, -- {'self', 'https://trusted.com'}
    default_allow BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE m23_governance.permission_policies IS 'Controls browser feature access permissions for the PARI web interface.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 131 - cors_origins
-- Description: Allowed CORS origins.
-- Business Case: Same-origin policy relaxation. Securely allows authorized frontend applications
-- (e.g., partner bank portals) to call PARI APIs from the browser.
-- KPIs: 1. CORS Error Rate.
-- Feature Reference: 82
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cors_origins (
    -- Primary Key
    origin_pattern VARCHAR(255) PRIMARY KEY, -- e.g., https://*.bank.com

    -- Configuration
    allow_credentials BOOLEAN DEFAULT FALSE,
    max_age_seconds INTEGER,
    allowed_methods TEXT[], -- GET, POST, PUT
    allowed_headers TEXT[]

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.cors_origins IS 'Whitelist of domains permitted to access PARI APIs via Cross-Origin Resource Sharing.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 132 - oauth_scopes
-- Description: Valid OAuth scopes.
-- Business Case: Granular Access Control. Defines what data a 3rd party app can access (e.g.,
-- `read:transactions` vs `write:transactions`).
-- KPIs: 1. Scope Usage Distribution.
-- Feature Reference: 118
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.oauth_scopes (
    -- Primary Key
    scope_name VARCHAR(100) PRIMARY KEY, -- e.g., repo:status, read:org

    -- Details
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    requires_approval BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE m23_governance.oauth_scopes IS 'Definition of OAuth2 permission scopes for API access.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 133 - jwt_configurations
-- Description: JWT algorithm requirements.
-- Business Case: Token security. Enforces strong signing algorithms (RS256, ES256) and bans weak
-- ones (none, HS256 with weak secret).
-- KPIs: 1. Weak Algorithm Usage (Target: 0).
-- Feature Reference: 119
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.jwt_configurations (
    -- Primary Key
    issuer VARCHAR(255) PRIMARY KEY,

    -- Configuration
    algorithm_whitelist_array VARCHAR(20)[] NOT NULL, -- {RS256, ES256}
    key_id VARCHAR(100), -- Kid in header
    clock_skew_seconds INTEGER DEFAULT 60
);

COMMENT ON TABLE m23_governance.jwt_configurations IS 'Security policies for JWT validation algorithms.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 134 - rate_limit_rules
-- Description: Rate limit configurations.
-- Business Case: Abuse prevention. Protects API endpoints from DDoS or brute-force attacks by
-- limiting request rates per IP or API key.
-- KPIs: 1. Rate Limit Trigger Rate, 2. False Positive Blocking Rate.
-- Feature Reference: 129
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.rate_limit_rules (
    -- Composite Primary Key
    endpoint VARCHAR(255) NOT NULL,
    scope VARCHAR(50) NOT NULL, -- ip, user, global

    -- Limits
    requests_per_minute INTEGER NOT NULL,
    requests_per_hour INTEGER,
    burst_size INTEGER,

    -- Response
    block_duration_seconds INTEGER DEFAULT 60,

    CONSTRAINT pk_rate_limits UNIQUE (endpoint, scope)
);

COMMENT ON TABLE m23_governance.rate_limit_rules IS 'Rules governing API request throttling to prevent abuse.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 135 - ip_reputation
-- Description: Reputation of IP addresses.
-- Business Case: Proactive blocking. Scores IPs based on past behavior (spam, attacks) to preemptively
-- block malicious actors.
-- KPIs: 1. Blocked Attack Count, 2. Reputation Score Accuracy.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ip_reputation (
    -- Primary Key
    ip_address INET PRIMARY KEY,

    -- Score
    score INTEGER CHECK (score BETWEEN 0 AND 100), -- 0 = Malicious, 100 = Trusted
    category VARCHAR(50), -- TOR, SPAM_MALICIOUS, CLOUD_PROVIDER

    -- Activity
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    request_count BIGINT DEFAULT 0,
    is_blocked BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE m23_governance.ip_reputation IS 'Reputation scores for client IP addresses to aid in access control.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 136 - code_owners
-- Description: CODEOWNERS file parsing result.
-- Business Case: Distributed review responsibility. Ensures code is reviewed by the experts
-- who own that specific area of the codebase (e.g., Crypto team reviews crypto code).
-- KPIs: 1. Code Owner Approval Coverage.
-- Feature Reference: 64
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_owners (
    -- Primary Key
    owner_id SERIAL PRIMARY KEY,

    -- Linking
    repo_id INTEGER NOT NULL,

    -- Pattern
    pattern VARCHAR(255) NOT NULL, -- e.g., /crypto/* *.go
    owner_handle VARCHAR(255) NOT NULL, -- @team-crypto @user123
    approval_count INTEGER DEFAULT 1, -- How many from this list must approve

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_owners_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

CREATE INDEX idx_owners_repo_pattern ON m23_governance.code_owners(repo_id, pattern);
COMMENT ON TABLE m23_governance.code_owners IS 'Parsed representation of the CODEOWNERS file for automated review assignment.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 137 - pr_review_assignments
-- Description: History of review assignments.
-- Business Case: Load balancing. Tracks who has been assigned to review what to ensure work is
-- distributed fairly and mentors don't get overwhelmed.
-- KPIs: 1. Review Load Distribution, 2. Reviewer Response Time.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_review_assignments (
    -- Primary Key
    assignment_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    reviewer_id BIGINT NOT NULL,

    -- Assignment
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by BIGINT,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED, DECLINED
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_assign_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_assign_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.pr_review_assignments IS 'Log of review requests to monitor contributor workload.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 138 - auto_ignored_files
-- Description: Files configured to be ignored by linters.
-- Business Case: Reducing noise. Explicitly lists generated code or vendor files that should not
-- be linted, keeping CI fast and focused.
-- KPIs: 1. Linter Execution Time.
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.auto_ignored_files (
    -- Primary Key
    file_pattern VARCHAR(255) PRIMARY KEY,

    -- Reason
    reason TEXT NOT NULL,
    linter_scope VARCHAR(50) DEFAULT 'ALL' -- ALL, ESLINT, PYLINT
);

COMMENT ON TABLE m23_governance.auto_ignored_files IS 'Patterns for files that are exempt from automated linting checks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 139 - ci_environment_variables
-- Description: Variables injected into CI runs.
-- Business Case: Security and configuration. Ensures sensitive secrets are injected securely into
-- the CI environment and masked in logs.
-- KPIs: 1. Secret Leakage Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ci_environment_variables (
    -- Primary Key
    var_name VARCHAR(255) PRIMARY KEY,

    -- Config
    is_secret BOOLEAN DEFAULT FALSE,
    value_mask VARCHAR(100), -- How it appears in logs, e.g., ***
    allowed_values TEXT[], -- Enum of allowed values if not secret

    -- Scope
    applies_to_runners VARCHAR(50)[] -- Labels of runners that get this var
);

COMMENT ON TABLE m23_governance.ci_environment_variables IS 'Configuration for environment variables used in CI pipelines.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 140 - runner_tags
-- Description: Tags for self-hosted CI runners.
-- Business Case: Job scheduling. Labels runners (e.g., 'gpu', 'arm64', 'high-memory') so CI jobs
-- can target the appropriate hardware.
-- KPIs: 1. Runner Utilization, 2. Job Queue Time.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.runner_tags (
    -- Primary Key
    tag_name VARCHAR(50) PRIMARY KEY,

    -- Details
    runner_type VARCHAR(50), -- SELF_HOSTED, GITHUB_HOSTED
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.runner_tags IS 'Tags for categorizing and targeting CI execution environments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 141 - runner_jobs
-- Description: Jobs assigned to specific runners.
-- Business Case: Audit trail. Which physical or virtual runner executed which job, useful for
-- debugging hardware-specific failures.
-- KPIs: 1. Runner Assignment Success Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.runner_jobs (
    -- Primary Key
    job_id BIGINT NOT NULL,

    -- Runner
    runner_name VARCHAR(255),
    runner_group VARCHAR(255),

    -- Timing
    assigned_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_runner_job FOREIGN KEY (job_id) REFERENCES m23_governance.ci_jobs(job_id)
);

COMMENT ON TABLE m23_governance.runner_jobs IS 'Links CI jobs to the specific runners that executed them.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 142 - cache_artifacts
-- Description: CI cache entries.
-- Business Case: Performance optimization. Tracks what dependencies/build artifacts are cached to
-- speed up subsequent CI runs.
-- KPIs: 1. Cache Hit Ratio, 2. Cache Size.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cache_artifacts (
    -- Primary Key
    cache_key VARCHAR(255) PRIMARY KEY,

    -- Storage
    location TEXT NOT NULL, -- S3 path or local mount
    size_bytes BIGINT,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE m23_governance.cache_artifacts IS 'Inventory of cached dependencies to accelerate CI builds.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 143 - workflow_runs
-- Description: Top level GitHub Actions workflow runs.
-- Business Case: Orchestration tracking. High-level view of the workflow execution (not individual jobs).
-- KPIs: 1. Workflow Success Rate, 2. Workflow Duration.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.workflow_runs (
    -- Primary Key
    run_id BIGINT PRIMARY KEY, -- Use external ID if applicable, else SERIAL

    -- Details
    workflow_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL, -- queued, in_progress, completed
    conclusion VARCHAR(50),
    event VARCHAR(50), -- push, pull_request

    -- Trigger
    triggered_by BIGINT,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Links
    head_commit_sha CHAR(40),
    head_branch VARCHAR(100)
);

COMMENT ON TABLE m23_governance.workflow_runs IS 'High-level tracking of CI workflow executions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 144 - workflow_jobs
-- Description: Jobs within a workflow run.
-- Business Case: Drill-down execution. Specific tasks within the workflow (Build, Test, Deploy).
-- KPIs: 1. Job Failure Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.workflow_jobs (
    -- Primary Key
    job_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Details
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    steps_json JSONB, -- Serialized step results

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_wfjob_run FOREIGN KEY (run_id) REFERENCES m23_governance.workflow_runs(run_id)
);

COMMENT ON TABLE m23_governance.workflow_jobs IS 'Detailed breakdown of jobs within a CI workflow.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 145 - workflow_steps
-- Description: Steps within a job.
-- Business Case: Fine-grained debugging. Identifies exactly which step (e.g., `npm install`) failed.
-- KPIs: 1. Step Duration.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.workflow_steps (
    -- Primary Key
    step_id BIGSERIAL PRIMARY KEY,

    -- Linking
    job_id BIGINT NOT NULL,

    -- Details
    name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    log_url TEXT, -- Pointer to log storage

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_step_job FOREIGN KEY (job_id) REFERENCES m23_governance.workflow_jobs(job_id)
);

COMMENT ON TABLE m23_governance.workflow_steps IS 'Atomic unit of execution within a CI job.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 146 - marketplace_listings
-- Description: Internal marketplace for plugins/integrations.
-- Business Case: Extensibility. Allows third-party developers to submit plugins for PARI (e.g.,
-- new payment adapters) which must be vetted before listing.
-- KPIs: 1. Plugin Submissions, 2. Plugin Security Pass Rate.
-- Feature Reference: 7
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.marketplace_listings (
    -- Primary Key
    listing_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50), -- PAYMENT_ADAPTER, THEME, TOOL
    status VARCHAR(20) DEFAULT 'PENDING_REVIEW', -- PENDING, APPROVED, REJECTED

    -- Audit
    submitted_by BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mkt_contributor FOREIGN KEY (submitted_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.marketplace_listings IS 'Directory of available plugins and integrations for the PARI ecosystem.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 147 - plugin_versions
-- Description: Versions of plugins.
-- Business Case: Version control. Ensures plugins are versioned and that users can pin to specific
-- versions for stability.
-- KPIs: 1. Plugin Update Frequency.
-- Feature Reference: 7
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.plugin_versions (
    -- Primary Key
    version_id SERIAL PRIMARY KEY,

    -- Linking
    listing_id INTEGER NOT NULL,

    -- Version
    version VARCHAR(50) NOT NULL, -- SemVer
    download_url TEXT NOT NULL,
    signature TEXT, -- GPG signature of the package

    -- Compatibility
    min_pari_version VARCHAR(50),
    max_pari_version VARCHAR(50),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_plugin_listing FOREIGN KEY (listing_id) REFERENCES m23_governance.marketplace_listings(listing_id)
);

COMMENT ON TABLE m23_governance.plugin_versions IS 'Version history for marketplace plugins.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 148 - verified_publishers
-- Description: Verified plugin publishers.
-- Business Case: Trust. Marks publishers who have completed identity verification, giving users
-- confidence to install their plugins.
-- KPIs: 1. Verified Publisher Rate.
-- Feature Reference: 7
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.verified_publishers (
    -- Primary Key
    publisher_id SERIAL PRIMARY KEY,

    -- Identity
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    verification_token CHAR(32), -- DNS TXT token

    -- Status
    is_verified BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.verified_publishers IS 'Registry of organizations verified to publish plugins for PARI.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 149 - sso_providers
-- Description: Configured SSO providers for contributors.
-- Business Case: Enterprise integration. Allows corporate partners to use their own IdP (Okta, Azure)
-- to log in to PARI contribution portal.
-- KPIs: 1. SSO Login Success Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sso_providers (
    -- Primary Key
    provider_id SERIAL PRIMARY KEY,

    -- Config
    provider_name VARCHAR(50) NOT NULL, -- okta, azure, google
    metadata_url TEXT NOT NULL, -- SAML Metadata URL or OIDC Discovery URL
    client_id VARCHAR(255),
    client_secret_encrypted TEXT,

    -- Settings
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.sso_providers IS 'Configuration for Single Sign-On integrations.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 150 - audit_log_exports
-- Description: History of audit log exports for auditors.
-- Business Case: Regulatory compliance. Tracks when logs were exported for external auditors (banks,
-- governments) to ensure chain of custody.
-- KPIs: 1. Export Delivery Time, 2. Export Data Integrity.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.audit_log_exports (
    -- Primary Key
    export_id SERIAL PRIMARY KEY,

    -- Request
    requested_by BIGINT NOT NULL,
    date_range_start TIMESTAMP WITH TIME ZONE NOT NULL,
    date_range_end TIMESTAMP WITH TIME ZONE NOT NULL,

    -- File
    file_url TEXT,
    file_checksum CHAR(64),
    file_size_bytes BIGINT,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, COMPLETED, FAILED
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_audit_export_requester FOREIGN KEY (requested_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.audit_log_exports IS 'Tracks requests and delivery of audit logs for compliance auditing.';

-- Triggers for Part 3
CREATE TRIGGER trg_sso_providers_updated_at BEFORE UPDATE ON m23_governance.sso_providers
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

    -- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 4: Database Objects Tables 151-200
-- ==========================================================================================================
-- Description:
-- This script concludes the definition of the database schema for Module M23, covering database
-- objects 151 through 200. This section focuses on compliance, security assets (keys, signatures),
-- community management (reactions, discussions), project management (boards, sprints), and
-- comprehensive statistics/analytics.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 151 - retention_policies
-- Description: Configured data retention policies.
-- Business Case: GDPR/Privacy Compliance. Defines how long different types of data (logs, personal
-- data, comments) must be kept before anonymization or deletion. Reduces liability and storage costs.
-- KPIs: 1. Policy Adherence Rate, 2. Storage Cost Reduction, 3. Data Deletion Latency.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.retention_policies (
    -- Primary Key
    policy_name VARCHAR(100) PRIMARY KEY,

    -- Configuration
    policy_type VARCHAR(50) NOT NULL, -- AUDIT_LOGS, PERSONAL_DATA, COMMENTS, ARTIFACTS
    retention_days INTEGER NOT NULL,
    action_after_expiry VARCHAR(50) NOT NULL, -- ANONYMIZE, DELETE, ARCHIVE

    -- Scope
    applies_to_schema VARCHAR(100) DEFAULT 'm23_governance',
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.retention_policies IS 'Rules governing the lifecycle and disposal of governance data for privacy compliance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 152 - compliance_reports
-- Description: Generated compliance reports (e.g., quarterly).
-- Business Case: Auditing. Automatically aggregates data into human-readable reports for regulators,
-- detailing security incidents, access logs, and code changes over a period.
-- KPIs: 1. Report Generation Time, 2. Audit Finding Count, 3. Report Accuracy.
-- Feature Reference: 84
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.compliance_reports (
    -- Primary Key
    report_id SERIAL PRIMARY KEY,

    -- Report Details
    report_type VARCHAR(50) NOT NULL, -- SOC2, PCI-DSS, GDPR, ISO27001
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Content
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    generated_by UUID NOT NULL,
    file_url TEXT, -- Link to PDF/CSV
    status VARCHAR(20) DEFAULT 'GENERATED', -- GENERATED, REVIEWED, SUBMITTED

    -- Summary
    total_changes INTEGER,
    security_incidents INTEGER,
    access_requests_denied INTEGER
);

COMMENT ON TABLE m23_governance.compliance_reports IS 'Stores generated documentation for regulatory and security audits.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 153 - api_keys
-- Description: API keys for bot accounts.
-- Business Case: Automation authentication. Allows CI/CD bots or external scripts to interact with
-- the Governance API (e.g., to update status or create checks) securely.
-- KPIs: 1. Key Usage Rate, 2. Failed Authentication Attempts.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_keys (
    -- Primary Key
    key_id SERIAL PRIMARY KEY,

    -- Identification
    account_id BIGINT NOT NULL, -- References contributor_id
    key_hash CHAR(64) NOT NULL, -- SHA256 of the key
    key_prefix VARCHAR(10) NOT NULL, -- First few chars for identification (e.g., 'pari_live...')

    -- Scope
    scopes TEXT[] NOT NULL, -- {read:repo, write:check}
    name VARCHAR(255), -- Descriptive name like "Jenkins Bot Key"

    -- Lifecycle
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    -- Constraints
    CONSTRAINT fk_apikey_contributor FOREIGN KEY (account_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_api_keys_hash ON m23_governance.api_keys(key_hash);
COMMENT ON TABLE m23_governance.api_keys IS 'Stores encrypted credentials for programmatic access to the governance API.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 154 - personal_access_tokens
-- Description: PATs for contributors.
-- Business Case: User convenience. Allows contributors to generate tokens for local Git operations
-- (e.g., pushing commits) without using their password.
-- KPIs: 1. Token Creation Rate, 2. Stale Token Count.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.personal_access_tokens (
    -- Primary Key
    token_id SERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,

    -- Token Details
    token_hash CHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL,

    -- Lifecycle
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    is_revoked BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_pat_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.personal_access_tokens IS 'Granular access tokens for contributor authentication.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 155 - ssh_keys
-- Description: SSH keys for git access.
-- Business Case: Secure Operations. Allows contributors to push code via SSH using public-key
-- cryptography, which is more secure than password authentication.
-- KPIs: 1. SSH Auth Success Rate.
-- Feature Reference: 122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ssh_keys (
    -- Primary Key
    key_id SERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,

    -- Key Details
    key_type VARCHAR(20) NOT NULL, -- RSA, ED25519, ECDSA
    key_data TEXT NOT NULL, -- The public key blob
    fingerprint VARCHAR(64) NOT NULL, -- SHA256 fingerprint
    name VARCHAR(255),

    -- Audit
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_ssh_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.ssh_keys IS 'Public SSH keys for secure git operations.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 156 - gpg_signatures
-- Description: GPG signatures for tags/commits.
-- Business Case: Release Integrity. Verifies that tags (release versions) were signed by a
-- trusted maintainer, preventing supply chain attacks via compromise of build servers.
-- KPIs: 1. Signature Verification Rate, 2. Trusted Signing Key Count.
-- Feature Reference: 121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.gpg_signatures (
    -- Primary Key
    sig_id BIGSERIAL PRIMARY KEY,

    -- Linking
    commit_sha CHAR(40) NOT NULL,
    key_id INTEGER NOT NULL,

    -- Signature Data
    signature_payload TEXT NOT NULL,
    signature_ascii TEXT NOT NULL, -- ASCII armored signature

    -- Verification
    is_valid BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_gpg_key FOREIGN KEY (key_id) REFERENCES m23_governance.pgp_keys(key_id),
    CONSTRAINT uq_gpg_commit UNIQUE (commit_sha)
);

COMMENT ON TABLE m23_governance.gpg_signatures IS 'Cryptographic proofs linking commits to specific GPG identities.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 157 - protected_tags
-- Description: Tags that require signing/protection.
-- Business Case: Release Control. Prevents anyone from overwriting or moving a tag (e.g., v1.0.0)
-- unless they have specific permissions, ensuring version stability.
-- KPIs: 1. Protected Tag Coverage.
-- Feature Reference: 121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.protected_tags (
    -- Primary Key
    tag_name VARCHAR(255) PRIMARY KEY,

    -- Configuration
    pattern VARCHAR(255) NOT NULL, -- e.g., "v*.*.*"
    allow_force_pushes BOOLEAN DEFAULT FALSE,
    create_allowed_roles VARCHAR(100)[], -- Array of role slugs

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.protected_tags IS 'Restrictions on git tags to preserve release integrity.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 158 - status_checks
-- Description: External status check contexts.
-- Business Case: Extensibility. Defines integrations with third-party CI systems (e.g., Jenkins,
-- CircleCI) that can report status back to a PR.
-- KPIs: 1. Check Response Time.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.status_checks (
    -- Primary Key
    context_name VARCHAR(100) PRIMARY KEY, -- e.g., "ci/circleci"

    -- Integration
    integration_url TEXT,
    description TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.status_checks IS 'Registry of external CI/CD systems allowed to report PR statuses.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 159 - status_check_results
-- Description: Results of external status checks.
-- Business Case: Integration. Stores the actual pass/fail results from external CI systems
-- linked to specific PR commits.
-- KPIs: 1. External Check Failure Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.status_check_results (
    -- Primary Key
    check_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    context_name VARCHAR(100) NOT NULL,

    -- Result
    state VARCHAR(20) NOT NULL, -- PENDING, SUCCESS, FAILURE, ERROR
    description TEXT,
    target_url TEXT, -- Link to the build log

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_scr_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_scr_context FOREIGN KEY (context_name) REFERENCES m23_governance.status_checks(context_name)
);

CREATE INDEX idx_scr_pr_context ON m23_governance.status_check_results(pr_id, context_name);
COMMENT ON TABLE m23_governance.status_check_results IS 'Records the outcomes of external system validations.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 160 - environments
-- Description: Deployment environments (dev, staging, prod).
-- Business Case: Deployment Governance. Manages the different stages of the pipeline and the
-- specific protection rules for Production (e.g., require 2 approvals).
-- KPIs: 1. Deployment Frequency, 2. Deployment Lead Time.
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.environments (
    -- Primary Key
    env_name VARCHAR(50) PRIMARY KEY,

    -- Details
    url TEXT, -- The public URL of the environment
    environment_type VARCHAR(20) DEFAULT 'STANDARD', -- STANDARD, PREVIEW, PRODUCTION

    -- Protection
    protection_rules JSONB, -- e.g., {required_reviewers: 2, wait_timer: 60}
    deployment_branch_strategy VARCHAR(50) -- all, filtered_branches
);

COMMENT ON TABLE m23_governance.environments IS 'Defines the deployment stages for the application.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 161 - deployment_protections
-- Description: Rules for protecting environments.
-- Business Case: Risk Mitigation. Enforces gates before code can reach production (e.g., wait timer,
-- required manual approval).
-- KPIs: 1. Production Incident Rate (reduction), 2. Rollback Frequency.
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.deployment_protections (
    -- Primary Key
    env_name VARCHAR(50) PRIMARY KEY,

    -- Rules
    required_reviewers BIGINT[], -- Array of contributor IDs
    wait_timer_minutes INTEGER DEFAULT 0,
    prevent_self_review BOOLEAN DEFAULT TRUE,

    -- Constraints
    CONSTRAINT fk_dep_prot_env FOREIGN KEY (env_name) REFERENCES m23_governance.environments(env_name) ON DELETE CASCADE
);

COMMENT ON TABLE m23_governance.deployment_protections IS 'Gates that must be passed before deploying to specific environments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 162 - deployments
-- Description: Record of deployments.
-- Business Case: History. Logs every deployment event to track what code is running where,
-- essential for incident response ("When was this bug deployed to prod?").
-- KPIs: 1. Deployment Success Rate, 2. Mean Time to Recovery (MTTR).
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.deployments (
    -- Primary Key
    deployment_id BIGSERIAL PRIMARY KEY,

    -- Linking
    env_name VARCHAR(50) NOT NULL,
    pr_id BIGINT,

    -- Details
    sha CHAR(40) NOT NULL, -- The commit SHA deployed
    ref VARCHAR(255), -- Branch or Tag
    task VARCHAR(50), -- DEPLOY, ROLLBACK
    environment VARCHAR(50), -- production, staging

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SUCCESS, FAILURE, INACTIVE
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Links
    logs_url TEXT,
    environment_url TEXT,

    -- Actor
    creator_id BIGINT,

    -- Constraints
    CONSTRAINT fk_deploy_env FOREIGN KEY (env_name) REFERENCES m23_governance.environments(env_name),
    CONSTRAINT fk_deploy_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_deploy_creator FOREIGN KEY (creator_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.deployments IS 'Historical record of all code deployments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 163 - deployment_statuses
-- Description: Status updates for deployments.
-- Business Case: Real-time Progress. Tracks intermediate steps of a deployment (e.g., "Building",
-- "Testing", "Live").
-- KPIs: 1. Step Failure Rate.
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.deployment_statuses (
    -- Primary Key
    status_id BIGSERIAL PRIMARY KEY,

    -- Linking
    deployment_id BIGINT NOT NULL,

    -- Status
    state VARCHAR(50) NOT NULL, -- queued, in_progress, success, failure, error
    description TEXT,
    log_url TEXT,

    -- Environment
    environment_url TEXT,
    deployed_url TEXT,

    -- Creator
    creator_id BIGINT,

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_dstat_deploy FOREIGN KEY (deployment_id) REFERENCES m23_governance.deployments(deployment_id),
    CONSTRAINT fk_dstat_creator FOREIGN KEY (creator_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.deployment_statuses IS 'Detailed timeline of a deployment lifecycle.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 164 - cron_jobs
-- Description: Scheduled jobs in the project.
-- Business Case: Automation. Recurring tasks like database backups, dependency updates, or
-- report generation.
-- KPIs: 1. Job Execution Accuracy, 2. Job Overrun Frequency.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cron_jobs (
    -- Primary Key
    job_id SERIAL PRIMARY KEY,

    -- Definition
    schedule VARCHAR(100) NOT NULL, -- Cron expression
    command TEXT NOT NULL, -- The command to run
    description TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE m23_governance.cron_jobs IS 'Registry of scheduled maintenance tasks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 165 - cron_job_history
-- Description: Execution history of cron jobs.
-- Business Case: Debugging. Logs the success/failure of scheduled jobs to detect flaky infrastructure.
-- KPIs: 1. Job Success Rate, 2. Average Execution Duration.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cron_job_history (
    -- Primary Key
    run_id BIGSERIAL PRIMARY KEY,

    -- Linking
    job_id INTEGER NOT NULL,

    -- Execution
    status VARCHAR(20) NOT NULL, -- SUCCESS, FAILURE
    duration INTEGER, -- Seconds
    output TEXT,

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_cronhist_job FOREIGN KEY (job_id) REFERENCES m23_governance.cron_jobs(job_id)
);

COMMENT ON TABLE m23_governance.cron_job_history IS 'Audit trail for scheduled task execution.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 166 - language_metrics
-- Description: Language breakdown of the repo.
-- Business Case: Technical Health. Monitors the composition of the codebase (e.g., % Rust vs % Python)
-- to ensure alignment with architectural goals.
-- KPIs: 1. Language Diversity, 2. Legacy Code Ratio (e.g., COBOL/Java).
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.language_metrics (
    -- Primary Key
    language_name VARCHAR(50) PRIMARY KEY,

    -- Metrics
    bytes_of_code BIGINT NOT NULL,
    file_count INTEGER NOT NULL,
    line_count INTEGER
);

COMMENT ON TABLE m23_governance.language_metrics IS 'Aggregated statistics on programming languages used in the project.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 167 - contributor_commits_history
-- Description: Aggregated commit history heatmap data.
-- Business Case: Activity Visualization. Stores the raw data for generating contribution graphs
-- (green squares) similar to GitHub's profile page.
-- KPIs: 1. Contribution Consistency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_commits_history (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    date DATE NOT NULL,

    -- Metrics
    commit_count INTEGER DEFAULT 0,
    addition_count INTEGER DEFAULT 0,
    deletion_count INTEGER DEFAULT 0,

    -- Audit
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_contrib_history UNIQUE (contributor_id, date),
    CONSTRAINT fk_contrib_history_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.contributor_commits_history IS 'Daily aggregation of contributor activity for heatmap visualization.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 168 - pr_time_to_merge
-- Description: Analytics for time to merge.
-- Business Case: Process Optimization. Measures how long PRs sit idle. High times indicate
-- bottlenecks in review processes.
-- KPIs: 1. Mean Time to Merge (MTTM), 2. Review Cycle Efficiency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_time_to_merge (
    -- Primary Key
    pr_id BIGINT PRIMARY KEY,

    -- Milestones
    opened_at TIMESTAMP WITH TIME ZONE NOT NULL,
    first_review_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE,
    merged_at TIMESTAMP WITH TIME ZONE,

    -- Calculated Metrics
    hours_to_first_review NUMERIC(10,2),
    hours_to_merge NUMERIC(10,2),
    hours_in_review NUMERIC(10,2),

    -- Constraints
    CONSTRAINT fk_ttm_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.pr_time_to_merge IS 'Tracks the latency of the Pull Request lifecycle process.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 169 - comment_activity
-- Description: Aggregated comment activity stats.
-- Business Case: Community Health. Volume of comments indicates engagement. Sudden drops or
-- spikes can signal issues.
-- KPIs: 1. Engagement Rate, 2. Toxic Comment Ratio.
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.comment_activity (
    -- Primary Key
    date DATE PRIMARY KEY,

    -- Metrics
    total_comments INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    pr_comments INTEGER DEFAULT 0,
    issue_comments INTEGER DEFAULT 0,
    discussion_comments INTEGER DEFAULT 0
);

COMMENT ON TABLE m23_governance.comment_activity IS 'Daily aggregation of community interaction metrics.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 170 - review_turnaround
-- Description: Time taken for reviewers to review.
-- Business Case: Performance Management. Identifies the fastest and slowest reviewers to help
-- balance load or recognize efficiency.
-- KPIs: 1. Average Review Time, 2. Review Backlog Size.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.review_turnaround (
    -- Composite Primary Key
    reviewer_id BIGINT PRIMARY KEY,

    -- Metrics
    avg_turnaround_hours NUMERIC(10,2),
    total_reviews_completed INTEGER,
    last_reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_reviewer_contributor FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.review_turnaround IS 'Analytics on reviewer performance and speed.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 171 - code_churn
-- Description: Lines added vs removed per day.
-- Business Case: Stability Analysis. High churn indicates instability or "churn" where code is
-- rewritten frequently. Low churn might indicate stagnation.
-- KPIs: 1. Churn Rate, 2. Code Stability Index.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_churn (
    -- Primary Key
    date DATE PRIMARY KEY,

    -- Metrics
    lines_added BIGINT DEFAULT 0,
    lines_removed BIGINT DEFAULT 0,
    files_changed INTEGER DEFAULT 0,
    commits_count INTEGER DEFAULT 0
);

COMMENT ON TABLE m23_governance.code_churn IS 'Daily measurement of code volume changes.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 172 - bug_reports
-- Description: Specifically tracks bug issue types.
-- Business Case: Quality Control. Separates bugs from features to track defect density and
-- fix rates specifically.
-- KPIs: 1. Bug Fix Rate, 2. Critical Bug Lifetime.
-- Feature Reference: 157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.bug_reports (
    -- Primary Key (External ID)
    issue_id VARCHAR(100) PRIMARY KEY,

    -- Details
    severity VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    priority INTEGER NOT NULL, -- 1-5
    state VARCHAR(20), -- OPEN, CLOSED

    -- Classification
    category VARCHAR(100), -- PERFORMANCE, SECURITY, UI
    root_cause TEXT,

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,
    resolved_by BIGINT,

    -- Constraints
    CONSTRAINT fk_bug_resolved FOREIGN KEY (resolved_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.bug_reports IS 'Detailed tracking of software defect reports.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 173 - feature_requests
-- Description: Tracks feature requests.
-- Business Case: Roadmap Planning. Prioritizes what the community or stakeholders want built next.
-- KPIs: 1. Request Completion Rate, 2. Community Interest Level.
-- Feature Reference: 157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.feature_requests (
    -- Primary Key (External ID)
    issue_id VARCHAR(100) PRIMARY KEY,

    -- Details
    upvotes INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'PROPOSED', -- PROPOSED, PLANNED, IN_PROGRESS, COMPLETED
    target_release VARCHAR(50),
    estimated_story_points INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.feature_requests IS 'Manages the backlog of desired new functionalities.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 174 - project_boards
-- Description: Agile project boards.
-- Business Case: Task Management. Visual organization of work (Kanban boards) for teams.
-- KPIs: 1. Cycle Time, 2. Throughput.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.project_boards (
    -- Primary Key
    board_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL,
    columns_json JSONB NOT NULL, -- Ordered list of columns e.g. ["To Do", "In Progress", "Done"]
    visibility VARCHAR(20) DEFAULT 'PRIVATE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.project_boards IS 'Agile board configurations for task tracking.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 175 - board_cards
-- Description: Cards on project boards.
-- Business Case: Workflow tracking. Links Issues or PRs to specific columns on a board.
-- KPIs: 1. Card Movement Velocity.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.board_cards (
    -- Primary Key
    card_id BIGSERIAL PRIMARY KEY,

    -- Linking
    board_id INTEGER NOT NULL,
    issue_id VARCHAR(100), -- External ID

    -- State
    column_name VARCHAR(255) NOT NULL,
    position INTEGER NOT NULL, -- Order in the column

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_card_board FOREIGN KEY (board_id) REFERENCES m23_governance.project_boards(board_id)
);

COMMENT ON TABLE m23_governance.board_cards IS 'Maps issues to positions on project boards.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 176 - sprints
-- Description: Agile sprints.
-- Business Case: Time-boxing. Groups work into fixed duration cycles (e.g., 2 weeks).
-- KPIs: 1. Sprint Velocity, 2. Goal Completion Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sprints (
    -- Primary Key
    sprint_id SERIAL PRIMARY KEY,

    -- Linking
    board_id INTEGER NOT NULL,

    -- Timing
    name VARCHAR(255) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    state VARCHAR(20) DEFAULT 'FUTURE', -- FUTURE, ACTIVE, CLOSED

    -- Goals
    goal TEXT,
    completed_points INTEGER,

    -- Constraints
    CONSTRAINT fk_sprint_board FOREIGN KEY (board_id) REFERENCES m23_governance.project_boards(board_id)
);

COMMENT ON TABLE m23_governance.sprints IS 'Defines time-boxed iterations for Agile development.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 177 - team_members
-- Description: Members of teams.
-- Business Case: Group Management. Organizes contributors into logical teams (e.g., @pari/security).
-- KPIs: 1. Team Size Distribution.
-- Feature Reference: 178
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.team_members (
    -- Composite Primary Key
    team_id INTEGER NOT NULL,
    contributor_id BIGINT NOT NULL,

    -- Role
    role VARCHAR(50) NOT NULL, -- MAINTAINER, MEMBER, GUEST
    is_leader BOOLEAN DEFAULT FALSE,

    -- Audit
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_team_members UNIQUE (team_id, contributor_id),
    CONSTRAINT fk_tm_team FOREIGN KEY (team_id) REFERENCES m23_governance.teams(team_id),
    CONSTRAINT fk_tm_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.team_members IS 'Links contributors to organizational teams.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 178 - teams
-- Description: Definition of teams.
-- Business Case: Collaboration. Groups sets of people to be assigned reviews, issues, or
-- mentioned together.
-- KPIs: 1. Team Creation Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.teams (
    -- Primary Key
    team_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    parent_team_id INTEGER, -- For nested teams

    -- Visibility
    is_private BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    CONSTRAINT fk_team_parent FOREIGN KEY (parent_team_id) REFERENCES m23_governance.teams(team_id)
);

COMMENT ON TABLE m23_governance.teams IS 'Organizational groups of contributors.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 179 - team_permissions
-- Description: Permissions for teams.
-- Business Case: Access Control. Grants teams specific permissions on repositories (e.g., Write,
-- Admin, Triage).
-- KPIs: 1. Permission Audit Accuracy.
-- Feature Reference: 178
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.team_permissions (
    -- Primary Key
    permission_id SERIAL PRIMARY KEY,

    -- Linking
    team_id INTEGER NOT NULL,

    -- Scope
    resource VARCHAR(50) NOT NULL, -- REPOSITORY, ORGANIZATION
    permission_type VARCHAR(50) NOT NULL, -- PULL, PUSH, ADMIN, MAINTAIN
    resource_id INTEGER, -- e.g. repo_id if resource is REPOSITORY

    -- Audit
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID,

    -- Constraints
    CONSTRAINT fk_tp_team FOREIGN KEY (team_id) REFERENCES m23_governance.teams(team_id)
);

COMMENT ON TABLE m23_governance.team_permissions IS 'Access control list for teams.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 180 - external_identities
-- Description: Links external accounts (Google, etc).
-- Business Case: SSO Integration. Connects a local contributor account to their identity from an
-- external Identity Provider (IdP).
-- KPIs: 1. Link Success Rate.
-- Feature Reference: 149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.external_identities (
    -- Primary Key
    identity_id SERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,

    -- Provider Info
    provider VARCHAR(50) NOT NULL, -- google, github, okta
    provider_user_id VARCHAR(255) NOT NULL, -- The user's ID in that system
    provider_email VARCHAR(255),

    -- Tokens (if OAuth)
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_ext_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT uq_ext_provider UNIQUE (provider, provider_user_id)
);

COMMENT ON TABLE m23_governance.external_identities IS 'Associates local accounts with external identity providers.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 181 - notifications
-- Description: Generic notification queue.
-- Business Case: Engagement Engine. Queues messages (emails, webhooks, in-app) to be sent to users
-- about relevant events.
-- KPIs: 1. Delivery Rate, 2. Notification Latency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.notifications (
    -- Primary Key
    notification_id BIGSERIAL PRIMARY KEY,

    -- Recipient
    recipient_id BIGINT NOT NULL,

    -- Content
    type VARCHAR(50) NOT NULL, -- PR_MERGED, MENTIONED, SECURITY_ALERT
    title VARCHAR(255) NOT NULL,
    body TEXT,
    payload_json JSONB,

    -- Delivery
    channels TEXT[] NOT NULL, -- EMAIL, WEBHOOK, IN_APP
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, SENT, FAILED
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_notif_recipient FOREIGN KEY (recipient_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.notifications IS 'Central queue for user notifications.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 182 - notification_deliveries
-- Description: Status of notification delivery.
-- Business Case: Reliability. Tracks the specific delivery attempts to each channel for auditing
-- (did the email bounce?).
-- KPIs: 1. Channel Delivery Success Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.notification_deliveries (
    -- Primary Key
    delivery_id BIGSERIAL PRIMARY KEY,

    -- Linking
    notification_id BIGINT NOT NULL,

    -- Delivery
    channel VARCHAR(50) NOT NULL, -- EMAIL, SLACK, SMS
    status VARCHAR(20) NOT NULL, -- SENT, FAILED, RETRYING
    external_id VARCHAR(255), -- e.g. Message ID from SendGrid

    -- Details
    response_code INTEGER,
    response_body TEXT,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_nd_notif FOREIGN KEY (notification_id) REFERENCES m23_governance.notifications(notification_id)
);

COMMENT ON TABLE m23_governance.notification_deliveries IS 'Log of individual notification transmission attempts.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 183 - saved_replies
-- Description: Saved text for quick replies.
-- Business Case: Efficiency. Allows maintainers to save common responses (e.g., "Please add tests")
-- to speed up review workflows.
-- KPIs: 1. Reply Frequency.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.saved_replies (
    -- Primary Key
    reply_id SERIAL PRIMARY KEY,

    -- Owner
    contributor_id BIGINT NOT NULL,

    -- Content
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,

    -- Usage
    usage_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_saved_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.saved_replies IS 'Template responses for common review scenarios.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 184 - draft_releases
-- Description: Draft release metadata.
-- Business Case: Release Management. Allows maintainers to prepare release notes and tag metadata
-- before the official cut.
-- KPIs: 1. Release Preparation Time.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.draft_releases (
    -- Primary Key
    release_id SERIAL PRIMARY KEY,

    -- Tagging
    tag_name VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    body TEXT, -- Release notes

    -- Status
    is_draft BOOLEAN DEFAULT TRUE,
    is_prerelease BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP WITH TIME ZONE,

    -- Author
    author_id BIGINT,

    -- Constraints
    CONSTRAINT fk_draft_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.draft_releases IS 'Work-in-progress storage for release notes and tags.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 185 - release_assets
-- Description: Files attached to releases.
-- Business Case: Distribution. Stores binary packages, checksums, or signatures attached to a
-- release (e.g., pari-linux-amd64.zip).
-- KPIs: 1. Download Count.
-- Feature Reference: 184
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.release_assets (
    -- Primary Key
    asset_id SERIAL PRIMARY KEY,

    -- Linking
    release_id INTEGER NOT NULL,

    -- File
    name VARCHAR(255) NOT NULL,
    size BIGINT,
    download_count BIGINT DEFAULT 0,
    content_type VARCHAR(100),

    -- Storage
    url TEXT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_asset_release FOREIGN KEY (release_id) REFERENCES m23_governance.draft_releases(release_id)
);

COMMENT ON TABLE m23_governance.release_assets IS 'Binary files distributed with software releases.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 186 - emoji_reactions
-- Description: Reactions on comments/PRs.
-- Business Case: Feedback Loop. Allows users to express sentiment quickly (:+1:, :confused:)
-- without writing a full comment.
-- KPIs: 1. Reaction Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.emoji_reactions (
    -- Primary Key
    reaction_id BIGSERIAL PRIMARY KEY,

    -- Context
    content_type VARCHAR(50) NOT NULL, -- PR, ISSUE, COMMENT
    content_id BIGINT NOT NULL, -- ID of the PR/Issue/Comment

    -- Reaction
    emoji VARCHAR(50) NOT NULL, -- e.g. thumbs_up, rocket
    user_id BIGINT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_reaction_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT uq_user_reaction UNIQUE (content_type, content_id, user_id, emoji)
);

COMMENT ON TABLE m23_governance.emoji_reactions IS 'Sentiment indicators attached to contributions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 187 - referenced_issues
-- Description: Issues referenced in PRs/Comments.
-- Business Case: Traceability. Captures implicit links where an issue is mentioned in text or code.
-- KPIs: 1. Link Discovery Rate.
-- Feature Reference: 160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.referenced_issues (
    -- Primary Key
    ref_id BIGSERIAL PRIMARY KEY,

    -- Source
    source_type VARCHAR(50) NOT NULL, -- PR, COMMENT
    source_id BIGINT NOT NULL,

    -- Target
    issue_id VARCHAR(100) NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.referenced_issues IS 'Auto-detected references to issues from content.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 188 - pinned_issues
-- Description: Issues pinned to repo top.
-- Business Case: Visibility. Highlights important announcements or pinned trackers for the community.
-- KPIs: 1. Pinned Issue Click-through.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pinned_issues (
    -- Composite Primary Key
    repo_id INTEGER NOT NULL,
    issue_id VARCHAR(100) NOT NULL,

    -- Ordering
    position INTEGER NOT NULL,

    -- Constraints
    CONSTRAINT pk_pinned_issues UNIQUE (repo_id, issue_id),
    CONSTRAINT fk_pinned_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.pinned_issues IS 'Ordering of important issues displayed at the top of the repository.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 189 - locked_resources
-- Description: Resources locked for commenting (e.g. due to spam).
-- Business Case: Moderation. Temporarily freezes discussions on heated topics or spam targets.
-- KPIs: 1. Lock Duration.
-- Feature Reference: 23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.locked_resources (
    -- Composite Primary Key
    resource_type VARCHAR(50) NOT NULL, -- ISSUE, PR, COMMENT
    resource_id BIGINT NOT NULL,

    -- Lock Details
    locked_reason TEXT,
    locked_by BIGINT NOT NULL,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_locked_user FOREIGN KEY (locked_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.locked_resources IS 'Prevents new comments on specific resources for moderation purposes.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 190 - transferred_issues
-- Description: History of issues transferred between repos.
-- Business Case: Organization. Tracks when an issue is moved (e.g., from repo 'core' to 'docs')
-- to maintain history.
-- KPIs: 1. Transfer Volume.
-- Feature Reference: 160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.transferred_issues (
    -- Primary Key
    issue_id VARCHAR(100) PRIMARY KEY,

    -- Transfer Details
    from_repo_id INTEGER NOT NULL,
    to_repo_id INTEGER NOT NULL,
    transferred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    transferred_by BIGINT,

    -- Constraints
    CONSTRAINT fk_trans_from_repo FOREIGN KEY (from_repo_id) REFERENCES m23_governance.repositories(repo_id),
    CONSTRAINT fk_trans_to_repo FOREIGN KEY (to_repo_id) REFERENCES m23_governance.repositories(repo_id),
    CONSTRAINT fk_trans_user FOREIGN KEY (transferred_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.transferred_issues IS 'Audit log for issues moved between repositories.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 191 - linked_issues
-- Description: Explicit linking of related issues.
-- Business Case: Dependency Tracking. Marks issues as duplicates, blocking, or related to each other.
-- KPIs: 1. Linkage Accuracy.
-- Feature Reference: 160
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.linked_issues (
    -- Composite Primary Key
    issue_id_a VARCHAR(100) NOT NULL,
    issue_id_b VARCHAR(100) NOT NULL,

    -- Relationship
    relationship_type VARCHAR(50) NOT NULL, -- BLOCKED_BY, DUPLICATES, RELATES_TO

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_linked_issues UNIQUE (issue_id_a, issue_id_b, relationship_type)
);

COMMENT ON TABLE m23_governance.linked_issues IS 'Semantic connections between issues.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 192 - issue_timelines
-- Description: History of state changes on issues.
-- Business Case: Full History. Immutable log of every change (label added, milestone set, closed)
-- on an issue.
-- KPIs: 1. State Change Frequency.
-- Feature Reference: 157
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.issue_timelines (
    -- Primary Key
    event_id BIGSERIAL PRIMARY KEY,

    -- Context
    issue_id VARCHAR(100) NOT NULL,

    -- Event
    actor_id BIGINT NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- LABELED, UNLABELED, CLOSED, REFERENCED
    event_data JSONB, -- e.g. {"label": "bug"}

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_timeline_actor FOREIGN KEY (actor_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_timeline_issue ON m23_governance.issue_timelines(issue_id);
COMMENT ON TABLE m23_governance.issue_timelines IS 'Immutable record of all changes to an issue.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 193 - issue_assignees
-- Description: Users assigned to issues.
-- Business Case: Accountability. Tracks who is responsible for resolving a specific issue.
-- KPIs: 1. Assignment Resolution Time.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.issue_assignees (
    -- Composite Primary Key
    issue_id VARCHAR(100) NOT NULL,
    assignee_id BIGINT NOT NULL,

    -- Audit
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_assignees UNIQUE (issue_id, assignee_id),
    CONSTRAINT fk_assignee_user FOREIGN KEY (assignee_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.issue_assignees IS 'Maps issues to the responsible contributors.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 194 - issue_labels
-- Description: Labels applied to issues.
-- Business Case: Categorization. Flexible metadata for filtering and organizing work.
-- KPIs: 1. Label Usage Consistency.
-- Feature Reference: 32
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.issue_labels (
    -- Composite Primary Key
    issue_id VARCHAR(100) NOT NULL,
    label_id INTEGER NOT NULL,

    -- Audit
    labeled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_issue_labels UNIQUE (issue_id, label_id),
    CONSTRAINT fk_issue_label_ref FOREIGN KEY (label_id) REFERENCES m23_governance.labels(label_id)
);

COMMENT ON TABLE m23_governance.issue_labels IS 'Associates categorical tags with issues.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 195 - milestone_issues
-- Description: Issues attached to milestones.
-- Business Case: Tracking. Groups issues intended for a specific release target.
-- KPIs: 1. Milestone Completion Percentage.
-- Feature Reference: 34
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.milestone_issues (
    -- Composite Primary Key
    milestone_id INTEGER NOT NULL,
    issue_id VARCHAR(100) NOT NULL,

    -- Ordering (optional)
    position INTEGER,

    -- Constraints
    CONSTRAINT pk_milestone_issues UNIQUE (milestone_id, issue_id),
    CONSTRAINT fk_ms_issue_milestone FOREIGN KEY (milestone_id) REFERENCES m23_governance.milestones(milestone_id)
);

COMMENT ON TABLE m23_governance.milestone_issues IS 'Links issues to time-bound milestones.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 196 - stale_issues
-- Description: Issues marked as stale.
-- Business Case: Hygiene. Automatically identifies issues that haven't had activity in a set period
-- to close them or ask for updates.
-- KPIs: 1. Stale Issue Cleanup Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.stale_issues (
    -- Primary Key
    issue_id VARCHAR(100) PRIMARY KEY,

    -- State
    marked_stale_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    close_after_days INTEGER DEFAULT 7,
    is_stale BOOLEAN DEFAULT TRUE,

    -- Audit
    processed_by BIGINT,

    -- Constraints
    CONSTRAINT fk_stale_user FOREIGN KEY (processed_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.stale_issues IS 'Tracks issues identified as inactive for potential closure.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 197 - blockchain_transactions
-- Description: Tracks bounties paid on-chain.
-- Business Case: Transparency and Audit. Records the on-chain transaction hash for bounties paid
-- in crypto (BTC/ETH) to provide proof of payment.
-- KPIs: 1. Payment Confirmation Time.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.blockchain_transactions (
    -- Primary Key
    tx_hash VARCHAR(255) PRIMARY KEY,

    -- Linking
    bounty_id INTEGER NOT NULL,

    -- Transaction Details
    amount NUMERIC(20,8) NOT NULL,
    network VARCHAR(20) NOT NULL, -- ETHEREUM, BITCOIN, POLYGON
    from_address VARCHAR(255),
    to_address VARCHAR(255),

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, CONFIRMED, FAILED
    confirmations INTEGER DEFAULT 0,
    block_number BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    confirmed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT fk_bc_bounty FOREIGN KEY (bounty_id) REFERENCES m23_governance.bounties(bounty_id)
);

COMMENT ON TABLE m23_governance.blockchain_transactions IS 'Immutable record of cryptocurrency bounty payments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 198 - forks
-- Description: List of forks of the main repo.
-- Business Case: Ecosystem Health. Tracks who is contributing via forks and identifies potential
-- forks for merging back (Pull Requests).
-- KPIs: 1. Fork Growth Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.forks (
    -- Primary Key
    fork_id BIGSERIAL PRIMARY KEY,

    -- Linking
    parent_repo_id INTEGER NOT NULL,
    fork_name VARCHAR(255),
    owner_id BIGINT,

    -- Details
    is_stale BOOLEAN DEFAULT FALSE,
    last_synced_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_fork_parent FOREIGN KEY (parent_repo_id) REFERENCES m23_governance.repositories(repo_id),
    CONSTRAINT fk_fork_owner FOREIGN KEY (owner_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.forks IS 'Registry of repository forks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 199 - stars
-- Description: Users who starred the repo.
-- Business Case: Popularity Metric. Simple gauge of interest and support.
-- KPIs: 1. Star Velocity.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.stars (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    repo_id INTEGER NOT NULL,

    -- Audit
    starred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_stars UNIQUE (contributor_id, repo_id),
    CONSTRAINT fk_star_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_star_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.stars IS 'Mapping of repository bookmarks (stars) to contributors.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 200 - watchers
-- Description: Users watching the repo for notifications.
-- Business Case: Engagement. Tracks users who want notifications for all updates on a repo.
-- KPIs: 1. Watcher Retention.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.watchers (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    repo_id INTEGER NOT NULL,

    -- Subscription Level
    subscription_type VARCHAR(50) DEFAULT 'ALL', -- ALL, IGNORED, CUSTOM

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_watchers UNIQUE (contributor_id, repo_id),
    CONSTRAINT fk_watcher_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_watcher_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.watchers IS 'Tracks users who have subscribed to repository notifications.';

-- ==========================================================================================================
-- End of Part 4 (Tables 151-200)
-- Total Database Objects Created: 200
-- ==========================================================================================================


-- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 5: Extended Database Objects Tables 201-250
-- ==========================================================================================================
-- Description:
-- This script extends the M23 schema with Tables 201-250, addressing advanced needs in high-frequency
-- payment infrastructure governance. This section introduces advanced cryptographic management for
-- Zero-Knowledge proofs, detailed hardware attestation for CI runners, granular service mesh
-- governance, and precise latency analytics for sub-millisecond transaction processing.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 201 - zk_circuit_parameters
-- Description: Public parameters for Zero-Knowledge circuits.
-- Business Case: ZK-cryptographic systems require trusted setup ceremonies (powers of tau).
-- This table stores the immutable public parameters used to verify proofs generated in PRs.
-- Tampering with these parameters would break the entire ZK trust model.
-- KPIs: 1. Parameter Verification Time, 2. Setup Ceremony Participation, 3. Parameter Security Audit Score.
-- Feature Reference: 47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.zk_circuit_parameters (
    -- Primary Key
    param_id SERIAL PRIMARY KEY,

    -- Identification
    circuit_name VARCHAR(255) NOT NULL,
    setup_id VARCHAR(100) NOT NULL, -- Identifies the specific ceremony (e.g., "Pari-Mainnet-2024")

    -- Details
    protocol VARCHAR(50) NOT NULL, -- GROTH16, PLONK, BULLETProofs
    curve_type VARCHAR(50) DEFAULT 'BN254', -- BN254, BLS12_381

    -- Storage
    srs_key_url TEXT NOT NULL, -- URL to the Structured Reference String (SRS)
    transcript_url TEXT, -- Transcript of the MPC ceremony
    hash_g2 CHAR(98), -- G2 point hash for verification

    -- Lifecycle
    is_active BOOLEAN DEFAULT TRUE,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    CONSTRAINT uq_circuit_setup UNIQUE (circuit_name, setup_id)
);

COMMENT ON TABLE m23_governance.zk_circuit_parameters IS 'Cryptographic parameters required to verify Zero-Knowledge proofs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 202 - zk_verification_keys
-- Description: Verification keys for specific ZK instances.
-- Business Case: While parameters are global to a setup, verification keys are specific to a
-- circuit instance. This table ensures that the `vk` used in the PARI wallet matches the `vk`
-- on the blockchain node.
-- KPIs: 1. Key Sync Latency, 2. Verification Key Integrity Checks.
-- Feature Reference: 47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.zk_verification_keys (
    -- Primary Key
    vk_id SERIAL PRIMARY KEY,

    -- Linking
    param_id INTEGER NOT NULL,
    pr_id BIGINT, -- The PR that introduced/updated this circuit

    -- Details
    circuit_hash CHAR(64) NOT NULL, -- Hash of the R1CS/Arithmetic circuit
    alpha_1 CHAR(98), -- G1 point
    beta_1 CHAR(98), -- G1 point
    beta_2 CHAR(98), -- G2 point
    gamma_2 CHAR(98), -- G2 point
    delta_2 CHAR(98), -- G2 point
    ic_coeffs TEXT[], -- Array of G1 points (Serialized)

    -- Storage
    raw_vk_url TEXT,
    size_bytes BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vk_params FOREIGN KEY (param_id) REFERENCES m23_governance.zk_circuit_parameters(param_id),
    CONSTRAINT fk_vk_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.zk_verification_keys IS 'Specific public inputs required to validate a specific Zero-Knowledge circuit instance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 203 - hardware_attestations
-- Description: Attestation reports from CI runners.
-- Business Case: For a financial system, CI runners cannot be just "generic VMs". They must be
-- running in specific, confidential environments (e.g., AWS Nitro enclaves, SEV-SNP). This table
-- stores the cryptographic proof of the runner's hardware state.
-- KPIs: 1. Attestation Verification Rate, 2. Trusted Runner Availability.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.hardware_attestations (
    -- Primary Key
    attestation_id BIGSERIAL PRIMARY KEY,

    -- Linking
    job_id BIGINT NOT NULL,

    -- Report
    attestation_provider VARCHAR(50) NOT NULL, -- NITRO, SEV-SNP, SGX
    document_raw TEXT NOT NULL, -- CBOR or Binary encoded as Hex/Base64
    signature TEXT,
    certificate_chain TEXT,

    -- Parsed Claims
    tcb_version VARCHAR(100),
    digest_svn INTEGER,
    launch_measurement CHAR(64),

    -- Verification
    is_valid BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attestation_job FOREIGN KEY (job_id) REFERENCES m23_governance.ci_jobs(job_id)
);

COMMENT ON TABLE m23_governance.hardware_attestations IS 'Cryptographic proof of CI runner hardware integrity (Confidential Computing).';

-- --------------------------------------------------------------------------------------------------------
-- Table: 204 - runner_inventory
-- Description: Real-time status of self-hosted runners.
-- Business Case: Resource Management. In a dedicated governance setup, knowing exactly which
-- runners are idle, busy, or offline is crucial for scheduling expensive tests (e.g., fuzzing).
-- KPIs: 1. Runner Utilization Rate, 2. Queue Wait Time.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.runner_inventory (
    -- Primary Key
    runner_id BIGSERIAL PRIMARY KEY,

    -- Identity
    runner_name VARCHAR(255) NOT NULL UNIQUE,
    runner_group VARCHAR(100),
    labels TEXT[] NOT NULL, -- e.g., {self-hosted, linux, x64, gpu}

    -- Status
    status VARCHAR(20) DEFAULT 'OFFLINE', -- ONLINE, OFFLINE, BUSY, IDLE
    current_job_id BIGINT,

    -- Specs
    os_name VARCHAR(50),
    os_version VARCHAR(50),
    cpu_cores INTEGER,
    memory_gb INTEGER,
    disk_gb INTEGER,

    -- Network
    ip_address INET,

    -- Heartbeat
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_inv_job FOREIGN KEY (current_job_id) REFERENCES m23_governance.ci_jobs(job_id)
);

COMMENT ON TABLE m23_governance.runner_inventory IS 'Real-time inventory and status of build infrastructure.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 205 - service_mesh_policies
-- Description: Traffic policies for service mesh (Istio/Linkerd).
-- Business Case: PARI is a microservices architecture. This table governs how services talk
-- to each other (e.g., "Wallet Service" can only talk to "Ledger Service"). Prevents lateral
-- movement in case of breach.
-- KPIs: 1. Policy Violation Count, 2. Mesh Latency P99.
-- Feature Reference: 117
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.service_mesh_policies (
    -- Primary Key
    policy_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(255) NOT NULL UNIQUE,
    namespace VARCHAR(100) NOT NULL,

    -- Rules
    source_namespaces TEXT[], -- e.g., {default, payments}
    destination_service VARCHAR(255), -- e.g., ledger.pari.svc.cluster.local
    destination_port INTEGER,

    -- Actions
    action VARCHAR(20) NOT NULL, -- ALLOW, DENY
    protocol VARCHAR(20) -- TCP, HTTP, gRPC
);

COMMENT ON TABLE m23_governance.service_mesh_policies IS 'Network governance rules defining service-to-service communication rights.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 206 - network_latency_tests
-- Description: Inter-service latency benchmarks.
-- Business Case: Payments must clear in milliseconds. This table tracks latency between
-- microservices over time to detect network degradation or DNS issues introduced by config changes.
-- KPIs: 1. Mean Latency, 2. P99 Latency, 3. Packet Loss.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.network_latency_tests (
    -- Primary Key
    test_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Test Details
    source_service VARCHAR(100) NOT NULL,
    target_service VARCHAR(100) NOT NULL,

    -- Metrics
    latency_mean_ms NUMERIC(10,3),
    latency_p50_ms NUMERIC(10,3),
    latency_p95_ms NUMERIC(10,3),
    latency_p99_ms NUMERIC(10,3),
    jitter_ms NUMERIC(10,3),

    -- Comparison
    baseline_p99_ms NUMERIC(10,3),
    is_regression BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_netlat_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.network_latency_tests IS 'Stores precise timing data for network requests between microservices.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 207 - dependency_conflicts
-- Description: Resolution of dependency version conflicts.
-- Business Case: Monorepo dependency hell. When two modules depend on different versions of a
-- shared library, this table tracks the resolution strategy (e.g., upgrading Module A or
-- downgrading Module B).
-- KPIs: 1. Resolution Time, 2. Conflict Recurrence Rate.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_conflicts (
    -- Primary Key
    conflict_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Conflict Details
    package_name VARCHAR(255) NOT NULL,
    version_a VARCHAR(100),
    version_b VARCHAR(100),
    requesting_module_a VARCHAR(255),
    requesting_module_b VARCHAR(255),

    -- Resolution
    resolution_strategy VARCHAR(50), -- UPGRADE_A, DOWNGRADE_B, ALIASING
    resolved_version VARCHAR(100),
    is_resolved BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dep_conflict_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.dependency_conflicts IS 'Tracks and manages version conflicts in the dependency graph.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 208 - api_contract_tests
-- Description: Consumer-Driven Contract Tests (PACT).
-- Business Case: Ensures that breaking changes in a provider service don't crash consumer
-- services (e.g., Wallet App vs Payment API). Stores the contract JSON to verify against.
-- KPIs: 1. Contract Compatibility, 2. Provider Verification Rate.
-- Feature Reference: 17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_contract_tests (
    -- Primary Key
    contract_id SERIAL PRIMARY KEY,

    -- Details
    consumer_name VARCHAR(255) NOT NULL, -- e.g., "mobile-wallet"
    provider_name VARCHAR(255) NOT NULL, -- e.g., "payment-gateway"

    -- Contract
    contract_jsonb JSONB NOT NULL, -- The PACT file content
    contract_version VARCHAR(50) NOT NULL,

    -- Verification
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP WITH TIME ZONE,
    verification_build_url TEXT,

    -- Linking
    pr_id BIGINT, -- The PR that updated the contract

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_contract_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.api_contract_tests IS 'Stores consumer-driven contracts to ensure API compatibility across services.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 209 - chaos_experiments
-- Description: Chaos Engineering experiment definitions.
-- Business Case: Proactive resilience. PARI must survive infrastructure failure. This table
-- stores definitions of chaos experiments (e.g., "Kill 10% of DB nodes") to be run in CI.
-- KPIs: 1. System Availability during Chaos, 2. MTTR in Chaos.
-- Feature Reference: 26
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.chaos_experiments (
    -- Primary Key
    experiment_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,

    -- Target
    target_service VARCHAR(255),
    target_pod_label VARCHAR(100),

    -- Fault Injection
    fault_type VARCHAR(50) NOT NULL, -- POD_KILL, LATENCY, LOSS
    magnitude INTEGER, -- e.g., 50ms delay or 10% packet loss
    duration_seconds INTEGER,

    -- Hypothesis
    hypothesis TEXT, -- "The system will return 200 OK within 500ms"

    -- Audit
    created_by BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE m23_governance.chaos_experiments IS 'Defines resilience tests by intentionally breaking infrastructure.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 210 - chaos_experiment_results
-- Description: Results of chaos runs.
-- Business Case: Validating resilience. Did the system recover automatically? If not, the PR
-- fails.
-- KPIs: 1. Recovery Time Objective (RTO) Compliance.
-- Feature Reference: 26
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.chaos_experiment_results (
    -- Primary Key
    result_id BIGSERIAL PRIMARY KEY,

    -- Linking
    experiment_id INTEGER NOT NULL,
    pr_id BIGINT NOT NULL,

    -- Execution
    status VARCHAR(20) NOT NULL, -- PASSED, FAILED, INTERRUPTED
    error_message TEXT,

    -- Metrics
    availability_pct NUMERIC(5,2), -- % of requests succeeding
    recovery_time_seconds NUMERIC(10,2),
    error_spike_count INTEGER,

    -- Audit
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_chaos_exp FOREIGN KEY (experiment_id) REFERENCES m23_governance.chaos_experiments(experiment_id),
    CONSTRAINT fk_chaos_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.chaos_experiment_results IS 'Logs the outcome of resilience testing against infrastructure faults.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 211 - schema_diff_reports
-- Description: Detailed structural diffs for DB schemas.
-- Business Case: Database governance. Visualizes exactly how a `CREATE TABLE` or `ALTER COLUMN`
-- in a PR differs from the current production schema.
-- KPIs: 1. Schema Change Detection Accuracy.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.schema_diff_reports (
    -- Primary Key
    diff_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    migration_id BIGINT,

    -- Diff Data
    diff_jsonb JSONB NOT NULL, -- Structured representation of added/removed/modified columns
    summary_text TEXT, -- Human readable summary
    is_destructive BOOLEAN DEFAULT FALSE,

    -- Audit
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_diff_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_diff_mig FOREIGN KEY (migration_id) REFERENCES m23_governance.db_migration_scripts(migration_id)
);

COMMENT ON TABLE m23_governance.schema_diff_reports IS 'Stores the structural differences between proposed and current database schemas.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 212 - cost_anomalies
-- Description: Detected cost anomalies in infrastructure.
-- Business Case: FinOps. Prevents a PR from deploying a config that accidentally spins up
-- 1000 expensive GPU nodes.
-- KPIs: 1. Cost Savings Anomaly Detection.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cost_anomalies (
    -- Primary Key
    anomaly_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Anomaly Details
    resource_type VARCHAR(50), -- COMPUTE, STORAGE, NETWORK
    estimated_monthly_cost_delta NUMERIC(15,2),
    threshold_breach_pct NUMERIC(5,2),

    -- Context
    terraform_plan_id INTEGER,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,

    CONSTRAINT fk_cost_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_cost_tf FOREIGN KEY (terraform_plan_id) REFERENCES m23_governance.terraform_plans(plan_id)
);

COMMENT ON TABLE m23_governance.cost_anomalies IS 'Flags infrastructure changes that deviate significantly from expected costs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 213 - data_lineage_checks
-- Description: Validation of data flow diagrams.
-- Business Case: Compliance (GDPR Article 30). PARI must map data flows. This table validates
-- that code changes don't violate documented data lineage (e.g., sending PII to a 3rd party).
-- KPIs: 1. Data Lineage Integrity.
-- Feature Reference: 45
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.data_lineage_checks (
    -- Primary Key
    check_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Check
    source_column VARCHAR(255),
    destination_node VARCHAR(255), -- e.g., "External_Analytics_API"
    data_classification VARCHAR(50), -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

    -- Result
    is_compliant BOOLEAN DEFAULT TRUE,
    violation_reason TEXT,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lineage_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.data_lineage_checks IS 'Verifies that data flows in code adhere to documented privacy policies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 214 - policy_as_code_results
-- Description: Results of OPA/Rego policy evaluation.
-- Business Case: Centralized Governance. Instead of writing checks in Python/Go, policies are
-- written in Rego. This table logs the result of evaluating these policies against PR assets.
-- KPIs: 1. Policy Evaluation Success Rate.
-- Feature Reference: 37
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.policy_as_code_results (
    -- Primary Key
    result_id BIGSERIAL PRIMARY KEY,

    -- Linking
    policy_id INTEGER NOT NULL,
    pr_id BIGINT NOT NULL,
    asset_path TEXT NOT NULL,

    -- Evaluation
    is_allowed BOOLEAN NOT NULL,
    deny_reason TEXT,
    policy_details_jsonb JSONB,

    -- Audit
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT_fk_policy FOREIGN KEY (policy_id) REFERENCES m23_governance.access_control_policies(policy_id),
    CONSTRAINT fk_policy_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.policy_as_code_results IS 'Stores the output of Open Policy Agent evaluations for code governance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 215 - smart_contract_abi_compatibility
-- Description: Checks ABI compatibility for smart contracts.
-- Business Case: PARI uses smart contracts for bridge/settlement. Changing an ABI breaks
-- off-chain integration. This table detects non-backwards-compatible ABI changes.
-- KPIs: 1. Contract Upgrade Safety.
-- Feature Reference: 16
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.smart_contract_abi_compatibility (
    -- Primary Key
    abi_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Contract Details
    contract_name VARCHAR(255) NOT NULL,
    network VARCHAR(50), -- MAINNET, GOERLI, POLYGON

    -- Diff
    old_abi_hash CHAR(64),
    new_abi_hash CHAR(64),
    is_compatible BOOLEAN DEFAULT TRUE,
    breaking_changes TEXT[], -- List of changed function signatures

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_abi_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.smart_contract_abi_compatibility IS 'Detects breaking changes in Smart Contract ABIs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 216 - bytecode_verification
-- Description: Solidity bytecode verification.
-- Business Case: Security. Ensures the compiled bytecode exactly matches the source code provided
-- in the PR (detects compiler bugs or modified compilers).
-- KPIs: 1. Bytecode Match Rate.
-- Feature Reference: 16
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.bytecode_verification (
    -- Primary Key
    verify_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Verification
    contract_address VARCHAR(42), -- On-chain address (0x...)
    expected_bytecode CHAR(66), -- Keccak256 hash
    actual_bytecode CHAR(66),
    compiler_version VARCHAR(50),

    -- Result
    is_verified BOOLEAN DEFAULT TRUE,
    verification_status TEXT,

    -- Audit
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bytecode_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.bytecode_verification IS 'Confirms that deployed smart contract bytecode matches the source code.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 217 - slang_linter_results
-- Description: Slang (Solidity linter) results.
-- Business Case: Smart Contract Quality. Detects vulnerabilities (Reentrancy, Overflow) before
-- deployment to mainnet.
-- KPIs: 1. Critical Vulnerability Count.
-- Feature Reference: 16
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.slang_linter_results (
    -- Primary Key
    slang_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Findings
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity VARCHAR(20),
    code VARCHAR(50), -- e.g., "SWC-107"
    message TEXT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_slang_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.slang_linter_results IS 'Security analysis results for Solidity smart contracts.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 218 - fuzzing_corpus
-- Description: Seed corpus for fuzzing.
-- Business Case: Improving fuzzing efficiency. Stores the "interesting" inputs that crashed
-- the code so they can be replayed every time to prevent regressions.
-- KPIs: 1. Corpus Coverage Growth.
-- Feature Reference: 26
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.fuzzing_corpus (
    -- Primary Key
    corpus_id BIGSERIAL PRIMARY KEY,

    -- Target
    target_function VARCHAR(255) NOT NULL,
    pr_id BIGINT, -- The PR that found this crash

    -- Data
    input_blob BYTEA NOT NULL, -- The crashing input
    crash_signal VARCHAR(50), -- SIGSEGV, SIGABRT
    stack_trace TEXT,

    -- Usage
    usage_count INTEGER DEFAULT 0,
    last_reproduced_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_corpus_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.fuzzing_corpus IS 'Repository of inputs that previously caused software crashes.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 219 - api_mock_servers
-- Description: Configuration of mock servers for testing.
-- Business Case: Dependency isolation. Allows CI to test "Wallet Service" even if "Ledger
-- Service" is down, by mocking the API responses based on stored definitions.
-- KPIs: 1. Mock Server Availability, 2. Mock Fidelity.
-- Feature Reference: 17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_mock_servers (
    -- Primary Key
    mock_id SERIAL PRIMARY KEY,

    -- Details
    name VARCHAR(255) NOT NULL,
    upstream_url TEXT, -- Real URL to record from
    mock_url TEXT, -- URL of the mock server

    -- Definition
    spec_type VARCHAR(20) DEFAULT 'OPENAPI', -- OPENAPI, GRAPHQL, PROTO
    spec_url TEXT NOT NULL, -- Path to the OpenAPI/Proto spec

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    environment VARCHAR(20) -- TEST, DEV
);

COMMENT ON TABLE m23_governance.api_mock_servers IS 'Configures virtual servers to mimic external dependencies for testing.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 220 - grpc_interop_tests
-- Description: gRPC interoperability test results.
-- Business Case: PARI uses gRPC for internal comms. Ensures that a client written in Go can
-- talk to a server written in Rust without errors.
-- KPIs: 1. Interop Test Success Rate.
-- Feature Reference: 102
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.grpc_interop_tests (
    -- Primary Key
    test_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    client_lang VARCHAR(50), -- Go, Python, Java
    server_lang VARCHAR(50), -- Rust, C++
    service_name VARCHAR(255) NOT NULL,
    method_name VARCHAR(255) NOT NULL,

    -- Result
    status VARCHAR(20) NOT NULL,
    latency_ms NUMERIC(10,3),
    error_message TEXT,

    -- Audit
    run_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_grpc_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.grpc_interop_tests IS 'Validates cross-language compatibility of gRPC services.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 221 - sql_injection_proofs
-- Description: Proof of SQL injection attempts or fixes.
-- Business Case: Security Training/Validation. Stores examples of SQLi vulnerabilities found
-- and fixed, used as training data for AI linters.
-- KPIs: 1. SQLi Vulnerability Count (Target: 0).
-- Feature Reference: 80
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sql_injection_proofs (
    -- Primary Key
    proof_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Vulnerability
    vulnerable_query TEXT NOT NULL,
    sanitized_query TEXT,
    payload_used TEXT, -- The "' OR 1=1" string
    cwe_id VARCHAR(10),

    -- Result
    is_fixed BOOLEAN DEFAULT FALSE,

    -- Audit
    found_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sqli_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.sql_injection_proofs IS 'Records SQL injection vulnerabilities and their remediation.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 222 - shadow_dom_tests
-- Description: Tests for Shadow DOM encapsulation.
-- Business Case: Web Component security. Ensures PARI's web components don't leak styles or
-- break when integrated into 3rd party bank portals.
-- KPIs: 1. Encapsulation Integrity.
-- Feature Reference: 143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.shadow_dom_tests (
    -- Primary Key
    shadow_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Details
    component_name VARCHAR(255) NOT NULL,
    host_page_url TEXT,

    -- Checks
    style_leak_detected BOOLEAN DEFAULT FALSE,
    script_access_detected BOOLEAN DEFAULT FALSE,

    -- Audit
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_shadow_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.shadow_dom_tests IS 'Verifies the isolation of Web Component Shadow DOMs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 223 - resource_hints_checks
-- Description: Checks for `preload`, `prefetch`, `preconnect`.
-- Business Case: Wallet UX optimization. Ensures critical resources (fonts, scripts) are hinted
-- to the browser for faster loading.
-- KPIs: 1. Time to Interactive (TTI).
-- Feature Reference: 143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.resource_hints_checks (
    -- Primary Key
    hint_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Missing Hints
    missing_preconnect TEXT[], -- e.g., {"https://api.pari.com"}
    missing_preload TEXT[], -- e.g., {"/fonts/main.woff2"}
    missing_dns_prefetch TEXT[],

    -- Score
    optimization_score INTEGER, -- 0-100

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hint_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.resource_hints_checks IS 'Identifies missing browser resource hints to improve load performance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 224 - intl_segmenter_tests
-- Description: Tests for Internationalization Segmenter.
-- Business Case: PARI handles multi-currency. Ensures text segmentation (word boundaries) works
-- correctly for non-Latin scripts (Japanese, Arabic).
-- KPIs: 1. Locale Coverage.
-- Feature Reference: 40
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.intl_segmenter_tests (
    -- Primary Key
    seg_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Test
    locale CHAR(5) NOT NULL, -- e.g., ja-JP
    input_text TEXT NOT NULL,
    expected_segments TEXT[] NOT NULL,
    actual_segments TEXT[],
    is_correct BOOLEAN DEFAULT FALSE,

    -- Audit
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_intl_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.intl_segmenter_tests IS 'Validates correct word/line breaking for international text.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 225 - wcag_22_compliance
-- Description: Detailed WCAG 2.2 compliance checks.
-- Business Case: Accessibility compliance. Going beyond basic a11y to meet WCAG 2.2 strict
-- criteria (focus appearance, target size).
-- KPIs: 1. WCAG 2.2 Pass Rate.
-- Feature Reference: 41
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.wcag_22_compliance (
    -- Primary Key
    check_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Criteria
    success_criterion VARCHAR(100) NOT NULL, -- e.g., "2.4.7 Focus Visible"
    level VARCHAR(10) NOT NULL, -- A, AA, AAA
    status VARCHAR(20) NOT NULL, -- PASS, FAIL, INAPPLICABLE

    -- Context
    element_selector VARCHAR(255),
    violation_description TEXT,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_wcag_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.wcag_22_compliance IS 'Detailed tracking of WCAG 2.2 accessibility criteria.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 226 - cloudevents_validation
-- Description: Validation of CloudEvents specification.
-- Business Case: Event-driven architecture. Ensures internal events (e.g., "PaymentInitiated")
-- strictly follow the CloudEvents spec (content-type, tracing headers).
-- KPIs: 1. Event Spec Compliance.
-- Feature Reference: 105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cloudevents_validation (
    -- Primary Key
    event_val_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Event
    source_url TEXT,
    event_type VARCHAR(100) NOT NULL,

    -- Checks
    has_spec_version BOOLEAN DEFAULT FALSE,
    has_id BOOLEAN DEFAULT FALSE,
    has_source BOOLEAN DEFAULT FALSE,
    has_datacontenttype BOOLEAN DEFAULT FALSE,
    has_traceparent BOOLEAN DEFAULT FALSE,

    -- Audit
    validated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ce_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.cloudevents_validation IS 'Ensures events adhere to the CloudEvents standard.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 227 - graphql_persisted_queries
-- Description: Registry of persisted queries.
-- Business Case: Performance & Security. Allowlisting specific GraphQL hashes prevents malicious
-- queries and optimizes parsing.
-- KPIs: 1. Query Cache Hit Rate.
-- Feature Reference: 100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.graphql_persisted_queries (
    -- Primary Key
    persisted_id BIGSERIAL PRIMARY KEY,

    -- Query
    query_hash CHAR(64) NOT NULL UNIQUE,
    query_text TEXT NOT NULL,
    query_name VARCHAR(255),

    -- Metadata
    version VARCHAR(50),
    created_by BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_gql_user FOREIGN KEY (created_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.graphql_persisted_queries IS 'Store of known-good GraphQL queries identified by hash.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 228 - graphql_complexity_analysis
-- Description: Complexity scoring for GraphQL queries.
-- Business Case: DoS prevention. Prevents clients from submitting nested queries (e.g.,
-- `user.friends.friends.friends...`) that crash the server.
-- KPIs: 1. Max Query Complexity Score.
-- Feature Reference: 100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.graphql_complexity_analysis (
    -- Primary Key
    analysis_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Analysis
    operation_name VARCHAR(255),
    complexity_score INTEGER NOT NULL, -- Calculated cost
    depth INTEGER,
    estimated_cost_ms NUMERIC(10,2),

    -- Threshold
    limit INTEGER,
    is_allowed BOOLEAN DEFAULT TRUE,

    -- Audit
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_gql_comp_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.graphql_complexity_analysis IS 'Analyzes GraphQL query cost to prevent denial of service.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 229 - wasm_module_checks
-- Description: Checks for WebAssembly modules.
-- Business Case: Secure sandboxing. PARI uses WASM for user-defined logic. This table validates
-- that WASM modules are well-formed and don't use forbidden imports (e.g., `fs_read`).
-- KPIs: 1. WASM Validation Success.
-- Feature Reference: 143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.wasm_module_checks (
    -- Primary Key
    wasm_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Module
    file_path TEXT NOT NULL,
    module_hash CHAR(64),

    -- Validation
    is_valid_wasm BOOLEAN DEFAULT TRUE,
    forbidden_imports TEXT[], -- List of disallowed imports found
    memory_limit_bytes INTEGER,
    stack_size_bytes INTEGER,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_wasm_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.wasm_module_checks IS 'Security validation for WebAssembly modules.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 230 - hermetic_build_checks
-- Description: Verification of hermetic builds.
-- Business Case: Reproducibility. Ensures the build environment was completely hermetic (no
-- network access, system deps), preventing supply chain attacks during build time.
-- KPIs: 1. Hermeticity Score.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.hermetic_build_checks (
    -- Primary Key
    hermetic_id BIGSERIAL PRIMARY KEY,

    -- Linking
    run_id BIGINT NOT NULL,

    -- Checks
    network_access_detected BOOLEAN DEFAULT FALSE,
    system_dependency_found TEXT[],
    environment_variable_leak TEXT[],

    -- Result
    is_hermetic BOOLEAN DEFAULT TRUE,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hermetic_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

COMMENT ON TABLE m23_governance.hermetic_build_checks IS 'Validates that builds occurred in a completely isolated environment.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 231 - reproducibility_matrix
-- Description: Matrix tracking build reproducibility.
-- Business Case: Supply chain security. Compares the binary hash produced locally vs in CI.
-- If they differ, the build is not reproducible (potential supply chain issue).
-- KPIs: 1. Reproducibility Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.reproducibility_matrix (
    -- Primary Key
    matrix_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Comparison
    source_hash CHAR(64),
    local_build_hash CHAR(64), -- Built by contributor
    ci_build_hash CHAR(64), -- Built by M23 CI

    -- Result
    is_reproducible BOOLEAN DEFAULT FALSE,
    diff_details TEXT,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_repro_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.reproducibility_matrix IS 'Tracks whether build outputs are identical across environments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 232 - code_ownership_analytics
-- Description: Advanced ownership analysis beyond CODEOWNERS.
-- Business Case: Dynamically calculating ownership based on git blame frequency. Helps identify
-- "bus factor" risks.
-- KPIs: 1. Ownership Entropy, 2. Bus Factor.
-- Feature Reference: 64
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_ownership_analytics (
    -- Primary Key
    analytic_id BIGSERIAL PRIMARY KEY,

    -- Target
    file_path TEXT NOT NULL,
    contributor_id BIGINT NOT NULL,

    -- Metrics
    lines_owned INTEGER,
    ownership_pct NUMERIC(5,2), -- Percentage of file owned
    last_commit_date DATE,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_own_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_own_file ON m23_governance.code_ownership_analytics(file_path);
COMMENT ON TABLE m23_governance.code_ownership_analytics IS 'Statistical analysis of code ownership based on commit history.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 233 - semantic_search_index
-- Description: Vector embeddings for semantic code search.
-- Business Case: Advanced discoverability. Instead of grep, allows developers to search "how
-- do I verify a signature?" and find relevant code snippets using embeddings.
-- KPIs: 1. Search Relevance (NDCG), 2. Index Size.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.semantic_search_index (
    -- Primary Key
    search_id BIGSERIAL PRIMARY KEY,

    -- Data
    file_path TEXT NOT NULL,
    function_name VARCHAR(255),
    code_snippet TEXT NOT NULL,

    -- Vector
    embedding_vector vector(1536), -- Assumes OpenAI ada-002 or similar

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_semantic_vector ON m23_governance.semantic_search_index USING ivfflat (embedding_vector vector_cosine_ops);
COMMENT ON TABLE m23_governance.semantic_search_index IS 'Stores vector embeddings for AI-powered semantic code search.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 234 - cross_compilation_tests
-- Description: Results of cross-platform builds.
-- Business Case: PARI must run on Linux, Windows, and embedded devices. Ensures a commit
-- builds correctly for all target architectures (x64, ARM).
-- KPIs: 1. Cross-Platform Success Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cross_compilation_tests (
    -- Primary Key
    xcomp_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Build
    target_arch VARCHAR(50) NOT NULL, -- linux-amd64, windows-arm64
    target_os VARCHAR(50) NOT NULL,
    cc_compiler VARCHAR(100),

    -- Result
    status VARCHAR(20) NOT NULL, -- SUCCESS, FAILURE
    binary_size_bytes BIGINT,
    compile_time_sec INTEGER,

    -- Audit
    compiled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_xcomp_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.cross_compilation_tests IS 'Tracks build success across different operating systems and architectures.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 235 - dependency_confidence_scores
-- Description: Health score of dependencies.
-- Business Case: Supply chain risk assessment. Combines metrics like "last commit date",
-- "open issues", "maintainer count" into a single score to auto-reject risky libs.
-- KPIs: 1. Mean Dependency Confidence.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_confidence_scores (
    -- Primary Key
    score_id BIGSERIAL PRIMARY KEY,

    -- Dependency
    package_name VARCHAR(255) NOT NULL,
    package_manager VARCHAR(50) NOT NULL,
    version VARCHAR(100),

    -- Metrics
    score NUMERIC(3,2) CHECK (score BETWEEN 0 AND 1), -- 0.0 (Risky) to 1.0 (Safe)
    last_commit_days_ago INTEGER,
    open_issue_count INTEGER,
    maintainer_count INTEGER,
    download_volume_rank INTEGER,

    -- Status
    is_threshold_met BOOLEAN DEFAULT TRUE,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.dependency_confidence_scores IS 'Algorithmic assessment of open-source library reliability.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 236 - api_deprecation_audit
-- Description: Audit of API deprecation adherence.
-- Business Case: Lifecycle management. Tracks if deprecated APIs are still being used in new PRs,
-- which should be blocked.
-- KPIs: 1. Deprecated API Usage (Target: 0).
-- Feature Reference: 61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_deprecation_audit (
    -- Primary Key
    audit_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Violation
    deprecated_endpoint VARCHAR(255) NOT NULL,
    replacement_endpoint VARCHAR(255),
    line_number INTEGER,
    file_path TEXT,

    -- Context
    severity VARCHAR(20), -- ERROR, WARNING
    removal_deadline DATE,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_deprec_audit_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.api_deprecation_audit IS 'Detects usage of deprecated APIs in new code.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 237 - configuration_drift_detection
-- Description: Detects drift between environments.
-- Business Case: Environment Parity. Compares Terraform/K8s state in Dev vs Staging. Drift
-- leads to "it works on my machine" bugs.
-- KPIs: 1. Configuration Drift Count.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.configuration_drift_detection (
    -- Primary Key
    drift_id BIGSERIAL PRIMARY KEY,

    -- Context
    resource_id VARCHAR(255) NOT NULL, -- aws_instance.web-1
    env_a VARCHAR(50) NOT NULL, -- staging
    env_b VARCHAR(50) NOT NULL, -- prod

    -- Diff
    attribute_changed VARCHAR(100), -- instance_type
    value_a TEXT,
    value_b TEXT,

    -- Severity
    risk_level VARCHAR(20), -- HIGH, LOW

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.configuration_drift_detection IS 'Identifies configuration inconsistencies between deployment environments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 238 - secret_rotation_schedule
-- Description: Schedule for rotating secrets.
-- Business Case: Least Privilege/Automated Security. Ensures secrets (DB passwords, API keys)
-- are rotated every N days.
-- KPIs: 1. Secret Rotation Compliance.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.secret_rotation_schedule (
    -- Primary Key
    schedule_id SERIAL PRIMARY KEY,

    -- Secret
    secret_identifier VARCHAR(255) NOT NULL UNIQUE,
    secret_type VARCHAR(50), -- DB_PASSWORD, API_KEY
    environment VARCHAR(20), -- PROD, STAGING

    -- Schedule
    rotation_frequency_days INTEGER NOT NULL,
    last_rotated_at TIMESTAMP WITH TIME ZONE,
    next_rotation_at TIMESTAMP WITH TIME ZONE NOT NULL,
    auto_rotate_enabled BOOLEAN DEFAULT FALSE,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, ROTATED, FAILED
    rotation_message TEXT
);

COMMENT ON TABLE m23_governance.secret_rotation_schedule IS 'Automates the lifecycle management of sensitive credentials.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 239 - git_object_integrity
-- Description: Verification of git object integrity.
-- Business Case: Anti-tampering. Periodically checks that the git objects in the database
-- match the hash of the object in the actual git object store.
-- KPIs: 1. Object Mismatch Count.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.git_object_integrity (
    -- Primary Key
    object_id BIGSERIAL PRIMARY KEY,

    -- Git Object
    object_type VARCHAR(20) NOT NULL, -- BLOB, TREE, COMMIT, TAG
    object_hash CHAR(40) NOT NULL,

    -- Integrity
    database_hash CHAR(40), -- Hash derived from stored content
    is_valid BOOLEAN DEFAULT TRUE,
    corruption_reason TEXT,

    -- Audit
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.git_object_integrity IS 'Detects bit-rot or tampering in the stored git object database.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 240 - license_text_similarity
-- Description: Similarity checks for license headers.
-- Business Case: License Compliance. Detects if a source file has a license header that is
-- suspiciously similar to an incompatible one (e.g., GPL text instead of MIT).
-- KPIs: 1. Header Anomaly Detection Rate.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.license_text_similarity (
    -- Primary Key
    similarity_id BIGSERIAL PRIMARY KEY,

    -- Context
    file_path TEXT NOT NULL,
    detected_license_id INTEGER,
    header_text TEXT,

    -- Analysis
    similarity_score NUMERIC(3,2) CHECK (similarity_score BETWEEN 0 AND 1),
    expected_license_id INTEGER, -- From approved_licenses
    is_mismatch BOOLEAN DEFAULT TRUE,

    -- Audit
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lic_sim_det FOREIGN KEY (detected_license_id) REFERENCES m23_governance.approved_licenses(license_id),
    CONSTRAINT fk_lic_sim_exp FOREIGN KEY (expected_license_id) REFERENCES m23_governance.approved_licenses(license_id)
);

COMMENT ON TABLE m23_governance.license_text_similarity IS 'Checks file headers for potentially incompatible license text.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 241 - supply_chain_ownership
-- Description: Ownership of upstream dependencies.
-- Business Case: Risk Assessment. Who maintains the libs you use? If a critical crypto lib
-- is maintained by one person who quit, that's a risk.
-- KPIs: 1. Maintainers Count.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.supply_chain_ownership (
    -- Primary Key
    ownership_id SERIAL PRIMARY KEY,

    -- Dependency
    dependency_id BIGINT NOT NULL,

    -- Owner
    maintainer_login VARCHAR(255) NOT NULL,
    is_organizations BOOLEAN DEFAULT FALSE,
    organization_name VARCHAR(255),

    -- Impact
    commit_count INTEGER,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_own_dep FOREIGN KEY (dependency_id) REFERENCES m23_governance.sca_dependencies(dep_id)
);

COMMENT ON TABLE m23_governance.supply_chain_ownership IS 'Profiles the maintainers of upstream dependencies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 242 - semantic_version_conflicts
-- Description: Logic checks for SemVer.
-- Business Case: Dependency Resolution. Detects situations where a dependency requires
-- `lib >= 2.0` but another requires `lib < 2.0`, which is impossible to satisfy.
-- KPIs: 1. Resolution Success Rate.
-- Feature Reference: 12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.semantic_version_conflicts (
    -- Primary Key
    conflict_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Conflict
    package_name VARCHAR(255) NOT NULL,
    constraint_a TEXT NOT NULL, -- ">= 2.0"
    constraint_b TEXT NOT NULL, -- "< 2.0"
    requesting_modules TEXT[],

    -- Result
    is_resolvable BOOLEAN DEFAULT FALSE,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_semver_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.semantic_version_conflicts IS 'Detects mathematically impossible version requirement sets.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 243 - telemetry_compliance
-- Description: Checks for telemetry data leaks.
-- Business Case: Privacy. PARI deals with financial data. Ensures that code does not send
-- telemetry containing PII to external vendors (Google Analytics, etc.) without consent.
-- KPIs: 1. Privacy Violation Count.
-- Feature Reference: 45
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.telemetry_compliance (
    -- Primary Key
    telemetry_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Check
    vendor_name VARCHAR(100), -- google, mixpanel, segment
    code_snippet TEXT,

    -- Violation
    pii_detected BOOLEAN DEFAULT FALSE, -- True if email, name, card number found
    detected_pii_type TEXT[], -- {email, phone, ip}

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tele_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.telemetry_compliance IS 'Detects accidental transmission of PII in telemetry libraries.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 244 - binary_diff
-- Description: Diff of compiled binaries.
-- Business Case: Zero-trust verification. Even if source code looks good, the compiler could
-- be hacked. Compares binary diffs.
-- KPIs: 1. Binary Anomaly Detection.
-- Feature Reference: 58
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.binary_diff (
    -- Primary Key
    bdiff_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    artifact_id BIGINT NOT NULL,

    -- Analysis
    binary_name VARCHAR(255) NOT NULL,
    diff_summary TEXT,
    added_bytes INTEGER,
    removed_bytes INTEGER,

    -- Risk
    suspicious_sections TEXT[], -- e.g., {".init", ".text"}

    -- Audit
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bdiff_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_bdiff_artifact FOREIGN KEY (artifact_id) REFERENCES m23_governance.build_artifacts(artifact_id)
);

COMMENT ON TABLE m23_governance.binary_diff IS 'Analyzes differences in compiled artifacts for anomalies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 245 - test_flakiness_detection
-- Description: Statistical detection of flaky tests.
-- Business Case: CI Reliability. A test that fails 10% of the time randomly destroys trust
-- in the CI gate. This table tracks test reliability over time.
-- KPIs: 1. Flaky Test Percentage.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.test_flakiness_detection (
    -- Primary Key
    flake_id BIGSERIAL PRIMARY KEY,

    -- Test
    test_name VARCHAR(500) NOT NULL,
    file_path TEXT NOT NULL,

    -- Metrics
    total_runs INTEGER,
    fail_count INTEGER,
    flake_rate NUMERIC(5,2), -- 0.00 to 1.00

    -- Status
    is_quarantined BOOLEAN DEFAULT FALSE,
    last_failure_reason TEXT,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.test_flakiness_detection IS 'Statistical tracking of test reliability to identify flaky tests.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 246 - git_worktree_management
-- Description: Management of git worktrees.
-- Business Case: CI Optimization. Using git worktrees allows parallel CI jobs on the same repo
-- without cloning multiple times.
-- KPIs: 1. Disk Space Savings, 2. Clone Time Reduction.
-- Feature Reference: 89
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.git_worktree_management (
    -- Primary Key
    worktree_id BIGSERIAL PRIMARY KEY,

    -- Details
    base_commit_sha CHAR(40) NOT NULL,
    worktree_path TEXT NOT NULL,
    branch_name VARCHAR(255),

    -- Status
    is_locked BOOLEAN DEFAULT FALSE, -- In use by a job
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    pruned_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE m23_governance.git_worktree_management IS 'Manages lightweight checkouts for parallel CI processing.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 247 - subresource_integrity_cache
-- Description: Cache for SRI hashes.
-- Business Case: Supply Chain Security. Stores the SHA-384 hashes of JS libraries loaded by the
-- web wallet to ensure they haven't been tampered with (subresource integrity).
-- KPIs: 1. SRI Cache Hit Rate.
-- Feature Reference: 140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.subresource_integrity_cache (
    -- Primary Key
    sri_id BIGSERIAL PRIMARY KEY,

    -- Resource
    resource_url TEXT NOT NULL,
    algorithm VARCHAR(10) DEFAULT 'sha384', -- sha256, sha384, sha512

    -- Hash
    integrity_hash CHAR(128) NOT NULL,
    cross_origin VARCHAR(50),

    -- Status
    is_valid BOOLEAN DEFAULT TRUE,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.subresource_integrity_cache IS 'Stores cryptographic hashes of external scripts for Subresource Integrity checks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 248 - web_worker_tasks
-- Description: Tasks executed by Web Workers.
-- Business Case: UI Performance. Heavy computations in the wallet (crypto, signing) run in
-- Web Workers. This table validates the worker scripts.
-- KPIs: 1. Worker Initialization Time.
-- Feature Reference: 143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.web_worker_tasks (
    -- Primary Key
    task_id SERIAL PRIMARY KEY,

    -- Script
    worker_name VARCHAR(255) NOT NULL,
    script_path TEXT NOT NULL,

    -- Validation
    has_dom_access BOOLEAN DEFAULT FALSE, -- Should be false
    chunk_size_kb INTEGER, -- Optimal transfer size

    -- Audit
    validated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.web_worker_tasks IS 'Validates scripts intended for execution in Web Worker threads.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 249 - http_archive_validations
-- Description: Validation of http_archive rules (Bazel).
-- Business Case: Monorepo build tooling. Ensures that external dependencies fetched via http_archive
-- are pinned and verified (shas256).
-- KPIs: 1. Http Archive Integrity.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.http_archive_validations (
    -- Primary Key
    archive_id BIGSERIAL PRIMARY KEY,

    -- Archive
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    strip_prefix TEXT,

    -- Integrity
    expected_sha256 CHAR(64) NOT NULL,
    actual_sha256 CHAR(64),
    is_match BOOLEAN DEFAULT TRUE,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.http_archive_validations IS 'Verifies the integrity of Bazel http_archive dependencies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 250 - critical_path_analysis
-- Description: Analysis of critical dependency paths.
-- Business Case: Risk Management. Identifies which libraries are "single points of failure"
-- (used by 100% of the codebase).
-- KPIs: 1. Critical Dependency Count.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.critical_path_analysis (
    -- Primary Key
    analysis_id BIGSERIAL PRIMARY KEY,

    -- Dependency
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,

    -- Impact
    dependency_depth INTEGER,
    usage_percentage NUMERIC(5,2), -- % of codebase using this
    is_transitive BOOLEAN DEFAULT TRUE,

    -- Risk
    risk_score INTEGER CHECK (risk_score BETWEEN 1 AND 10),

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.critical_path_analysis IS 'Identifies dependencies that, if removed, would break the entire project.';

-- ==========================================================================================================
-- End of Part 5 (Tables 201-250)
-- Total Database Objects Created: 250
-- ==========================================================================================================

-- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 6: Extended Database Objects Tables 251-350
-- ==========================================================================================================
-- Description:
-- This script extends the M23 schema with Tables 251-350. This segment focuses on advanced
-- operational security (Secrets Scanning, Leak Prevention), detailed Analytics & Reporting
-- for governance health, Cloud Infrastructure Governance (AWS/Azure specific), and Deep Learning
-- operations (MLOps) for AI-assisted code review.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Implementation of RLS (Row Level Security) where applicable.
-- 6. Automated timestamp management via triggers.
-- 7. Strategic indexing for performance optimization.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 251 - secrets_scanner_baseline
-- Description: Baseline of known secrets for whitelisting.
-- Business Case: False Positive Reduction. In a financial codebase, dummy keys (e.g., "0000-0000-...")
-- are often used for testing. This table stores these known "safe" secrets so the scanner doesn't flag
-- them as critical incidents every time.
-- KPIs: 1. False Positive Rate Reduction, 2. Incident Fatigue Reduction.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.secrets_scanner_baseline (
    -- Primary Key
    baseline_id BIGSERIAL PRIMARY KEY,

    -- Secret Details
    secret_hash CHAR(64) NOT NULL UNIQUE,
    secret_type VARCHAR(50) NOT NULL, -- AWS_KEY, GENERIC_PASSWORD
    file_path TEXT NOT NULL,
    repository_id INTEGER, -- NULL implies global

    -- Whitelist Details
    owner_id BIGINT, -- Who approved this whitelist entry
    justification TEXT NOT NULL, -- e.g., "Test vector for unit tests"
    expiry_date DATE, -- Temporary whitelists

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    CONSTRAINT fk_secret_owner FOREIGN KEY (owner_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.secrets_scanner_baseline IS 'Stores known-good secrets to prevent scanner noise for test vectors.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 252 - leaked_credentials_report
-- Description: Report of credentials leaked in public repos.
-- Business Case: Brand Protection & Security. Automated scans of public forks or mirror repos
-- to detect if a contributor accidentally pushed credentials to a public fork. Triggers
-- immediate revocation workflows.
-- KPIs: 1. Leak Detection Time (MTTD), 2. Credential Revocation Success Rate.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.leaked_credentials_report (
    -- Primary Key
    leak_id BIGSERIAL PRIMARY KEY,

    -- Source
    source_url TEXT NOT NULL, -- GitHub URL
    fork_id BIGINT,

    -- Credential
    credential_type VARCHAR(50) NOT NULL,
    signature_hash CHAR(64), -- Fingerprint to match against internal secrets
    exposure_detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Response
    status VARCHAR(20) DEFAULT 'DETECTED', -- DETECTED, REVOKING, REVOKED, IGNORED
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by BIGINT,
    incident_ticket_id VARCHAR(100), -- Link to Jira/ServiceNow

    -- Constraints
    CONSTRAINT fk_leak_fork FOREIGN KEY (fork_id) REFERENCES m23_governance.forks(fork_id)
);

CREATE INDEX idx_leak_hash ON m23_governance.leaked_credentials_report(signature_hash);
COMMENT ON TABLE m23_governance.leaked_credentials_report IS 'Tracks exposed secrets found in public repositories for immediate remediation.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 253 - anomaly_detection_logs
-- Description: ML-based anomaly detection logs.
-- Business Case: Proactive Threat Hunting. Using unsupervised learning on CI logs and API usage
-- to detect "weird" behavior that signature-based scanners miss (e.g., a PR that changes 100
-- unrelated files at 3 AM).
-- KPIs: 1. Anomaly Detection Accuracy, 2. False Positive Rate.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.anomaly_detection_logs (
    -- Primary Key
    anomaly_id BIGSERIAL PRIMARY KEY,

    -- Context
    target_type VARCHAR(50) NOT NULL, -- PR, BUILD_RUN, USER_SESSION
    target_id BIGINT NOT NULL,

    -- Detection
    model_version VARCHAR(50) NOT NULL,
    anomaly_score NUMERIC(5,2) CHECK (anomaly_score BETWEEN 0 AND 1), -- 0 = normal, 1 = highly anomalous
    anomaly_type VARCHAR(100) NOT NULL, -- e.g., "Unusual File Access", "Burst Activity"

    -- Details
    features_jsonb JSONB, -- The vector of features that caused the score
    is_threat BOOLEAN DEFAULT FALSE,
    reviewed_by BIGINT,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_anomaly_score ON m23_governance.anomaly_detection_logs(anomaly_score DESC);
COMMENT ON TABLE m23_governance.anomaly_detection_logs IS 'Stores outputs from machine learning models identifying suspicious patterns.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 254 - pr_lifecycle_history
-- Description: Complete state transition history for PRs.
-- Business Case: Detailed Auditing. While `pull_requests` has the current state, this table
-- tracks every state change (OPEN -> REVIEW -> CHANGES_REQUESTED -> APPROVED) with timestamps
-- for precise SLA analysis.
-- KPIs: 1. State Transition Frequency, 2. Cycle Time Variance.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.pr_lifecycle_history (
    -- Primary Key
    history_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Transition
    from_state m23_governance.pr_state,
    to_state m23_governance.pr_state NOT NULL,

    -- Actor
    actor_id BIGINT,
    actor_type VARCHAR(20) DEFAULT 'USER', -- USER, BOT, SYSTEM

    -- Timing
    transitioned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_lifecycle_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_lifecycle_pr ON m23_governance.pr_lifecycle_history(pr_id, transitioned_at DESC);
COMMENT ON TABLE m23_governance.pr_lifecycle_history IS 'Immutable audit trail of state changes for Pull Requests.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 255 - reviewer_calibration
-- Description: Calibration of reviewer strictness.
-- Business Case: Process Optimization. Different reviewers have different thresholds. This table
-- tracks if "Reviewer A" usually approves what "Reviewer B" rejects, identifying calibration
-- issues or politics.
-- KPIs: 1. Review Consistency Score, 2. Reviewer Bias Variance.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.reviewer_calibration (
    -- Primary Key
    calibration_id BIGSERIAL PRIMARY KEY,

    -- Event
    pr_id BIGINT NOT NULL,
    reviewer_id BIGINT NOT NULL,

    -- Metrics
    review_decision VARCHAR(20) NOT NULL, -- APPROVED, REJECTED, CHANGES_REQUESTED
    consensus_decision VARCHAR(20), -- What the majority did
    code_complexity_score INTEGER,
    pr_author_reputation NUMERIC(5,2),

    -- Analysis
    is_outlier BOOLEAN DEFAULT FALSE, -- True if decision differed significantly from average
    delta_score NUMERIC(5,2),

    -- Audit
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_calib_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_calib_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.reviewer_calibration IS 'Analyzes reviewer behavior to ensure consistent quality standards.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 256 - contributor_retention_cohorts
-- Description: Cohort analysis for contributor retention.
-- Business Case: Community Health. Groups contributors by the month they joined and tracks
-- if they are still active in month 1, month 2, month 3. Essential for measuring onboarding success.
-- KPIs: 1. Month 1 Retention Rate, 2. Month 3 Retention Rate.
-- Feature Reference: 15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_retention_cohorts (
    -- Composite Primary Key
    cohort_month DATE NOT NULL,
    contributor_id BIGINT NOT NULL,

    -- Tracking
    is_active_month_1 BOOLEAN DEFAULT FALSE,
    is_active_month_2 BOOLEAN DEFAULT FALSE,
    is_active_month_3 BOOLEAN DEFAULT FALSE,
    is_active_month_6 BOOLEAN DEFAULT FALSE,
    is_active_month_12 BOOLEAN DEFAULT FALSE,

    -- Audit
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_retention UNIQUE (cohort_month, contributor_id),
    CONSTRAINT fk_ret_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.contributor_retention_cohorts IS 'Tracks long-term engagement of contributors grouped by start date.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 257 - code_review_ai_suggestions
-- Description: AI-generated code review suggestions.
-- Business Case: Automated Assistance. Stores suggestions from Large Language Models (LLMs)
-- (e.g., "Refactor this to use async/await") to assist human reviewers.
-- KPIs: 1. Suggestion Acceptance Rate, 2. False Suggestion Rate.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_review_ai_suggestions (
    -- Primary Key
    suggestion_id BIGSERIAL PRIMARY KEY,

    -- Context
    pr_id BIGINT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,

    -- Suggestion
    suggestion_text TEXT NOT NULL,
    confidence_score NUMERIC(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    category VARCHAR(50), -- PERFORMANCE, SECURITY, STYLE

    -- Interaction
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, ACCEPTED, REJECTED, DISMISSED
    human_reviewer_id BIGINT,
    feedback_text TEXT, -- Why did human reject it?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ai_sugg_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_ai_sugg_reviewer FOREIGN KEY (human_reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.code_review_ai_suggestions IS 'Stores machine-generated recommendations for code improvements.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 258 - aws_iam_role_templates
-- Description: Templates for IAM roles in AWS.
-- Business Case: Cloud Security Governance. Defines approved IAM role templates (e.g., "LambdaExecRole")
-- that CI can assume, ensuring strict adherence to least privilege.
-- KPIs: 1. Template Adherence Rate.
-- Feature Reference: 116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.aws_iam_role_templates (
    -- Primary Key
    template_id SERIAL PRIMARY KEY,

    -- Template Definition
    template_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    trust_policy_json JSONB NOT NULL, -- The AssumeRolePolicyDocument
    permissions_policy_json JSONB, -- The standard managed policy to attach
    max_session_duration_seconds INTEGER DEFAULT 3600

    -- Audit
    ,created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.aws_iam_role_templates IS 'Pre-verified AWS IAM role definitions for secure cloud deployments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 259 - azure_policy_assignments
-- Description: Azure Policy assignments tracking.
-- Business Case: Regulatory Compliance on Azure. Ensures that resources deployed in Azure
-- (e.g., SQL Databases) comply with corporate policies (e.g., "Must have TDE enabled").
-- KPIs: 1. Policy Compliance Rate, 2. Non-compliant Resource Count.
-- Feature Reference: 116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.azure_policy_assignments (
    -- Primary Key
    assignment_id SERIAL PRIMARY KEY,

    -- Assignment
    policy_name VARCHAR(255) NOT NULL,
    assignment_scope VARCHAR(255) NOT NULL, -- /subscriptions/.../resourceGroups/...
    enforcement_mode VARCHAR(20) DEFAULT 'Default', -- Default, DoNotEnforce

    -- Effect
    effect VARCHAR(50) NOT NULL, -- Append, Audit, Deny, DeployIfNotExists

    -- Parameters
    parameters_json JSONB,

    -- Audit
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.azure_policy_assignments IS 'Tracks governance policies applied to Azure cloud resources.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 260 - cloud_asset_inventory
-- Description: Comprehensive inventory of cloud assets.
-- Business Case: Asset Management & Security. A continuously updated CMDB (Configuration Management
-- Database) of all cloud resources (EC2, S3, Lambda) linked to the PR/Terraform that created them.
-- KPIs: 1. Asset Discovery Rate, 2. Orphaned Asset Count.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cloud_asset_inventory (
    -- Primary Key
    asset_id BIGSERIAL PRIMARY KEY,

    -- Asset Identity
    cloud_provider VARCHAR(20) NOT NULL, -- AWS, AZURE, GCP
    resource_type VARCHAR(50) NOT NULL, -- AWS::EC2::Instance
    resource_id VARCHAR(255) NOT NULL UNIQUE, -- ARN or Resource ID
    name VARCHAR(255),

    -- Origin
    created_by_pr_id BIGINT,
    terraform_state_file TEXT,

    -- Status
    state VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, TERMINATED, ORPHANED
    lifecycle_state VARCHAR(50), -- managed, unmanaged

    -- Cost/Compliance
    cost_center VARCHAR(50),
    compliance_tags JSONB,

    -- Audit
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_inv_pr FOREIGN KEY (created_by_pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

CREATE INDEX idx_asset_provider_type ON m23_governance.cloud_asset_inventory(cloud_provider, resource_type);
COMMENT ON TABLE m23_governance.cloud_asset_inventory IS 'CMDB tracking all cloud resources linked to their source code origin.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 261 - network_traffic_analysis
-- Description: Analysis of network flows between services.
-- Business Case: Microservices Governance. Uses NetFlow/IPFIX data to verify that services
-- are only talking to authorized partners (East-West traffic).
-- KPIs: 1. Unauthorized Connection Attempts, 2. Network Latency P95.
-- Feature Reference: 129
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.network_traffic_analysis (
    -- Primary Key
    flow_id BIGSERIAL PRIMARY KEY,

    -- Traffic
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10), -- TCP, UDP

    -- Context
    service_name VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    bytes_transferred BIGINT,
    duration_ms INTEGER,

    -- Analysis
    is_allowed BOOLEAN,
    policy_action VARCHAR(20) -- ALLOW, DENY, ALERT
);

COMMENT ON TABLE m23_governance.network_traffic_analysis IS 'Logs network flows for security policy validation.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 262 - dns_security_records
-- Description: Audit of DNS security records (DNSSEC, SPF, DMARC).
-- Business Case: Brand & Email Security. Ensures that PARI's DNS records are properly configured
-- to prevent phishing (DMARC) and ensure integrity (DNSSEC).
-- KPIs: 1. DNS Health Score, 2. SPF/DMARC Compliance.
-- Feature Reference: 113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dns_security_records (
    -- Primary Key
    record_id SERIAL PRIMARY KEY,

    -- Domain
    domain_name VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL, -- TXT, CNAME, A, AAAA

    -- Record Data
    record_value TEXT NOT NULL,
    ttl INTEGER,

    -- Security
    is_secure BOOLEAN DEFAULT TRUE, -- Validated by DNSSEC?
    dkim_selector VARCHAR(100),
    spf_policy VARCHAR(20),
    dmarc_policy VARCHAR(20),

    -- Audit
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.dns_security_records IS 'Audits DNS records to prevent spoofing and phishing.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 263 - certificate_transparency_monitor
-- Description: Monitoring of Certificate Transparency logs.
-- Business Case: Detecting MitM attacks. Monitors public CT logs for certificates issued to
-- `*.pari.net` that weren't issued by the authorized CA. Indicates compromise.
-- KPIs: 1. Rogue Certificate Detection Time.
-- Feature Reference: 120
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.certificate_transparency_monitor (
    -- Primary Key
    cert_id BIGSERIAL PRIMARY KEY,

    -- Certificate
    cert_fingerprint CHAR(64) NOT NULL,
    issuer_name VARCHAR(255),
    subject_name VARCHAR(255),
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Detection
    ct_log_url TEXT,
    logged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_authorized BOOLEAN DEFAULT FALSE, -- Was this issued by our CA?

    -- Response
    incident_status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CLOSED
    detected_by VARCHAR(50) -- "CT_Monitor_Bot"
);

COMMENT ON TABLE m23_governance.certificate_transparency_monitor IS 'Detects unauthorized SSL/TLS certificates issued for PARI domains.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 264 - supply_chain_tiers
-- Description: Categorization of dependency tiers.
-- Business Case: Risk Scoping. Classifies dependencies into Direct, Indirect, Transitive
-- to focus security reviews on the most critical (Direct) tier.
-- KPIs: 1. Direct Dependency Count, 2. Transitive Dependency Growth Rate.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.supply_chain_tiers (
    -- Primary Key
    tier_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,

    -- Tier
    tier_level INTEGER NOT NULL, -- 1 = Direct, 2 = Indirect, 3 = Transitive
    dependency_path TEXT[], -- The chain of packages leading here

    -- Risk
    is_cve_affected BOOLEAN DEFAULT FALSE,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tier_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.supply_chain_tiers IS 'Maps the depth of dependencies to identify transitive risks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 265 - automated_security_tests
-- Description: Configuration for automated security scanners.
-- Business Case: DevSecOps Orchestration. Defines *what* runs, *when*, and on *what* branches
-- for security tools (SAST, DAST, SCA).
-- KPIs: 1. Scanner Coverage, 2. False Positive Adjustment Rate.
-- Feature Reference: 4
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.automated_security_tests (
    -- Primary Key
    test_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(255) NOT NULL,
    tool_type VARCHAR(50) NOT NULL, -- SAST, DAST, SCA, CONTAINER_SCAN
    image_name TEXT, -- Docker image of the scanner
    command_args TEXT, -- CLI arguments

    -- Trigger
    trigger_on_branch_pattern VARCHAR(255), -- e.g., "*/main"
    trigger_on_paths TEXT[], -- Only run on changes to these paths

    -- Settings
    fail_on_severity VARCHAR(20), -- CRITICAL, HIGH, MEDIUM
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.automated_security_tests IS 'Configuration for DevSecOps automated scanning pipelines.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 266 - dast_scan_results
-- Description: Results of Dynamic Application Security Testing.
-- Business Case: Runtime Security. Attacks a running instance of the application (e.g., from ZAP)
-- to find vulnerabilities that static analysis misses (authentication bypass, runtime errors).
-- KPIs: 1. Critical Runtime Vulnerability Count.
-- Feature Reference: 4
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dast_scan_results (
    -- Primary Key
    scan_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT,
    env_url TEXT, -- The URL that was scanned

    -- Scan Details
    scanner_name VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP WITH TIME ZONE,

    -- Findings
    total_alerts INTEGER DEFAULT 0,
    high_risk_alerts INTEGER DEFAULT 0,
    findings_jsonb JSONB,

    -- Constraints
    CONSTRAINT fk_dast_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.dast_scan_results IS 'Stores findings from black-box security scans of running applications.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 267 - dependency_licensing_obligations
-- Description: Tracking of legal obligations (Copyleft).
-- Business Case: Legal Compliance. When using a copyleft license (GPL), you might be legally
-- obligated to open source *your* code. This table tracks these obligations triggered by dependencies.
-- KPIs: 1. License Obligation Coverage, 2. Legal Risk Score.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_licensing_obligations (
    -- Primary Key
    obligation_id BIGSERIAL PRIMARY KEY,

    -- Context
    dependency_id BIGINT NOT NULL,
    license_id INTEGER NOT NULL,

    -- Obligation
    obligation_type VARCHAR(50) NOT NULL, -- DISCLOSE_SOURCE, PROVIDE_COPYRIGHT, SHARE_ALIKE
    obligation_text TEXT,
    is_triggered BOOLEAN DEFAULT FALSE, -- Did this PR actually trigger the obligation?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lic_dep FOREIGN KEY (dependency_id) REFERENCES m23_governance.sca_dependencies(dep_id),
    CONSTRAINT fk_lic_license FOREIGN KEY (license_id) REFERENCES m23_governance.approved_licenses(license_id)
);

COMMENT ON TABLE m23_governance.dependency_licensing_obligations IS 'Tracks legal requirements imposed by open source licenses.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 268 - vulnerability_exploit_intelligence
-- Description: Intelligence on known exploits (KEV).
-- Business Case: Prioritization. Knowing a CVE exists is one thing; knowing there is a weaponized
-- exploit (e.g., in Metasploit) bumps the priority to "Fix Immediately".
-- KPIs: 1. Exploit Awareness Rate.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.vulnerability_exploit_intelligence (
    -- Primary Key
    intel_id SERIAL PRIMARY KEY,

    -- CVE
    cve_id VARCHAR(20) NOT NULL UNIQUE,

    -- Exploit
    exploit_source VARCHAR(100), -- CISA_KEV, METASPLOIT, GITHUB_POC
    exploit_url TEXT,
    is_active_threat BOOLEAN DEFAULT TRUE,

    -- Impact
    known_ransomware_use BOOLEAN DEFAULT FALSE,

    -- Audit
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.vulnerability_exploit_intelligence IS 'Enriches CVE data with active exploit information.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 269 - governance_metrics_daily
-- Description: High-level daily governance metrics.
-- Business Case: Executive Dashboards. A rollup table showing the "health" of the FOSS
-- community (Activity, Quality, Security) at a glance.
-- KPIs: 1. Daily Merge Rate, 2. Avg Time to Review, 3. Active User Count.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.governance_metrics_daily (
    -- Composite Primary Key
    metric_date DATE PRIMARY KEY,

    -- Activity
    total_prs_opened INTEGER DEFAULT 0,
    total_prs_merged INTEGER DEFAULT 0,
    total_commits INTEGER DEFAULT 0,

    -- Quality
    pr_merge_success_rate NUMERIC(5,2), -- % of PRs that passed CI
    avg_time_to_merge_hours NUMERIC(10,2),
    critical_bugs_found INTEGER DEFAULT 0,

    -- Security
    vulnerabilities_auto_closed INTEGER DEFAULT 0,
    secrets_detected INTEGER DEFAULT 0,

    -- Community
    new_contributors INTEGER DEFAULT 0,
    active_contributors INTEGER DEFAULT 0
);

COMMENT ON TABLE m23_governance.governance_metrics_daily IS 'Daily rollup of community and quality health indicators.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 270 - ml_model_registry
-- Description: Registry for ML models used in governance.
-- Business Case: MLOps. Tracks versions of models used for code review AI, sentiment analysis,
-- or anomaly detection.
-- KPIs: 1. Model Deployment Frequency, 2. Model Drift Monitoring.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ml_model_registry (
    -- Primary Key
    model_id SERIAL PRIMARY KEY,

    -- Identity
    model_name VARCHAR(100) NOT NULL, -- e.g., "sentiment-analyzer-v1"
    version VARCHAR(50) NOT NULL UNIQUE, -- SemVer
    framework VARCHAR(50), -- PYTORCH, TENSORFLOW, ONNX

    -- Artifacts
    artifact_url TEXT NOT NULL, -- S3 path
    model_hash CHAR(64), -- Hash of the model file
    config_json JSONB, -- Hyperparameters

    -- Performance
    accuracy_score NUMERIC(3,2),
    precision_score NUMERIC(3,2),
    recall_score NUMERIC(3,2),

    -- Status
    is_deployment BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);

COMMENT ON TABLE m23_governance.ml_model_registry IS 'Catalog of machine learning models used in automated governance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 271 - feature_flag_rollouts
-- Description: History of feature flag changes.
-- Business Case: Release Control. Tracks the gradual rollout of flags (0% -> 10% -> 50% -> 100%)
-- to correlate performance changes with specific rollouts.
-- KPIs: 1. Rollout Duration, 2. Incident Correlation with Rollouts.
-- Feature Reference: 76
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.feature_flag_rollouts (
    -- Primary Key
    rollout_id BIGSERIAL PRIMARY KEY,

    -- Flag
    flag_name VARCHAR(255) NOT NULL,

    -- Change
    previous_value NUMERIC(5,2),
    new_value NUMERIC(5,2) NOT NULL,
    rollout_strategy VARCHAR(50), -- IMMEDIATE, GRADUAL, USER_TARGETED

    -- Context
    pr_id BIGINT,
    performed_by BIGINT,

    -- Timing
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    rollback_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_rollout_flag FOREIGN KEY (flag_name) REFERENCES m23_governance.feature_flags(flag_name),
    CONSTRAINT fk_rollout_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_rollout_user FOREIGN KEY (performed_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.feature_flag_rollouts IS 'Audit trail of feature flag value changes and rollbacks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 272 - incident_correlation_matrix
-- Description: Links code changes to incidents.
-- Business Case: Causality Analysis. When a production incident occurs (e.g., "Payment Latency"),
-- this table links it to the PRs deployed just prior, helping root cause analysis (RCA).
-- KPIs: 1. Mean Time to Identify Root Cause.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.incident_correlation_matrix (
    -- Primary Key
    correlation_id BIGSERIAL PRIMARY KEY,

    -- Incident
    incident_id VARCHAR(100) NOT NULL, -- External ID (PagerDuty, OpsGenie)
    incident_title TEXT,
    incident_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Suspect PRs
    pr_id BIGINT NOT NULL,
    deployment_id BIGINT,

    -- Analysis
    confidence_score NUMERIC(3,2), -- How likely is this PR to be the cause?
    notes TEXT,
    is_confirmed_cause BOOLEAN DEFAULT FALSE,

    -- Audit
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    linked_by BIGINT,

    CONSTRAINT fk_corr_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_corr_deploy FOREIGN KEY (deployment_id) REFERENCES m23_governance.deployments(deployment_id),
    CONSTRAINT fk_corr_user FOREIGN KEY (linked_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.incident_correlation_matrix IS 'Maps production incidents to likely contributing code changes.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 273 - api_mock_expectations
-- Description: Recorded expectations for API mocks.
-- Business Case: Testing Precision. Stores the specific requests that a mock server expects to
-- receive, allowing "replay" of tests with exact request/response validation.
-- KPIs: 1. Mock Replay Accuracy.
-- Feature Reference: 17
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_mock_expectations (
    -- Primary Key
    expectation_id BIGSERIAL PRIMARY KEY,

    -- Mock
    mock_id INTEGER NOT NULL,

    -- Expectation
    http_method VARCHAR(10) NOT NULL, -- GET, POST
    path_pattern TEXT NOT NULL,
    request_body_json JSONB,

    -- Response
    response_status INTEGER NOT NULL,
    response_body_json JSONB,
    response_headers_json JSONB,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_exp_mock FOREIGN KEY (mock_id) REFERENCES m23_governance.api_mock_servers(mock_id)
);

COMMENT ON TABLE m23_governance.api_mock_expectations IS 'Defines specific request/response scenarios for API mocking servers.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 274 - service_level_objectives
-- Description: Definition of SLOs.
-- Business Case: Reliability Engineering. Defines target reliability (e.g., "99.9% availability")
-- and error budgets. Code changes that consume too much error budget might be blocked.
-- KPIs: 1. Error Budget Remaining, 2. SLO Attainment.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.service_level_objectives (
    -- Primary Key
    slo_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(255) NOT NULL,
    description TEXT,
    service_name VARCHAR(255) NOT NULL,

    -- Goal
    target_percentage NUMERIC(5,2) NOT NULL, -- 99.95
    time_window_hours INTEGER NOT NULL, -- Rolling 30 days (720h)

    -- Current Status
    current_value NUMERIC(5,2),
    error_budget_remaining_pct NUMERIC(5,2),
    is_breached BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.service_level_objectives IS 'Defines reliability targets for critical services.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 275 - slo_burn_rate_alerts
-- Description: Alerts triggered by SLO burn rate.
-- Business Case: Proactive Stability. If error budget is burning *too fast* (e.g., multiple outages
-- in 1 hour), triggers alerts before the SLO is officially breached.
-- KPIs: 1. Alert Lead Time.
-- Feature Reference: 28
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.slo_burn_rate_alerts (
    -- Primary Key
    burn_id BIGSERIAL PRIMARY KEY,

    -- Linking
    slo_id INTEGER NOT NULL,

    -- Alert Details
    burn_window_minutes INTEGER NOT NULL, -- Look at last 1h, 24h
    burn_rate_pct NUMERIC(5,2) NOT NULL, -- Consuming X% per minute
    threshold_trigger_pct NUMERIC(5,2), -- Alert if burning > 10x normal

    -- Status
    status VARCHAR(20) DEFAULT 'FIRING', -- FIRING, RESOLVED
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_burn_slo FOREIGN KEY (slo_id) REFERENCES m23_governance.service_level_objectives(slo_id)
);

COMMENT ON TABLE m23_governance.slo_burn_rate_alerts IS 'Notifies teams when error budgets are depleting rapidly.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 276 - build_reproducibility_cache
-- Description: Cache of deterministic build artifacts.
-- Business Case: Build Speed. If a PR changes only documentation, reuse the previously
-- verified binary for the Rust core from the cache.
-- KPIs: 1. Cache Hit Rate, 2. Build Time Reduction.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.build_reproducibility_cache (
    -- Primary Key
    cache_id BIGSERIAL PRIMARY KEY,

    -- Key
    source_hash CHAR(64) NOT NULL UNIQUE, -- Hash of all source files
    build_config_hash CHAR(64) NOT NULL, -- Hash of Cargo.toml/compile flags
    target_triple VARCHAR(100) NOT NULL, -- x86_64-unknown-linux-gnu

    -- Artifact
    artifact_url TEXT NOT NULL,
    artifact_size_bytes BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.build_reproducibility_cache IS 'Stores verified build artifacts for reuse in subsequent pipelines.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 277 - git_reflog
-- Description: Audit log of reference updates.
-- Business Case: Forensics. Git reflog tracks movement of refs (branches, tags). If a branch is
-- force-deleted, this table helps recover *when* and *by whom* (if integrated with server hooks).
-- KPIs: 1. Reflog Availability.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.git_reflog (
    -- Primary Key
    reflog_id BIGSERIAL PRIMARY KEY,

    -- Ref
    ref_name VARCHAR(255) NOT NULL, -- refs/heads/main
    old_sha CHAR(40),
    new_sha CHAR(40),

    -- Actor
    committer_name VARCHAR(255),
    committer_email VARCHAR(255),

    -- Operation
    operation VARCHAR(20) NOT NULL, -- commit, update, push, fetch
    message TEXT,

    -- Audit
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.git_reflog IS 'Stores the history of changes to git references.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 278 - file_change_heatmaps
-- Description: Aggregation of file change frequency.
-- Business Case: Code Stability. Identifies "Hotspots" (files changed very frequently) which
-- indicate design issues or high volatility.
-- KPIs: 1. File Stability Index.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.file_change_heatmaps (
    -- Composite Primary Key
    file_path TEXT NOT NULL,
    date DATE NOT NULL,

    -- Metrics
    change_count INTEGER DEFAULT 0,
    contributor_distinct_count INTEGER DEFAULT 0,

    -- Analysis
    volatility_score NUMERIC(5,2), -- Calculated over rolling window

    CONSTRAINT pk_heatmap UNIQUE (file_path, date)
);

COMMENT ON TABLE m23_governance.file_change_heatmaps IS 'Tracks which files are most frequently modified to identify volatility.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 279 - merge_conflict_resolution
-- Description: Analysis of merge conflict resolution.
-- Business Case: Workflow Optimization. Analyzes how conflicts are resolved (e.g., "Theirs", "Mine",
-- Manual") to suggest improvements to branching strategy.
-- KPIs: 1. Conflict Resolution Time.
-- Feature Reference: 22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.merge_conflict_resolution (
    -- Primary Key
    resolution_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT NOT NULL,

    -- Conflict
    file_path TEXT NOT NULL,
    conflicted_lines INTEGER,

    -- Resolution
    resolution_method VARCHAR(50), -- MANUAL, AUTO_THEIRS, AUTO_OURS
    resolution_time_seconds INTEGER,
    resolver_id BIGINT,

    -- Audit
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_resolve_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_resolve_user FOREIGN KEY (resolver_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.merge_conflict_resolution IS 'Analyzes how code conflicts are detected and resolved.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 280 - code_freeze_windows
-- Description: Defines code freeze periods.
-- Business Case: Release Stability. Prevents merging non-critical PRs (e.g., refactoring)
-- during critical periods (Black Friday, End of Quarter).
-- KPIs: 1. Freeze Compliance.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_freeze_windows (
    -- Primary Key
    freeze_id SERIAL PRIMARY KEY,

    -- Window
    name VARCHAR(255) NOT NULL,
    reason TEXT,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Rules
    allowed_pr_types TEXT[], -- {HOTFIX, SECURITY}
    exempt_team_ids INTEGER[],

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_by BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.code_freeze_windows IS 'Defines periods during which code changes are restricted.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 281 - deployment_rollback_strategies
-- Description: Pre-defined rollback strategies.
-- Business Case: Disaster Recovery. For each deployment, stores the specific strategy to revert
-- (e.g., "Revert migration X", "Disable feature flag Y").
-- KPIs: 1. Rollback Success Rate, 2. Rollback Time.
-- Feature Reference: 71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.deployment_rollback_strategies (
    -- Primary Key
    strategy_id SERIAL PRIMARY KEY,

    -- Linking
    deployment_id BIGINT NOT NULL,

    -- Strategy
    rollback_type VARCHAR(50) NOT NULL, -- CODE_REVERT, MIGRATION_DOWN, FEATURE_FLAG, TRAFFIC_SHIFT
    description TEXT,
    script_url TEXT,

    -- Validation
    is_tested BOOLEAN DEFAULT FALSE,
    last_tested_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_rb_deploy FOREIGN KEY (deployment_id) REFERENCES m23_governance.deployments(deployment_id)
);

COMMENT ON TABLE m23_governance.deployment_rollback_strategies IS 'Documents the approved methods to revert specific deployments.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 282 - external_commits
-- Description: Commits fetched from external remotes.
-- Business Case: Sync Management. When syncing from an upstream repo (e.g., a library PARI forks),
-- tracks those commits to manage merge conflicts.
-- KPIs: 1. Sync Frequency.
-- Feature Reference: 198
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.external_commits (
    -- Primary Key
    commit_sha CHAR(40) PRIMARY KEY,

    -- Source
    remote_url TEXT NOT NULL,
    remote_branch VARCHAR(100),
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Status
    is_merged BOOLEAN DEFAULT FALSE,
    merged_into_pr_id BIGINT,

    CONSTRAINT fk_ext_pr FOREIGN KEY (merged_into_pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.external_commits IS 'Tracks commits imported from upstream forked repositories.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 283 - contributor_tiers
-- Description: Categorizes contributors by impact.
-- Business Case: Gamification & Access. Assigns "Tiers" (Bronze, Silver, Gold) based on contribution
-- volume and quality, unlocking specific permissions.
-- KPIs: 1. Tier Advancement Rate.
-- Feature Reference: 15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_tiers (
    -- Composite Primary Key
    contributor_id BIGINT NOT NULL,
    tier_name VARCHAR(50) NOT NULL, -- BRONZE, SILVER, GOLD, PLATINUM

    -- Metrics
    points INTEGER DEFAULT 0,
    current_rank_position INTEGER,

    -- Audit
    awarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Tiers can expire if inactive

    CONSTRAINT pk_tiers UNIQUE (contributor_id, tier_name),
    CONSTRAINT fk_tier_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.contributor_tiers IS 'Gamification levels reflecting contributor status and privileges.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 284 - sponsorships
-- Description: Tracks sponsorships/donations.
-- Business Case: Financial Sustainability. Links financial sponsors (companies/individuals)
-- to their contributions or specific funds (e.g., "Core Infrastructure Fund").
-- KPIs: 1. Sponsor Retention, 2. Funding Diversity.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.sponsorships (
    -- Primary Key
    sponsorship_id SERIAL PRIMARY KEY,

    -- Sponsor
    sponsor_id BIGINT, -- Can be a contributor or org
    sponsor_name VARCHAR(255),

    -- Details
    tier VARCHAR(50), -- PLATINUM, GOLD
    amount NUMERIC(15,2),
    currency VARCHAR(10) DEFAULT 'USD',
    frequency VARCHAR(20), -- ONE_TIME, MONTHLY, YEARLY

    -- Fulfillment
    pr_sponsored_id BIGINT, -- Optional: Link to specific PR bounty or work
    start_date DATE,
    end_date DATE,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sponsor_user FOREIGN KEY (sponsor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.sponsorships IS 'Manages financial sponsor relationships and bounties.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 285 - budget_allocations
-- Description: Budget allocated for bounties and incentives.
-- Business Case: Financial Governance. Ensures that bounties are not over-spent. Tracks
-- allocation to different programs (Security, UX, Performance).
-- KPIs: 1. Budget Utilization, 2. Bounty ROI.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.budget_allocations (
    -- Primary Key
    allocation_id SERIAL PRIMARY KEY,

    -- Budget
    fiscal_period VARCHAR(50) NOT NULL, -- Q1-2024
    program_name VARCHAR(100) NOT NULL, -- SECURITY, CORE_DEV
    total_allocated_amount NUMERIC(15,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',

    -- Status
    spent_amount NUMERIC(15,2) DEFAULT 0,
    remaining_amount NUMERIC(15,2) GENERATED ALWAYS AS (total_allocated_amount - spent_amount) STORED,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    manager_id BIGINT
);

COMMENT ON TABLE m23_governance.budget_allocations IS 'Tracks financial limits for community incentive programs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 286 - payment_processor_logs
-- Description: Logs of payment processing for bounties.
-- Business Case: Audit Trail. When paying contributors via Stripe/PayPal, logs the request
-- and response to ensure funds are delivered correctly.
-- KPIs: 1. Payment Success Rate, 2. Payment Latency.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.payment_processor_logs (
    -- Primary Key
    log_id BIGSERIAL PRIMARY KEY,

    -- Payment
    bounty_claim_id BIGINT NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    currency VARCHAR(10) NOT NULL,

    -- Processor
    processor_name VARCHAR(50) NOT NULL, -- STRIPE, PAYPAL, CRYPTO
    transaction_id VARCHAR(255),
    processor_response JSONB,

    -- Status
    status VARCHAR(20) NOT NULL, -- PENDING, SUCCESS, FAILED, REFUNDED
    failure_reason TEXT,

    -- Audit
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    settled_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_pay_claim FOREIGN KEY (bounty_claim_id) REFERENCES m23_governance.bounty_claims(bounty_id, pr_id)
);

COMMENT ON TABLE m23_governance.payment_processor_logs IS 'Financial logs for bounty and sponsorship payouts.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 287 - marketing_campaigns
-- Description: Marketing campaigns to drive contributions.
-- Business Case: Growth. Tracks campaigns (e.g., "Hacktoberfest") to see which marketing
-- channels bring in the best contributors.
-- KPIs: 1. Contributor Acquisition Cost, 2. Conversion Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.marketing_campaigns (
    -- Primary Key
    campaign_id SERIAL PRIMARY KEY,

    -- Campaign
    name VARCHAR(255) NOT NULL,
    channel VARCHAR(50), -- TWITTER, LINKEDIN, EMAIL, BLOG
    start_date DATE,
    end_date DATE,
    budget NUMERIC(15,2),

    -- Results
    link_clicks INTEGER DEFAULT 0,
    signups INTEGER DEFAULT 0,
    active_contributors INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.marketing_campaigns IS 'Tracks outreach efforts to recruit new contributors.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 288 - ux_feedback_surveys
-- Description: Feedback from contributors on tools.
-- Business Case: Developer Experience (DevEx). Periodic surveys to ask contributors how easy
-- it is to contribute to PARI.
-- KPIs: 1. NPS Score, 2. Friction Score.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ux_feedback_surveys (
    -- Primary Key
    survey_id SERIAL PRIMARY KEY,

    -- Survey
    name VARCHAR(255) NOT NULL,
    distributed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Results (Aggregated)
    response_count INTEGER DEFAULT 0,
    nps_score INTEGER, -- Net Promoter Score -100 to 100
    avg_friction_score NUMERIC(3,2), -- 1 (Easy) to 5 (Hard)

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.ux_feedback_surveys IS 'Aggregates feedback on the developer experience.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 289 - mentorship_feedback
-- Description: Feedback from mentorship pairs.
-- Business Case: Program Improvement. Allows mentees and mentors to rate each other, ensuring
-- quality of the mentorship program.
-- KPIs: 1. Match Satisfaction Score.
-- Feature Reference: 97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.mentorship_feedback (
    -- Primary Key
    feedback_id BIGSERIAL PRIMARY KEY,

    -- Pair
    mentorship_pair_id INTEGER NOT NULL,

    -- Review
    reviewer_id BIGINT NOT NULL, -- Who is giving feedback
    subject_id BIGINT NOT NULL, -- Who is being reviewed
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    comments TEXT,

    -- Audit
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_fb_pair FOREIGN KEY (mentorship_pair_id) REFERENCES m23_governance.mentorship_pairs(mentor_id, mentee_id),
    CONSTRAINT fk_fb_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_fb_subject FOREIGN KEY (subject_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.mentorship_feedback IS 'Evaluates the effectiveness of mentorship pairings.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 290 - documentation_quality_metrics
-- Description: Metrics on doc quality (readability, liveness).
-- Business Case: Knowledge Management. Scores docs based on readability (Flesch-Kincaid) and
-- whether links are rotting.
-- KPIs: 1. Readability Score, 2. Link Rot Rate.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.documentation_quality_metrics (
    -- Primary Key
    metric_id BIGSERIAL PRIMARY KEY,

    -- Doc
    file_path TEXT NOT NULL,
    pr_id BIGINT NOT NULL,

    -- Metrics
    readability_score NUMERIC(5,2), -- 0 to 100
    word_count INTEGER,
    sentence_count INTEGER,
    broken_link_count INTEGER DEFAULT 0,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_docq_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.documentation_quality_metrics IS 'Quantifies the quality and maintainability of documentation.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 291 - security_policy_acknowledgments
-- Description: Acknowledgment of security policies.
-- Business Case: Legal Protection. Forces contributors to "sign" (click I Agree) security policies
-- (Responsible Disclosure) before accessing certain repos.
-- KPIs: 1. Policy Acknowledgment Rate.
-- Feature Reference: 11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.security_policy_acknowledgments (
    -- Primary Key
    ack_id BIGSERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,
    policy_id INTEGER, -- If stored in a policy table, or just policy_name
    policy_name VARCHAR(255) NOT NULL,
    policy_version VARCHAR(20),

    -- Ack
    acknowledged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,

    CONSTRAINT fk_ack_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.security_policy_acknowledgments IS 'Tracks who has agreed to security and conduct policies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 292 - code_ownership_disputes
-- Description: Disputes over code ownership.
-- Business Case: Conflict Resolution. If two contributors claim ownership of a module or disagree
-- on the direction, this table tracks the dispute and its resolution.
-- KPIs: 1. Dispute Resolution Time.
-- Feature Reference: 64
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_ownership_disputes (
    -- Primary Key
    dispute_id BIGSERIAL PRIMARY KEY,

    -- Subject
    file_path_or_module TEXT NOT NULL,
    claimed_by_a BIGINT NOT NULL,
    claimed_by_b BIGINT NOT NULL,

    -- Dispute
    reason TEXT,
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, MEDIATING, RESOLVED
    mediator_id BIGINT,

    -- Resolution
    resolution_text TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dispute_a FOREIGN KEY (claimed_by_a) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_dispute_b FOREIGN KEY (claimed_by_b) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_dispute_mediator FOREIGN KEY (mediator_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.code_ownership_disputes IS 'Manages conflicts regarding code ownership and authority.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 293 - test_coverage_drift
-- Description: Tracks drift in code coverage over time.
-- Business Case: Quality Regression. Even if coverage is 95% today, if it was 96% yesterday, that's
-- a drift. Tracks the delta to prevent slow decay.
-- KPIs: 1. Coverage Stability.
-- Feature Reference: 9
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.test_coverage_drift (
    -- Primary Key
    drift_id BIGSERIAL PRIMARY KEY,

    -- Context
    pr_id BIGINT NOT NULL,
    file_path TEXT,

    -- Metrics
    baseline_coverage_pct NUMERIC(5,2),
    current_coverage_pct NUMERIC(5,2),
    drift_pct NUMERIC(5,2), -- Negative means coverage dropped

    -- Assessment
    is_acceptable BOOLEAN DEFAULT TRUE, -- Based on threshold

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_drift_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.test_coverage_drift IS 'Detects gradual decay in code quality metrics.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 294 - dependency_licensing_risks
-- Description: High-level summary of license risks.
-- Business Case: Executive Dashboard. Aggregates low-level license compliance results into a
-- "Risk Score" for the entire repository or release.
-- KPIs: 1. Legal Risk Score.
-- Feature Reference: 20
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_licensing_risks (
    -- Primary Key
    risk_id SERIAL PRIMARY KEY,

    -- Context
    repo_id INTEGER NOT NULL,
    snapshot_date DATE NOT NULL,

    -- Scores
    high_risk_count INTEGER DEFAULT 0, -- GPL/AGPL in closed source
    medium_risk_count INTEGER DEFAULT 0,
    total_dependency_count INTEGER DEFAULT 0,

    -- Overall
    overall_risk_level VARCHAR(20), -- LOW, MEDIUM, HIGH, CRITICAL

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_risk_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.dependency_licensing_risks IS 'Summarizes the legal risk profile of project dependencies.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 295 - vulnerability_patch_availability
-- Description: Availability of patches for CVEs.
-- Business Case: Remediation Planning. Not all CVEs have a fix yet. This table tracks if
-- a fix is available, is in beta, or is "Wont Fix".
-- KPIs: 1. Patch Availability Rate.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.vulnerability_patch_availability (
    -- Primary Key
    patch_id BIGSERIAL PRIMARY KEY,

    -- CVE
    cve_id VARCHAR(20) NOT NULL,

    -- Patch Info
    fixed_version VARCHAR(100),
    patch_url TEXT,
    package_name VARCHAR(255),

    -- Status
    patch_status VARCHAR(20) DEFAULT 'UNKNOWN', -- AVAILABLE, IN_PROGRESS, WONT_FIX, UNKNOWN
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.vulnerability_patch_availability IS 'Tracks the status of fixes for known security vulnerabilities.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 296 - binary_vulnerability_scan
-- Description: SCA on compiled binaries (Binary Analysis).
-- Business Case: Deep Supply Chain. Sometimes source SCA misses deps that are statically linked
-- or vendored. Scanning the binary catches these "hidden" dependencies.
-- KPIs: 1. Hidden Dependency Detection.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.binary_vulnerability_scan (
    -- Primary Key
    scan_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT,
    binary_artifact_id BIGINT NOT NULL,

    -- Scanner
    scanner_name VARCHAR(50) NOT NULL, -- e.g., Grype, Trivy

    -- Findings
    vuln_count INTEGER DEFAULT 0,
    details_jsonb JSONB,

    -- Audit
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bin_artifact FOREIGN KEY (binary_artifact_id) REFERENCES m23_governance.build_artifacts(artifact_id),
    CONSTRAINT fk_bin_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.binary_vulnerability_scan IS 'Detects security issues in compiled binaries via Software Composition Analysis.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 297 - code_pattern_library
-- Description: Library of approved code patterns.
-- Business Case: Standardization. Stores "Golden" code snippets (e.g., "Correct way to derive
-- a key") that AI reviewers can suggest as alternatives to custom implementations.
-- KPIs: 1. Pattern Usage Frequency.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.code_pattern_library (
    -- Primary Key
    pattern_id SERIAL PRIMARY KEY,

    -- Pattern
    name VARCHAR(255) NOT NULL,
    language VARCHAR(50) NOT NULL,
    category VARCHAR(100), -- CRYPTO, ERROR_HANDLING, LOGGING

    -- Content
    snippet TEXT NOT NULL,
    snippet_hash CHAR(64) NOT NULL,

    -- Attributes
    is_secure BOOLEAN DEFAULT TRUE,
    is_performance_optimized BOOLEAN DEFAULT FALSE,
    reference_url TEXT,

    -- Usage
    usage_count INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approved_by BIGINT
);

COMMENT ON TABLE m23_governance.code_pattern_library IS 'Repository of canonical, vetted code patterns for reference.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 298 - ci_performance_metrics
-- Description: Performance metrics of the CI system itself.
-- Business Case: DevOps Efficiency. Tracks how long the CI takes to queue, run, and return results.
-- Slow CI blocks developers.
-- KPIs: 1. Queue Time, 2. Agent Utilization, 3. Pipeline Success Rate.
-- Feature Reference: 8
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ci_performance_metrics (
    -- Primary Key
    metric_id BIGSERIAL PRIMARY KEY,

    -- Context
    run_id BIGINT NOT NULL,
    job_id BIGINT,

    -- Timing
    queue_wait_duration_ms INTEGER,
    agent_startup_duration_ms INTEGER,
    checkout_duration_ms INTEGER,
    execution_duration_ms INTEGER,
    upload_artifacts_duration_ms INTEGER,

    -- Resource
    cpu_percent_avg NUMERIC(5,2),
    memory_mb_max INTEGER,

    CONSTRAINT fk_perf_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id),
    CONSTRAINT fk_perf_job FOREIGN KEY (job_id) REFERENCES m23_governance.ci_jobs(job_id)
);

COMMENT ON TABLE m23_governance.ci_performance_metrics IS 'Detailed telemetry on CI/CD pipeline performance and resource usage.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 299 - git_large_file_storage_stats
-- Description: Statistics for Git LFS.
-- Business Case: Storage Management. Tracks which binary assets (models, images) are stored in
-- LFS, their size, and access frequency.
-- KPIs: 1. LFS Storage Size, 2. LFS Bandwidth Usage.
-- Feature Reference: 35
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.git_large_file_storage_stats (
    -- Primary Key
    lfs_id BIGSERIAL PRIMARY KEY,

    -- Object
    oid CHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    file_path TEXT NOT NULL,

    -- Usage
    download_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP WITH TIME ZONE,
    is_stale BOOLEAN DEFAULT FALSE, -- Not accessed in > 1 year
    pr_introduced_id BIGINT, -- Which PR added this large file

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lfs_pr FOREIGN KEY (pr_introduced_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.git_large_file_storage_stats IS 'Tracks usage and costs of large binary files in version control.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 300 - contributor_timezone_overlap
-- Description: Calculates timezone overlap for teams.
-- Business Case: Collaboration. Helps pair reviewers and contributors who are awake at the same time
-- to reduce wait times.
-- KPIs: 1. Overlap Hours, 2. Review Turnaround vs Overlap.
-- Feature Reference: 51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_timezone_overlap (
    -- Composite Primary Key
    user_a_id BIGINT NOT NULL,
    user_b_id BIGINT NOT NULL,

    -- Overlap
    overlap_hours INTEGER, -- Hours of shared work time
    score NUMERIC(5,2), -- 0 to 5 (Perfect overlap)

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_overlap UNIQUE (user_a_id, user_b_id),
    CONSTRAINT fk_overlap_user_a FOREIGN KEY (user_a_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_overlap_user_b FOREIGN KEY (user_b_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.contributor_timezone_overlap IS 'Optimizes assignment of reviewers based on working hours.';
-- ==========================================================================================================
-- PARI Payment Infrastructure - Module M23: Community Governance & FOSS Contribution Hub
-- Part 6b: Extended Database Objects Tables 301-350
-- ==========================================================================================================
-- Description:
-- This script continues the M23 schema definition with Tables 301-350. This section covers
-- advanced topics including AI model training metadata (MLOps), regulatory compliance tracking,
-- financial reconciliation for bounties, detailed security incident handling, and advanced
-- repository analytics.
--
-- Standards & Guidelines:
-- 1. All DDL statements are idempotent (CREATE IF NOT EXISTS).
-- 2. Comprehensive COMMENT ON documentation for all objects and columns.
-- 3. Business Case and KPIs documented for all major tables.
-- 4. Feature References mapped to the provided Feature Matrix.
-- 5. Automated timestamp management via triggers.
-- ==========================================================================================================

-- --------------------------------------------------------------------------------------------------------
-- Table: 301 - ml_training_datasets
-- Description: Metadata for training datasets used in governance models.
-- Business Case: MLOps Data Lineage. Tracks which versions of PRs, Issues, and Comments were
-- used to train the "Code Review AI" or "Sentiment Analysis" models to ensure reproducibility.
-- KPIs: 1. Dataset Drift, 2. Training Data Quality Score.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ml_training_datasets (
    -- Primary Key
    dataset_id SERIAL PRIMARY KEY,

    -- Identity
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL, -- v1.0.0
    description TEXT,

    -- Composition
    start_date DATE NOT NULL, -- Data window start
    end_date DATE NOT NULL,   -- Data window end

    -- Statistics
    row_count BIGINT,
    class_balance_jsonb JSONB, -- Distribution of labels (e.g., {positive: 5000, negative: 500})

    -- Storage
    data_url TEXT NOT NULL, -- S3/MinIO path
    hash_char64 CHAR(64), -- Hash of the dataset file for integrity

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);

COMMENT ON TABLE m23_governance.ml_training_datasets IS 'Catalog of datasets used to train machine learning governance models.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 302 - ml_experiment_tracking
-- Description: Tracking of ML model training runs (MLflow style).
-- Business Case: Experiment Management. Data scientists try different hyperparameters. This table
-- logs every run (learning rate, epochs) to identify the best performing model version.
-- KPIs: 1. Model Accuracy Improvement, 2. Training Cost (GPU hours).
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.ml_experiment_tracking (
    -- Primary Key
    run_id BIGSERIAL PRIMARY KEY,

    -- Linking
    experiment_name VARCHAR(255) NOT NULL,
    model_name VARCHAR(100) NOT NULL,

    -- Config
    parameters_jsonb JSONB NOT NULL, -- Hyperparameters (lr, batch_size, layers)
    dataset_id INTEGER NOT NULL,

    -- Metrics
    metrics_jsonb JSONB, -- {accuracy: 0.95, precision: 0.92, recall: 0.90}
    validation_loss NUMERIC(10,5),

    -- Artifacts
    artifact_url TEXT, -- Path to model weights
    model_binary_hash CHAR(64),

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, COMPLETED, FAILED
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    -- Audit
    user_id BIGINT,

    CONSTRAINT fk_exp_dataset FOREIGN KEY (dataset_id) REFERENCES m23_governance.ml_training_datasets(dataset_id),
    CONSTRAINT fk_exp_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.ml_experiment_tracking IS 'Logs training runs for machine learning models to optimize hyperparameters.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 303 - model_performance_monitoring
-- Description: Live monitoring of deployed ML models.
-- Business Case: Model Drift Detection. Once a model (e.g., "Sentiment Analyzer") is deployed,
-- this table tracks its prediction accuracy over time. If accuracy drops, the model needs retraining.
-- KPIs: 1. Prediction Latency, 2. Drift Magnitude, 3. Error Rate.
-- Feature Reference: 2
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.model_performance_monitoring (
    -- Primary Key
    monitor_id BIGSERIAL PRIMARY KEY,

    -- Model
    model_id INTEGER NOT NULL,
    model_version VARCHAR(50) NOT NULL,

    -- Context
    evaluation_window TIMESTAMP WITH TIME ZONE NOT NULL, -- e.g., last 1 hour

    -- Metrics
    prediction_count BIGINT,
    ground_truth_count BIGINT, -- How many were labeled as correct/incorrect later
    accuracy NUMERIC(5,4),
    precision NUMERIC(5,4),
    recall NUMERIC(5,4),
    f1_score NUMERIC(5,4),

    -- Drift
    drift_score NUMERIC(5,2), -- Statistical distance from training data
    is_alerting BOOLEAN DEFAULT FALSE,

    -- Audit
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_perf_model FOREIGN KEY (model_id) REFERENCES m23_governance.ml_model_registry(model_id)
);

CREATE INDEX idx_perf_monitor_model ON m23_governance.model_performance_monitoring(model_id, recorded_at DESC);
COMMENT ON TABLE m23_governance.model_performance_monitoring IS 'Tracks ongoing accuracy of AI models to detect degradation or drift.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 304 - regulatory_audit_logs
-- Description: Specific logs for regulatory compliance (GDPR/PSD2).
-- Business Case: Financial Compliance. Banks and governments require unalterable logs of who
-- accessed financial transaction logic or PII. This is a subset of audit_trail filtered
-- for high-sensitivity.
-- KPIs: 1. Audit Log Completeness, 2. Access Latency.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.regulatory_audit_logs (
    -- Primary Key
    log_id BIGSERIAL PRIMARY KEY,

    -- Event
    actor_type VARCHAR(50) NOT NULL, -- USER, SERVICE, SYSTEM
    actor_id VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL, -- ACCESS_PII, MODIFY_TX_LOG, EXPORT_AUDIT

    -- Context
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    justification TEXT,

    -- Result
    success BOOLEAN NOT NULL,
    failure_reason TEXT,

    -- Environment
    source_ip INET,
    user_agent TEXT,

    -- Timing
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reg_audit_time ON m23_governance.regulatory_audit_logs(event_timestamp DESC);
COMMENT ON TABLE m23_governance.regulatory_audit_logs IS 'Immutable access logs for sensitive financial and personal data.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 305 - data_subject_requests
-- Description: Tracking of GDPR DSARs (Right to be Forgotten/Access).
-- Business Case: Privacy Rights. When a user exercises GDPR rights, this table tracks the request
-- status and actions taken (e.g., "Anonymized comments", "Deleted email").
-- KPIs: 1. DSAR Response Time (SLA: 30 days), 2. Erasure Success Rate.
-- Feature Reference: 45
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.data_subject_requests (
    -- Primary Key
    dsr_id SERIAL PRIMARY KEY,

    -- Requester
    requester_email VARCHAR(255) NOT NULL,
    requester_type VARCHAR(20) DEFAULT 'CONTRIBUTOR', -- CONTRIBUTOR, USER
    contributor_id BIGINT, -- If applicable

    -- Request
    request_type VARCHAR(20) NOT NULL, -- ACCESS, ERASURE, PORTABILITY, RECTIFICATION
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, IN_PROGRESS, COMPLETED, REJECTED
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Processing
    assigned_to BIGINT,
    due_date DATE, -- Legal deadline
    completed_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,

    -- Audit
    created_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID,

    CONSTRAINT fk_dsr_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_dsr_assigned FOREIGN KEY (assigned_to) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.data_subject_requests IS 'Manages GDPR data subject access and erasure requests.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 306 - compliance_exception_requests
-- Description: Requests to waive compliance rules.
-- Business Case: Business Agility. Sometimes a rule (e.g., "100% coverage") blocks a critical
-- hotfix. This table tracks the formal request and approval to bypass a control.
-- KPIs: 1. Exception Approval Rate, 2. Exception Closure Rate.
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.compliance_exception_requests (
    -- Primary Key
    exception_id BIGSERIAL PRIMARY KEY,

    -- Linking
    pr_id BIGINT,
    rule_id INTEGER, -- e.g., quality_gate_id or branch_protection_rule_id

    -- Request
    requested_by BIGINT NOT NULL,
    reason TEXT NOT NULL,
    risk_assessment TEXT, -- What is the risk of granting this?
    proposed_mitigation TEXT, -- How do we reduce the risk?

    -- Approval
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, DENIED, EXPIRED
    approved_by BIGINT,
    approved_at TIMESTAMP WITH TIME ZONE,
    expiry_date DATE, -- Exception is temporary

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_exc_pr FOREIGN KEY (pr_id) REFERENCES m23_governance.pull_requests(pr_id),
    CONSTRAINT fk_exc_requester FOREIGN KEY (requested_by) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_exc_approver FOREIGN KEY (approved_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.compliance_exception_requests IS 'Tracks requests to bypass specific governance controls.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 307 - tax_documents
-- Description: Tax forms and documentation for contributors.
-- Business Case: Financial Compliance. For bounties > $600 (US), W-9 forms or VAT invoices
-- are required. This table stores metadata and secure links to these documents.
-- KPIs: 1. Document Collection Rate, 2. Tax Filing Accuracy.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.tax_documents (
    -- Primary Key
    doc_id BIGSERIAL PRIMARY KEY,

    -- Linking
    contributor_id BIGINT NOT NULL,
    fiscal_year INTEGER NOT NULL,

    -- Document
    document_type VARCHAR(50) NOT NULL, -- W9, W8BEN, VAT_INVOICE, TAX_ID
    storage_path TEXT NOT NULL, -- Secure S3 bucket path
    is_encrypted BOOLEAN DEFAULT TRUE,
    checksum CHAR(64) NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'SUBMITTED', -- SUBMITTED, VERIFIED, REJECTED
    verified_by BIGINT,
    verified_at TIMESTAMP WITH TIME ZONE,
    rejection_reason TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tax_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_tax_verifier FOREIGN KEY (verified_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.tax_documents IS 'Secure storage for tax compliance documents related to bounties.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 308 - payout_aggregation
-- Description: Aggregates small payments into larger transfers.
-- Business Case: Cost Optimization. Transaction fees on blockchains can be high. Aggregating
-- multiple small bounty payouts into one transaction reduces gas/fees.
-- KPIs: 1. Gas Cost Savings, 2. Aggregation Delay.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.payout_aggregation (
    -- Primary Key
    aggregation_id BIGSERIAL PRIMARY KEY,

    -- Batch
    batch_name VARCHAR(100) NOT NULL, -- e.g., "Weekly_Payouts_2024_W42"
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    total_amount NUMERIC(15,2),
    recipient_count INTEGER,

    -- Processing
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, PROCESSING, COMPLETED, FAILED
    processing_started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Blockchain / Bank
    transaction_hash VARCHAR(255),
    transfer_method VARCHAR(50), -- CRYPTO_BATCH, WIRE_TRANSFER, PAYPAL_MASS_PAY

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);

COMMENT ON TABLE m23_governance.payout_aggregation IS 'Batches multiple small payments into a single transaction to reduce fees.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 309 - financial_reconciliation
-- Description: Reconciles budget vs actual spend.
-- Business Case: Financial Control. Ensures that the amount allocated in Table 285 matches the
-- sum of payouts in Table 306/308 to catch fraud or accounting errors.
-- KPIs: 1. Reconciliation Match Rate, 2. Variance Amount.
-- Feature Reference: 70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.financial_reconciliation (
    -- Primary Key
    reconciliation_id BIGSERIAL PRIMARY KEY,

    -- Period
    fiscal_period VARCHAR(50) NOT NULL, -- Q3-2024
    program_name VARCHAR(100) NOT NULL, -- SECURITY_BOUNTIES

    -- Figures
    allocated_budget NUMERIC(15,2) NOT NULL,
    actual_spend NUMERIC(15,2) NOT NULL,
    pending_commitments NUMERIC(15,2),
    variance NUMERIC(15,2) GENERATED ALWAYS AS (allocated_budget - actual_spend - pending_commitments) STORED,

    -- Status
    status VARCHAR(20) DEFAULT 'RECONCILED', -- RECONCILED, DISCREPANCY
    discrepancy_notes TEXT,

    -- Audit
    reconciled_by BIGINT,
    reconciled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_recon_user FOREIGN KEY (reconciled_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.financial_reconciliation IS 'Matches allocated budgets against actual bounty payouts.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 310 - security_incidents
-- Description: Tracking of security incidents.
-- Business Case: Incident Response (IR). Formal tracking of security events (Code leak,
-- Unauthorized Access) from detection to resolution.
-- KPIs: 1. MTTR (Mean Time to Resolve), 2. MTTD (Mean Time to Detect).
-- Feature Reference: 49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.security_incidents (
    -- Primary Key
    incident_id SERIAL PRIMARY KEY,

    -- Classification
    severity VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    category VARCHAR(50) NOT NULL, -- DATA_LEAK, INTRUSION, DOS, MALWARE
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'OPEN', -- OPEN, INVESTIGATING, CONTAINED, CLOSED
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    contained_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Attribution
    attributed_to VARCHAR(100), -- e.g., "External Actor", "Internal Error"
    is_confirmed BOOLEAN DEFAULT FALSE,

    -- Linking
    related_pr_id BIGINT, -- If caused by a specific PR
    related_cve_id VARCHAR(20),

    -- Audit
    reported_by BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_inc_reporter FOREIGN KEY (reported_by) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_inc_pr FOREIGN KEY (related_pr_id) REFERENCES m23_governance.pull_requests(pr_id)
);

COMMENT ON TABLE m23_governance.security_incidents IS 'Tracks security events from detection to resolution.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 311 - incident_tasks
-- Description: Actionable items during an incident.
-- Business Case: Incident Response (IR) Coordination. During a security breach, specific
-- tasks (e.g., "Rotate DB credentials", "Block IP") must be assigned and tracked.
-- KPIs: 1. Task Resolution Time, 2. Task Completion Rate.
-- Feature Reference: 310
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.incident_tasks (
    -- Primary Key
    task_id BIGSERIAL PRIMARY KEY,

    -- Incident
    incident_id INTEGER NOT NULL,

    -- Task
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'TODO', -- TODO, IN_PROGRESS, DONE, BLOCKED
    priority INTEGER DEFAULT 1, -- 1=Low, 5=Critical

    -- Assignment
    assignee_id BIGINT,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT,

    -- Constraints
    CONSTRAINT fk_task_incident FOREIGN KEY (incident_id) REFERENCES m23_governance.security_incidents(incident_id),
    CONSTRAINT fk_task_assignee FOREIGN KEY (assignee_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.incident_tasks IS 'Tracks remediation steps required to resolve security incidents.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 312 - incident_communications
-- Description: Log of comms sent during an incident.
-- Business Case: Legal/PR Protection. Automatically logs emails/status pages sent to
-- stakeholders (Banks, Users) to prove transparency during an outage.
-- KPIs: 1. Communication Latency (Time to Notify), 2. Stakeholder Reach.
-- Feature Reference: 310
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.incident_communications (
    -- Primary Key
    comm_id BIGSERIAL PRIMARY KEY,

    -- Incident
    incident_id INTEGER NOT NULL,

    -- Channel
    channel VARCHAR(50) NOT NULL, -- EMAIL, STATUS_PAGE, SLACK, TWITTER
    audience VARCHAR(100), -- PUBLIC, INTERNAL, BANKS

    -- Content
    subject VARCHAR(255),
    body_text TEXT,
    external_url TEXT, -- Link to public post

    -- Audit
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    sent_by BIGINT,

    -- Constraints
    CONSTRAINT fk_comm_incident FOREIGN KEY (incident_id) REFERENCES m23_governance.security_incidents(incident_id),
    CONSTRAINT fk_comm_sender FOREIGN KEY (sent_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.incident_communications IS 'Records notifications sent to stakeholders during security events.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 313 - post_mortems
-- Description: Analysis of incidents after resolution.
-- Business Case: Blameless Learning. "What went wrong? Why? How do we prevent it again?".
-- Essential for CMMI Level 5 (Optimizing).
-- KPIs: 1. Post-Mortem Completion Rate (Target: 100%), 2. Action Item Closure Rate.
-- Feature Reference: 310
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.post_mortems (
    -- Primary Key
    postmortem_id SERIAL PRIMARY KEY,

    -- Incident
    incident_id INTEGER NOT NULL UNIQUE, -- 1:1 with incident

    -- Report
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    timeline_text TEXT,
    root_cause TEXT,

    -- Follow-up
    action_items_json JSONB, -- List of follow-up tasks
    assignee_ids BIGINT[], -- Owners of action items

    -- Approval
    status VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, REVIEW, PUBLISHED
    approved_by BIGINT,
    approved_at TIMESTAMP WITH TIME ZONE,
    published_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_pm_incident FOREIGN KEY (incident_id) REFERENCES m23_governance.security_incidents(incident_id),
    CONSTRAINT fk_pm_creator FOREIGN KEY (created_by) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_pm_approver FOREIGN KEY (approved_by) REFERENCES m23_governance.contributors(contributor_id)
);

-- Trigger for post_mortems
CREATE TRIGGER trg_postmortems_updated_at BEFORE UPDATE ON m23_governance.post_mortems
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

COMMENT ON TABLE m23_governance.post_mortems IS 'Detailed analysis of incidents to prevent recurrence.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 314 - repository_maintenance_tasks
-- Description: Routine maintenance tasks for repos.
-- Business Case: Repository Health. Periodic tasks like "Archive old branches",
-- "Stale PR cleanup", "Update dependencies".
-- KPIs: 1. Maintenance Backlog, 2. Automation Success Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.repository_maintenance_tasks (
    -- Primary Key
    task_id SERIAL PRIMARY KEY,

    -- Definition
    title VARCHAR(255) NOT NULL,
    description TEXT,
    task_type VARCHAR(50), -- BRANCH_CLEANUP, DEPENDENCY_UPDATE, STALE_ISSUE_CLOSE

    -- Scheduling
    frequency VARCHAR(50) -- DAILY, WEEKLY, MONTHLY, ADHOC

    -- Execution
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, RUNNING, SUCCESS, FAILED
    run_log TEXT,

    -- Ownership
    owner_team_id INTEGER, -- Team responsible if bot fails

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.repository_maintenance_tasks IS 'Automated or manual upkeep tasks for repository hygiene.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 315 - stale_branch_cleanup
-- Description: Log of deleted stale branches.
-- Business Case: Repository Performance. Removing old branches speeds up `git fetch` and
-- reduces disk usage. Logs ensure no "oops" deletions occurred.
-- KPIs: 1. Branch Retention Period, 2. Auto-Delete Error Rate.
-- Feature Reference: 22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.stale_branch_cleanup (
    -- Primary Key
    cleanup_id BIGSERIAL PRIMARY KEY,

    -- Branch
    repo_id INTEGER NOT NULL,
    branch_name VARCHAR(255) NOT NULL,
    last_commit_date DATE,

    -- Action
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_by VARCHAR(100), -- "AutomatedBot" or username
    reason VARCHAR(100), -- "90 days inactive"

    -- Constraints
    CONSTRAINT fk_stale_repo FOREIGN KEY (repo_id) REFERENCES m23_governance.repositories(repo_id)
);

COMMENT ON TABLE m23_governance.stale_branch_cleanup IS 'Audit log of automated branch deletion for repository hygiene.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 316 - api_gateway_config
-- Description: Configuration for API Gateway/Ingress.
-- Business Case: Centralized API Management. Defines rate limits, caching, and routing rules
-- at the edge before hitting the PARI core services.
-- KPIs: 1. Gateway Latency P50, 2. Route Configuration Errors.
-- Feature Reference: 82
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_gateway_config (
    -- Primary Key
    route_id SERIAL PRIMARY KEY,

    -- Route
    path_pattern VARCHAR(255) NOT NULL, -- e.g., /v1/payments/*
    methods TEXT[] NOT NULL, -- {GET, POST}
    service_name VARCHAR(100) NOT NULL, -- Backend service name
    service_url TEXT NOT NULL,

    -- Policies
    rate_limit_qps INTEGER, -- Queries per second
    cache_ttl_seconds INTEGER,
    auth_required BOOLEAN DEFAULT TRUE,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID DEFAULT current_setting('app.current_user_id', true)::UUID
);

COMMENT ON TABLE m23_governance.api_gateway_config IS 'Defines routing and throttling rules for the API edge layer.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 317 - api_gateway_keys
-- Description: Keys for external API access.
-- Business Case: Partnership Access. Partner Banks or Fintechs get keys to access PARI APIs.
-- KPIs: 1. Key Validity, 2. Quota Utilization.
-- Feature Reference: 82
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_gateway_keys (
    -- Primary Key
    key_id SERIAL PRIMARY KEY,

    -- Key Details
    api_key_hash CHAR(64) NOT NULL, -- SHA256
    key_prefix VARCHAR(10) NOT NULL, -- For display

    -- Owner
    owner_id INTEGER, -- org_id or similar
    owner_name VARCHAR(255),
    contact_email VARCHAR(255),

    -- Quotas
    daily_limit INTEGER,
    monthly_limit INTEGER,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);

CREATE INDEX idx_gateway_key_hash ON m23_governance.api_gateway_keys(api_key_hash);
COMMENT ON TABLE m23_governance.api_gateway_keys IS 'Credentials issued to external partners for API consumption.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 318 - api_usage_stats
-- Description: Aggregated API usage statistics.
-- Business Case: Capacity Planning. Tracks QPS (Queries Per Second) to plan scaling and
-- detect abuse patterns.
-- KPIs: 1. API Availability, 2. Average Latency, 3. Error Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.api_usage_stats (
    -- Composite Primary Key
    stat_date DATE NOT NULL,
    api_key_id INTEGER,
    route_id INTEGER,

    -- Metrics
    request_count BIGINT DEFAULT 0,
    success_count BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    avg_latency_ms NUMERIC(10,2),

    -- Constraints
    CONSTRAINT pk_api_usage UNIQUE (stat_date, api_key_id, route_id),
    CONSTRAINT fk_usage_key FOREIGN KEY (api_key_id) REFERENCES m23_governance.api_gateway_keys(key_id),
    CONSTRAINT fk_usage_route FOREIGN KEY (route_id) REFERENCES m23_governance.api_gateway_config(route_id)
);

COMMENT ON TABLE m23_governance.api_usage_stats IS 'Daily aggregation of API traffic volume and performance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 319 - webhooks_deliveries_v2
-- Description: Enhanced webhook delivery logs.
-- Business Case: Deep Debugging. Includes full request/response bodies to debug why a
-- 3rd party integration failed.
-- KPIs: 1. Retry Success Rate, 2. 4xx Error Rate (Client Error).
-- Feature Reference: 55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.webhooks_deliveries_v2 (
    -- Primary Key
    delivery_v2_id BIGSERIAL PRIMARY KEY,

    -- Linking
    webhook_id INTEGER NOT NULL,

    -- Request
    event_type VARCHAR(50) NOT NULL,
    request_headers JSONB,
    request_body TEXT, -- Full payload (might be large)

    -- Response
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,

    -- Retry Logic
    attempt_count INTEGER DEFAULT 1,
    next_retry_at TIMESTAMP WITH TIME ZONE,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, SUCCESS, FAILED, EXPIRED

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_wh_v2_webhook FOREIGN KEY (webhook_id) REFERENCES m23_governance.webhooks(webhook_id)
);

COMMENT ON TABLE m23_governance.webhooks_deliveries_v2 IS 'Detailed log of HTTP transmission to webhook endpoints.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 320 - governance_audits
-- Description: Audits of the governance tool itself.
-- Business Case: Trust in Tool. If the Governance Tool (M23) has a bug, we need a log
-- separate from the application audit log to debug the tool.
-- KPIs: 1. Admin Action Count, 2. Tool Configuration Drift.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.governance_audits (
    -- Primary Key
    audit_id BIGSERIAL PRIMARY KEY,

    -- Actor
    actor_id BIGINT,
    actor_role VARCHAR(50), -- ADMIN, MODERATOR, SYSTEM

    -- Action
    action_type VARCHAR(100) NOT NULL, -- UPDATE_POLICY, BAN_USER, OVERRIDE_GATE
    target_type VARCHAR(50),
    target_id VARCHAR(255),

    -- Context
    details_jsonb JSONB,
    reason TEXT,

    -- Timing
    actioned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,

    -- Constraints
    CONSTRAINT fk_gov_actor FOREIGN KEY (actor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.governance_audits IS 'Audit trail for administrative actions within the M23 platform.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 321 - admin_audit_logs
-- Description: Sensitive admin operations.
-- Business Case: Separation of Duties. Strict logging for admins (who can change settings,
-- ban users) to prevent internal abuse.
-- KPIs: 1. Privileged Account Activity.
-- Feature Reference: 53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.admin_audit_logs (
    -- Primary Key
    log_id BIGSERIAL PRIMARY KEY,

    -- Admin
    admin_id BIGINT NOT NULL,
    admin_session_id UUID,

    -- Action
    action VARCHAR(100) NOT NULL,
    resource_affected VARCHAR(255),
    old_value TEXT,
    new_value TEXT,

    -- Result
    success BOOLEAN DEFAULT TRUE,
    failure_reason TEXT,

    -- Timing
    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_admin_user FOREIGN KEY (admin_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_admin_log_time ON m23_governance.admin_audit_logs(performed_at DESC);
COMMENT ON TABLE m23_governance.admin_audit_logs IS 'High-security logging for privileged administrator actions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 322 - feature_usage_analytics
-- Description: Usage stats for M23 features.
-- Business Case: Product Management. Which features do users actually use? (e.g.,
-- "Do they use the 'Blame' view?" or "Do they rely on 'Merge Queues'?").
-- KPIs: 1. Feature Adoption Rate, 2. User Engagement Score.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.feature_usage_analytics (
    -- Primary Key
    usage_id BIGSERIAL PRIMARY KEY,

    -- Context
    user_id BIGINT, -- NULL for anonymous
    feature_name VARCHAR(100) NOT NULL,
    page_or_component VARCHAR(255),

    -- Interaction
    action_type VARCHAR(50), -- CLICK, VIEW, API_CALL
    duration_seconds INTEGER, -- Time spent (if applicable)

    -- Technical
    client_type VARCHAR(50), -- WEB, CLI, API
    browser_name VARCHAR(50),

    -- Timing
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_usage_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id)
);

-- Partition by month (Example of advanced optimization)
-- CREATE TABLE m23_governance.feature_usage_analytics_y2024m01 PARTITION OF m23_governance.feature_usage_analytics
-- FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

COMMENT ON TABLE m23_governance.feature_usage_analytics IS 'Tracks how contributors interact with the M23 platform.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 323 - search_query_logs
-- Description: Logs of user search queries.
-- Business Case: Search Optimization. Identifying what users search for (and fail to find)
-- helps improve documentation and code navigation.
-- KPIs: 1. Search Success Rate (Click-through), 2. Top Missed Queries.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.search_query_logs (
    -- Primary Key
    query_id BIGSERIAL PRIMARY KEY,

    -- Query
    user_id BIGINT,
    query_string TEXT NOT NULL,
    search_type VARCHAR(50), -- CODE, DOCS, ISSUES, COMMITS

    -- Results
    result_count INTEGER DEFAULT 0,
    clicked_result_id BIGINT,
    clicked_result_position INTEGER,

    -- Timing
    query_latency_ms INTEGER,
    searched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_search_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.search_query_logs IS 'Analyzes search behavior to improve platform discoverability.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 324 - notification_failures
-- Description: Failed notification attempts.
-- Business Case: Reliability. If email bounces or Slack returns 4xx, we log it here
-- to maintain contact validity.
-- KPIs: 1. Delivery Failure Rate, 2. Invalid Contact Count.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.notification_failures (
    -- Primary Key
    failure_id BIGSERIAL PRIMARY KEY,

    -- Linking
    notification_id BIGINT NOT NULL,

    -- Failure
    channel VARCHAR(50) NOT NULL, -- EMAIL, SLACK, WEBHOOK
    destination VARCHAR(255), -- email address or webhook URL
    error_code VARCHAR(50), -- 550, 404
    error_message TEXT,

    -- Retries
    is_permanent_failure BOOLEAN DEFAULT FALSE,
    last_attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_notif_fail FOREIGN KEY (notification_id) REFERENCES m23_governance.notifications(notification_id)
);

COMMENT ON TABLE m23_governance.notification_failures IS 'Tracks errors encountered during notification delivery.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 325 - system_health_metrics
-- Description: Health metrics of the M23 platform.
-- Business Case: Infrastructure Monitoring. CPU, RAM, DB connections for the Postgres
-- instance running M23 itself.
-- KPIs: 1. System Availability, 2. DB Connection Pool Usage.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.system_health_metrics (
    -- Primary Key
    metric_id BIGSERIAL PRIMARY KEY,

    -- Service
    service_name VARCHAR(100) NOT NULL, -- WEB_APP, API, WORKER, DB

    -- Metrics
    cpu_percent NUMERIC(5,2),
    memory_percent NUMERIC(5,2),
    disk_io_percent NUMERIC(5,2),
    active_connections INTEGER,
    queue_depth INTEGER,

    -- Status
    status VARCHAR(20) DEFAULT 'HEALTHY', -- HEALTHY, DEGRADED, DOWN

    -- Audit
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_health_service_time ON m23_governance.system_health_metrics(service_name, measured_at DESC);
COMMENT ON TABLE m23_governance.system_health_metrics IS 'Telemetry regarding the operational health of the governance platform.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 326 - background_jobs
-- Description: Queue of background tasks.
-- Business Case: Async Processing. Tasks like "Generate PDF Report" or "Recalculate Stats"
-- are pushed here and picked up by workers.
-- KPIs: 1. Job Queue Latency, 2. Job Failure Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.background_jobs (
    -- Primary Key
    job_id BIGSERIAL PRIMARY KEY,

    -- Definition
    job_type VARCHAR(100) NOT NULL, -- GENERATE_REPORT, CALC_STATS
    payload_jsonb JSONB NOT NULL,
    priority INTEGER DEFAULT 5,

    -- Status
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    locked_by VARCHAR(100), -- Worker instance ID
    locked_at TIMESTAMP WITH TIME ZONE,

    -- Result
    result_jsonb JSONB,
    error_message TEXT,

    -- Timing
    scheduled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    queue_duration_seconds INTEGER, -- Time waited in queue
    run_duration_seconds INTEGER,   -- Time spent processing

    -- Constraints
    CONSTRAINT uq_background_jobs UNIQUE (job_id) -- In Pg, SERIAL is already unique
);

CREATE INDEX idx_bg_status_priority ON m23_governance.background_jobs(status, priority DESC, scheduled_at);
COMMENT ON TABLE m23_governance.background_jobs IS 'Queue for asynchronous background processing tasks.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 327 - lock_management
-- Description: Distributed locks for tasks.
-- Business Case: Concurrency Control. Prevents two workers from processing the same PR
-- or report simultaneously.
-- KPIs: 1. Lock Contention Time.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.lock_management (
    -- Primary Key
    lock_name VARCHAR(255) PRIMARY KEY,

    -- Lock Info
    owner_token VARCHAR(100) NOT NULL, -- Unique ID of the worker holding the lock
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_lock_expiry ON m23_governance.lock_management(expires_at);
COMMENT ON TABLE m23_governance.lock_management IS 'Provides advisory locking for background workers.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 328 - oauth_state_tokens
-- Description: State tokens for OAuth flows.
-- Business Case: Security. OAuth requires a `state` param to prevent CSRF. Stores these
-- temporarily during login/signup.
-- KPIs: 1. CSRF Attempt Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.oauth_state_tokens (
    -- Primary Key
    token_id SERIAL PRIMARY KEY,

    -- Token
    state_token CHAR(64) NOT NULL UNIQUE, -- Random hash

    -- Context
    provider VARCHAR(50) NOT NULL, -- google, github
    redirect_url TEXT NOT NULL,
    user_context JSONB, -- Data to restore after auth

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_oauth_state ON m23_governance.oauth_state_tokens(state_token);
COMMENT ON TABLE m23_governance.oauth_state_tokens IS 'Short-lived tokens to secure OAuth authentication flows.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 329 - captcha_challenges
-- Description: Captcha logs for anti-automation.
-- Business Case: Bot Prevention. Logs Captcha solves (success/fail) to detect bot
-- swarms trying to spam issues.
-- KPIs: 1. Bot Block Rate.
-- Feature Reference: 1
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.captcha_challenges (
    -- Primary Key
    challenge_id BIGSERIAL PRIMARY KEY,

    -- Context
    ip_address INET,
    user_agent TEXT,
    action_attempted VARCHAR(50), -- CREATE_ISSUE, SIGN_UP

    -- Result
    provider VARCHAR(50), -- RECAPTCHA, HCAPTCHA
    score NUMERIC(3,2), -- 0.0 to 1.0 (Human vs Bot)
    is_passed BOOLEAN DEFAULT FALSE,
    failure_reason TEXT,

    -- Timing
    challenged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.captcha_challenges IS 'Records Captcha verification attempts to mitigate automated spam.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 330 - rate_limit_buckets
-- Description: Token bucket state for rate limiting.
-- Business Case: Throttling. Stores current token count for users/IPs to enforce API limits.
-- KPIs: 1. Rate Limit Violation Count.
-- Feature Reference: 134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.rate_limit_buckets (
    -- Primary Key
    bucket_key VARCHAR(255) PRIMARY KEY, -- e.g., "user:123" or "ip:1.2.3.4"

    -- Bucket Config
    max_tokens INTEGER NOT NULL,
    refill_rate INTEGER NOT NULL, -- Tokens per second/minute

    -- State
    current_tokens INTEGER NOT NULL,
    last_refill_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.rate_limit_buckets IS 'State storage for the token bucket algorithm.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 331 - feedback_submissions
-- Description: User feedback forms.
-- Business Case: Continuous Improvement. General "How are we doing?" forms distinct from
-- specific UX surveys.
-- KPIs: 1. Response Rate, 2. Sentiment Score.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.feedback_submissions (
    -- Primary Key
    submission_id BIGSERIAL PRIMARY KEY,

    -- User
    contributor_id BIGINT,
    email VARCHAR(255), -- Optional for non-users

    -- Feedback
    category VARCHAR(50) NOT NULL, -- BUG, FEATURE_REQUEST, COMPLAINT, PRAISE
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    comment TEXT,

    -- Context
    page_url TEXT,
    platform_user_agent TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_fb_user FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.feedback_submissions IS 'Collects general user feedback and sentiment.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 332 - content_moderation_queue
-- Description: Queue for reported content.
-- Business Case: Community Safety. When a user reports a comment/PR as offensive, it goes
-- here for moderator review.
-- KPIs: 1. Moderation Queue Size, 2. Resolution Time.
-- Feature Reference: 44
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.content_moderation_queue (
    -- Primary Key
    report_id BIGSERIAL PRIMARY KEY,

    -- Content
    content_type VARCHAR(50) NOT NULL, -- COMMENT, PR_TITLE, ISSUE_BODY
    content_id BIGINT NOT NULL,
    text_snippet TEXT, -- The offending text

    -- Report
    reporter_id BIGINT NOT NULL,
    reason VARCHAR(50), -- ABUSE, SPAM, OFF_TOPIC
    severity VARCHAR(20), -- LOW, MEDIUM, HIGH

    -- Review
    reviewer_id BIGINT,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    reviewed_at TIMESTAMP WITH TIME ZONE,
    action_taken VARCHAR(100), -- DELETED_CONTENT, BANNED_USER, WARNED

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_mod_reporter FOREIGN KEY (reporter_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_mod_reviewer FOREIGN KEY (reviewer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.content_moderation_queue IS 'Manages workflow for user-reported content violations.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 333 - dynamic_configurations
-- Description: Runtime config stored in DB.
-- Business Case: Agility. Allows changing feature flags or banners without redeploying code.
-- KPIs: 1. Config Update Frequency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dynamic_configurations (
    -- Primary Key
    config_key VARCHAR(255) PRIMARY KEY,

    -- Value
    value_text TEXT,
    value_json JSONB,
    value_type VARCHAR(20) DEFAULT 'TEXT', -- TEXT, JSON, BOOL, INT

    -- Metadata
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE, -- Can clients read this?
    requires_restart BOOLEAN DEFAULT FALSE,

    -- Versioning
    version INTEGER DEFAULT 1,

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT
);

COMMENT ON TABLE m23_governance.dynamic_configurations IS 'Runtime feature flags and settings.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 334 - scheduled_report_queue
-- Description: Queue for scheduled reports.
-- Business Case: Automation. Queues jobs to generate weekly reports (Contributor stats,
-- Security summary) and email them.
-- KPIs: 1. On-Time Delivery.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.scheduled_report_queue (
    -- Primary Key
    queue_id BIGSERIAL PRIMARY KEY,

    -- Report
    report_type VARCHAR(50) NOT NULL, -- WEEKLY_DIGEST, MONTHLY_SECURITY
    parameters_jsonb JSONB NOT NULL, -- Date ranges, filters

    -- Recipient
    recipient_type VARCHAR(50), -- USER, TEAM, SLACK_CHANNEL
    recipient_address VARCHAR(255),

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, GENERATING, SENT, FAILED
    generated_url TEXT,
    error_message TEXT,

    -- Scheduling
    scheduled_for TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.scheduled_report_queue IS 'Manages periodic report generation and delivery.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 335 - cache_invalidation_logs
-- Description: Logs of cache invalidation events.
-- Business Case: Data Consistency. When we purge a cache (e.g., for a PR), we log why
-- and when to debug stale data issues.
-- KPIs: 1. Cache Hit Efficiency.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.cache_invalidation_logs (
    -- Primary Key
    invalidation_id BIGSERIAL PRIMARY KEY,

    -- Cache
    cache_key VARCHAR(255) NOT NULL,
    cache_type VARCHAR(50), -- API_RESPONSE, FILE_CONTENT, PERMISSIONS

    -- Context
    trigger_event VARCHAR(100), -- PR_MERGED, USER_UPDATED, MANUAL_PURGE
    triggerer_id BIGINT,
    reason TEXT,

    -- Audit
    invalided_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_cache_triggerer FOREIGN KEY (triggerer_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.cache_invalidation_logs IS 'Tracks when and why application cache entries were cleared.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 336 - external_service_health
-- Description: Health of external dependencies.
-- Business Case: Availability. Is GitHub API up? Is S3 reachable? Pinger checks.
-- KPIs: 1. External Dependency Uptime.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.external_service_health (
    -- Primary Key
    health_id BIGSERIAL PRIMARY KEY,

    -- Service
    service_name VARCHAR(100) NOT NULL, -- GITHUB_API, S3, SLACK_WEBHOOK
    endpoint_url TEXT,

    -- Status
    status VARCHAR(20) NOT NULL, -- UP, DOWN, DEGRADED
    latency_ms INTEGER,
    status_code INTEGER,

    -- Timing
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ext_health_service_time ON m23_governance.external_service_health(service_name, checked_at DESC);
COMMENT ON TABLE m23_governance.external_service_health IS 'Heartbeat checks for third-party services.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 337 - email_templates
-- Description: Content of email notifications.
-- Business Case: Consistency. Stores HTML/Text bodies for emails so we can update
-- wording without code deploy.
-- KPIs: 1. Template Click-through Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.email_templates (
    -- Primary Key
    template_id SERIAL PRIMARY KEY,

    -- Definition
    name VARCHAR(100) NOT NULL UNIQUE, -- PR_MERGED, SECURITY_ALERT
    subject_line VARCHAR(255) NOT NULL,

    -- Content
    body_html TEXT,
    body_text TEXT,
    variables_json JSONB, -- e.g., {user_name, pr_number}

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    locale VARCHAR(10) DEFAULT 'en_US', -- en_US, fr_FR

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT
);

COMMENT ON TABLE m23_governance.email_templates IS 'Stores customizable content for transactional emails.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 338 - user_sessions
-- Description: Active user sessions.
-- Business Case: Session Management. Tracks active web sessions to allow "Logout everywhere"
-- and security revocation.
-- KPIs: 1. Average Session Duration.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.user_sessions (
    -- Primary Key
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- User
    user_id BIGINT NOT NULL,

    -- Session
    ip_address INET,
    user_agent TEXT,
    device_fingerprint CHAR(32),

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ended_at TIMESTAMP WITH TIME ZONE,

    -- Status
    is_revoked BOOLEAN DEFAULT FALSE,

    -- Constraints
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id)
);

CREATE INDEX idx_session_user ON m23_governance.user_sessions(user_id);
CREATE INDEX idx_session_expiry ON m23_governance.user_sessions(expires_at);
COMMENT ON TABLE m23_governance.user_sessions IS 'Manages authentication sessions for web users.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 339 - failed_login_attempts
-- Description: Logs of failed auth attempts.
-- Business Case: Security Monitoring. Detects brute force attacks or credential stuffing.
-- KPIs: 1. Lockout Trigger Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.failed_login_attempts (
    -- Primary Key
    attempt_id BIGSERIAL PRIMARY KEY,

    -- Attempt
    username_or_email VARCHAR(255),
    ip_address INET NOT NULL,
    user_agent TEXT,

    -- Result
    failure_reason VARCHAR(50), -- INVALID_CREDENTIALS, ACCOUNT_LOCKED, CAPTCHA_FAIL

    -- Timing
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_failed_login_ip ON m23_governance.failed_login_attempts(ip_address, attempted_at DESC);
COMMENT ON TABLE m23_governance.failed_login_attempts IS 'Security log tracking failed authentication attempts.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 340 - data_retention_queue
-- Description: Queue for data deletion jobs.
-- Business Case: Privacy/GDPR. Anonymization tasks (e.g., "Anonymize comments > 3 years old")
-- are queued here.
-- KPIs: 1. Retention Compliance.
-- Feature Reference: 151
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.data_retention_queue (
    -- Primary Key
    task_id BIGSERIAL PRIMARY KEY,

    -- Target
    target_type VARCHAR(50) NOT NULL, -- CONTRIBUTOR, COMMENT, AUDIT_LOG
    target_id BIGINT NOT NULL,
    retention_policy_applied VARCHAR(100),

    -- Action
    action VARCHAR(20) NOT NULL, -- ANONYMIZE, DELETE, ARCHIVE
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, PROCESSING, DONE

    -- Audit
    scheduled_for TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,
    processed_by BIGINT
);

COMMENT ON TABLE m23_governance.data_retention_queue IS 'Manages lifecycle of data deletion and anonymization jobs.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 341 - platform_announcements
-- Description: Global announcements.
-- Business Case: Communication. Site-wide banners (e.g., "Scheduled Maintenance")
-- displayed to all users.
-- KPIs: 1. View Count.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.platform_announcements (
    -- Primary Key
    announcement_id SERIAL PRIMARY KEY,

    -- Content
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    announcement_type VARCHAR(50), -- INFO, WARNING, MAINTENANCE

    -- Display
    is_active BOOLEAN DEFAULT FALSE,
    show_from TIMESTAMP WITH TIME ZONE,
    show_until TIMESTAMP WITH TIME ZONE,
    dismissible BOOLEAN DEFAULT TRUE,

    -- Audience
    target_audience VARCHAR(50) DEFAULT 'ALL', -- ALL, ADMINS, CONTRIBUTORS

    -- Audit
    created_by BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_announce_creator FOREIGN KEY (created_by) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.platform_announcements IS 'Broadcasts important messages to all platform users.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 342 - integration_logs
-- Description: Logs from 3rd party integrations.
-- Business Case: Debugging. Logs raw JSON payloads received from Jira, Slack, PagerDuty webhooks
-- to ensure M23 is processing them correctly.
-- KPIs: 1. Integration Processing Error Rate.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.integration_logs (
    -- Primary Key
    log_id BIGSERIAL PRIMARY KEY,

    -- Source
    source_system VARCHAR(50) NOT NULL, -- JIRA, GITHUB, SLACK
    event_type VARCHAR(100),

    -- Data
    payload_json JSONB NOT NULL,
    raw_headers TEXT,

    -- Processing
    processing_status VARCHAR(20) DEFAULT 'RECEIVED', -- RECEIVED, PROCESSED, FAILED
    error_message TEXT,

    -- Audit
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE m23_governance.integration_logs IS 'Detailed logs of incoming data from external systems.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 343 - theme_settings
-- Description: UI theme preferences.
-- Business Case: Accessibility/User Preference. Stores user choices for Dark Mode, font size, etc.
-- KPIs: 1. Theme Adoption.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.theme_settings (
    -- Primary Key
    setting_id BIGSERIAL PRIMARY KEY,

    -- User
    user_id BIGINT NOT NULL,

    -- Preferences
    theme_mode VARCHAR(20) DEFAULT 'LIGHT', -- LIGHT, DARK, SYSTEM
    accent_color VARCHAR(7), -- Hex code
    font_size VARCHAR(20) DEFAULT 'MEDIUM', -- SMALL, MEDIUM, LARGE

    -- Accessibility
    high_contrast BOOLEAN DEFAULT FALSE,
    reduced_motion BOOLEAN DEFAULT FALSE,

    -- Audit
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT fk_theme_user FOREIGN KEY (user_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT uq_theme_user UNIQUE (user_id)
);

COMMENT ON TABLE m23_governance.theme_settings IS 'Personalization settings for user interface appearance.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 344 - documentation_likes
-- Description: Likes on documentation pages.
-- Business Case: Feedback. Helps identify which docs are helpful and which are confusing.
-- KPIs: 1. Doc Engagement.
-- Feature Reference: 46
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.documentation_likes (
    -- Composite Primary Key
    doc_id BIGINT NOT NULL, -- Refers to doc id in wiki_pages or file system
    user_id BIGINT NOT NULL,

    -- Feedback
    is_helpful BOOLEAN DEFAULT TRUE,
    feedback_text TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_doc_likes UNIQUE (doc_id, user_id)
);

COMMENT ON TABLE m23_governance.documentation_likes IS 'User feedback on documentation utility.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 345 - contributor_notes
-- Description: Private admin notes on contributors.
-- Business Case: Admin Tool. Allows admins to tag users (e.g., "VIP", "Troublesome")
-- visible only to staff.
-- KPIs: N/A
-- Feature Reference: 15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.contributor_notes (
    -- Primary Key
    note_id BIGSERIAL PRIMARY KEY,

    -- Subject
    contributor_id BIGINT NOT NULL,

    -- Note
    note_text TEXT NOT NULL,
    note_type VARCHAR(50) DEFAULT 'GENERAL', -- WARNING, VIP, SPAMMER

    -- Author
    author_id BIGINT NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_note_contributor FOREIGN KEY (contributor_id) REFERENCES m23_governance.contributors(contributor_id),
    CONSTRAINT fk_note_author FOREIGN KEY (author_id) REFERENCES m23_governance.contributors(contributor_id)
);

COMMENT ON TABLE m23_governance.contributor_notes IS 'Internal staff annotations on community members.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 346 - event_logs
-- Description: Generic high-volume event logs.
-- Business Case: Analytics. Storing clickstreams, page views, and detailed UI events that are
-- too voluminous for the primary audit trail.
-- KPIs: 1. User Path Analysis.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.event_logs (
    -- Primary Key
    event_id BIGSERIAL PRIMARY KEY,

    -- Event
    event_name VARCHAR(100) NOT NULL,
    event_category VARCHAR(50),

    -- Context
    user_id BIGINT,
    session_id UUID,
    url TEXT,
    properties_jsonb JSONB,

    -- Timing
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Partition by month recommended for this table
CREATE INDEX idx_event_logs_user_time ON m23_governance.event_logs(user_id, occurred_at DESC);
COMMENT ON TABLE m23_governance.event_logs IS 'High-volume telemetry for user interaction analytics.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 347 - error_logs
-- Description: Application error logs.
-- Business Case: Debugging. Centralizing exceptions thrown by the M23 web/app workers.
-- KPIs: 1. Error Rate per Endpoint.
-- Feature Reference: 68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.error_logs (
    -- Primary Key
    error_id BIGSERIAL PRIMARY KEY,

    -- Error
    error_message TEXT NOT NULL,
    stack_trace TEXT,
    error_code VARCHAR(50),

    -- Context
    request_id UUID,
    user_id BIGINT,
    url TEXT,
    http_method VARCHAR(10),

    -- Severity
    severity VARCHAR(20) DEFAULT 'ERROR', -- DEBUG, INFO, WARN, ERROR, FATAL

    -- Timing
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_error_logs_time ON m23_governance.error_logs(occurred_at DESC);
CREATE INDEX idx_error_logs_user ON m23_governance.error_logs(user_id);
COMMENT ON TABLE m23_governance.error_logs IS 'Centralized repository for application exceptions.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 348 - migration_checksums
-- Description: Checksums of applied DB migrations.
-- Business Case: Data Integrity. Ensures that the SQL file on disk matches what was actually
-- applied to the DB, detecting accidental edits.
-- KPIs: 1. Migration Integrity.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.migration_checksums (
    -- Primary Key
    checksum_id SERIAL PRIMARY KEY,

    -- Migration
    version VARCHAR(255) NOT NULL,
    filename TEXT NOT NULL,

    -- Checksums
    file_checksum CHAR(64) NOT NULL, -- SHA256 of the file
    applied_checksum CHAR(64) NOT NULL, -- SHA256 of the SQL actually executed (injected statements)

    -- Audit
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_mig_checksums UNIQUE (version, filename)
);

COMMENT ON TABLE m23_governance.migration_checksums IS 'Verifies file integrity against database migration history.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 349 - dependency_graph_cache
-- Description: Pre-calculated dependency graph.
-- Business Case: Visualization. Rendering a graph of 1000 dependencies is slow. Stores
-- adjacency list here for instant retrieval.
-- KPIs: 1. Graph Load Time.
-- Feature Reference: 5
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.dependency_graph_cache (
    -- Composite Primary Key
    run_id BIGINT NOT NULL,
    parent_dep_id BIGINT NOT NULL,
    child_dep_id BIGINT NOT NULL,

    -- Graph Properties
    depth INTEGER,
    is_transitive BOOLEAN DEFAULT FALSE,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_graph_run FOREIGN KEY (run_id) REFERENCES m23_governance.ci_pipeline_runs(run_id)
);

CREATE INDEX idx_graph_parent ON m23_governance.dependency_graph_cache(parent_dep_id);
COMMENT ON TABLE m23_governance.dependency_graph_cache IS 'Optimized storage for visualizing dependency relationships.';

-- --------------------------------------------------------------------------------------------------------
-- Table: 350 - schema_snapshot_history
-- Description: Full snapshots of DB schema.
-- Business Case: Disaster Recovery. If a migration destroys data, having a full snapshot
-- of the DDL before the change helps recovery (aside from backups).
-- KPIs: 1. Snapshot Frequency.
-- Feature Reference: 6
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m23_governance.schema_snapshot_history (
    -- Primary Key
    snapshot_id SERIAL PRIMARY KEY,

    -- Context
    migration_version VARCHAR(255) NOT NULL,
    git_commit_sha CHAR(40) NOT NULL,

    -- Snapshot
    schema_ddl JSONB NOT NULL, -- Full DDL of all tables
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE m23_governance.schema_snapshot_history IS 'Point-in-time copies of database schema definitions.';

-- ==========================================================================================================
-- Final Cleanup and Validation (Triggers)
-- ==========================================================================================================

-- Apply Updated At triggers to remaining tables
CREATE TRIGGER trg_dynamic_configurations_updated_at BEFORE UPDATE ON m23_governance.dynamic_configurations
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

CREATE TRIGGER trg_email_templates_updated_at BEFORE UPDATE ON m23_governance.email_templates
    FOR EACH ROW EXECUTE FUNCTION m23_governance.trigger_set_updated_at();

-- ==========================================================================================================
-- End of Part 6c (Tables 311-350)
-- Total Database Objects Created: 350
-- ==========================================================================================================
