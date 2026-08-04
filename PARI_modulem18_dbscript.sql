-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation
-- Database Schema: PostgreSQL
-- Description: Comprehensive schema for Quantitative Management, SPC, Risk Modeling, and Automated Governance.
-- =====================================================================================================================

-- 1. Schema Creation
-- =====================================================================================================================
CREATE SCHEMA IF NOT EXISTS cmmi AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA cmmi IS 'CMMI Level 5 Process Automation Schema: Manages quantitative metrics, SPC data, Monte Carlo simulations, and process optimization records for the PARI ecosystem.';

-- 2. Extensions
-- =====================================================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides functions to generate universally unique identifiers (UUIDs) for primary keys and references.';

CREATE EXTENSION IF NOT EXISTS "pg_trgm";
COMMENT ON EXTENSION "pg_trgm" IS 'Provides functions and operators for determining the similarity of alphanumeric text based on trigram matching, essential for searching log messages and commit notes.';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to handle standard B-tree equality checks, useful for composite indexes involving JSONB and standard types.';

CREATE EXTENSION IF NOT EXISTS "tsm_system_rows";
COMMENT ON EXTENSION "tsm_system_rows" IS 'Provides table sampling method for SYSTEM_ROWS, useful for statistical sampling in Monte Carlo simulations.';

-- 2.a List of Database Objects to be Implemented (First 50)
-- Tables: metric_raw_data, metric_sources, spc_control_limits, spc_violations, monte_carlo_simulations, defect_records,
--          code_churn_metrics, commit_sentiments, test_coverage_reports, technical_debt_metrics, peer_reviews,
--          five_why_analyses, log_clusters, release_risk_scores, developer_fatigue, flaky_tests, sast_findings,
--          dependency_vulnerabilities, process_capability_indices, build_failure_predictions, rollback_decisions,
--          sprint_burndowns, code_duplications, security_policy_violations, pipeline_efficiency, incident_mttr_predictions,
--          deployments, author_reputation, retrospective_summaries, defect_aging, test_execution_times, arch_violations,
--          api_contract_drifts, pr_cognitive_load, merge_conflict_predictions, onboarding_metrics, license_compliance,
--          doc_coverage, dead_code_analysis, sql_performance, memory_leak_simulation, thread_safety_warnings,
--          req_traceability, skill_gaps, meeting_load, remote_collab_index, code_ownership, release_notes, slo_error_budgets,
--          risk_hotspots
-- Enums: defect_severity_enum, sentiment_label_enum, finding_status_enum, deployment_status_enum, license_risk_enum, circuit_state_enum

-- =====================================================================================================================
-- 3. Enumerated Types (Enums)
-- =====================================================================================================================

-- Enum: M18-E001 - defect_severity_enum
-- Description: Defines the criticality levels of defects discovered during the SDLC.
-- Business Case: Standardizing severity allows for automated prioritization of fixes and accurate calculation of defect escape rates.
--                 High-severity defects trigger immediate SPC violations.
-- Feature Reference: M18-F006 (Defect Density Trend Analysis)
CREATE TYPE cmmi.defect_severity_enum AS ENUM (
    'Critical',
    'High',
    'Medium',
    'Low'
);
COMMENT ON TYPE cmmi.defect_severity_enum IS 'Severity classification for software defects determining priority and impact on SPC limits.';

-- Enum: M18-E002 - sentiment_label_enum
-- Description: Categorizes the emotional tone of developer communications and commit messages.
-- Business Case: Tracking developer sentiment serves as a leading indicator for defect injection. High stress or negative sentiment
--                 correlates with lower code quality and higher technical debt.
-- Feature Reference: M18-F008 (AI-Driven Commit Sentiment Analysis)
CREATE TYPE cmmi.sentiment_label_enum AS ENUM (
    'Positive',
    'Neutral',
    'Negative'
);
COMMENT ON TYPE cmmi.sentiment_label_enum IS 'NLP-derived sentiment classification for analyzing team morale and code quality correlation.';

-- Enum: M18-E003 - finding_status_enum
-- Description: Status lifecycle for Static Application Security Testing (SAST) findings.
-- Business Case: Managing the lifecycle of security findings ensures that vulnerabilities are tracked from detection to resolution,
--                 preventing code containing known vulnerabilities from reaching production.
-- Feature Reference: M18-F017 (Static Analysis Severity Triaging)
CREATE TYPE cmmi.finding_status_enum AS ENUM (
    'True Positive',
    'False Positive',
    'Pending'
);
COMMENT ON TYPE cmmi.finding_status_enum IS 'Workflow status for security analysis findings, distinguishing confirmed vulnerabilities from noise.';

-- Enum: M18-E004 - deployment_status_enum
-- Description: Current state of a deployment event in the pipeline.
-- Business Case: Accurate status tracking is required for real-time monitoring of DORA metrics (Deployment Frequency, Change Failure Rate)
--                 and triggering automated rollback procedures.
-- Feature Reference: M18-F027 (Change Failure Rate Monitor)
CREATE TYPE cmmi.deployment_status_enum AS ENUM (
    'Success',
    'Failed',
    'Rolled Back'
);
COMMENT ON TYPE cmmi.deployment_status_enum IS 'Status indicator for deployment operations, used in calculating process reliability metrics.';

-- Enum: M18-E005 - license_risk_enum
-- Description: Risk level assessment for open-source library licenses.
-- Business Case: Legal compliance is critical in fintech. Automatically categorizing license risk prevents the accidental inclusion
--                 of GPL/AGPL code that could compromise proprietary algorithms.
-- Feature Reference: M18-F039 (Open Source License Compliance Check)
CREATE TYPE cmmi.license_risk_enum AS ENUM (
    'High',
    'Medium',
    'Low',
    'Approved'
);
COMMENT ON TYPE cmmi.license_risk_enum IS 'Categorization of legal and copyright risk associated with third-party software licenses.';

-- Enum: M18-E006 - circuit_state_enum
-- Description: Operational state of circuit breakers in the microservices architecture.
-- Business Case: Circuit breakers prevent cascading failures. Monitoring their state is essential for SLO error budget calculations
--                 and maintaining system availability.
-- Feature Reference: M18-F106 (Circuit Breaker State Monitor)
CREATE TYPE cmmi.circuit_state_enum AS ENUM (
    'Closed',
    'Open',
    'Half-Open'
);
COMMENT ON TYPE cmmi.circuit_state_enum IS 'State of a circuit breaker mechanism used to fault-tolerant service communication.';

-- =====================================================================================================================
-- Common Trigger Function for Timestamp Management
-- =====================================================================================================================
CREATE OR REPLACE FUNCTION cmmi.update_modified_column()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;
COMMENT ON FUNCTION cmmi.update_modified_column() IS 'Automatically updates the updated_at timestamp whenever a record is modified.';

-- =====================================================================================================================
-- 4. DDL Statements (Tables 1-50)
-- =====================================================================================================================

-- Table: M18-T001 - metric_raw_data
-- Description: Stores high-volume time-series metric data ingested from Git, CI/CD, Jira, and infrastructure monitoring.
-- Business Case: As the foundational data lake for Module M18, this table stores the raw events required for Statistical Process Control (SPC).
--                 It enables historical analysis of process performance, correlation analysis between code churn and defects, and provides
--                 the input stream for AI-driven anomaly detection. Efficient partitioning and indexing are critical to handle the massive
--                 throughput of telemetry data in a high-frequency trading environment.
-- KPIs: Ingestion Latency (ms), Data Completeness (%), Storage Utilization (%), Query Performance (p95), Retention Compliance.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion Service)
CREATE TABLE IF NOT EXISTS cmmi.metric_raw_data (
    -- Primary Key
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identifiers
    source_id VARCHAR(100) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,

    -- Measurement
    value NUMERIC(18, 6) NOT NULL,
    unit VARCHAR(50), -- e.g., 'ms', 'count', 'bytes'

    -- Context
    tags JSONB DEFAULT '{}', -- Flexible key-value pairs for dimensions (e.g., env, service)
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metadata
    ingestion_lag_ms INTEGER, -- Time from event occurrence to DB write
    data_quality_score NUMERIC(3,2), -- 0.00 to 1.00

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT metric_raw_data_timestamp_check CHECK (timestamp <= CURRENT_TIMESTAMP),
    CONSTRAINT metric_raw_data_quality_check CHECK (data_quality_score IS NULL OR (data_quality_score >= 0 AND data_quality_score <= 1))
) PARTITION BY RANGE (timestamp);

-- Create a default partition for future data (Postgres 10+)
CREATE TABLE IF NOT EXISTS cmmi.metric_raw_data_default PARTITION OF cmmi.metric_raw_data DEFAULT;

COMMENT ON TABLE cmmi.metric_raw_data IS 'Partitioned time-series storage for all raw system and process metrics.';
COMMENT ON COLUMN cmmi.metric_raw_data.tags IS 'JSONB object containing flexible dimensions for filtering (e.g., {"team": "payments", "region": "us-east-1"}).';

-- Indexes for T001
CREATE INDEX idx_metric_raw_data_source_name_time ON cmmi.metric_raw_data (source_id, metric_name, timestamp DESC);
CREATE INDEX idx_metric_raw_data_tags ON cmmi.metric_raw_data USING GIN (tags);
CREATE INDEX idx_metric_raw_data_timestamp ON cmmi.metric_raw_data (timestamp);

-- Table: M18-T002 - metric_sources
-- Description: Registry of all systems and tools providing metrics to Module M18.
-- Business Case: Centralized configuration management for metric sources. This allows for dynamic reconfiguration of the data ingestion
--                 pipeline without code changes. It provides metadata for lineage tracking, ensuring that every data point in the
--                 raw metrics table can be traced back to a verified, authorized source, which is a requirement for CMMI high maturity.
-- KPIs: Source Availability (%), Connection Success Rate (%), Configuration Drift Incidents, Source Onboarding Time, Auth Failures.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion Service)
CREATE TABLE IF NOT EXISTS cmmi.metric_sources (
    source_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- e.g., 'JIRA', 'GIT', 'PROMETHEUS', 'SONARQUBE'

    -- Connection Details (Encrypted or in Vault ref ideally, simplified here)
    connection_config JSONB NOT NULL, -- Stores URLs, API keys (hashed), ports

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    health_status VARCHAR(50) DEFAULT 'UNKNOWN', -- 'HEALTHY', 'DEGRADED', 'DOWN'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE cmmi.metric_sources IS 'Registry of metric providers and their connection configurations.';

-- Indexes for T002
CREATE INDEX idx_metric_sources_type ON cmmi.metric_sources (type);
CREATE INDEX idx_metric_sources_active ON cmmi.metric_sources (is_active) WHERE is_active = true;

-- Table: M18-T003 - spc_control_limits
-- Description: Stores calculated Upper Control Limits (UCL), Lower Control Limits (LCL), and Center Lines (CL) for metrics.
-- Business Case: Statistical Process Control (SPC) is the core of CMMI Level 5. This table persists the control limits that define
--                 the "voice of the process." By comparing real-time metrics against these stored limits, the system can
--                 automatically detect "special cause" variations—statistically significant deviations that indicate process
--                 instability and trigger automatic deployment halts.
-- KPIs: Process Capability (Cpk), Control Limit Recalculation Frequency, False Positive Rate (OOS), Limit Stability, Metric Coverage.
-- Feature Reference: M18-F003 (Automated SPC Chart Generation), M18-F019 (Process Capability Cpk Calculator)
CREATE TABLE IF NOT EXISTS cmmi.spc_control_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,

    -- Statistical Limits
    ucl NUMERIC(18, 6) NOT NULL, -- Upper Control Limit
    lcl NUMERIC(18, 6) NOT NULL, -- Lower Control Limit
    cl NUMERIC(18, 6) NOT NULL,  -- Center Line (Mean)

    -- Metadata
    sample_size INTEGER NOT NULL, -- N used for calculation
    sigma_level NUMERIC(4, 2) DEFAULT 3.0, -- Typically 3 sigma

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE, -- NULL implies current
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    calculated_by VARCHAR(100), -- 'SYSTEM' or user ID

    CONSTRAINT spc_control_limits_ucl_lcl_check CHECK (ucl > lcl)
);

COMMENT ON TABLE cmmi.spc_control_limits IS 'Storage for Statistical Process Control limits defining acceptable process variation.';

-- Indexes for T003
CREATE INDEX idx_spc_control_limits_metric ON cmmi.spc_control_limits (metric_name);
CREATE INDEX idx_spc_control_limits_validity ON cmmi.spc_control_limits (valid_from, valid_to);

-- Table: M18-T004 - spc_violations
-- Description: Logs instances where metrics breach defined control limits.
-- Business Case: This is the operational log of process instability. Every breach represents a potential quality escape or
--                 infrastructure failure. By logging these events with severity and context, M18 enables automated Root Cause
--                 Analysis (RCA) and provides data for calculating Process Sigma levels.
-- KPIs: Violations per Week, Mean Time To Restore (MTTR) from violation, Recurrence Rate (%), Critical Violation Count, Automated Containment Success.
-- Feature Reference: M18-F004 (Control Limit Breach Alerting)
CREATE TABLE IF NOT EXISTS cmmi.spc_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    value NUMERIC(18, 6) NOT NULL,

    -- Context
    ucl NUMERIC(18, 6),
    lcl NUMERIC(18, 6),
    deviation_magnitude NUMERIC(18, 6), -- How far outside the limit

    -- Severity
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Minor', 'Major', 'Critical')),

    -- Resolution
    acknowledged_by UUID,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT spc_violations_metric_fk FOREIGN KEY (metric_name) REFERENCES cmmi.spc_control_limits(metric_name) ON DELETE SET NULL
);

COMMENT ON TABLE cmmi.spc_violations IS 'Log of all special cause variations detected when metrics exceed control limits.';

-- Indexes for T004
CREATE INDEX idx_spc_violations_time ON cmmi.spc_violations (timestamp DESC);
CREATE INDEX idx_spc_violations_metric ON cmmi.spc_violations (metric_name);
CREATE INDEX idx_spc_violations_resolved ON cmmi.spc_violations (resolved_at) WHERE resolved_at IS NULL;

-- Table: M18-T005 - monte_carlo_simulations
-- Description: Stores parameters and results of Monte Carlo simulations used for risk modeling.
-- Business Case: Monte Carlo simulations provide probabilistic forecasting rather than single-point estimates. This table stores
--                 the inputs (velocity, risk profiles) and outputs (confidence intervals for delivery dates, success probabilities).
--                 This transforms release decisions from intuition into calculated business risks.
-- KPIs: Forecast Accuracy (%), Simulation Execution Time, Confidence Interval Width, Decision Support Usage, Risk Prediction Error.
-- Feature Reference: M18-F005 (Monte Carlo Velocity Simulation)
CREATE TABLE IF NOT EXISTS cmmi.monte_carlo_simulations (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    scenario_name VARCHAR(255) NOT NULL,

    -- Parameters
    iterations INTEGER NOT NULL, -- e.g., 10,000
    input_parameters JSONB NOT NULL, -- Velocity history, risk factors, etc.

    -- Results (Percentiles)
    p50 NUMERIC(10, 2), -- Median
    p85 NUMERIC(10, 2),
    p95 NUMERIC(10, 2),
    p99 NUMERIC(10, 2),

    -- Decision Metrics
    success_probability NUMERIC(5, 2), -- 0.00 to 1.00
    on_time_date_probability NUMERIC(5, 2),

    -- Context
    target_release_id UUID,
    created_by UUID
);

COMMENT ON TABLE cmmi.monte_carlo_simulations IS 'Results of probabilistic risk modeling for release planning and capacity management.';

-- Indexes for T005
CREATE INDEX idx_monte_carlo_release ON cmmi.monte_carlo_simulations (target_release_id);
CREATE INDEX idx_monte_carlo_time ON cmmi.monte_carlo_simulations (timestamp DESC);

-- Table: M18-T006 - defect_records
-- Description: Master log of all software defects tracked by the organization.
-- Business Case: Central defect tracking is essential for Causal Analysis and Resolution (CAR). This table provides the data for
--                 calculating Defect Density, Escape Rate, and Age. It links defects to specific code modules, allowing M18 to
--                 identify "hotspots" and trigger automated training for developers associated with high defect injection rates.
-- KPIs: Defect Escape Rate (<0.05%), Defect Density (Defects/KLOC), Mean Time To Resolve (MTTR), Reopened Defect Rate (%), Defect Age.
-- Feature Reference: M18-F006 (Defect Density Trend Analysis), M18-F032 (Defect Age Analysis)
CREATE TABLE IF NOT EXISTS cmmi.defect_records (
    defect_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Origin
    external_id VARCHAR(100), -- Jira Key, etc.
    source_module VARCHAR(255),

    -- Details
    title TEXT NOT NULL,
    description TEXT,
    severity cmmi.defect_severity_enum NOT NULL,
    phase_found VARCHAR(50), -- 'Requirement', 'Coding', 'Unit Test', 'QA', 'Production'

    -- Lifecycle
    status VARCHAR(50) DEFAULT 'Open',
    found_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_date TIMESTAMP WITH TIME ZONE,

    -- Attribution
    assigned_to UUID,
    reporter_id UUID,

    -- Analysis
    root_cause_id UUID, -- Links to 5-why analysis
    is_escaping_defect BOOLEAN DEFAULT false, -- True if found in production

    -- Metrics
    affected_components TEXT[], -- Array of microservices/modules
    environment VARCHAR(50), -- Where found

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE cmmi.defect_records IS 'Comprehensive defect tracking lifecycle record for quality analysis.';

-- Indexes for T006
CREATE INDEX idx_defect_records_severity ON cmmi.defect_records (severity);
CREATE INDEX idx_defect_records_status ON cmmi.defect_records (status);
CREATE INDEX idx_defect_records_phase_found ON cmmi.defect_records (phase_found);
CREATE INDEX idx_defect_records_module ON cmmi.defect_records USING GIN (affected_components);

-- Table: M18-T007 - code_churn_metrics
-- Description: Tracks code churn (lines added/deleted) per commit.
-- Business Case: High code churn is a leading indicator of instability. This table allows the system to correlate rewrites with
--                 subsequent defect spikes. It helps identify modules that are in constant flux and may need refactoring or
--                 stabilization freezes before a release.
-- KPIs: Churn Rate (%), Churn vs Defect Correlation, High Churn Module Count, Refactoring ROI, Stabilization Time.
-- Feature Reference: M18-F007 (Code Churn Correlation Engine)
CREATE TABLE IF NOT EXISTS cmmi.code_churn_metrics (
    churn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    commit_id VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    author_id UUID NOT NULL,

    -- Metrics
    file_path TEXT NOT NULL,
    lines_added INTEGER NOT NULL,
    lines_deleted INTEGER NOT NULL,
    net_change INTEGER GENERATED ALWAYS AS (lines_added - lines_deleted) STORED,

    -- Analysis
    complexity_delta INTEGER, -- Change in cyclomatic complexity
    churn_score NUMERIC(5,2), -- Calculated impact score

    CONSTRAINT code_churn_metrics_check CHECK (lines_added >= 0 AND lines_deleted >= 0)
);

COMMENT ON TABLE cmmi.code_churn_metrics IS 'Tracks the volatility of code artifacts to predict potential defect injection.';

-- Indexes for T007
CREATE INDEX idx_code_churn_commit ON cmmi.code_churn_metrics (commit_id);
CREATE INDEX idx_code_churn_file ON cmmi.code_churn_metrics (file_path);
CREATE INDEX idx_code_churn_time ON cmmi.code_churn_metrics (timestamp DESC);

-- Table: M18-T008 - commit_sentiments
-- Description: Stores AI analysis of developer sentiment derived from commit messages.
-- Business Case: Developer burnout and stress are invisible risks. By analyzing commit messages for negative sentiment, M18 can
--                 predict increases in defect rates and intervene with support or workload adjustment before quality degrades.
-- KPIs: Negative Sentiment Ratio (%), Sentiment vs Defect Correlation, Burnout Prediction Accuracy, Team Morale Index, Intervention Effectiveness.
-- Feature Reference: M18-F008 (AI-Driven Commit Sentiment Analysis)
CREATE TABLE IF NOT EXISTS cmmi.commit_sentiments (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    commit_id VARCHAR(100) NOT NULL UNIQUE,
    author_id UUID,

    -- NLP Results
    sentiment_score NUMERIC(4, 3) NOT NULL, -- e.g., -0.9 to 0.9
    sentiment_label cmmi.sentiment_label_enum NOT NULL,
    confidence NUMERIC(3, 2), -- 0 to 1

    -- Categorization
    emotion_tags TEXT[], -- ['frustration', 'urgency', 'fatigue']

    -- Processing
    model_version VARCHAR(50),
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT commit_sentiments_score_check CHECK (sentiment_score >= -1 AND sentiment_score <= 1)
);

COMMENT ON TABLE cmmi.commit_sentiments IS 'Sentiment analysis of commit messages to gauge developer health and risk.';

-- Indexes for T008
CREATE INDEX idx_commit_sentiments_author ON cmmi.commit_sentiments (author_id);
CREATE INDEX idx_commit_sentiments_label ON cmmi.commit_sentiments (sentiment_label);
CREATE INDEX idx_commit_sentiments_tags ON cmmi.commit_sentiments USING GIN (emotion_tags);

-- Table: M18-T009 - test_coverage_reports
-- Description: Aggregated code coverage metrics per build.
-- Business Case: High test coverage is a primary gate for quality. This table enforces the "Shift Left" philosophy by preventing
--                 code with insufficient coverage from merging. It tracks trends in coverage to ensure that new features are adequately
--                 tested before reaching production.
-- KPIs: Line Coverage (>95%), Branch Coverage (%), Coverage Gate Enforcement Rate, Build Success vs Coverage, Test Suite Growth.
-- Feature Reference: M18-F009 (Automated Test Coverage Gate)
CREATE TABLE IF NOT EXISTS cmmi.test_coverage_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Metrics
    line_coverage NUMERIC(5, 2) NOT NULL, -- Percentage
    branch_coverage NUMERIC(5, 2) NOT NULL,

    -- Compliance
    threshold_met BOOLEAN NOT NULL, -- True if > 95%
    threshold_value NUMERIC(5, 2) DEFAULT 95.00,

    -- Context
    project_name VARCHAR(100),
    branch_name VARCHAR(100),

    CONSTRAINT test_coverage_reports_range CHECK (line_coverage >= 0 AND line_coverage <= 100 AND branch_coverage >= 0 AND branch_coverage <= 100)
);

COMMENT ON TABLE cmmi.test_coverage_reports IS 'Stores code coverage metrics to enforce quality gates.';

-- Indexes for T009
CREATE INDEX idx_test_coverage_build ON cmmi.test_coverage_reports (build_id);
CREATE INDEX idx_test_coverage_threshold ON cmmi.test_coverage_reports (threshold_met) WHERE NOT threshold_met;

-- Table: M18-T010 - technical_debt_metrics
-- Description: Snapshots of technical debt ratio and estimated remediation cost.
-- Business Case: Technical debt slows down velocity and increases defect risk. This table quantifies debt in financial terms,
--                 allowing engineering management to make data-driven decisions about when to pay down debt versus building new features.
-- KPIs: Debt Ratio (<5%), Remediation Cost ($), Interest (dev hours lost), Debt Repayment Velocity, Aged Debt (>6 months).
-- Feature Reference: M18-F010 (Technical Debt Ratio Calculator)
CREATE TABLE IF NOT EXISTS cmmi.technical_debt_metrics (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_date DATE NOT NULL,

    -- Metrics
    debt_ratio NUMERIC(5, 2) NOT NULL, -- Cost to fix / Cost to rebuild
    remediation_cost_est NUMERIC(15, 2), -- Estimated cost in currency
    principal NUMERIC(15, 2), -- The actual effort of fixing
    interest_hours NUMERIC(10, 2), -- Extra time spent due to debt

    -- Categorization
    debt_category VARCHAR(50), -- 'Code', 'Architecture', 'Process', 'Documentation'
    component_affected TEXT,

    CONSTRAINT technical_debt_metrics_positive CHECK (remediation_cost_est >= 0 AND principal >= 0)
);

COMMENT ON TABLE cmmi.technical_debt_metrics IS 'Financial and effort-based tracking of accrued technical debt.';

-- Indexes for T010
CREATE INDEX idx_tech_debt_date ON cmmi.technical_debt_metrics (snapshot_date DESC);

-- Table: M18-T011 - peer_reviews
-- Description: Metadata on pull request reviews to assess review quality and depth.
-- Business Case: Shallow peer reviews are a major source of escaped defects. This table tracks review duration and lines changed
--                 to identify "rubber stamping" behavior. It enforces a culture of thorough examination.
-- KPIs: Review Latency (Avg Time), Lines Reviewed per Minute, Reviewer Participation Rate, Defects Found in Review, Rejection Rate.
-- Feature Reference: M18-F011 (Peer Review Depth Analyzer)
CREATE TABLE IF NOT EXISTS cmmi.peer_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id VARCHAR(100) NOT NULL,
    reviewer_id UUID NOT NULL,

    -- Metrics
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    duration_minutes INTEGER NOT NULL,
    lines_changed INTEGER NOT NULL,

    -- Outcome
    state VARCHAR(20) NOT NULL, -- 'APPROVED', 'CHANGES_REQUESTED', 'COMMENTED'
    comments_count INTEGER DEFAULT 0,

    CONSTRAINT peer_reviews_check CHECK (duration_minutes >= 0)
);

COMMENT ON TABLE cmmi.peer_reviews IS 'Tracks the effectiveness and depth of code peer reviews.';

-- Indexes for T011
CREATE INDEX idx_peer_reviews_pr ON cmmi.peer_reviews (pr_id);
CREATE INDEX idx_peer_reviews_reviewer ON cmmi.peer_reviews (reviewer_id);

-- Table: M18-T012 - five_why_analyses
-- Description: Automated root cause analysis records for incidents.
-- Business Case: CMMI Level 5 requires preventing recurrence. The 5-Why engine traces incidents back to systemic causes.
--                 Storing this structured data allows the system to identify patterns (e.g., "Lack of Crypto Training") and
--                 automatically trigger training updates.
-- KPIs: RCA Completion Time (%), Root Cause Accuracy, Recurrence Rate (%), Training Triggered Count, Resolution Effectiveness.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
CREATE TABLE IF NOT EXISTS cmmi.five_why_analyses (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id VARCHAR(100) NOT NULL,

    -- The 5 Whys
    why_1 TEXT NOT NULL,
    why_2 TEXT,
    why_3 TEXT,
    why_4 TEXT,
    why_5 TEXT,

    -- Conclusion
    root_cause_category VARCHAR(100) NOT NULL, -- 'Process', 'Training', 'Tooling', 'Communication'
    systemic_issue BOOLEAN DEFAULT false,

    -- Action
    corrective_action_id UUID, -- Link to action item
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(50) DEFAULT 'AI_ENGINE'
);

COMMENT ON TABLE cmmi.five_why_analyses IS 'Structured storage for root cause analysis using the 5-Whys methodology.';

-- Indexes for T012
CREATE INDEX idx_five_why_incident ON cmmi.five_why_analyses (incident_id);
CREATE INDEX idx_five_why_category ON cmmi.five_why_analyses (root_cause_category);

-- Table: M18-T013 - log_clusters
-- Description: Clustered error logs from production for pattern analysis.
-- Business Case: Production logs generate massive noise. Unsupervised learning (DBSCAN) clusters similar errors, reducing
--                 thousands of log lines into actionable incident patterns. This drastically improves SRE efficiency.
-- KPIs: Cluster Accuracy, Noise Reduction Ratio, Pattern Discovery Rate, MTTR Improvement, Alert Consolidation Factor.
-- Feature Reference: M18-F013 (NLP-Based Log Clusterization)
CREATE TABLE IF NOT EXISTS cmmi.log_clusters (
    cluster_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pattern_signature TEXT NOT NULL, -- Hash or representative log line

    -- Stats
    occurrence_count INTEGER NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Details
    representative_hash VARCHAR(100),
    affected_services TEXT[],

    -- Status
    is_suppressed BOOLEAN DEFAULT false,

    CONSTRAINT log_clusters_count_check CHECK (occurrence_count > 0)
);

COMMENT ON TABLE cmmi.log_clusters IS 'Groups similar error logs to identify distinct operational failure modes.';

-- Indexes for T013
CREATE INDEX idx_log_clusters_seen ON cmmi.log_clusters (last_seen DESC);
CREATE INDEX idx_log_clusters_suppressed ON cmmi.log_clusters (is_suppressed) WHERE is_suppressed = false;

-- Table: M18-T014 - release_risk_scores
-- Description: Calculated composite risk scores for release candidates.
-- Business Case: Release decisions must be data-driven. This table aggregates churn, complexity, author experience, and test
--                 coverage into a single score. If the score exceeds a threshold, the release is automatically blocked.
-- KPIs: Risk Score Accuracy, False Positive Risk Rate, Release Block Rate, Post-Release Incident Correlation, Risk Trend.
-- Feature Reference: M18-F014 (Release Risk Scoring Model)
CREATE TABLE IF NOT EXISTS cmmi.release_risk_scores (
    release_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- The Score
    risk_score NUMERIC(5, 2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_factors JSONB NOT NULL, -- Detailed breakdown: {"churn": 80, "complexity": 20...}

    -- Decision
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Go', 'No-Go', 'Review Required')),
    approver_id UUID,

    CONSTRAINT release_risk_scores_decision_check CHECK ( (risk_score > 80 AND decision = 'No-Go') OR (risk_score <= 80) )
);

COMMENT ON TABLE cmmi.release_risk_scores IS 'Aggregated risk assessment determining deployment eligibility.';

-- Indexes for T014
CREATE INDEX idx_release_risk_id ON cmmi.release_risk_scores (release_id);
CREATE INDEX idx_release_risk_decision ON cmmi.release_risk_scores (decision);

-- Table: M18-T015 - developer_fatigue
-- Description: Metrics indicating developer burnout risk based on activity patterns.
-- Business Case: Fatigued developers make mistakes. By tracking commit frequency during off-hours and work intensity,
--                 M18 can predict when a team is at risk of burnout and suggest rest or assistance to maintain quality.
-- KPIs: Fatigue Index, Off-Hours Commit %, Continuous Work Streaks, Correlation with Defects, Turnover Prediction.
-- Feature Reference: M18-F015 (Developer Fatigue Detection)
CREATE TABLE IF NOT EXISTS cmmi.developer_fatigue (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    week_start DATE NOT NULL,

    -- Metrics
    commit_frequency INTEGER NOT NULL,
    commit_hour_variance NUMERIC(10, 2), -- Standard deviation of commit times
    off_hours_commits INTEGER DEFAULT 0,

    -- Assessment
    fatigue_index NUMERIC(5, 2) NOT NULL CHECK (fatigue_index >= 0 AND fatigue_index <= 100),
    risk_level VARCHAR(20) CHECK (risk_level IN ('Low', 'Medium', 'High'))
);

COMMENT ON TABLE cmmi.developer_fatigue IS 'Monitors developer activity patterns to detect potential burnout risks.';

-- Indexes for T015
CREATE INDEX idx_dev_fatigue_dev ON cmmi.developer_fatigue (developer_id);
CREATE INDEX idx_dev_fatigue_week ON cmmi.developer_fatigue (week_start);

-- Table: M18-T016 - flaky_tests
-- Description: Registry of non-deterministic tests.
-- Business Case: Flaky tests destroy trust in CI/CD. If tests fail randomly, developers ignore failures. This table tracks
--                 unstable tests so they can be quarantined or fixed without blocking valid releases.
-- KPIs: Flaky Test Count, Quarantine Success Rate, Fix Rate for Flaky Tests, CI Trust Score, Wasted Compute Time.
-- Feature Reference: M18-F016 (Unit Test Flakiness Detector)
CREATE TABLE IF NOT EXISTS cmmi.flaky_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_name VARCHAR(255) NOT NULL,
    suite_name VARCHAR(100),

    -- Stats
    last_flaky_date TIMESTAMP WITH TIME ZONE,
    flake_count INTEGER NOT NULL DEFAULT 0,
    total_runs INTEGER NOT NULL DEFAULT 0,

    -- Management
    is_quarantined BOOLEAN DEFAULT false,
    assigned_to UUID,

    CONSTRAINT flaky_tests_check CHECK (total_runs > 0)
);

COMMENT ON TABLE cmmi.flaky_tests IS 'Identifies and tracks non-deterministic unit tests to preserve CI/CD reliability.';

-- Indexes for T016
CREATE INDEX idx_flaky_tests_suite ON cmmi.flaky_tests (suite_name);
CREATE INDEX idx_flaky_tests_quarantined ON cmmi.flaky_tests (is_quarantined) WHERE is_quarantined = true;

-- Table: M18-T017 - sast_findings
-- Description: Results from Static Application Security Testing.
-- Business Case: Security cannot be an afterthought. This table stores SAST results for every build. By integrating with the
--                 pipeline, code with High/Critical vulnerabilities is automatically blocked from deployment.
-- KPIs: False Positive Rate, Time to Remediate, Vulnerability Density, Block Enforcement Rate, Scanner Coverage.
-- Feature Reference: M18-F017 (Static Analysis Severity Triaging)
CREATE TABLE IF NOT EXISTS cmmi.sast_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Source
    scanner_name VARCHAR(50) NOT NULL,
    build_id VARCHAR(100),

    -- Finding Details
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    cwe_id VARCHAR(20), -- Common Weakness Enumeration
    file_path TEXT NOT NULL,
    line_number INTEGER,

    -- Workflow
    status cmmi.finding_status_enum DEFAULT 'Pending',

    -- Attribution
    commit_id VARCHAR(100),
    author_id UUID,

    CONSTRAINT sast_findings_line_check CHECK (line_number > 0)
);

COMMENT ON TABLE cmmi.sast_findings IS 'Detailed log of static security analysis findings.';

-- Indexes for T017
CREATE INDEX idx_sast_build ON cmmi.sast_findings (build_id);
CREATE INDEX idx_sast_status ON cmmi.sast_findings (status);
CREATE INDEX idx_sast_severity ON cmmi.sast_findings (severity);

-- Table: M18-T018 - dependency_vulnerabilities
-- Description: Known CVEs (Common Vulnerabilities and Exposures) in dependencies.
-- Business Case: The supply chain is a major attack vector. This table maps CVEs to internal repositories, ensuring that
--                 teams are immediately aware if they are using a compromised library.
-- KPIs: CVE Coverage (%) , Remediation Time, Dependency Scanning Frequency, Supply Chain Risk Score, Vulnerable Library Count.
-- Feature Reference: M18-F018 (Dependency Vulnerability Ingestion)
CREATE TABLE IF NOT EXISTS cmmi.dependency_vulnerabilities (
    cve_id VARCHAR(50) PRIMARY KEY,
    dependency_name VARCHAR(255) NOT NULL,
    installed_version VARCHAR(100) NOT NULL,
    fixed_version VARCHAR(100),

    -- Severity
    severity_score NUMERIC(3, 1), -- CVSS Score
    severity_label VARCHAR(50),

    -- Affected Projects
    affected_projects TEXT[],

    discovered_date DATE DEFAULT CURRENT_DATE
);

COMMENT ON TABLE cmmi.dependency_vulnerabilities IS 'Tracks known security vulnerabilities in third-party libraries.';

-- Indexes for T018
CREATE INDEX idx_dep_vuln_name ON cmmi.dependency_vulnerabilities (dependency_name);
CREATE INDEX idx_dep_vuln_score ON cmmi.dependency_vulnerabilities (severity_score DESC);

-- Table: M18-T019 - process_capability_indices
-- Description: Cpk values for critical process attributes.
-- Business Case: Cpk measures how well a process can meet specification limits. A Cpk > 1.33 indicates a capable process.
--                 This table tracks the maturity of engineering processes over time.
-- KPIs: Process Cpk, Sigma Level, Spec Limit Adherence, Process Stability Trend, Capable Process %.
-- Feature Reference: M18-F019 (Process Capability Cpk Calculator)
CREATE TABLE IF NOT EXISTS cmmi.process_capability_indices (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    process_name VARCHAR(100) NOT NULL,

    -- Calculations
    cpk NUMERIC(5, 2) NOT NULL,
    cp NUMERIC(5, 2),

    -- Specs
    spec_lower NUMERIC(18, 6),
    spec_upper NUMERIC(18, 6),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT process_capability_indices_check CHECK (cpk > 0)
);

COMMENT ON TABLE cmmi.process_capability_indices IS 'Stores Process Capability Indices (Cpk) to quantify process maturity.';

-- Indexes for T019
CREATE INDEX idx_proc_cap_name ON cmmi.process_capability_indices (process_name);
CREATE INDEX idx_proc_cap_time ON cmmi.process_capability_indices (timestamp DESC);

-- Table: M18-T020 - build_failure_predictions
-- Description: ML predictions for build failures.
-- Business Case: Builds are expensive. Predicting failure before the build finishes (or based on commit characteristics)
--                 saves developer time and compute resources. It directs attention to the likely failure point immediately.
-- KPIs: Prediction Accuracy (>80%), False Negative Rate, Time Saved, Early Detection Rate, Model Confidence.
-- Feature Reference: M18-F020 (Build Failure Root Cause Prediction)
CREATE TABLE IF NOT EXISTS cmmi.build_failure_predictions (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,

    -- Prediction
    prediction VARCHAR(10) NOT NULL CHECK (prediction IN ('Success', 'Fail')),
    confidence NUMERIC(3, 2), -- 0 to 1
    primary_cause_feature TEXT, -- e.g., 'test_syntax', 'dependency_conflict'

    -- Reality (for training)
    actual_outcome VARCHAR(10),

    predicted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.build_failure_predictions IS 'Machine learning predictions of build success/failure to optimize CI/CD feedback loops.';

-- Indexes for T020
CREATE INDEX idx_build_pred_build ON cmmi.build_failure_predictions (build_id);

-- Table: M18-T021 - rollback_decisions
-- Description: Logs of automated rollback triggers.
-- Business Case: Fast recovery is critical. This table records when and why a rollback occurred, providing data to improve
--                 pre-deployment risk checks and preventing future rollbacks.
-- KPIs: Rollback Frequency, MTTR via Rollback, False Positive Rollback Rate, Trigger Metric Accuracy, Rollback Success Rate.
-- Feature Reference: M18-F021 (Automated Rollback Decision Engine)
CREATE TABLE IF NOT EXISTS cmmi.rollback_decisions (
    decision_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID,
    deployment_id UUID NOT NULL,

    -- Trigger
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    trigger_metric VARCHAR(100) NOT NULL, -- e.g., 'error_rate_spike'
    threshold_value NUMERIC(18, 6),
    actual_value NUMERIC(18, 6),

    -- Action
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Rollback', 'Ignore')), -- 'Rollback' or 'Held'
    executed_by VARCHAR(50) DEFAULT 'SYSTEM',
    execution_time_seconds INTEGER
);

COMMENT ON TABLE cmmi.rollback_decisions IS 'Audit log of automated rollback actions taken to preserve system stability.';

-- Indexes for T021
CREATE INDEX idx_rollback_deployment ON cmmi.rollback_decisions (deployment_id);
CREATE INDEX idx_rollback_time ON cmmi.rollback_decisions (timestamp DESC);

-- Table: M18-T022 - sprint_burndowns
-- Description: Daily burndown data tracking progress against the ideal.
-- Business Case: Monitoring burndown variance helps identify estimation errors or scope creep early. Accurate forecasting
--                 is essential for probabilistic release planning.
-- KPIs: Burndown Variance (<5%), Estimation Accuracy, Scope Creep Count, Sprint Completion Rate, Velocity Stability.
-- Feature Reference: M18-F022 (Sprint Burndown Variance Tracker)
CREATE TABLE IF NOT EXISTS cmmi.sprint_burndowns (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sprint_id VARCHAR(100) NOT NULL,
    date DATE NOT NULL,

    -- Metrics
    remaining_points NUMERIC(10, 2) NOT NULL,
    ideal_remaining NUMERIC(10, 2) NOT NULL,

    -- Context
    team_id VARCHAR(100)
);

COMMENT ON TABLE cmmi.sprint_burndowns IS 'Daily tracking of sprint progress against planned velocity.';

-- Indexes for T022
CREATE INDEX idx_burndown_sprint ON cmmi.sprint_burndowns (sprint_id, date);

-- Table: M18-T023 - code_duplications
-- Description: Instances of duplicate code blocks detected.
-- Business Case: Code duplication increases maintenance burden and defect risk (fixing a bug requires fixing it in N places).
--                 This table identifies clones for refactoring efforts.
-- KPIs: Duplication % (<3%), Duplicate Block Count, Lines Duplicated, Refactoring Backlog, Clone Removal Rate.
-- Feature Reference: M18-F023 (Code Duplication Detector)
CREATE TABLE IF NOT EXISTS cmmi.code_duplications (
    duplication_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Locations
    file_a TEXT NOT NULL,
    file_b TEXT NOT NULL,
    start_line_a INTEGER,
    start_line_b INTEGER,

    -- Metrics
    lines_affected INTEGER NOT NULL,
    similarity_score NUMERIC(3, 2) NOT NULL, -- 0.00 to 1.00

    -- Status
    status VARCHAR(50) DEFAULT 'Open', -- 'Open', 'Accepted', 'Refactored'

    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.code_duplications IS 'Records of duplicated code blocks identified by static analysis.';

-- Indexes for T023
CREATE INDEX idx_dup_files ON cmmi.code_duplications (file_a, file_b);
CREATE INDEX idx_dup_status ON cmmi.code_duplications (status);

-- Table: M18-T024 - security_policy_violations
-- Description: Logs of hardcoded secrets or insecure API usage found in code.
-- Business Case: Hardcoded secrets are a critical security violation. This table automatically blocks commits containing
--                 passwords or keys, enforcing security governance at the gate.
-- KPIs: Violation Catch Rate, Violation Recurrence, Time to Remediation, Secret Scanning Coverage, Blocked PR Count.
-- Feature Reference: M18-F024 (Security Policy Violation Auto-Check)
CREATE TABLE IF NOT EXISTS cmmi.security_policy_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    commit_id VARCHAR(100),

    -- Details
    scanner VARCHAR(50) NOT NULL,
    policy_rule VARCHAR(100) NOT NULL, -- e.g., 'No_Hardcoded_Keys'
    file_path TEXT,
    line_number INTEGER,

    -- Status
    status VARCHAR(50) DEFAULT 'Open', -- 'Open', 'Resolved'

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.security_policy_violations IS 'Tracks security policy violations such as hardcoded credentials or insecure functions.';

-- Indexes for T024
CREATE INDEX idx_sec_pol_commit ON cmmi.security_policy_violations (commit_id);
CREATE INDEX idx_sec_pol_status ON cmmi.security_policy_violations (status);

-- Table: M18-T025 - pipeline_efficiency
-- Description: Metrics on CI/CD pipeline stage duration and wait times.
-- Business Case: Developer velocity depends on fast feedback. This table identifies bottlenecks in the pipeline (e.g.,
--                 long queue times) so infrastructure can be optimized.
-- KPIs: Pipeline Duration, Wait Time %, Resource Utilization, Feedback Loop Time, Bottleneck Stage.
-- Feature Reference: M18-F025 (Pipeline Efficiency Monitor)
CREATE TABLE IF NOT EXISTS cmmi.pipeline_efficiency (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id VARCHAR(100) NOT NULL,
    stage_name VARCHAR(100) NOT NULL,

    -- Timing
    duration_seconds INTEGER NOT NULL,
    wait_time_seconds INTEGER DEFAULT 0,
    queue_depth INTEGER,

    -- Context
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pipeline_efficiency IS 'Tracks performance metrics for CI/CD pipeline stages to optimize throughput.';

-- Indexes for T025
CREATE INDEX idx_pipe_eff_pipeline ON cmmi.pipeline_efficiency (pipeline_id, timestamp);

-- Table: M18-T026 - incident_mttr_predictions
-- Description: Predicted time to resolve operational incidents.
-- Business Case: Setting accurate customer expectations for downtime is critical for trust. This model predicts MTTR
--                 based on historical incident data.
-- KPIs: Prediction Error (<20%), Customer Communication Accuracy, Resource Allocation Efficiency, Actual vs Predicted Gap.
-- Feature Reference: M18-F026 (Incident MTTR Prediction)
CREATE TABLE IF NOT EXISTS cmmi.incident_mttr_predictions (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id VARCHAR(100) NOT NULL,

    -- Prediction
    predicted_mttr_minutes INTEGER NOT NULL,
    confidence_interval VARCHAR(20), -- e.g., "+/- 5 mins"

    -- Actuals (for validation)
    actual_mttr_minutes INTEGER,

    -- Metadata
    model_version VARCHAR(50),
    prediction_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.incident_mttr_predictions IS 'Stores predictions for Mean Time To Restore (MTTR) for operational incidents.';

-- Indexes for T026
CREATE INDEX idx_mttr_incident ON cmmi.incident_mttr_predictions (incident_id);

-- Table: M18-T027 - deployments
-- Description: Master record of all deployments to all environments.
-- Business Case: The deployment table is the source of truth for DORA metrics (Frequency, Failure Rate, Lead Time).
--                 It links code changes to operational reality.
-- KPIs: Deployment Frequency, Lead Time for Changes, Change Failure Rate (<5%), Deployment Success Rate, Rollback Rate.
-- Feature Reference: M18-F027 (Change Failure Rate Monitor), M18-F028 (Deployment Frequency Tracker)
CREATE TABLE IF NOT EXISTS cmmi.deployments (
    deployment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    environment VARCHAR(50) NOT NULL, -- 'Dev', 'Stage', 'Prod'
    release_id UUID,

    -- Status
    status cmmi.deployment_status_enum NOT NULL,
    incident_flag BOOLEAN DEFAULT false, -- True if caused an incident

    -- Details
    deployer_id UUID,
    duration_seconds INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.deployments IS 'Master registry of all deployment events across environments.';

-- Indexes for T027
CREATE INDEX idx_deployments_release ON cmmi.deployments (release_id);
CREATE INDEX idx_deployments_env_time ON cmmi.deployments (environment, timestamp DESC);
CREATE INDEX idx_deployments_status ON cmmi.deployments (status);

-- Table: M18-T028 - author_reputation
-- Description: Scores based on author experience and defect history.
-- Business Case: Code written by junior developers or developers with a history of bugs may carry higher risk. This table
--                 adjusts release risk scores dynamically based on who wrote the code.
-- KPIs: Reputation Score Distribution, Defect Injection Rate per Author, Velocity per Author, Review Accuracy, Improvement Rate.
-- Feature Reference: M18-F030 (Author Experience Weighting)
CREATE TABLE IF NOT EXISTS cmmi.author_reputation (
    author_id UUID PRIMARY KEY,

    -- Metrics
    reputation_score NUMERIC(5, 2) NOT NULL CHECK (reputation_score >= 0 AND reputation_score <= 100),
    commits_count INTEGER NOT NULL DEFAULT 0,
    defect_introduction_rate NUMERIC(5, 2), -- Defects per 1000 lines

    -- History
    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.author_reputation IS 'Calculated reputation scores for developers based on code quality history.';

-- Indexes for T028
CREATE INDEX idx_author_rep_score ON cmmi.author_reputation (reputation_score);

-- Table: M18-T029 - retrospective_summaries
-- Description: AI-generated summaries of sprint issues and actions.
-- Business Case: Retrospectives are valuable but time-consuming. AI-generated summaries based on Jira, Git, and Slack data
--                 provide actionable insights immediately, reducing meeting overhead and ensuring nothing is missed.
-- KPIs: Summary Accuracy (%), Action Items Identified, Meeting Time Saved, Issue Coverage %, Follow-up Rate.
-- Feature Reference: M18-F031 (Automated Retrospective Summarizer)
CREATE TABLE IF NOT EXISTS cmmi.retrospective_summaries (
    summary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sprint_id VARCHAR(100) NOT NULL,

    -- Content
    summary_text TEXT NOT NULL,
    action_items_json JSONB NOT NULL, -- [{"task": "...", "owner": "..."}]

    -- Metadata
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50)
);

COMMENT ON TABLE cmmi.retrospective_summaries IS 'Stores AI-generated summaries and action items for sprint retrospectives.';

-- Indexes for T029
CREATE INDEX idx_retro_sprint ON cmmi.retrospective_summaries (sprint_id);

-- Table: M18-T030 - defect_aging
-- Description: Tracks how long defects remain open.
-- Business Case: Aging defects represent technical debt and customer dissatisfaction. This table helps prioritize the backlog
--                 and identify if specific types of defects are being neglected.
-- KPIs: Average Defect Age, Aged Defect Count (>30 days), Aging Trend, Resolution SLO Adherence.
-- Feature Reference: M18-F032 (Defect Age Analysis)
CREATE TABLE IF NOT EXISTS cmmi.defect_aging (
    aging_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    defect_id UUID NOT NULL,

    -- Timing
    open_date TIMESTAMP WITH TIME ZONE NOT NULL,
    current_age_days INTEGER NOT NULL,

    -- Categorization
    category_bucket VARCHAR(50) NOT NULL, -- 'Fresh', 'Stale', 'Critical', 'Zombie'

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT defect_aging_days_check CHECK (current_age_days >= 0)
);

COMMENT ON TABLE cmmi.defect_aging IS 'Tracks the age of open defects to prioritize backlog grooming.';

-- Indexes for T030
CREATE INDEX idx_defect_aging_id ON cmmi.defect_aging (defect_id);
CREATE INDEX idx_defect_aging_bucket ON cmmi.defect_aging (category_bucket);

-- Table: M18-T031 - test_execution_times
-- Description: Duration of individual test cases.
-- Business Case: Slow tests delay feedback. This table identifies tests that take too long, allowing teams to optimize
--                 them or move them to a slower nightly build suite.
-- KPIs: Avg Test Duration, Slowest Test Count, Test Suite Optimization Rate, Parallelization Potential, Flakiness vs Time.
-- Feature Reference: M18-F033 (Test Execution Time Optimization)
CREATE TABLE IF NOT EXISTS cmmi.test_execution_times (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_id VARCHAR(100) NOT NULL,
    suite_name VARCHAR(100),

    -- Metrics
    execution_time_ms INTEGER NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.test_execution_times IS 'Tracks execution time for individual test cases to identify performance bottlenecks.';

-- Indexes for T031
CREATE INDEX idx_test_time_id ON cmmi.test_execution_times (test_id);
CREATE INDEX idx_test_time_slow ON cmmi.test_execution_times (execution_time_ms DESC);

-- Table: M18-T032 - arch_violations
-- Description: Architecture compliance violations detected by static analysis.
-- Business Case: Architectural erosion leads to unmaintainable monoliths. This table enforces layering rules (e.g.,
--                 "UI cannot call DB") to preserve system design.
-- KPIs: Violation Count, Violation Severity, Architectural Debt, Violation Trend, Resolution Rate.
-- Feature Reference: M18-F034 (Architecture Compliance Checker)
CREATE TABLE IF NOT EXISTS cmmi.arch_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Violation Details
    layer_from VARCHAR(100) NOT NULL,
    layer_to VARCHAR(100) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,

    severity VARCHAR(20) NOT NULL, -- 'Critical', 'Major', 'Minor'
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    file_path TEXT
);

COMMENT ON TABLE cmmi.arch_violations IS 'Records violations of architectural rules such as layering or dependency constraints.';

-- Indexes for T032
CREATE INDEX idx_arch_layer_from ON cmmi.arch_violations (layer_from);
CREATE INDEX idx_arch_severity ON cmmi.arch_violations (severity);

-- Table: M18-T033 - api_contract_drifts
-- Description: Differences between API specs (OpenAPI) and implementation.
-- Business Case: Breaking changes in APIs cost integrators money and trust. This table compares the implemented code against
--                 the documented spec to detect drift before release.
-- KPIs: Drift Count, Drift Detection Time, API Consistency Score, Integration Failure Rate, Doc Coverage.
-- Feature Reference: M18-F035 (API Contract Drift Detector)
CREATE TABLE IF NOT EXISTS cmmi.api_contract_drifts (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100) NOT NULL,

    -- Hashes
    spec_hash VARCHAR(64) NOT NULL,
    impl_hash VARCHAR(64) NOT NULL,

    -- Status
    drift_detected_flag BOOLEAN DEFAULT true,

    -- Details
    details JSONB, -- {"missing_param": "...", "type_mismatch": "..."}

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.api_contract_drifts IS 'Identifies discrepancies between API documentation specifications and actual code implementation.';

-- Indexes for T033
CREATE INDEX idx_api_drift_endpoint ON cmmi.api_contract_drifts (endpoint_id);

-- Table: M18-T034 - pr_cognitive_load
-- Description: Estimated complexity of a Pull Request for reviewers.
-- Business Case: Large PRs are hard to review and prone to bugs. This table estimates the cognitive load (time/effort)
--                 required to review a PR, helping assign appropriate reviewers or suggest splitting the PR.
-- KPIs: Avg Cognitive Load, Review Quality vs Load, PR Split Rate, Review Time Prediction, Rejection Rate vs Load.
-- Feature Reference: M18-F036 (Cognitive Load Estimator)
CREATE TABLE IF NOT EXISTS cmmi.pr_cognitive_load (
    pr_id VARCHAR(100) PRIMARY KEY,

    -- Metrics
    cognitive_load_score NUMERIC(5, 2) NOT NULL, -- 1 to 100
    files_changed INTEGER NOT NULL,
    logical_complexity INTEGER, -- Cyclomatic complexity delta

    -- Context
    author_id UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pr_cognitive_load IS 'Estimates the effort required to review a Pull Request based on complexity and size.';

-- Indexes for T034
CREATE INDEX idx_pr_load_score ON cmmi.pr_cognitive_load (cognitive_load_score DESC);

-- Table: M18-T035 - merge_conflict_predictions
-- Description: Predicts likelihood of merge conflicts based on branch activity.
-- Business Case: Merge conflicts waste developer time. Predicting conflicts allows the system to suggest earlier merging
--                 or integration branches, reducing end-of-sprint chaos.
-- KPIs: Prediction Accuracy, Conflict Reduction Rate, Branch Integration Time, Merge Success Rate.
-- Feature Reference: M18-F037 (Merge Conflict Prediction)
CREATE TABLE IF NOT EXISTS cmmi.merge_conflict_predictions (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    branch_id VARCHAR(100) NOT NULL,
    target_branch VARCHAR(100) NOT NULL,

    -- Prediction
    conflict_probability NUMERIC(3, 2) NOT NULL CHECK (conflict_probability >= 0 AND conflict_probability <= 1),

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.merge_conflict_predictions IS 'Machine learning predictions of the likelihood of merge conflicts for feature branches.';

-- Indexes for T035
CREATE INDEX idx_merge_conflict_branch ON cmmi.merge_conflict_predictions (branch_id);

-- Table: M18-T036 - onboarding_metrics
-- Description: Time-to-first-commit for new hires.
-- Business Case: Faster onboarding means faster ROI. This table measures the effectiveness of training materials and
--                 developer environment setup by tracking how long it takes for a new hire to make their first commit.
-- KPIs: Time-to-First-Commit, Onboarding Satisfaction, Environment Setup Errors, Mentor Engagement, Early Defect Rate.
-- Feature Reference: M18-F038 (Onboarding Effectiveness Tracker)
CREATE TABLE IF NOT EXISTS cmmi.onboarding_metrics (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    start_date DATE NOT NULL,
    first_commit_date TIMESTAMP WITH TIME ZONE,
    days_to_first_commit INTEGER,

    -- Context
    team_id VARCHAR(100),
    role VARCHAR(50)
);

COMMENT ON TABLE cmmi.onboarding_metrics IS 'Tracks the effectiveness of the onboarding process by measuring time to first contribution.';

-- Indexes for T036
CREATE INDEX idx_onboard_dev ON cmmi.onboarding_metrics (developer_id);

-- Table: M18-T037 - license_compliance
-- Description: Scan results for open source licenses.
-- Business Case: Legal compliance is mandatory. This table checks dependencies against approved license lists to prevent
--                 IP contamination.
-- KPIs: License Violations, Compliance Status %, Scan Coverage, Risk Assessment Score, Approved Library Usage.
-- Feature Reference: M18-F039 (Open Source License Compliance Check)
CREATE TABLE IF NOT EXISTS cmmi.license_compliance (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dependency_id VARCHAR(100) NOT NULL,

    -- License Info
    license_type VARCHAR(100) NOT NULL,
    compliance_status VARCHAR(50) NOT NULL, -- 'Compliant', 'Non-Compliant', 'Review Required'
    risk_level cmmi.license_risk_enum NOT NULL,

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.license_compliance IS 'Records license compliance status for third-party dependencies.';

-- Indexes for T037
CREATE INDEX idx_license_dep ON cmmi.license_compliance (dependency_id);
CREATE INDEX idx_license_status ON cmmi.license_compliance (compliance_status);

-- Table: M18-T038 - doc_coverage
-- Description: Percentage of code annotated with documentation.
-- Business Case: Maintainability depends on documentation. This table incentivizes developers to document code by
--                 tracking coverage metrics.
-- KPIs: Documentation Coverage (%), Doc Update Latency, Undocumented Complex Code %, Doc Link Validity.
-- Feature Reference: M18-F040 (Documentation Coverage Analyzer)
CREATE TABLE IF NOT EXISTS cmmi.doc_coverage (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_name VARCHAR(255) NOT NULL,

    -- Metrics
    doc_percent NUMERIC(5, 2) NOT NULL, -- 0 to 100
    public_api_doc_percent NUMERIC(5, 2),

    last_analyzed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT doc_coverage_check CHECK (doc_percent >= 0 AND doc_percent <= 100)
);

COMMENT ON TABLE cmmi.doc_coverage IS 'Tracks the percentage of codebase that is covered by documentation.';

-- Indexes for T038
CREATE INDEX idx_doc_module ON cmmi.doc_coverage (module_name);

-- Table: M18-T039 - dead_code_analysis
-- Description: Identified unused code blocks.
-- Business Case: Dead code increases attack surface and confusion. This table identifies functions that are never called
--                 so they can be safely removed.
-- KPIs: Dead Code LOC, Removal Rate, Safety of Removal (verified by tests), Refactoring Impact.
-- Feature Reference: M18-F041 (Dead Code Elimination Suggester)
CREATE TABLE IF NOT EXISTS cmmi.dead_code_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_path TEXT NOT NULL,
    function_name VARCHAR(255) NOT NULL,

    last_called_date TIMESTAMP WITH TIME ZONE, -- Null if never called
    status VARCHAR(50) DEFAULT 'Candidate', -- 'Candidate', 'Confirmed', 'Removed'

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dead_code_analysis IS 'Identifies functions and methods that are not referenced anywhere in the codebase.';

-- Indexes for T039
CREATE INDEX idx_dead_code_file ON cmmi.dead_code_analysis (file_path);
CREATE INDEX idx_dead_code_status ON cmmi.dead_code_analysis (status);

-- Table: M18-T040 - sql_performance
-- Description: Performance stats for SQL queries.
-- Business Case: Database performance is critical for fintech latency. This table tracks query costs and durations
--                 to identify regressions early.
-- KPIs: Avg Query Duration, Slow Query Count, DB CPU Usage, Index Hit Ratio, Query Cost Delta.
-- Feature Reference: M18-F042 (SQL Query Performance Analyzer)
CREATE TABLE IF NOT EXISTS cmmi.sql_performance (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash VARCHAR(64) NOT NULL,

    -- Metrics
    avg_duration_ms NUMERIC(10, 2),
    call_count BIGINT,

    -- Details
    query_signature TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sql_performance IS 'Tracks execution statistics for SQL queries to detect performance regressions.';

-- Indexes for T040
CREATE INDEX idx_sql_perf_hash ON cmmi.sql_performance (query_hash);

-- Table: M18-T041 - memory_leak_simulation
-- Description: Results of memory analysis simulations.
-- Business Case: Memory leaks cause OOM crashes in production. Simulation tools analyze heap dumps to predict leaks
--                 before they take down the server.
-- KPIs: Leak Prediction Accuracy, Memory Usage Trend, OOM Incident Prevention, Heap Analysis Time.
-- Feature Reference: M18-F043 (Memory Leak Detection Simulation)
CREATE TABLE IF NOT EXISTS cmmi.memory_leak_simulation (
    simulation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    module_name VARCHAR(100) NOT NULL,

    -- Prediction
    predicted_leak_rate NUMERIC(10, 2), -- MB per hour
    confidence NUMERIC(3, 2),

    -- Context
    heap_dump_path TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.memory_leak_simulation IS 'Stores results of memory leak analysis derived from heap dump simulations.';

-- Indexes for T041
CREATE INDEX idx_mem_leak_module ON cmmi.memory_leak_simulation (module_name);

-- Table: M18-T042 - thread_safety_warnings
-- Description: Potential race conditions detected.
-- Business Case: Race conditions cause unpredictable behavior and data corruption, which is fatal in payments.
--                 This table stores static analysis findings related to concurrency.
-- KPIs: Race Condition Count, Severity Distribution, Fix Rate, Concurrency Test Coverage.
-- Feature Reference: M18-F044 (Thread Safety Violation Detector)
CREATE TABLE IF NOT EXISTS cmmi.thread_safety_warnings (
    warning_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,

    race_condition_type VARCHAR(50) NOT NULL, -- 'Data Race', 'Deadlock Risk'
    severity VARCHAR(20) NOT NULL,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT thread_safety_line_check CHECK (line_number > 0)
);

COMMENT ON TABLE cmmi.thread_safety_warnings IS 'Logs potential concurrency violations such as data races and deadlock risks.';

-- Indexes for T042
CREATE INDEX idx_thread_safe_file ON cmmi.thread_safety_warnings (file_path);

-- Table: M18-T043 - req_traceability
-- Description: Links requirements to code/tests.
-- Business Case: Every line of code should trace back to a requirement. This table ensures compliance and that no
--                 "ghost code" exists without purpose.
-- KPIs: Traceability Coverage (%), Orphaned Code %, Unimplemented Requirements, Test-to-Req Traceability.
-- Feature Reference: M18-F045 (Regulatory Requirement Traceability)
CREATE TABLE IF NOT EXISTS cmmi.req_traceability (
    trace_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    req_id VARCHAR(100) NOT NULL,
    artifact_type VARCHAR(50) NOT NULL, -- 'Code', 'Test', 'Doc'
    artifact_id VARCHAR(100) NOT NULL,

    coverage_status VARCHAR(20) DEFAULT 'Covered',

    CONSTRAINT req_traceability_type_check CHECK (artifact_type IN ('Code', 'Test', 'Doc'))
);

COMMENT ON TABLE cmmi.req_traceability IS 'Maps regulatory and functional requirements to code and test artifacts.';

-- Indexes for T043
CREATE INDEX idx_req_traceability_req ON cmmi.req_traceability (req_id);
CREATE INDEX idx_req_traceability_artifact ON cmmi.req_traceability (artifact_id);

-- Table: M18-T044 - skill_gaps
-- Description: Identified gaps in team skills.
-- Business Case: To maintain CMMI Level 5, the workforce must be skilled. This table analyzes the types of code
--                 and bugs generated to identify missing skills (e.g., lack of Crypto knowledge) and trigger training.
-- KPIs: Skill Gap Severity, Training Completion Rate, Skill Improvement Velocity, Expertise Distribution, Hiring Alignment.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
CREATE TABLE IF NOT EXISTS cmmi.skill_gaps (
    gap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    skill_name VARCHAR(100) NOT NULL,

    -- Levels
    required_level INTEGER NOT NULL, -- 1 to 5
    current_avg_level NUMERIC(3, 2) NOT NULL,

    -- Assessment
    gap_severity VARCHAR(20) NOT NULL, -- 'Low', 'Medium', 'Critical'

    last_analyzed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.skill_gaps IS 'Identifies discrepancies between required skills for a project and the team''s current proficiency.';

-- Indexes for T044
CREATE INDEX idx_skill_gap_severity ON cmmi.skill_gaps (gap_severity);

-- Table: M18-T045 - meeting_load
-- Description: Time spent in meetings per person.
-- Business Case: Meeting overload kills coding time and quality. This table correlates meeting time with output
--                 to find the optimal balance for deep work.
-- KPIs: Meeting Hours/Week, Coding Hours/Week, Impact Score, Meeting Efficiency, Deep Work %.
-- Feature Reference: M18-F047 (Meeting Load Impact Analyzer)
CREATE TABLE IF NOT EXISTS cmmi.meeting_load (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    person_id UUID NOT NULL,
    week_start DATE NOT NULL,

    -- Metrics
    total_hours_meeting NUMERIC(4, 2) NOT NULL,
    total_hours_work NUMERIC(4, 2) NOT NULL,

    impact_score NUMERIC(5, 2) -- Calculated negative impact on velocity
);

COMMENT ON TABLE cmmi.meeting_load IS 'Analyzes the correlation between meeting time and developer output velocity.';

-- Indexes for T045
CREATE INDEX idx_meeting_load_person ON cmmi.meeting_load (person_id, week_start);

-- Table: M18-T046 - remote_collab_index
-- Description: Metrics on remote team efficiency.
-- Business Case: In a distributed team, communication latency is a risk. This table measures efficiency
--                 (e.g., PR review lag) to optimize "Follow-the-sun" workflows.
-- KPIs: Async Communication Score, Handoff Delay, Cross-Region Velocity, Remote Satisfaction, Collaboration Index.
-- Feature Reference: M18-F048 (Remote Work Collaboration Index)
CREATE TABLE IF NOT EXISTS cmmi.remote_collab_index (
    index_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_id VARCHAR(100) NOT NULL,

    -- Metrics
    timezone_overlap_hours NUMERIC(4, 2),
    async_comm_score NUMERIC(5, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.remote_collab_index IS 'Measures the effectiveness of collaboration processes for distributed engineering teams.';

-- Indexes for T046
CREATE INDEX idx_remote_team ON cmmi.remote_collab_index (team_id);

-- Table: M18-T047 - code_ownership
-- Description: Ownership distribution per file.
-- Business Case: "Bus Factor" risk: if only one person knows a module, losing them is catastrophic. This table
--                 tracks ownership to ensure knowledge sharing and redundancy.
-- KPIs: Bus Factor, Ownership Concentration, File Owner Count, Knowledge Redundancy, Onboarding Impact.
-- Feature Reference: M18-F049 (Code Ownership Distribution)
CREATE TABLE IF NOT EXISTS cmmi.code_ownership (
    file_path TEXT PRIMARY KEY,
    primary_owner_id UUID,

    -- Metrics
    bus_factor INTEGER NOT NULL, -- Number of people who understand this code
    ownership_concentration NUMERIC(3, 2), -- 0.0 (Shared) to 1.0 (Monopoly)

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT code_ownership_check CHECK (bus_factor > 0)
);

COMMENT ON TABLE cmmi.code_ownership IS 'Tracks the distribution of code ownership to mitigate bus factor risks.';

-- Indexes for T047
CREATE INDEX idx_code_ownership_owner ON cmmi.code_ownership (primary_owner_id);
CREATE INDEX idx_code_ownership_bus ON cmmi.code_ownership (bus_factor);

-- Table: M18-T048 - release_notes
-- Description: Auto-generated release notes.
-- Business Case: Manual release notes are error-prone and delayed. This table stores AI-generated notes
--                 from commits and PRs for immediate stakeholder communication.
-- KPIs: Note Accuracy (%), Generation Speed, Stakeholder Satisfaction, Comprehensiveness, Format Consistency.
-- Feature Reference: M18-F050 (Release Notes Automator)
CREATE TABLE IF NOT EXISTS cmmi.release_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    release_id UUID NOT NULL,

    -- Content
    note_content TEXT NOT NULL,
    summary TEXT,

    -- Sources
    sources_used JSONB, -- {'commits': 50, 'prs': 20}

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.release_notes IS 'Stores automatically generated release notes derived from commit history and pull requests.';

-- Indexes for T048
CREATE INDEX idx_release_notes_rel ON cmmi.release_notes (release_id);

-- Table: M18-T049 - slo_error_budgets
-- Description: Error budget state for various SLOs.
-- Business Case: Error budgets balance innovation with reliability. This table calculates the remaining budget
--                 to decide if a team can deploy risky features or must freeze for stability.
-- KPIs: Error Budget Remaining (%), Burn Rate, Time to Exhaustion, SLO Adherence, Freeze Trigger Count.
-- Feature Reference: M18-F051 (Latency SLO Error Budget Calculator), M18-F052 (Availability SLO Error Budget Calculator)
CREATE TABLE IF NOT EXISTS cmmi.slo_error_budgets (
    budget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_name VARCHAR(100) NOT NULL,

    -- Metrics
    current_budget_pct NUMERIC(5, 2) NOT NULL,
    target_pct NUMERIC(5, 2) DEFAULT 100.00,

    -- Window
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.slo_error_budgets IS 'Calculates and tracks the remaining error budget for defined Service Level Objectives (SLOs).';

-- Indexes for T049
CREATE INDEX idx_slo_budget_name ON cmmi.slo_error_budgets (slo_name);
CREATE INDEX idx_slo_budget_period ON cmmi.slo_error_budgets (period_start, period_end);

-- Table: M18-T050 - risk_hotspots
-- Description: Heatmap data for risky files.
-- Business Case: Visualizing risk allows managers to direct refactoring efforts where they matter most.
--                 This table aggregates churn, defects, and complexity into a single risk score per file.
-- KPIs: Hotspot Risk Score, High Risk File Count, Risk Reduction Rate, Refactoring Target Accuracy.
-- Feature Reference: M18-F053 (Hotspot Risk Mapping)
CREATE TABLE IF NOT EXISTS cmmi.risk_hotspots (
    file_path TEXT PRIMARY KEY,

    -- Components
    defect_count INTEGER NOT NULL,
    churn_score NUMERIC(10, 2) NOT NULL,
    complexity_score NUMERIC(10, 2) NOT NULL,

    -- Aggregate
    risk_score NUMERIC(10, 2) NOT NULL GENERATED ALWAYS AS (defect_count * 0.5 + churn_score * 0.3 + complexity_score * 0.2) STORED,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.risk_hotspots IS 'Aggregates risk factors to identify files that require immediate refactoring attention.';

-- Indexes for T050
CREATE INDEX idx_risk_hotspots_score ON cmmi.risk_hotspots (risk_score DESC);

-- =====================================================================================================================
-- 5. Entity Relationships and Constraints (Foreign Keys)
-- =====================================================================================================================
-- Note: These are defined here to ensure all tables exist before constraint application.

ALTER TABLE cmmi.spc_violations ADD CONSTRAINT fk_spc_violations_metric
    FOREIGN KEY (metric_name) REFERENCES cmmi.spc_control_limits(metric_name);

ALTER TABLE cmmi.defect_records ADD CONSTRAINT fk_defect_root_cause
    FOREIGN KEY (root_cause_id) REFERENCES cmmi.five_why_analyses(analysis_id);

ALTER TABLE cmmi.rollback_decisions ADD CONSTRAINT fk_rollback_deployment
    FOREIGN KEY (deployment_id) REFERENCES cmmi.deployments(deployment_id);

ALTER TABLE cmmi.rollback_decisions ADD CONSTRAINT fk_rollback_incident
    FOREIGN KEY (incident_id) REFERENCES cmmi.incidents(incident_id); -- Assuming M18-T149 exists later

ALTER TABLE cmmi.deployments ADD CONSTRAINT fk_deployment_release
    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id); -- Assuming M18-T176 exists later

ALTER TABLE cmmi.release_risk_scores ADD CONSTRAINT fk_risk_release
    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id);

ALTER TABLE cmmi.release_notes ADD CONSTRAINT fk_notes_release
    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id);

ALTER TABLE cmmi.monte_carlo_simulations ADD CONSTRAINT fk_sim_release
    FOREIGN KEY (target_release_id) REFERENCES cmmi.releases(release_id);

ALTER TABLE cmmi.incident_mttr_predictions ADD CONSTRAINT fk_mttr_incident
    FOREIGN KEY (incident_id) REFERENCES cmmi.incidents(incident_id);

ALTER TABLE cmmi.sast_findings ADD CONSTRAINT fk_sast_author
    FOREIGN KEY (author_id) REFERENCES cmmi.users(user_id); -- Assuming M18-T167 exists later

-- Trigger Implementations for Update Timestamps
CREATE TRIGGER trigger_update_metric_sources
    BEFORE UPDATE ON cmmi.metric_sources
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_spc_violations
    BEFORE UPDATE ON cmmi.spc_violations
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_defect_records
    BEFORE UPDATE ON cmmi.defect_records
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_release_risk_scores
    BEFORE UPDATE ON cmmi.release_risk_scores
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_defect_aging
    BEFORE UPDATE ON cmmi.defect_aging
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_code_ownership
    BEFORE UPDATE ON cmmi.code_ownership
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_slo_error_budgets
    BEFORE UPDATE ON cmmi.slo_error_budgets
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_risk_hotspots
    BEFORE UPDATE ON cmmi.risk_hotspots
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Row Level Security (RLS) Policies
-- =====================================================================================================================
ALTER TABLE cmmi.defect_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY defect_records_isolation_policy ON cmmi.defect_records
    FOR ALL
    USING (
        -- Allow access if user is assigned, reporter, or has super admin role
        assigned_to = current_setting('app.current_user_id')::UUID
        OR reporter_id = current_setting('app.current_user_id')::UUID
        OR current_setting('app.current_role', TRUE) IN ('ADMIN', 'QA_MANAGER', 'CTO')
    );

-- =====================================================================================================================
-- End of Script Segment (First 50 Objects)
-- =====================================================================================================================

-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 2
-- Tables DB051 - DB100
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T051 - branch_lifetimes
-- Description: Tracks the duration of feature branches from creation to merge or deletion.
-- Business Case: Long-lived branches increase integration risk and merge conflict complexity. In a CMMI Level 5 environment,
--                 process stability is key. This table monitors branch longevity to enforce "Trunk Based Development" or
--                 "Short Lived Branch" policies, reducing the "Integration Hell" phase and improving overall delivery velocity.
--                 Identifying branches that live too long allows managers to intervene, assist teams with blocking issues,
--                 or enforce archiving to prevent massive, monolithic merges that are prone to regression.
-- KPIs: Average Branch Lifetime (Hours), Stale Branch Count (>7 days), Merge Success Rate vs Lifetime, Integration Conflict Frequency, Branch Policy Adherence.
-- Feature Reference: M18-F056 (Branch Lifetime Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.branch_lifetimes (
    branch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identification
    branch_name VARCHAR(255) NOT NULL,
    repository_id VARCHAR(100) NOT NULL, -- Refers to M18-T144

    -- Timeline
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    merged_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Metrics
    lifetime_hours NUMERIC(10, 2) GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (COALESCE(merged_at, deleted_at, CURRENT_TIMESTAMP) - created_at)) / 3600
    ) STORED,

    -- Categorization
    branch_type VARCHAR(50) CHECK (branch_type IN ('feature', 'bugfix', 'hotfix', 'release')),
    is_stale BOOLEAN GENERATED ALWAYS AS (
        (COALESCE(merged_at, deleted_at) IS NULL AND (CURRENT_TIMESTAMP - created_at) > INTERVAL '7 days')
    ) STORED,

    -- Author
    author_id UUID
);

COMMENT ON TABLE cmmi.branch_lifetimes IS 'Tracks the lifespan of feature branches to identify integration risks and enforce development policies.';
COMMENT ON COLUMN cmmi.branch_lifetimes.lifetime_hours IS 'Calculated duration in hours from creation to merge/deletion/current time.';

CREATE INDEX idx_branch_lifetime_repo ON cmmi.branch_lifetimes (repository_id, created_at DESC);
CREATE INDEX idx_branch_lifetime_stale ON cmmi.branch_lifetimes (is_stale) WHERE is_stale = true;

-- =====================================================================================================================
-- Table: M18-T052 - pr_sizes
-- Description: Tracks the size of Pull Requests to enforce quality gates.
-- Business Case: Large Pull Requests are notoriously difficult to review effectively, leading to escaped defects. This table
--                 quantifies PR size (Lines of Code, number of files) to enforce a "Small Batch Size" policy. By blocking or
--                 warning on oversized PRs, M18 improves the effectiveness of peer reviews, reduces cognitive load on reviewers,
--                 and increases the speed of feedback loops, which are all critical for high-velocity engineering.
-- KPIs: Average PR Size (LOC), Oversized PR Rate (%), Review Latency vs Size, Defect Rate vs PR Size, PR Split Frequency.
-- Feature Reference: M18-F057 (PR Size Validator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pr_sizes (
    pr_id UUID PRIMARY KEY, -- Matches PR identifier in version control

    -- Metrics
    lines_added INTEGER NOT NULL,
    lines_deleted INTEGER NOT NULL,
    lines_changed INTEGER GENERATED ALWAYS AS (lines_added + lines_deleted) STORED,
    files_changed INTEGER NOT NULL,

    -- Categorization
    size_category VARCHAR(20) GENERATED ALWAYS AS (
        CASE
            WHEN (lines_added + lines_deleted) < 50 THEN 'XS'
            WHEN (lines_added + lines_deleted) < 200 THEN 'S'
            WHEN (lines_added + lines_deleted) < 500 THEN 'M'
            WHEN (lines_added + lines_deleted) < 1000 THEN 'L'
            ELSE 'XL'
        END
    ) STORED,

    -- Context
    target_branch VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pr_sizes_positive CHECK (lines_added >= 0 AND lines_deleted >= 0 AND files_changed >= 0)
);

COMMENT ON TABLE cmmi.pr_sizes IS 'Analyzes Pull Request sizes to enforce manageable code review batches.';
CREATE INDEX idx_pr_sizes_category ON cmmi.pr_sizes (size_category, created_at DESC);

-- =====================================================================================================================
-- Table: M18-T053 - external_api_latency
-- Description: Tracks latency metrics for third-party APIs (e.g., Tax Authorities, Credit Bureaus).
-- Business Case: PARI relies on external services. Degradation in these dependencies directly impacts the user experience.
--                 This table provides historical latency data (P50, P95, P99) to set accurate timeouts, trigger circuit breakers,
--                 and hold external vendors accountable to their SLAs. It also feeds into Monte Carlo simulations to predict
--                 transaction completion times under variable external load.
-- KPIs: External P95 Latency (ms), Latency Trend, SLA Breach Count, Timeout Error Rate, Vendor Comparison Score.
-- Feature Reference: M18-F060 (Third-Party API Latency Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.external_api_latency (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- API Identity
    api_name VARCHAR(100) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,

    -- Metrics (Percentiles)
    latency_p50 NUMERIC(10, 2) NOT NULL,
    latency_p95 NUMERIC(10, 2) NOT NULL,
    latency_p99 NUMERIC(10, 2) NOT NULL,

    -- Context
    error_rate NUMERIC(5, 2), -- Percentage
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT external_api_latency_check CHECK (latency_p50 > 0 AND error_rate >= 0 AND error_rate <= 100)
);

COMMENT ON TABLE cmmi.external_api_latency IS 'Historical performance data for critical third-party API integrations.';
CREATE INDEX idx_ext_api_name_time ON cmmi.external_api_latency (api_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T054 - job_skew
-- Description: Detects data skew in batch processing jobs (e.g., analytics or ETL).
-- Business Case: Data skew in distributed systems (e.g., Spark/Hadoop) leads to "straggler" tasks that delay entire jobs,
--                 causing SLA breaches for internal reporting. This table tracks the distribution of input rows across tasks.
--                 High skew indicates partitioning issues that need architectural remediation to ensure consistent processing windows.
-- KPIs: Max Skew Factor, Task Duration Variance, Job Completion Time, Cluster Utilization %, Skew Remediation Time.
-- Feature Reference: M18-F061 (Data Skew Detection (Jobs))
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.job_skew (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Job Identity
    job_id VARCHAR(100) NOT NULL,
    task_id VARCHAR(100) NOT NULL,

    -- Metrics
    input_rows BIGINT NOT NULL,
    duration_sec INTEGER NOT NULL,

    -- Analysis
    skew_factor NUMERIC(10, 2) GENERATED ALWAYS AS (
        NULLIF(input_rows, 0) -- Placeholder, usually calculated against avg
    ) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT job_skew_positive CHECK (input_rows >= 0 AND duration_sec >= 0)
);

COMMENT ON TABLE cmmi.job_skew IS 'Identifies uneven data distribution across batch processing tasks to optimize resource utilization.';
CREATE INDEX idx_job_skew_job ON cmmi.job_skew (job_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T055 - migration_risks
-- Description: Risk assessment for database schema migrations.
-- Business Case: Schema changes are the highest-risk operations in a production database. A failure can cause data loss or
--                 extended downtime. This table assesses risk based on table size, locking potential, and backward compatibility.
--                 It enforces a manual review gate for high-risk migrations, ensuring that DBAs and SREs are prepared before execution.
-- KPIs: High Risk Migration Count, Migration Failure Rate, Migration Execution Time, Rollback Success Rate, Data Loss Incidents.
-- Feature Reference: M18-F062 (Schema Migration Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.migration_risks (
    migration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    migration_name VARCHAR(255) NOT NULL,
    target_table VARCHAR(100) NOT NULL,

    -- Assessment
    risk_score NUMERIC(5, 2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    impact_analysis JSONB, -- {"estimated_downtime": "5m", "locks_required": true}

    -- Decision
    blocking_flag BOOLEAN DEFAULT false, -- If true, blocks automatic execution
    approved_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.migration_risks IS 'Risk assessment scores for database schema changes to prevent production outages.';
CREATE INDEX idx_migration_risk_score ON cmmi.migration_risks (risk_score DESC);

-- =====================================================================================================================
-- Table: M18-T056 - feature_flags
-- Description: Inventory and status of feature flags.
-- Business Case: Feature flags enable decoupling of deployment from release. However, stale flags increase code complexity and
--                 "dead code" execution paths. This table tracks usage metrics to identify flags that can be removed, ensuring the
--                 codebase remains clean and maintainable.
-- KPIs: Stale Flag Count, Flag Usage Frequency, Cleanup Velocity, Active Flag Count, Code Complexity Impact.
-- Feature Reference: M18-F063 (Feature Flag Adoption Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_flags (
    flag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL UNIQUE,

    -- Dates
    created_date DATE NOT NULL,
    last_used_date TIMESTAMP WITH TIME ZONE, -- Updated when accessed in prod
    expiry_date DATE,

    -- Configuration
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'STALE', 'REMOVED', 'PERMANENT'
    type VARCHAR(20) CHECK (type IN ('Release', 'Ops', 'Experiment', 'Permission')),

    -- Rollout
    rollout_percentage INTEGER DEFAULT 0 CHECK (rollout_percentage >= 0 AND rollout_percentage <= 100),

    CONSTRAINT feature_flags_dates CHECK (last_used_date IS NULL OR last_used_date >= created_date)
);

COMMENT ON TABLE cmmi.feature_flags IS 'Manages the lifecycle and usage metrics of feature toggles.';
CREATE INDEX idx_feature_flags_status ON cmmi.feature_flags (status);
CREATE INDEX idx_feature_flags_last_used ON cmmi.feature_flags (last_used_date DESC);

-- =====================================================================================================================
-- Table: M18-T057 - ab_test_results
-- Description: Statistical results of A/B testing experiments.
-- Business Case: Data-driven product decisions require statistical validity. This table stores the results of A/B tests,
--                 including p-values and conversion rates. It prevents "Hype Driven Development" by ensuring that only changes
--                 with statistically significant improvements are rolled out to 100% of users.
-- KPIs: Experiment Duration, Statistical Significance Rate (p < 0.05), Conversion Lift, False Positive Rate, Test Coverage.
-- Feature Reference: M18-F064 (A/B Test Statistical Significance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ab_test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id VARCHAR(100) NOT NULL,
    variant VARCHAR(50) NOT NULL, -- 'Control', 'Variant A'

    -- Metrics
    conversion_rate NUMERIC(5, 4) NOT NULL,
    sample_size INTEGER NOT NULL,

    -- Statistics
    p_value NUMERIC(10, 6),
    significance BOOLEAN,
    confidence_interval_low NUMERIC(5, 4),
    confidence_interval_high NUMERIC(5, 4),

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ab_test_results IS 'Stores statistical outcomes of A/B experiments to validate product changes.';
CREATE INDEX idx_ab_test_exp ON cmmi.ab_test_results (experiment_id, variant);

-- =====================================================================================================================
-- Table: M18-T058 - feedback_correlation
-- Description: Correlation between specific releases and customer feedback sentiment.
-- Business Case: Engineering quality is ultimately judged by the customer. This table correlates negative sentiment from support
--                 tickets or app store reviews with specific software releases. If a release causes a spike in negative feedback,
--                 it triggers an automatic investigation, linking technical performance to user experience.
-- KPIs: Sentiment Drop Trigger, Feedback Volume Spike, Correlation Coefficient, Issue Resolution Time, Customer Satisfaction Score (CSAT).
-- Feature Reference: M18-F065 (Customer Feedback Sentiment Correlation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feedback_correlation (
    correlation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    release_id UUID NOT NULL,

    -- Feedback Metrics
    sentiment_score NUMERIC(3, 2), -- -1.0 to 1.0
    feedback_volume INTEGER NOT NULL,

    -- Analysis
    correlation_coef NUMERIC(5, 2),
    significant_negative_surge BOOLEAN DEFAULT false,

    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE cmmi.feedback_correlation IS 'Links software releases to customer sentiment trends to detect quality regressions.';
CREATE INDEX idx_feedback_correlation_release ON cmmi.feedback_correlation (release_id);

-- =====================================================================================================================
-- Table: M18-T059 - container_vulnerabilities
-- Description: Security scan results for Docker/container images.
-- Business Case: Container images include the OS and libraries. A vulnerable base image can compromise the entire application stack.
--                 This table tracks CVEs found in images at build time, enforcing a policy that images with High/Critical vulnerabilities
--                 cannot be deployed, securing the supply chain.
-- KPIs: Vulnerable Image Count, CVE Severity Distribution, Build Failure due to Vulns, Remediation Time, Image Patching Cadence.
-- Feature Reference: M18-F067 (Container Image Scanning)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.container_vulnerabilities (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    image_id VARCHAR(100) NOT NULL, -- Image hash
    image_tag VARCHAR(100),

    -- Vulnerability
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')),
    package_name VARCHAR(100) NOT NULL,
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.container_vulnerabilities IS 'Logs security vulnerabilities found within Docker container images.';
CREATE INDEX idx_container_vuln_image ON cmmi.container_vulnerabilities (image_id, severity);
CREATE INDEX idx_container_vuln_cve ON cmmi.container_vulnerabilities (cve_id);

-- =====================================================================================================================
-- Table: M18-T060 - iac_drift
-- Description: Detects configuration drift between IaC definitions (Terraform/Ansible) and actual infrastructure.
-- Business Case: "Configuration Drift" occurs when manual changes are made to production infrastructure outside of the IaC pipeline.
--                 This breaks the "Infrastructure as Code" promise and leads to unrepeatable deployments. This table logs detected drifts,
--                 alerting SREs to reconcile the state or update the code.
-- KPIs: Drift Incidents per Week, Reconciliation Time, Drift Severity, Manual Change Attempts, Infrastructure Compliance %.
-- Feature Reference: M18-F068 (Infrastructure as Code (IaC) Drift Check)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.iac_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- 'AWS Instance', 'K8s Pod'

    -- Details
    drift_type VARCHAR(50) NOT NULL, -- 'Configuration Mismatch', 'Extra Resource', 'Missing Resource'
    expected_state JSONB,
    actual_state JSONB,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reconciled_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.iac_drift IS 'Tracks discrepancies between declared infrastructure code and running infrastructure.';
CREATE INDEX idx_iac_drift_resource ON cmmi.iac_drift (resource_id, detected_at DESC);

-- =====================================================================================================================
-- Table: M18-T061 - cost_metrics
-- Description: Detailed cost breakdown for cloud resources.
-- Business Case: Cloud costs can spiral without visibility. This table links costs to specific teams or features (Cost Allocation),
--                 enabling FinOps. By associating cost with transaction volume (Cost/TX), M18 helps identify inefficient algorithms
--                 or architectural choices that are financially unsustainable.
-- KPIs: Cost per Transaction, Monthly Cloud Spend, Cost Anomaly Detection %, Idle Resource Cost, Budget Utilization.
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cost_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Context
    resource_id VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50), -- 'Compute', 'Storage', 'Network'
    cost_center_id VARCHAR(50),

    -- Financials
    cost_usd NUMERIC(15, 4) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',

    -- Utilization (for efficiency calc)
    transaction_count BIGINT, -- To calc Cost/TX
    usage_hours NUMERIC(10, 2),

    date DATE NOT NULL
);

COMMENT ON TABLE cmmi.cost_metrics IS 'Granular tracking of cloud infrastructure costs for financial optimization and accountability.';
CREATE INDEX idx_cost_metrics_date ON cmmi.cost_metrics (date DESC);
CREATE INDEX idx_cost_metrics_resource ON cmmi.cost_metrics (resource_id);

-- =====================================================================================================================
-- Table: M18-T062 - accessibility_scans
-- Description: Results of accessibility (WCAG) scans.
-- Business Case: Digital accessibility is a legal requirement and a marker of quality. This table stores scan results from tools
--                 like Lighthouse or Axe. It tracks violation counts over time to ensure that new features do not regress accessibility
--                 standards, preventing lawsuits and ensuring inclusivity.
-- KPIs: WCAG Violation Count, Accessibility Score, Violation Fix Rate, Compliance Status, Scan Coverage.
-- Feature Reference: M18-F071 (Automated Accessibility Audit)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.accessibility_scans (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    page_url TEXT NOT NULL,

    -- Results
    violation_count INTEGER NOT NULL DEFAULT 0,
    wcag_level VARCHAR(10) CHECK (wcag_level IN ('A', 'AA', 'AAA')),
    accessibility_score NUMERIC(3, 0), -- 0 to 100

    -- Context
    build_id VARCHAR(100),
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT accessibility_scans_check CHECK (violation_count >= 0 AND accessibility_score BETWEEN 0 AND 100)
);

COMMENT ON TABLE cmmi.accessibility_scans IS 'Records results of WCAG compliance scans to ensure accessibility standards are met.';
CREATE INDEX idx_access_scans_url ON cmmi.accessibility_scans (page_url);

-- =====================================================================================================================
-- Table: M18-T063 - mobile_performance
-- Description: App performance metrics for mobile wallets (Crash free users).
-- Business Case: Mobile app performance directly impacts user adoption and churn. This table tracks crash rates, startup time,
--                 and ANR (Application Not Responding) rates. High crash rates trigger an automatic rollback of the mobile binary
--                 in the app store to prevent mass user loss.
-- KPIs: Crash Free Users (%) > 98%, App Startup Time, ANR Rate, App Store Rating, Bug Report Volume.
-- Feature Reference: M18-F074 (Mobile App Performance Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.mobile_performance (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    app_version VARCHAR(20) NOT NULL,
    platform VARCHAR(10) NOT NULL CHECK (platform IN ('iOS', 'Android')),

    -- Metrics
    crash_free_users NUMERIC(5, 2) NOT NULL, -- Percentage
    crash_count INTEGER NOT NULL,
    users_affected INTEGER NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT mobile_performance_check CHECK (crash_free_users >= 0 AND crash_free_users <= 100)
);

COMMENT ON TABLE cmmi.mobile_performance IS 'Monitors stability and performance metrics for mobile applications.';
CREATE INDEX idx_mobile_perf_version ON cmmi.mobile_performance (app_version, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T064 - pii_access_logs
-- Description: Audit log for access to Personally Identifiable Information.
-- Business Case: Under GDPR and other privacy regulations, access to PII must be strictly logged and justifiable. This table
--                 records every query or view action on sensitive data fields, providing an immutable audit trail for compliance
--                 officers and forensic analysis in case of a leak.
-- KPIs: PII Access Volume, Justification Acceptance Rate, Anomalous Access Alerts, Audit Log Completeness, Compliance Report Readiness.
-- Feature Reference: M18-F080 (PII Data Access Logger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pii_access_logs (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Data Context
    data_type VARCHAR(50) NOT NULL, -- 'Customer Name', 'Transaction History'
    record_id UUID NOT NULL, -- ID of the record accessed

    -- Access Details
    action VARCHAR(20) NOT NULL, -- 'READ', 'EXPORT', 'UPDATE'
    justification TEXT, -- Required reason for access
    session_id VARCHAR(100),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pii_access_logs IS 'Immutable audit trail for accessing Personally Identifiable Information (PII).';
CREATE INDEX idx_pii_access_user ON cmmi.pii_access_logs (user_id, timestamp DESC);
CREATE INDEX idx_pii_access_record ON cmmi.pii_access_logs (record_id);

-- =====================================================================================================================
-- Table: M18-T065 - consent_records
-- Description: User consent tracking for data processing.
-- Business Case: Legal compliance requires proof of consent. This table stores the user's agreement to specific processing activities
--                 (e.g., "Marketing Emails", "Analytics"). It ensures that PARI does not process data beyond the scope granted by the user.
-- KPIs: Consent Granted Rate, Consent Withdrawal Rate, Consent Compliance, Record Accuracy, Audit Query Performance.
-- Feature Reference: M18-F082 (Consent Management Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.consent_records (
    consent_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Consent Details
    consent_type VARCHAR(50) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,

    -- Validity
    is_valid BOOLEAN GENERATED ALWAYS AS (revoked_at IS NULL) STORED,
    ip_address INET,
    user_agent TEXT
);

COMMENT ON TABLE cmmi.consent_records IS 'Manages user permissions and consent history for GDPR compliance.';
CREATE INDEX idx_consent_user ON cmmi.consent_records (user_id, consent_type);
CREATE INDEX idx_consent_valid ON cmmi.consent_records (is_valid) WHERE is_valid = true;

-- =====================================================================================================================
-- Table: M18-T066 - model_bias_metrics
-- Description: Fairness metrics for AI models used in PARI.
-- Business Case: Algorithmic bias (e.g., gender or race bias in loan decisions) is a major ethical and legal risk. This table stores
--                 fairness metrics (e.g., Disparate Impact) for production models. If bias exceeds acceptable thresholds, the model
--                 is automatically deprecated or retrained.
-- KPIs: Demographic Parity Difference, Equal Opportunity Difference, Model Fairness Score, Bias Alert Count, Retraining Frequency.
-- Feature Reference: M18-F083 (Algorithmic Bias Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_bias_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Bias Analysis
    metric_name VARCHAR(50) NOT NULL, -- 'DisparateImpact', 'EqualOdds'
    group_attribute VARCHAR(50) NOT NULL, -- 'Gender', 'AgeGroup'
    bias_score NUMERIC(5, 2) NOT NULL,

    -- Thresholds
    threshold NUMERIC(5, 2),
    is_violation BOOLEAN GENERATED ALWAYS AS (ABS(bias_score) > COALESCE(threshold, 0.2)) STORED,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.model_bias_metrics IS 'Tracks fairness and bias metrics to ensure ethical AI operations.';
CREATE INDEX idx_model_bias_model ON cmmi.model_bias_metrics (model_id, measured_at DESC);

-- =====================================================================================================================
-- Table: M18-T067 - model_drift
-- Description: Drift metrics for production ML models (e.g., Fraud Detection).
-- Business Case: Model drift occurs when the statistical properties of real-world data change, making the model less accurate over time.
--                 This table tracks metrics like KL Divergence or PSI (Population Stability Index). Significant drift triggers an
--                 automated retraining pipeline to maintain fraud detection accuracy.
-- KPIs: Drift Magnitude, Drift Detection Latency, Model Accuracy vs Drift, Retraining Success Rate, False Positive Rate Impact.
-- Feature Reference: M18-F084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Metrics
    drift_metric VARCHAR(50) NOT NULL, -- 'KLDivergence', 'PSI'
    value NUMERIC(10, 6) NOT NULL,
    threshold NUMERIC(10, 6),

    -- Context
    data_window_start TIMESTAMP WITH TIME ZONE,
    data_window_end TIMESTAMP WITH TIME ZONE,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.model_drift IS 'Monitors statistical divergence between training data and live production data.';
CREATE INDEX idx_model_drift_model ON cmmi.model_drift (model_id, detected_at DESC);

-- =====================================================================================================================
-- Table: M18-T068 - training_data_versions
-- Description: Versioning of training datasets.
-- Business Case: Reproducibility is critical for AI. To debug a model failure, one must know exactly which data version it was trained on.
--                 This table links model versions to specific snapshots of the training data (hashes or paths), enabling auditability
--                 and precise rollback if data contamination is discovered.
-- KPIs: Version Storage Size, Data Lineage Completeness, Retrieval Speed, Contamination Detection Time, Version Rollback Frequency.
-- Feature Reference: M18-F085 (Training Data Versioning)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_data_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_name VARCHAR(100) NOT NULL,
    version_number VARCHAR(50) NOT NULL,

    -- Storage
    storage_path TEXT NOT NULL,
    data_hash CHAR(64) NOT NULL, -- SHA-256

    -- Metadata
    row_count BIGINT,
    creation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_by UUID
);

COMMENT ON TABLE cmmi.training_data_versions IS 'Immutable version control for datasets used to train machine learning models.';
CREATE INDEX idx_training_data_name ON cmmi.training_data_versions (dataset_name, creation_date DESC);

-- =====================================================================================================================
-- Table: M18-T069 - hyperparameters
-- Description: Tuned hyperparameters for models.
-- Business Case: Model performance depends heavily on hyperparameters (learning rate, tree depth). This table stores the optimal
--                 parameters found during the tuning phase, ensuring that the deployed model uses the best known configuration for
--                 accuracy and efficiency.
-- KPIs: Model Accuracy Lift, Hyperparameter Search Time, Best Score Achieved, Parameter Stability, Overfitting Indicators.
-- Feature Reference: M18-F087 (Automated Hyperparameter Tuning)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.hyperparameters (
    param_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Parameters
    param_name VARCHAR(100) NOT NULL,
    param_value JSONB NOT NULL, -- Can store complex types like arrays

    -- Outcome
    accuracy_score NUMERIC(5, 4),

    tuned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.hyperparameters IS 'Stores optimal configuration parameters for trained machine learning models.';
CREATE INDEX idx_hyperparams_model ON cmmi.hyperparameters (model_id, accuracy_score DESC);

-- =====================================================================================================================
-- Table: M18-T070 - shadow_deployments
-- Description: Shadow mode runs (running new models alongside production without serving traffic).
-- Business Case: Testing new models on production data without user risk. Shadow deployments route a copy of production traffic
--                 to the new model and compare its predictions to the live model. This table logs the performance delta to decide
--                 when to cut over.
-- KPIs: Prediction Consistency, Latency Difference, Resource Overhead, Error Comparison, Cutover Readiness.
-- Feature Reference: M18-F088 (Shadow Mode Deployment)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.shadow_deployments (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL, -- The new candidate model

    -- Latency Comparison
    shadow_latency_ms NUMERIC(10, 2),
    production_latency_ms NUMERIC(10, 2),

    -- Accuracy/Outcome Comparison
    shadow_accuracy NUMERIC(5, 4),
    production_accuracy NUMERIC(5, 4),

    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ended_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.shadow_deployments IS 'Logs performance comparisons of candidate models running in shadow mode against production models.';
CREATE INDEX idx_shadow_model ON cmmi.shadow_deployments (model_id);

-- =====================================================================================================================
-- Table: M18-T071 - chaos_experiments
-- Description: Record of chaos engineering tests (fault injection).
-- Business Case: Proactively finding weaknesses. Chaos engineering injects failures (latency, pod kills) to verify resilience.
--                 This table records the parameters and results, ensuring that the system actually fails gracefully and recovers
--                 automatically, as required for high-availability fintech systems.
-- KPIs: Recovery Success Rate, Blast Radius Containment, MTTR during Chaos, Experiment Coverage, System Resilience Score.
-- Feature Reference: M18-F091 (Chaos Engineering Integration)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.chaos_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    experiment_name VARCHAR(255) NOT NULL,
    fault_type VARCHAR(50) NOT NULL, -- 'latency', 'pod_kill', 'cpu_stress'

    -- Scope
    blast_radius JSONB NOT NULL, -- {"service": "payment-api", "region": "us-east-1"}

    -- Outcome
    result VARCHAR(20) NOT NULL CHECK (result IN ('Passed', 'Failed', 'Inconclusive')),
    recovery_time_seconds INTEGER,

    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.chaos_experiments IS 'Records fault injection experiments to verify system resilience and self-healing capabilities.';
CREATE INDEX idx_chaos_result ON cmmi.chaos_experiments (result, executed_at DESC);

-- =====================================================================================================================
-- Table: M18-T072 - game_days
-- Description: Disaster recovery drills.
-- Business Case: Testing the team, not just the software. Game days simulate major outages (e.g., "Region is down") to train
--                 the team on incident response. This table logs the scenario, participants, and outcome to track team readiness
--                 and identify gaps in runbooks.
-- KPIs: Drill Completion Rate, Team Response Time, Procedure Accuracy, Knowledge Gap Identification, Frequency of Drills.
-- Feature Reference: M18-F092 (Game Day Scenario Runner)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.game_days (
    drill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scenario
    scenario VARCHAR(255) NOT NULL,
    severity VARCHAR(20), -- 'Sev1', 'Sev2'

    -- Execution
    date DATE NOT NULL,
    participants TEXT[], -- List of user IDs or team names
    outcome VARCHAR(50), -- 'Success', 'Lessons Learned', 'Failure'

    lessons_learned TEXT
);

COMMENT ON TABLE cmmi.game_days IS 'Logs execution of disaster recovery drills to assess team readiness.';
CREATE INDEX idx_gameday_date ON cmmi.game_days (date DESC);

-- =====================================================================================================================
-- Table: M18-T073 - runbook_executions
-- Description: Logs of automated runbook runs.
-- Business Case: Reducing human error during incidents. Automating runbooks ensures consistent execution of remediation steps.
--                 This table tracks which scripts were triggered, by what event, and if they succeeded, providing data to refine
--                 the automation logic.
-- KPIs: Auto-Remediation Rate (%), Execution Success Rate, Time Saved vs Manual, Failure Rate of Scripts, Incident Resolution Impact.
-- Feature Reference: M18-F093 (Runbook Automation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.runbook_executions (
    execution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    runbook_id VARCHAR(100) NOT NULL,

    -- Trigger
    trigger_event VARCHAR(100), -- 'HighCPU', 'DiskFull'

    -- Timing
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    -- Result
    success BOOLEAN NOT NULL,
    output TEXT,
    error_message TEXT
);

COMMENT ON TABLE cmmi.runbook_executions IS 'Audit log of automated remediation scripts triggered by operational events.';
CREATE INDEX idx_runbook_runbook ON cmmi.runbook_executions (runbook_id, start_time DESC);

-- =====================================================================================================================
-- Table: M18-T074 - alert_noise
-- Description: Metrics on alerting noise and efficacy.
-- Business Case: Alert fatigue causes real incidents to be missed. This table tracks how often alerts fire vs. how many are actionable.
--                 High noise ratios trigger a review of alert thresholds to suppress notifications that don't require human intervention.
-- KPIs: Noise Ratio (%), Actionable Alert Rate, Alert Fatigue Score, Suppression Effectiveness, DORA Alert Reliability.
-- Feature Reference: M18-F094 (Alert Noise Reduction)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.alert_noise (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_rule_id VARCHAR(100) NOT NULL,

    -- Metrics
    total_fired BIGINT NOT NULL,
    actionable_count BIGINT NOT NULL,
    noise_ratio NUMERIC(5, 2) GENERATED ALWAYS AS (
        CASE WHEN total_fired > 0 THEN 1.0 - (actionable_count::NUMERIC / total_fired) ELSE 0 END
    ) STORED,

    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL
);

COMMENT ON TABLE cmmi.alert_noise IS 'Calculates the signal-to-noise ratio of monitoring alerts to reduce fatigue.';
CREATE INDEX idx_alert_noise_rule ON cmmi.alert_noise (alert_rule_id, period_start DESC);

-- =====================================================================================================================
-- Table: M18-T075 - anomaly_baselines
-- Description: Current baseline for anomaly detection (dynamic thresholds).
-- Business Case: Static thresholds don't work for variable traffic (e.g., weekend vs weekday). This table stores the calculated
--                 baseline (expected normal behavior) for metrics, updated periodically or via online learning. Anomalies are detected
--                 based on deviation from this moving baseline.
-- KPIs: Baseline Accuracy, Adaptation Speed, False Anomaly Rate, Seasonality Capture, Baseline Stability.
-- Feature Reference: M18-F095 (Anomaly Detection Baseline Learner)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.anomaly_baselines (
    baseline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,

    -- Baseline Data
    baseline_value NUMERIC(18, 6) NOT NULL,
    upper_bound NUMERIC(18, 6),
    lower_bound NUMERIC(18, 6),
    seasonality_period INTERVAL, -- e.g., '1 day'

    -- Metadata
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE,

    learning_algorithm VARCHAR(50) DEFAULT 'MovingAverage'
);

COMMENT ON TABLE cmmi.anomaly_baselines IS 'Stores dynamic baseline values for metrics used in adaptive anomaly detection.';
CREATE INDEX idx_anomaly_baseline_metric ON cmmi.anomaly_baselines (metric_name, valid_from DESC);

-- =====================================================================================================================
-- Table: M18-T076 - backup_integrity
-- Description: Verification of backup restores.
-- Business Case: A backup that cannot be restored is worthless. This table records the results of periodic "fire drills" where
--                 backups are actually restored to a sandbox to verify data integrity and RPO/RTO compliance.
-- KPIs: Restore Success Rate, Backup Verification Frequency, RTO Compliance, RPO Compliance, Data Corruption Detection.
-- Feature Reference: M18-F097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.backup_integrity (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id VARCHAR(100) NOT NULL,

    -- Execution
    restore_test_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    size_gb NUMERIC(10, 2),

    -- Outcome
    success_flag BOOLEAN NOT NULL,
    corruption_found BOOLEAN DEFAULT false,
    error_message TEXT
);

COMMENT ON TABLE cmmi.backup_integrity IS 'Verification logs for database backup restorability.';
CREATE INDEX idx_backup_integrity_id ON cmmi.backup_integrity (backup_id);

-- =====================================================================================================================
-- Table: M18-T077 - replication_lag
-- Description: Database replica lag history.
-- Business Case: Replicas serve read traffic. If they lag significantly, users see stale data, which is unacceptable for financial balances.
--                 This table tracks lag bytes or seconds to identify read replicas that need resync or hardware upgrades.
-- KPIs: Max Replication Lag (Seconds), Replica Availability, Lag Frequency, Data Freshness Score, Resync Required Count.
-- Feature Reference: M18-F098 (Follower Lag Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.replication_lag (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    replica_name VARCHAR(100) NOT NULL,

    -- Metrics
    lag_bytes BIGINT,
    lag_seconds NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT replication_lag_check CHECK (lag_bytes >= 0 AND lag_seconds >= 0)
);

COMMENT ON TABLE cmmi.replication_lag IS 'Monitors the delay between data commit on primary and visibility on replicas.';
CREATE INDEX idx_rep_lag_replica ON cmmi.replication_lag (replica_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T078 - connection_pools
-- Description: Pool utilization metrics for database connections.
-- Business Case: Exhausting the connection pool causes application errors. Underutilizing it wastes resources. This table tracks
--                 active vs. idle connections to tune pool sizes (min/max) for optimal throughput and stability under load.
-- KPIs: Pool Usage %, Connection Wait Time, Peak Usage, Connection Leak Detection, Pool Efficiency.
-- Feature Reference: M18-F099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.connection_pools (
    pool_name VARCHAR(100) NOT NULL,
    active_connections INTEGER NOT NULL,
    idle_connections INTEGER NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    total_size INTEGER,
    waiting_threads INTEGER
);
-- Add composite primary key since pool_name + timestamp is unique, or use UUID. Let's use UUID for consistency.
ALTER TABLE cmmi.connection_pools ADD COLUMN pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY;

COMMENT ON TABLE cmmi.connection_pools IS 'Tracks utilization metrics for database connection pools.';
CREATE INDEX idx_pool_name_time ON cmmi.connection_pools (pool_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T079 - cache_stats
-- Description: Cache performance metrics (Redis/Memcached).
-- Business Case: Cache is critical for low latency. A low hit ratio increases load on the database and slows down transactions.
--                 This table tracks hit/miss ratios to identify cache eviction policies that need tuning or data that isn't being cached.
-- KPIs: Cache Hit Ratio (>95%), Eviction Rate, Memory Usage %, Latency (p99), Key Count.
-- Feature Reference: M18-F100 (Cache Hit Rate Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cache_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_node VARCHAR(100) NOT NULL,

    -- Metrics
    hit_count BIGINT NOT NULL,
    miss_count BIGINT NOT NULL,
    hit_ratio NUMERIC(5, 2) GENERATED ALWAYS AS (
        CASE WHEN (hit_count + miss_count) > 0 THEN (hit_count::NUMERIC / (hit_count + miss_count)) * 100 ELSE 0 END
    ) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cache_stats IS 'Monitors hit/miss ratios and efficiency of caching layers.';
CREATE INDEX idx_cache_node_time ON cmmi.cache_stats (cache_node, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T080 - queue_depths
-- Description: Message queue sizes (Kafka/RabbitMQ).
-- Business Case: Growing queue depth indicates a consumer bottleneck. If messages pile up, events (like payments) are delayed.
--                 This table monitors queue depth to trigger auto-scaling of consumers or alert ops teams to processing delays.
-- KPIs: Queue Depth (Count), Consumer Lag, Processing Throughput, Message Age, Empty Queue %.
-- Feature Reference: M18-F101 (Queue Depth Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.queue_depths (
    measurement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    queue_name VARCHAR(100) NOT NULL,

    depth BIGINT NOT NULL,
    consumer_lag BIGINT, -- Messages lagging behind consumer offset

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.queue_depths IS 'Tracks the size of message queues to detect processing bottlenecks.';
CREATE INDEX idx_queue_name_time ON cmmi.queue_depths (queue_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T081 - dlq_messages
-- Description: Dead Letter Queue analysis.
-- Business Case: Messages in the DLQ are failures. Analyzing them reveals integration issues (e.g., partner API is down).
--                 This table aggregates error types and frequencies to prioritize fixes with external vendors or internal validation logic.
-- KPIs: DLQ Size, Error Type Frequency, Retry Success Rate, Time in DLQ, Resolution Rate.
-- Feature Reference: M18-F102 (Dead Letter Queue (DLQ) Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dlq_messages (
    message_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_queue VARCHAR(100) NOT NULL,

    -- Error Context
    error_reason TEXT NOT NULL,
    error_category VARCHAR(50), -- 'Validation', 'Timeout', '500Error'

    -- Metadata
    payload_hash CHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dlq_messages IS 'Aggregates and analyzes messages that have failed processing and moved to the Dead Letter Queue.';
CREATE INDEX idx_dlq_queue ON cmmi.dlq_messages (original_queue, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T082 - throttling_metrics
-- Description: API rate limiting stats.
-- Business Case: Protecting the system from abuse or overload. This table tracks how often rate limits are hit. A high rate of
--                 throttling legitimate users suggests a need to increase capacity or optimize the API; high throttling of a single
--                 IP suggests an attack.
-- KPIs: Throttled Requests (%), Rate Limit Breaches, User Impact Score, DDoS Effectiveness, Capacity Planning Trigger.
-- Feature Reference: M18-F103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.throttling_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100) NOT NULL,

    -- Limits
    requests_limit INTEGER NOT NULL,
    requests_throttled INTEGER NOT NULL,

    -- Context
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.throttling_metrics IS 'Tracks the frequency and impact of API rate limiting.';
CREATE INDEX idx_throttle_endpoint ON cmmi.throttling_metrics (endpoint_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T083 - webhook_deliveries
-- Description: Status of outgoing webhooks.
-- Business Case: PARI needs to notify partners (e.g., merchants) of events. Failed webhooks mean lost notifications. This table
--                 tracks delivery status, retry attempts, and success rates to ensure reliable external communication.
-- KPIs: Delivery Success Rate (>99.5%), Retry Frequency, Latency, Partner Error Count, Notification Gap.
-- Feature Reference: M18-F104 (Webhook Delivery Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.webhook_deliveries (
    delivery_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    webhook_id VARCHAR(100) NOT NULL,
    event_id VARCHAR(100) NOT NULL,

    -- Delivery
    status_code INTEGER, -- 200, 404, 500
    attempts INTEGER NOT NULL DEFAULT 0,

    -- Final State
    delivery_status VARCHAR(20) NOT NULL CHECK (delivery_status IN ('Success', 'Failed', 'Pending')),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.webhook_deliveries IS 'Monitors the success rate and latency of outgoing webhook notifications.';
CREATE INDEX idx_webhook_id ON cmmi.webhook_deliveries (webhook_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T084 - idempotency_tests
-- Description: Results of idempotency tests.
-- Business Case: Idempotency prevents double-charging. This table logs the results of automated tests that send the same request
--                 twice to verify the system only processes it once. Failure here is a critical financial bug.
-- KPIs: Idempotency Failure Count, Test Coverage of Endpoints, Consistency Rate, Financial Safety Score.
-- Feature Reference: M18-F105 (Idempotency Validation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.idempotency_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100) NOT NULL,

    -- Result
    result VARCHAR(20) NOT NULL CHECK (result IN ('Consistent', 'Inconsistent', 'Error')),

    -- Details
    attempt_1_status VARCHAR(20),
    attempt_2_status VARCHAR(20),
    response_body_diff BOOLEAN,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.idempotency_tests IS 'Validates that API endpoints handle duplicate requests correctly without side effects.';
CREATE INDEX idx_idempotency_endpoint ON cmmi.idempotency_tests (endpoint_id);

-- =====================================================================================================================
-- Table: M18-T085 - circuit_breakers
-- Description: State of circuit breakers in the system.
-- Business Case: Circuit breakers stop cascading failures. Monitoring their state (Open/Closed) gives a real-time view of system health.
--                 If a breaker is Open, dependent services are unavailable, requiring immediate investigation.
-- KPIs: Circuit Open Time, Breaker Trip Frequency, Recovery Rate, System Availability Impact, Manual Override Count.
-- Feature Reference: M18-F106 (Circuit Breaker State Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.circuit_breakers (
    monitor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,

    -- State
    state cmmi.circuit_state_enum NOT NULL,
    last_transition TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Context
    failure_threshold INTEGER,
    current_failure_count INTEGER,
    reason TEXT,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.circuit_breakers IS 'Tracks the operational state of circuit breakers used to prevent cascading failures.';
CREATE INDEX idx_circuit_state ON cmmi.circuit_breakers (service_name, state);

-- =====================================================================================================================
-- Table: M18-T086 - slow_queries
-- Description: Log of slow database queries.
-- Business Case: Slow queries degrade the entire user experience. This table automatically captures queries exceeding a threshold,
--                 flagging them for optimization (indexing, rewriting) to maintain low latency SLOs.
-- KPIs: Slow Query Count, Avg Query Duration, Improvement Rate, Query Optimization ROI, Database CPU Impact.
-- Feature Reference: M18-F109 (Slow Query Logger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.slow_queries (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash VARCHAR(64) NOT NULL,

    -- Metrics
    duration_ms NUMERIC(10, 2) NOT NULL,
    query_plan TEXT,

    -- Context
    database_name VARCHAR(50),
    application_name VARCHAR(50),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.slow_queries IS 'Stores details of queries that exceed performance thresholds for optimization analysis.';
CREATE INDEX idx_slow_query_hash ON cmmi.slow_queries (query_hash);
CREATE INDEX idx_slow_query_time ON cmmi.slow_queries (duration_ms DESC);

-- =====================================================================================================================
-- Table: M18-T087 - index_usage
-- Description: Usage stats for DB indexes.
-- Business Case: Unused indexes waste disk space and slow down writes (INSERT/UPDATE). Overused indexes might need caching.
--                 This table identifies indexes that haven't been read in a long time for deletion, and hot indexes for optimization.
-- KPIs: Unused Index Count, Index Scan Ratio, Write Overhead, Index Size Reduction, Hotspot Identification.
-- Feature Reference: M18-F110 (Index Usage Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.index_usage (
    index_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    index_name VARCHAR(255) NOT NULL,

    -- Stats
    index_scans BIGINT NOT NULL,
    tuples_read BIGINT,
    tuples_fetched BIGINT,

    -- Analysis
    last_used TIMESTAMP WITH TIME ZONE,
    is_unused BOOLEAN GENERATED ALWAYS AS (index_scans = 0) STORED,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.index_usage IS 'Analyzes read/write patterns on database indexes to optimize performance.';
CREATE INDEX idx_index_usage_name ON cmmi.index_usage (index_name);

-- =====================================================================================================================
-- Table: M18-T088 - table_bloat
-- Description: Bloat metrics for tables.
-- Business Case: In PostgreSQL (and others), UPDATEs and DELETEs leave "dead space" (bloat). High bloat slows down scans and wastes
--                 storage. This table identifies tables needing VACUUM or reindexing to maintain performance.
-- KPIs: Bloat Ratio (%), Table Size Waste, Vacuum Effectiveness, Storage Savings, Scan Performance Impact.
-- Feature Reference: M18-F111 (Table Bloat Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.table_bloat (
    bloat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,

    -- Metrics
    bloat_bytes BIGINT NOT NULL,
    bloat_percentage NUMERIC(5, 2) NOT NULL,

    -- Recommendation
    action_required VARCHAR(50) CHECK (action_required IN ('None', 'Vacuum', 'Reindex', 'Cluster')),

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.table_bloat IS 'Identifies storage inefficiency (bloat) in database tables.';
CREATE INDEX idx_table_bloat_ratio ON cmmi.table_bloat (bloat_percentage DESC);

-- =====================================================================================================================
-- Table: M18-T089 - lock_waits
-- Description: Database lock wait events.
-- Business Case: Lock contention causes transaction stalls. If a transaction waits too long for a lock, it times out, failing
--                 the user request. This table tracks lock waits to identify hot tables or long-running transactions that need to
--                 be shortened or optimized.
-- KPIs: Lock Wait Time (ms), Deadlock Count, Contention Ratio, Transaction Timeout Rate, Blocking Transaction Analysis.
-- Feature Reference: M18-F112 (Lock Contention Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.lock_waits (
    wait_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    lock_type VARCHAR(50) NOT NULL,
    relation TEXT, -- Table name
    duration_ms NUMERIC(10, 2) NOT NULL,

    blocked_query TEXT,
    blocking_query TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.lock_waits IS 'Logs database lock contention events that delay transactions.';
CREATE INDEX idx_lock_waits_duration ON cmmi.lock_waits (duration_ms DESC);

-- =====================================================================================================================
-- Table: M18-T090 - cert_expiry
-- Description: SSL certificate expiry tracking.
-- Business Case: Expired certs cause immediate outages (security errors). This table monitors cert expiry dates across all services
--                 (Load Balancers, Databases, APIs) to trigger automated renewal workflows weeks before expiration.
-- KPIs: Days to Expiry, Cert Renewal Success Rate, Outage due to Certs, Coverage of Monitored Certs, Renewal Automation Trigger.
-- Feature Reference: M18-F114 (SSL/TLS Certificate Expiry Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cert_expiry (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    cert_issuer VARCHAR(255),

    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Monitoring
    days_remaining INTEGER GENERATED ALWAYS AS (
        EXTRACT(DAY FROM (expiry_date - CURRENT_DATE))
    ) STORED,

    status VARCHAR(20) GENERATED ALWAYS AS (
        CASE
            WHEN expiry_date < CURRENT_DATE THEN 'EXPIRED'
            WHEN expiry_date < CURRENT_DATE + INTERVAL '7 days' THEN 'CRITICAL'
            WHEN expiry_date < CURRENT_DATE + INTERVAL '30 days' THEN 'WARNING'
            ELSE 'OK'
        END
    ) STORED
);

COMMENT ON TABLE cmmi.cert_expiry IS 'Tracks expiration dates of SSL/TLS certificates to prevent outages.';
CREATE INDEX idx_cert_expiry_date ON cmmi.cert_expiry (expiry_date);
CREATE INDEX idx_cert_status ON cmmi.cert_expiry (status);

-- =====================================================================================================================
-- Table: M18-T091 - network_latency
-- Description: Internal network latency checks.
-- Business Case: Microservice communication latency adds up. High inter-node latency increases the SLO budget burn rate.
--                 This table monitors latency between critical nodes (App to DB, Service to Service) to detect network issues
--                 or hardware degradation.
-- KPIs: Internal Latency (p95), Packet Loss %, Jitter (ms), Network Availability, Bottleneck Identification.
-- Feature Reference: M18-F116 (Bandwidth Utilization Tracker) - Latency aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.network_latency (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_host VARCHAR(100) NOT NULL,
    dest_host VARCHAR(100) NOT NULL,

    -- Metrics
    latency_ms NUMERIC(10, 2) NOT NULL,
    packet_loss_pct NUMERIC(5, 2) NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT network_latency_check CHECK (packet_loss_pct >= 0 AND packet_loss_pct <= 100)
);

COMMENT ON TABLE cmmi.network_latency IS 'Monitors latency and packet loss between networked components.';
CREATE INDEX idx_net_latency_path ON cmmi.network_latency (source_host, dest_host, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T092 - disk_io
-- Description: Disk I/O metrics.
-- Business Case: Database and application servers are I/O bound. High I/O wait times indicate disk saturation, which throttles
--                 the entire application. This table tracks reads/writes and await times to validate storage performance or
--                 identify the need for faster SSDs.
-- KPIs: IOPS (Read/Write), Await Time (ms), Throughput (MB/s), Queue Length, Disk Saturation %.
-- Feature Reference: M18-F118 (Disk IOPS Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.disk_io (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    device_name VARCHAR(50) NOT NULL,

    -- Metrics
    read_ops NUMERIC(12, 2),
    write_ops NUMERIC(12, 2),
    await_time_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.disk_io IS 'Tracks disk input/output operations and latency to detect storage bottlenecks.';
CREATE INDEX idx_disk_io_device ON cmmi.disk_io (device_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T093 - disk_forecasts
-- Description: Predicts when disk will run out of space.
-- Business Case: Running out of disk space causes immediate crashes. This table uses historical growth rates to forecast the
--                 "Date Full" for all volumes, providing ample time for capacity planning (expansion or cleanup).
-- KPIs: Forecast Accuracy (%), Days Until Full, Storage Growth Rate (GB/day), Capacity Planning Lead Time, Alert Precision.
-- Feature Reference: M18-F119 (Disk Space Forecasting)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.disk_forecasts (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mount_point TEXT NOT NULL,

    -- Prediction
    forecast_full_date DATE NOT NULL,
    days_remaining INTEGER GENERATED ALWAYS AS (forecast_full_date - CURRENT_DATE) STORED,
    confidence NUMERIC(3, 2), -- 0 to 1

    -- Inputs
    current_usage_gb NUMERIC(10, 2),
    growth_rate_gb_day NUMERIC(10, 2),

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.disk_forecasts IS 'Predicts future disk exhaustion dates based on usage growth trends.';
CREATE INDEX idx_disk_forecast_mount ON cmmi.disk_forecasts (mount_point, forecast_full_date);

-- =====================================================================================================================
-- Table: M18-T094 - thread_dumps
-- Description: Metadata of collected thread dumps.
-- Business Case: When servers hang, thread dumps reveal what code is stuck. This table manages the metadata of dumps taken
--                 automatically when deadlock or high CPU is detected, linking them to specific incidents for debugging.
-- KPIs: Dump Collection Latency, Deadlock Detection Time, Analysis Resolution Time, Storage Used, Dump Utility Rate.
-- Feature Reference: M18-F123 (Thread Dump Collector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.thread_dumps (
    dump_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,

    -- Trigger
    trigger_reason VARCHAR(50) NOT NULL, -- 'Deadlock', 'HighCPU', 'Manual'

    -- File
    file_path TEXT NOT NULL, -- Path to the stored dump file

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.thread_dumps IS 'Manages the inventory of thread dumps collected for debugging concurrency issues.';
CREATE INDEX idx_thread_dump_server ON cmmi.thread_dumps (server_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T095 - heap_dumps
-- Description: Metadata of collected heap dumps.
-- Business Case: Out of Memory (OOM) errors are fatal. Heap dumps allow post-mortem analysis to find memory leaks. This table
--                 tracks dumps taken during OOM events or high memory usage alerts.
-- KPIs: OOM Detection Time, Dump Collection Success, Leak Identification Rate, Storage Retention, Analysis Speed.
-- Feature Reference: M18-F124 (Heap Dump Collector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.heap_dumps (
    dump_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,

    -- Trigger
    trigger_reason VARCHAR(50) NOT NULL, -- 'OOM', 'HighUsage', 'Manual'

    -- File
    file_path TEXT NOT NULL,
    dump_size_mb NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.heap_dumps IS 'Stores metadata for heap dumps used to analyze memory usage and leaks.';
CREATE INDEX idx_heap_dump_server ON cmmi.heap_dumps (server_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T096 - gc_metrics
-- Description: Garbage collection stats for JVM-based apps.
-- Business Case: Frequent or long GC pauses cause "stop-the-world" events that freeze the application. In a high-frequency trading
--                 or payment system, this is unacceptable. This table tracks GC frequency and duration to tune heap sizes
--                 or fix memory allocation code.
-- KPIs: GC Pause Time (Avg/Max), GC Frequency (per min), Heap Usage %, Old Gen Promotion Rate, GC CPU Overhead.
-- Feature Reference: M18-F125 (Garbage Collection Frequency Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gc_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,

    -- GC Event
    gc_name VARCHAR(50) NOT NULL, -- 'G1 Young Gen', 'G1 Old Gen'
    pause_time_sec NUMERIC(8, 4) NOT NULL,

    -- Memory
    memory_before_mb INTEGER,
    memory_after_mb INTEGER,
    memory_total_mb INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT gc_metrics_check CHECK (pause_time_sec >= 0)
);

COMMENT ON TABLE cmmi.gc_metrics IS 'Monitors Garbage Collection behavior to identify performance pauses.';
CREATE INDEX idx_gc_metrics_server ON cmmi.gc_metrics (server_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T097 - class_loaders
-- Description: JVM class loader counts.
-- Business Case: A constantly growing class loader count indicates a "ClassLoader Leak," which is a type of memory leak (PermGen/Metaspace).
--                 This table monitors class counts to predict OOM errors specific to metadata space before they crash the server.
-- KPIs: Loaded Class Count, Unloaded Class Count, Class Growth Rate, Metaspace Usage %, Leak Prediction Alert.
-- Feature Reference: M18-F127 (Class Leak Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.class_loaders (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_name VARCHAR(100) NOT NULL,

    -- Stats
    loaded_count BIGINT NOT NULL,
    unloaded_count BIGINT NOT NULL,
    total_loaded BIGINT GENERATED ALWAYS AS (loaded_count + unloaded_count) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.class_loaders IS 'Monitors JVM class loading activity to detect ClassLoader memory leaks.';
CREATE INDEX idx_class_loaders_server ON cmmi.class_loaders (server_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T098 - payload_sizes
-- Description: HTTP request and response payload sizes.
-- Business Case: Oversized payloads waste bandwidth and increase latency. Tiny payloads might indicate missing data.
--                 This table tracks sizes to detect anomalies (e.g., a payload suddenly growing to 10MB) which could indicate
--                 abuse or bugs (e.g., recursive serialization).
-- KPIs: Avg Payload Size, Max Payload Size, Bandwidth Usage, Anomaly Detection Rate, Response Time Correlation.
-- Feature Reference: M18-F129 (Request Payload Size Analyzer), M18-F130 (Response Payload Size Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.payload_sizes (
    measurement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100) NOT NULL,
    direction VARCHAR(10) NOT NULL CHECK (direction IN ('req', 'resp')),

    avg_size_bytes BIGINT NOT NULL,
    p95_size_bytes BIGINT,
    p99_size_bytes BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.payload_sizes IS 'Analyzes the size of HTTP payloads to optimize bandwidth and detect anomalies.';
CREATE INDEX idx_payload_endpoint ON cmmi.payload_sizes (endpoint_id, direction, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T099 - geoip_traffic
-- Description: Traffic volume by geographic region.
-- Business Case: Fraud detection and CDN optimization require geographic visibility. Sudden spikes from a specific region might
--                 indicate a DDoS attack or fraud ring. This table aggregates traffic by country/region to trigger geo-fencing
--                 or alert security teams.
-- KPIs: Traffic Distribution, Geo-Specific Error Rate, Fraud Rate by Region, CDN Cache Hit Ratio by Geo, Latency by Region.
-- Feature Reference: M18-F132 (GeoIP Traffic Distribution)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.geoip_traffic (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code CHAR(2) NOT NULL,

    request_count BIGINT NOT NULL,
    unique_users BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.geoip_traffic IS 'Aggregates traffic metrics by geographic location for security and performance analysis.';
CREATE INDEX idx_geoip_country ON cmmi.geoip_traffic (country_code, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T100 - api_versions
-- Description: Usage of different API versions.
-- Business Case: Managing API lifecycle (v1, v2, v3). Users must migrate from deprecated versions to shut them down.
--                 This table tracks call volume per version, providing data to enforce deprecation policies and ensure
--                 legacy clients aren't breaking production stability.
-- KPIs: Legacy Version Usage (%), Migration Rate, Deprecation Schedule Adherence, Version-Specific Error Rate, Client Breakage Prevention.
-- Feature Reference: M18-F133 (API Version Usage)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_versions (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version VARCHAR(20) NOT NULL, -- 'v1.0', 'v2.0'

    request_count BIGINT NOT NULL,

    -- Metadata
    status VARCHAR(20) NOT NULL, -- 'Active', 'Deprecated', 'Retired'
    deprecation_date DATE,
    sunset_date DATE,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.api_versions IS 'Tracks usage volume of different API versions to manage lifecycle and deprecation.';
CREATE INDEX idx_api_version_usage ON cmmi.api_versions (version, timestamp DESC);

-- =====================================================================================================================
-- Triggers for Timestamp Updates (Part 2 Tables)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_branch_lifetimes
    BEFORE UPDATE ON cmmi.branch_lifetimes
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_pr_sizes
    BEFORE UPDATE ON cmmi.pr_sizes
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_feature_flags
    BEFORE UPDATE ON cmmi.feature_flags
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_external_api_latency
    BEFORE UPDATE ON cmmi.external_api_latency
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_migration_risks
    BEFORE UPDATE ON cmmi.migration_risks
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_feature_flags
    BEFORE UPDATE ON cmmi.feature_flags
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_mobile_performance
    BEFORE UPDATE ON cmmi.mobile_performance
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_hyperparameters
    BEFORE UPDATE ON cmmi.hyperparameters
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_chaos_experiments
    BEFORE UPDATE ON cmmi.chaos_experiments
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_runbook_executions
    BEFORE UPDATE ON cmmi.runbook_executions
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_circuit_breakers
    BEFORE UPDATE ON cmmi.circuit_breakers
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_cert_expiry
    BEFORE UPDATE ON cmmi.cert_expiry
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_disk_forecasts
    BEFORE UPDATE ON cmmi.disk_forecasts
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 51-100)
-- =====================================================================================================================

-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 3
-- Tables DB101 - DB150
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T101 - dependency_graph
-- Description: Stores the relationships between microservices (upstream/downstream).
-- Business Case: Understanding the impact of a change requires knowing what depends on what. This table builds a directed graph of the
--                 system architecture. When a service is deployed (M18-F138) or a rollback occurs (M18-F139), M18 queries this graph
--                 to calculate the "blast radius"—identifying exactly which upstream or downstream services might be affected.
--                 This is crucial for automated change risk assessment and incident containment.
-- KPIs: Dependency Depth, Circular Dependency Count, Service Coupling Score, Blast Radius Calculation Speed, Graph Completeness.
-- Feature Reference: M18-F137 (Service Dependency Graph)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dependency_graph (
    graph_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Relationship
    upstream_service VARCHAR(100) NOT NULL,
    downstream_service VARCHAR(100) NOT NULL,

    -- Edge Details
    dependency_type VARCHAR(50) NOT NULL CHECK (dependency_type IN ('SYNC', 'ASYNC', 'DATA', 'SHARED_LIB')),
    protocol VARCHAR(50), -- 'HTTP', 'GRPC', 'KAFKA'

    -- Metadata
    is_active BOOLEAN DEFAULT true,
    confidence_score NUMERIC(3, 2), -- How sure are we of this link? (Auto-detected vs Manual)

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT dependency_graph_no_self_loop CHECK (upstream_service != downstream_service)
);

COMMENT ON TABLE cmmi.dependency_graph IS 'Defines the directed graph of service dependencies used for impact analysis and blast radius calculation.';

CREATE INDEX idx_dep_graph_upstream ON cmmi.dependency_graph (upstream_service);
CREATE INDEX idx_dep_graph_downstream ON cmmi.dependency_graph (downstream_service);
CREATE UNIQUE INDEX idx_dep_graph_unique ON cmmi.dependency_graph (upstream_service, downstream_service, dependency_type) WHERE is_active = true;

-- =====================================================================================================================
-- Table: M18-T102 - config_drift
-- Description: Detects if application configuration differs across environments.
-- Business Case: "It works on my machine" is a symptom of config drift. This table compares the intended configuration (IaC/Repo)
--                 against the actual running configuration (Dev, Stage, Prod). Drift is a major cause of failed deployments and
--                 unpredictable behavior. Detecting it ensures environment parity and stability.
-- KPIs: Drift Count by Env, Time to Drift Detection, Config Consistency Score, Auto-Remediation Success, Drift Recurrence Rate.
-- Feature Reference: M18-F140 (Configuration Drift Detection (App))
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.config_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Configuration Item
    config_key VARCHAR(255) NOT NULL,
    env_expected VARCHAR(50) NOT NULL, -- 'Prod'
    env_actual VARCHAR(50) NOT NULL, -- 'Stage'

    -- Values
    expected_value JSONB,
    actual_value JSONB,

    -- Status
    drift_detected BOOLEAN DEFAULT true,
    severity VARCHAR(20) CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),

    -- Context
    service_name VARCHAR(100),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.config_drift IS 'Identifies discrepancies between intended and actual application configuration across environments.';
CREATE INDEX idx_config_drift_env ON cmmi.config_drift (env_expected, env_actual);
CREATE INDEX idx_config_drift_detected ON cmmi.config_drift (drift_detected) WHERE drift_detected = true;

-- =====================================================================================================================
-- Table: M18-T103 - secret_rotation
-- Description: Tracks the history and status of secret rotations.
-- Business Case: Stale secrets are a massive security risk. Compliance standards (PCI-DSS, SOC2) mandate regular rotation.
--                 This table tracks the lifecycle of secrets (DB passwords, API keys), scheduling rotations and verifying they
--                 were successful without downtime.
-- KPIs: Rotation Success Rate, Rotation Age, Secrets Near Expiry, Rotation Execution Time, Downtime due to Rotation.
-- Feature Reference: M18-F141 (Secret Rotation Verifier)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.secret_rotation (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_name VARCHAR(255) NOT NULL,

    -- Scheduling
    last_rotated TIMESTAMP WITH TIME ZONE NOT NULL,
    next_rotation TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_interval INTERVAL NOT NULL,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'Pending', -- 'Pending', 'In Progress', 'Success', 'Failed'
    rotation_age_days NUMERIC(6, 2) GENERATED ALWAYS AS (EXTRACT(DAY FROM (CURRENT_TIMESTAMP - last_rotated))) STORED,

    -- Execution
    executed_by VARCHAR(50), -- 'System' or User
    notes TEXT,

    CONSTRAINT secret_rotation_check CHECK (next_rotation > last_rotated)
);

COMMENT ON TABLE cmmi.secret_rotation IS 'Monitors the rotation lifecycle of system secrets to ensure compliance and security.';
CREATE INDEX idx_secret_rotation_name ON cmmi.secret_rotation (secret_name);
CREATE INDEX idx_secret_rotation_next ON cmmi.secret_rotation (next_rotation);

-- =====================================================================================================================
-- Table: M18-T104 - auth_events
-- Description: Logs authentication and authorization token events.
-- Business Case: Security auditing requires an immutable trail of who accessed what and when. This table captures logins, token
--                 issuance, refresh, and expiry. It is the primary source for detecting brute force attacks (T105) and calculating
--                 session lifetimes.
-- KPIs: Successful Login Rate, Failed Login Rate, Token Expiry Frequency, Session Duration Avg, MFA Usage Rate.
-- Feature Reference: M18-F142 (Token Expiry Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.auth_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,

    -- Event Details
    event_type VARCHAR(50) NOT NULL, -- 'LOGIN', 'LOGOUT', 'TOKEN_ISSUE', 'TOKEN_REFRESH'
    token_expiry TIMESTAMP WITH TIME ZONE,

    -- Context
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,

    -- Result
    failure_reason TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.auth_events IS 'Audits authentication events for security analysis and anomaly detection.';
CREATE INDEX idx_auth_events_user ON cmmi.auth_events (user_id, timestamp DESC);
CREATE INDEX idx_auth_events_ip ON cmmi.auth_events (ip_address);

-- =====================================================================================================================
-- Table: M18-T105 - brute_force_attempts
-- Description: Aggregated logs of failed login attempts.
-- Business Case: Detecting and blocking brute force attacks early protects user accounts. This table aggregates failed attempts
--                 per IP or username to trigger account lockouts or IP bans via the WAF.
-- KPIs: Blocked Attack Count, Account Lockout Rate, False Positive Lockout Rate, Time to Detect Attack, Source Geo-Distribution.
-- Feature Reference: M18-F143 (Brute Force Attack Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.brute_force_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    ip_address INET,
    username VARCHAR(100),

    -- Metrics
    attempt_count INTEGER NOT NULL,
    last_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Action
    blocked_flag BOOLEAN DEFAULT false,
    blocked_until TIMESTAMP WITH TIME ZONE,

    CONSTRAINT brute_force_check CHECK (attempt_count > 0)
);

COMMENT ON TABLE cmmi.brute_force_attempts IS 'Tracks repeated failed login attempts to identify and block brute force attacks.';
CREATE INDEX idx_brute_force_ip ON cmmi.brute_force_attempts (ip_address) WHERE blocked_flag = false;

-- =====================================================================================================================
-- Table: M18-T106 - ddos_signatures
-- Description: Matches traffic patterns against known DDoS signatures.
-- Business Case: DDoS attacks can take down the payment platform. This table logs when traffic patterns match known malicious signatures
--                 (e.g., SYN flood, specific User-Agent strings), triggering automatic mitigation.
-- KPIs: Requests Blocked, Attack Severity, Time to Mitigation, False Positive Rate, Signature Update Frequency.
-- Feature Reference: M18-F144 (DDoS Attack Signature Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ddos_signatures (
    signature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    attack_type VARCHAR(50) NOT NULL,
    pattern_signature TEXT NOT NULL, -- Regex or structural description

    -- Impact
    requests_blocked BIGINT NOT NULL,
    peak_requests_per_sec NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ddos_signatures IS 'Logs detection of DDoS attack signatures and the volume of malicious traffic blocked.';
CREATE INDEX idx_ddos_signature_type ON cmmi.ddos_signatures (attack_type);

-- =====================================================================================================================
-- Table: M18-T107 - waf_rules
-- Description: Web App Firewall rules and their status.
-- Business Case: The WAF is the first line of defense. This table manages the lifecycle of WAF rules—creation, activation,
--                 and updates based on new threat intelligence. It ensures that the firewall configuration is versioned and auditable.
-- KPIs: Active Rule Count, Rule Trigger Rate, Rule Update Latency, Security Coverage, Blocked Malicious Requests.
-- Feature Reference: M18-F145 (WAF Rule Update Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.waf_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Rule Definition
    signature VARCHAR(255) NOT NULL,
    source VARCHAR(50) NOT NULL, -- 'ModSecurity', 'Custom', 'ThreatIntel'

    -- Status
    active_flag BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 1,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Description
    description TEXT
);

COMMENT ON TABLE cmmi.waf_rules IS 'Manages the configuration and status of Web Application Firewall rules.';
CREATE INDEX idx_waf_rules_active ON cmmi.waf_rules (active_flag) WHERE active_flag = true;

-- =====================================================================================================================
-- Table: M18-T108 - access_reviews
-- Description: Records periodic access rights reviews.
-- Business Case: Compliance (SOC2, ISO) requires periodic review of who has access to what. This table tracks the workflow
--                 of these reviews—who reviewed what access, and if the access was certified or revoked.
-- KPIs: Review Completion Rate (%), Access Revocation Rate, Review Latency, Orphaned Account Detection, Compliance Pass Rate.
-- Feature Reference: M18-F147 (Access Review Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.access_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reviewer_id UUID NOT NULL,
    grant_id UUID NOT NULL, -- Reference to the permission/access grant

    -- Decision
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Certify', 'Revoke', 'Modify')),
    comments TEXT,

    -- Timeline
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.access_reviews IS 'Stores the results of periodic access control reviews for compliance purposes.';
CREATE INDEX idx_access_reviewer ON cmmi.access_reviews (reviewer_id);

-- =====================================================================================================================
-- Table: M18-T109 - sod_violations
-- Description: Logs Separation of Duties violations.
-- Business Case: SoD prevents fraud (e.g., the same person cannot approve and pay a vendor). This table detects and logs
--                 when a user holds conflicting roles or permissions, alerting compliance officers automatically.
-- KPIs: Violation Count, Violation Resolution Time, Conflicting Role Pairs, Fraud Prevention Metrics, Policy Exception Rate.
-- Feature Reference: M18-F148 (Separation of Duties Enforcer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sod_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Conflict Details
    conflicting_role_count INTEGER NOT NULL,
    role_pair TEXT[], -- e.g., ['approver', 'payer']

    -- Status
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Exception Granted', 'Resolved'
    exception_reason TEXT,

    violation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sod_violations IS 'Detects and logs instances where a user has conflicting permissions that violate separation of duties.';
CREATE INDEX idx_sod_violations_user ON cmmi.sod_violations (user_id);

-- =====================================================================================================================
-- Table: M18-T110 - vendor_risks
-- Description: Scores third-party vendors based on security posture.
-- Business Case: The supply chain is a vulnerability. This table stores risk scores derived from questionnaires, scans, and
--                 public data (e.g., Have I Been Pwned). High-risk vendors trigger procurement blocks or contract renewals.
-- KPIs: Vendor Risk Score Average, High Risk Vendor Count, Assessment Completion Rate, Onboarding Block Rate, Third-Party Incident Count.
-- Feature Reference: M18-F150 (Vendor Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_risks (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Metrics
    risk_score NUMERIC(5, 2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    category VARCHAR(50), -- 'Security', 'Financial', 'Operational', 'Legal'

    -- Details
    assessment_date DATE NOT NULL,
    next_review_date DATE,

    -- Findings
    critical_findings_count INTEGER DEFAULT 0
);

COMMENT ON TABLE cmmi.vendor_risks IS 'Stores risk assessment scores and findings for third-party vendors and suppliers.';
CREATE INDEX idx_vendor_risks_score ON cmmi.vendor_risks (risk_score DESC);
CREATE INDEX idx_vendor_risks_vendor ON cmmi.vendor_risks (vendor_id);

-- =====================================================================================================================
-- Table: M18-T111 - sast_false_positives
-- Description: Feedback loop for SAST findings.
-- Business Case: SAST tools generate noise. If developers mark valid findings as false positives without feedback, the model
--                 never learns. This table records developer feedback, enabling the retraining of the ML triage model (M18-F017).
-- KPIs: False Positive Feedback Rate, Model Accuracy Improvement, Noise Reduction %, Developer Trust Score.
-- Feature Reference: M18-F151 (Code Scan False Positive Feedback)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sast_false_positives (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    finding_id UUID NOT NULL, -- Link to M18-T017

    -- Feedback
    user_feedback VARCHAR(20) NOT NULL CHECK (user_feedback IN ('True Positive', 'False Positive')),
    justification TEXT,

    -- Context
    user_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sast_false_positives IS 'Captures user feedback on security findings to improve automated triage accuracy.';
CREATE INDEX idx_sast_feedback_finding ON cmmi.sast_false_positives (finding_id);

-- =====================================================================================================================
-- Table: M18-T112 - dev_surveys
-- Description: Periodic surveys on tooling and process satisfaction.
-- Business Case: Process improvement requires understanding human pain points. This table stores the results of anonymous
--                 or identified surveys regarding the developer experience (DX), helping identify morale issues or tooling failures.
-- KPIs: Satisfaction Score (NPS), Response Rate, Tooling Dissatisfaction Hotspots, Process Sentiment Trend.
-- Feature Reference: M18-F152 (Developer Satisfaction Survey)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dev_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    survey_name VARCHAR(100) NOT NULL,

    -- Results
    satisfaction_score NUMERIC(3, 2) CHECK (satisfaction_score >= 1 AND satisfaction_score <= 10),
    comments TEXT,

    -- Demographics (Anonymized/Aggregated)
    team_id VARCHAR(100),
    role VARCHAR(50),

    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dev_surveys IS 'Stores feedback from engineering teams regarding tooling, processes, and satisfaction.';
CREATE INDEX idx_dev_surveys_score ON cmmi.dev_surveys (satisfaction_score);

-- =====================================================================================================================
-- Table: M18-T113 - innovation_time
-- Description: Tracks time spent on R&D vs. feature work.
-- Business Case: CMMI Level 5 focuses on innovation. If teams spend 100% of time on features, technical debt kills innovation.
--                 This table tracks the split between maintenance, feature work, and pure R&D (innovation spikes, refactoring)
--                 to ensure a healthy balance.
-- KPIs: R&D Ratio (%), Innovation Hours per Week, Feature Delivery Impact, Technical Debt Payback Rate, Strategic Project Velocity.
-- Feature Reference: M18-F153 (Innovation Time Tracking)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.innovation_time (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,
    week_start DATE NOT NULL,

    -- Hours Breakdown
    hours_rd NUMERIC(5, 2) NOT NULL,
    hours_feature NUMERIC(5, 2) NOT NULL,
    hours_maintenance NUMERIC(5, 2) NOT NULL,
    total_hours NUMERIC(5, 2) GENERATED ALWAYS AS (hours_rd + hours_feature + hours_maintenance) STORED,

    -- Metrics
    rd_ratio NUMERIC(5, 2) GENERATED ALWAYS AS (CASE WHEN total_hours > 0 THEN (hours_rd / total_hours) * 100 ELSE 0 END) STORED,

    CONSTRAINT innovation_time_positive CHECK (hours_rd >= 0 AND hours_feature >= 0)
);

COMMENT ON TABLE cmmi.innovation_time IS 'Analyzes how engineering effort is distributed between new features, maintenance, and R&D.';
CREATE INDEX idx_innovation_time_week ON cmmi.innovation_time (week_start);

-- =====================================================================================================================
-- Table: M18-T114 - cost_anomalies
-- Description: Anomalies in cloud billing.
-- Business Case: FinOps requires catching billing errors or runaway costs immediately. This table flags deviations from
--                 expected spend (e.g., a dev left a cluster on), allowing immediate action.
-- KPIs: Anomaly Detection Accuracy, Cost Savings via Alerts, False Positive Rate, Billing Error Count, Budget Variance.
-- Feature Reference: M18-F157 (Cost Anomaly Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cost_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Financials
    expected_cost NUMERIC(15, 2) NOT NULL,
    actual_cost NUMERIC(15, 2) NOT NULL,
    variance_pct NUMERIC(6, 2) GENERATED ALWAYS AS (((actual_cost - expected_cost) / expected_cost) * 100) STORED,

    -- Context
    resource_id VARCHAR(100),
    anomaly_type VARCHAR(50), -- 'Spike', 'Drop', 'Unexpected New Cost'

    -- Resolution
    acknowledged_by UUID,
    is_false_positive BOOLEAN DEFAULT false,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cost_anomalies IS 'Detects significant deviations in cloud spending to prevent budget overruns.';
CREATE INDEX idx_cost_anomalies_date ON cmmi.cost_anomalies (detected_at DESC);

-- =====================================================================================================================
-- Table: M18-T115 - reserved_instances
-- Description: Utilization of reserved cloud instances.
-- Business Case: Reserved instances save money only if used. If utilization drops below a threshold (e.g., 50%), it is cheaper
--                 to switch to on-demand. This table monitors usage to optimize cloud spend.
-- KPIs: Utilization % (>80%), Reserved Instance Coverage, Savings Realized vs On-Demand, Underutilization Count.
-- Feature Reference: M18-F158 (Reserved Instance Utilization)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.reserved_instances (
    instance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Instance Details
    instance_type VARCHAR(50) NOT NULL,
    region VARCHAR(50) NOT NULL,

    -- Utilization
    utilization_pct NUMERIC(5, 2) GENERATED ALWAYS AS ( utilized_hours / total_hours * 100 ) STORED, -- Placeholder logic, updated by app
    utilized_hours NUMERIC(10, 2) NOT NULL,
    total_hours NUMERIC(10, 2) NOT NULL,

    -- Financial
    coverage VARCHAR(20) CHECK (coverage IN ('Full', 'Partial', 'None')),

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.reserved_instances IS 'Monitors the usage of reserved cloud instances to validate cost savings.';
CREATE INDEX idx_reserved_instance_type ON cmmi.reserved_instances (instance_type);

-- =====================================================================================================================
-- Table: M18-T116 - idle_resources
-- Description: Detected idle compute/storage resources.
-- Business Case: Zombie resources cost money without providing value. This table identifies resources (e.g., unattached EBS volumes,
--                 stopped EC2 instances) that have been idle for a certain period, recommending deletion.
-- KPIs: Idle Resource Count, Potential Savings ($), Idle Resource Cleanup Rate, Reclamation Time.
-- Feature Reference: M18-F159 (Idle Resource Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.idle_resources (
    resource_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Resource Details
    resource_type VARCHAR(50) NOT NULL, -- 'Volume', 'Instance', 'IP'
    resource_arn VARCHAR(255),

    -- Idle Status
    last_active_date TIMESTAMP WITH TIME ZONE,
    idle_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM (CURRENT_DATE - COALESCE(last_active_date, CURRENT_DATE)))) STORED,

    -- Cost
    estimated_cost_month NUMERIC(10, 2),

    status VARCHAR(20) DEFAULT 'Detected' -- 'Detected', 'Deleted', 'Whitelisted'
);

COMMENT ON TABLE cmmi.idle_resources IS 'Identifies cloud resources that are not in use and can be terminated to save costs.';
CREATE INDEX idx_idle_resources_days ON cmmi.idle_resources (idle_days DESC);

-- =====================================================================================================================
-- Table: M18-T117 - capacity_recommendations
-- Description: AI recommendations for scaling.
-- Business Case: Manual capacity planning is reactive. AI can predict load and recommend scaling up/down or adding nodes
--                 proactively. This table stores these recommendations and the system's confidence level.
-- KPIs: Recommendation Accuracy, Proactive Scaling % vs Reactive, Capacity Lead Time, Over-provisioning Waste, Incident Prevention Rate.
-- Feature Reference: M18-F160 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.capacity_recommendations (
    recommendation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    resource_type VARCHAR(50) NOT NULL, -- 'Database', 'KubernetesCluster'
    current_capacity NUMERIC(10, 2),

    -- Recommendation
    recommended_capacity NUMERIC(10, 2) NOT NULL,
    action_type VARCHAR(20) NOT NULL CHECK (action_type IN ('SCALE_UP', 'SCALE_DOWN', 'ADD_NODE', 'REMOVE_NODE')),

    -- AI Context
    confidence NUMERIC(3, 2), -- 0 to 1
    reasoning TEXT, -- 'Predicted 20% traffic spike based on marketing campaign'

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Approved', 'Rejected', 'Applied'
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.capacity_recommendations IS 'Stores AI-driven scaling recommendations to proactively manage infrastructure capacity.';
CREATE INDEX idx_capacity_rec_status ON cmmi.capacity_recommendations (status);

-- =====================================================================================================================
-- Table: M18-T118 - model_training_runs
-- Description: Log of model training runs.
-- Business Case: Machine learning models require constant retraining (e.g., for fraud detection). This table logs the parameters,
--                 duration, and accuracy of every training run, providing an audit trail for model performance.
-- KPIs: Model Accuracy Trend, Training Duration, Feature Importance Stability, Retraining Frequency, Training Cost.
-- Feature Reference: M18-F084 (Model Drift Monitor), M18-F085 (Training Data Versioning)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_training_runs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,

    -- Parameters & Performance
    parameters_json JSONB NOT NULL,
    accuracy_score NUMERIC(5, 4),

    -- Timing
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds NUMERIC(10, 2),

    -- Artifacts
    artifact_path TEXT,

    status VARCHAR(20) DEFAULT 'Running'
);

COMMENT ON TABLE cmmi.model_training_runs IS 'Tracks the execution history of machine learning model training jobs.';
CREATE INDEX idx_model_training_name ON cmmi.model_training_runs (model_name, start_time DESC);

-- =====================================================================================================================
-- Table: M18-T119 - feature_store_syncs
-- Description: Sync status for feature store.
-- Business Case: MLOps requires that features used in training are exactly those used in inference. This table verifies
--                 that the Feature Store (where features are stored) is synced between training pipelines and serving (production)
--                 environments to prevent skew.
-- KPIs: Sync Latency, Sync Failure Rate, Feature Drift Count, Data Quality Score, Consistency Check Success.
-- Feature Reference: M18-F086 (Feature Store Sync)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_store_syncs (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,

    -- Status
    training_status VARCHAR(20) NOT NULL, -- 'Synced', 'Pending'
    serving_status VARCHAR(20) NOT NULL,  -- 'Synced', 'Pending'

    -- Details
    training_hash VARCHAR(64),
    serving_hash VARCHAR(64),

    last_sync_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_drift_detected BOOLEAN GENERATED ALWAYS AS (training_hash != serving_hash) STORED
);

COMMENT ON TABLE cmmi.feature_store_syncs IS 'Ensures that feature definitions are consistent between model training and serving environments.';
CREATE INDEX idx_feature_sync_name ON cmmi.feature_store_syncs (feature_name);

-- =====================================================================================================================
-- Table: M18-T120 - canary_releases
-- Description: Canary release tracking.
-- Business Case: Releasing to 100% of users is risky. Canary releases roll out to a small subset (e.g., 5%) first.
--                 This table tracks the traffic percentage and success metrics (error rates) to decide if the rollout should continue
--                 or be rolled back.
-- KPIs: Canary Success Rate, Time to Full Rollout, Canary Error Rate, Rollback from Canary Rate, User Impact %.
-- Feature Reference: M18-F089 (Canary Release Automation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.canary_releases (
    canary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    release_id UUID NOT NULL,

    -- Traffic
    traffic_percentage INTEGER NOT NULL CHECK (traffic_percentage >= 0 AND traffic_percentage <= 100),
    success_rate NUMERIC(5, 2), -- Based on error rates

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Promoted', 'RolledBack'

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.canary_releases IS 'Monitors the progress and success of canary deployments.';
CREATE INDEX idx_canary_release_id ON cmmi.canary_releases (release_id);

-- =====================================================================================================================
-- Table: M18-T121 - blue_green_switches
-- Description: Blue-green deployment switches.
-- Business Case: Blue-green deployments enable zero-downtime upgrades. This table logs the switch events—when traffic moved
--                 from Blue (old) to Green (new)—allowing for instant rollback if needed.
-- KPIs: Switch Success Rate, Switch Duration, Rollback Time, Downtime Incidents (Should be 0), Database Migration Sync.
-- Feature Reference: M18-F090 (Blue-Green Deployment Manager)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.blue_green_switches (
    switch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    env VARCHAR(50) NOT NULL,

    -- The Switch
    active_color VARCHAR(10) NOT NULL CHECK (active_color IN ('Blue', 'Green')),
    previous_color VARCHAR(10) NOT NULL,

    -- Metrics
    switch_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER,

    -- Outcome
    status VARCHAR(20) NOT NULL -- 'Success', 'Failed', 'RolledBack'
);

COMMENT ON TABLE cmmi.blue_green_switches IS 'Logs the traffic switching events for blue-green deployment strategies.';
CREATE INDEX idx_blue_green_env ON cmmi.blue_green_switches (env, switch_time DESC);

-- =====================================================================================================================
-- Table: M18-T122 - runbook_definitions
-- Description: Definitions of executable runbooks.
-- Business Case: Automating incident response requires storing the logic of the runbooks. This table stores the scripts,
--                 triggers, and parameters for automation workflows (e.g., "If HighCPU > 90%, scale up").
-- KPIs: Runbook Execution Success Rate, Automation Coverage, Runbook Update Frequency, Execution Time Reduction, MTTR Improvement.
-- Feature Reference: M18-F093 (Runbook Automation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.runbook_definitions (
    runbook_id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Definition
    script_path TEXT NOT NULL,
    parameters JSONB,

    -- Triggers
    triggers JSONB NOT NULL, -- Event definitions

    -- Metadata
    version VARCHAR(20),
    is_active BOOLEAN DEFAULT true,

    created_by UUID,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.runbook_definitions IS 'Defines the logic and triggers for automated remediation runbooks.';

-- =====================================================================================================================
-- Table: M18-T123 - throttling_policies
-- Description: API throttling configurations.
-- Business Case: Protecting the API from abuse requires granular control. This table defines rate limits per endpoint,
--                 user tier, or API key, allowing for dynamic adjustment of policies.
-- KPIs: Policy Change Frequency, Throttling Accuracy, Legitimate User Impact, Abuse Prevention Rate, Config Drift.
-- Feature Reference: M18-F103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.throttling_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100),

    -- Limits
    requests_per_second INTEGER NOT NULL,
    burst_limit INTEGER,

    -- Scope
    policy_type VARCHAR(50) NOT NULL, -- 'Global', 'PerUser', 'PerAPIKey'

    -- Status
    active BOOLEAN DEFAULT true,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.throttling_policies IS 'Configures rate limiting rules for API endpoints to protect system stability.';

-- =====================================================================================================================
-- Table: M18-T124 - api_endpoints
-- Description: Registry of all API endpoints.
-- Business Case: You can't monitor what you don't know exists. This table is the service registry, listing all public
--                 and internal endpoints, their methods, and deprecation status.
-- KPIs: Endpoint Count, Deprecated Endpoint Count, Documentation Coverage, Ownership Assignment, Version Consistency.
-- Feature Reference: M18-F135 (API Version Usage) - Registry aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_endpoints (
    endpoint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    path TEXT NOT NULL,
    method VARCHAR(10) NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH')),
    service_name VARCHAR(100) NOT NULL,

    -- Lifecycle
    deprecated_flag BOOLEAN DEFAULT false,
    deprecation_date DATE,

    -- Owner
    owner_team VARCHAR(100)
);

COMMENT ON TABLE cmmi.api_endpoints IS 'Central registry for all API endpoints within the architecture.';
CREATE INDEX idx_api_endpoints_path ON cmmi.api_endpoints (path, method);

-- =====================================================================================================================
-- Table: M18-T125 - service_mesh_config
-- Description: Service mesh routing rules.
-- Business Case: Service Mesh (Istio/Linkerd) controls traffic flow. This table stores the routing configuration (weights,
--                 headers) to ensure it matches the intended deployment strategy (e.g., Canary weights).
-- KPIs: Config Sync Success, Routing Error Rate, Latency Injection Success, Mesh Health Score.
-- Feature Reference: M18-F089 (Canary Release Automation) - Mesh aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.service_mesh_config (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    route_name VARCHAR(100) NOT NULL,

    -- Routing
    destination_weight NUMERIC(5, 2) NOT NULL, -- 0.00 to 1.00
    headers JSONB,

    -- Version
    version INTEGER,

    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.service_mesh_config IS 'Manages the routing rules within the service mesh for traffic management.';
CREATE INDEX idx_mesh_service ON cmmi.service_mesh_config (service_name);

-- =====================================================================================================================
-- Table: M18-T126 - ssl_certificates
-- Description: Inventory of SSL certificates.
-- Business Case: Managing the lifecycle of certificates is critical. This table stores metadata (Issuer, SAN list, status)
--                 for all certificates used across the platform, distinct from the expiry monitoring (T090).
-- KPIs: Certificate Inventory Count, Auto-Renewal Coverage, Expiry Compliance, Encryption Strength Distribution.
-- Feature Reference: M18-F114 (SSL/TLS Certificate Expiry Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ssl_certificates (
    cert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    common_name VARCHAR(255) NOT NULL,
    issuer VARCHAR(255),

    -- Details
    san_list TEXT[], -- Subject Alternative Names
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Expired', 'Revoked'
);

COMMENT ON TABLE cmmi.ssl_certificates IS 'Inventory of SSL/TLS certificates used across the platform.';
CREATE INDEX idx_ssl_common_name ON cmmi.ssl_certificates (common_name);

-- =====================================================================================================================
-- Table: M18-T127 - dns_records
-- Description: DNS record inventory.
-- Business Case: DNS issues cause outages. This table tracks the intended state of DNS records (A, CNAME, TXT)
--                 to detect drift or unauthorized changes.
-- KPIs: DNS Record Accuracy, Propagation Time, Drift Detection Rate, Record Update Success.
-- Feature Reference: M18-F115 (DNS Resolution Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dns_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS')),

    -- Value
    value TEXT NOT NULL,
    ttl INTEGER,

    -- Monitoring
    monitored_flag BOOLEAN DEFAULT true,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dns_records IS 'Inventory of DNS records with monitoring flags.';
CREATE INDEX idx_dns_domain ON cmmi.dns_records (domain, type);

-- =====================================================================================================================
-- Table: M18-T128 - user_agents
-- Description: Parsed user agent strings.
-- Business Case: Identifying bot traffic vs. real users is important for analytics and security. This table stores parsed
--                 UA strings (Browser, OS, Device) to speed up analysis.
-- KPIs: Bot Traffic %, Mobile Traffic %, Browser Version Distribution, Anomaly Detection (Spoofed UA).
-- Feature Reference: M18-F131 (User Agent Parser)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.user_agents (
    ua_string_hash CHAR(64) PRIMARY KEY, -- Hash of the raw string
    ua_string TEXT,

    -- Parsed Data
    browser VARCHAR(50),
    os VARCHAR(50),
    device_type VARCHAR(50),
    is_bot BOOLEAN DEFAULT false
);

COMMENT ON TABLE cmmi.user_agents IS 'Stores parsed User-Agent strings for traffic analysis.';

-- =====================================================================================================================
-- Table: M18-T129 - distributed_traces
-- Description: Storage for distributed trace spans.
-- Business Case: Distributed tracing is essential for debugging latency in microservices. This table stores the spans
--                 (trace_id, parent_id, operation) to reconstruct the call graph of a single transaction across many services.
-- KPIs: Trace Completeness, Span Ingestion Rate, Retention Policy Compliance, Search Latency, Trace Sampling Rate.
-- Feature Reference: M18-F136 (Request Flow Tracer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.distributed_traces (
    span_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trace_id UUID NOT NULL,
    parent_id UUID, -- NULL if root span

    -- Details
    service_name VARCHAR(100) NOT NULL,
    operation_name VARCHAR(255) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms NUMERIC(10, 2) NOT NULL,

    -- Tags
    tags JSONB,

    -- Indexing hint for trace retrieval
    CONSTRAINT dt_trace_check CHECK (trace_id IS NOT NULL)
);

COMMENT ON TABLE cmmi.distributed_traces IS 'Stores individual spans from distributed tracing systems for latency analysis.';
CREATE INDEX idx_distributed_trace_id ON cmmi.distributed_traces (trace_id);
CREATE INDEX idx_distributed_service ON cmmi.distributed_traces (service_name);

-- =====================================================================================================================
-- Table: M18-T130 - feature_dependencies
-- Description: Dependencies between product features.
-- Business Case: Features often depend on other features (e.g., "Apple Pay" depends on "Digital Wallet"). This table models
--                 these dependencies to determine the impact of enabling/disabling a feature flag.
-- KPIs: Dependency Depth, Circular Dependency Count, Feature Coupling, Impact Analysis Accuracy.
-- Feature Reference: M18-F137 (Service Dependency Graph) - Product feature equivalent
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_dependencies (
    feature_id UUID NOT NULL,
    depends_on_feature_id UUID NOT NULL,

    -- Type
    dependency_type VARCHAR(50) DEFAULT 'Hard', -- 'Hard', 'Soft'

    PRIMARY KEY (feature_id, depends_on_feature_id)
);

COMMENT ON TABLE cmmi.feature_dependencies IS 'Models the relationships between product features to manage rollouts and dependencies.';

-- =====================================================================================================================
-- Table: M18-T131 - deployment_impacts
-- Description: Calculated impact of a specific deployment.
-- Business Case: Knowing what a deployment touches is vital for risk assessment. This table pre-calculates the services
--                 affected by a specific deployment ID using the dependency graph (T101).
-- KPIs: Impact Calculation Speed, Blast Radius Accuracy, Affected Service Count, Risk Correlation.
-- Feature Reference: M18-F138 (Deployment Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.deployment_impacts (
    impact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    affected_service_id VARCHAR(100) NOT NULL,

    -- Details
    impact_type VARCHAR(50) CHECK (impact_type IN ('Direct', 'Transitive')),
    risk_level VARCHAR(20)
);

COMMENT ON TABLE cmmi.deployment_impacts IS 'Pre-calculated blast radius for specific deployments.';
CREATE INDEX idx_deployment_impact_id ON cmmi.deployment_impacts (deployment_id);

-- =====================================================================================================================
-- Table: M18-T132 - rollback_impacts
-- Description: Estimated downstream effects of a rollback.
-- Business Case: Rollbacks aren't free; they might break dependent services expecting new features. This table estimates
--                 the downstream impact to ensure a rollback is actually safer than the current degraded state.
-- KPIs: Rollback Safety Score, Downstream Service Count, Estimated Downtime, Rollback Decision Accuracy.
-- Feature Reference: M18-F139 (Rollback Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.rollback_impacts (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,
    affected_service_id VARCHAR(100) NOT NULL,

    -- Estimation
    downtime_estimate_minutes INTEGER,
    business_impact VARCHAR(20) -- 'Low', 'Medium', 'High'
);

COMMENT ON TABLE cmmi.rollback_impacts IS 'Estimates the downstream consequences of rolling back a specific deployment.';
CREATE INDEX idx_rollback_deployment ON cmmi.rollback_impacts (deployment_id);

-- =====================================================================================================================
-- Table: M18-T133 - security_scanners
-- Description: Configured security scanners.
-- Business Case: The security infrastructure (SAST, DAST, Dependency Scanners) needs configuration management. This table
--                 stores connection details and types for all active scanners.
-- KPIs: Scanner Availability, Scan Job Success Rate, Scanner Coverage, Configuration Drift.
-- Feature Reference: M18-F017 (Static Analysis Severity Triaging)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.security_scanners (
    scanner_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'SAST', 'DAST', 'DEPENDENCY', 'CONTAINER'

    -- Connection
    api_endpoint TEXT,
    auth_token_hash CHAR(64), -- Hashed for security

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_health_check TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.security_scanners IS 'Registry of security scanning tools and their connection configurations.';

-- =====================================================================================================================
-- Table: M18-T134 - scan_schedules
-- Description: Schedule for recurring scans.
-- Business Case: Security scanning must be continuous. This table defines the cron schedules for automated scans (nightly builds,
--                 weekly dependency checks).
-- KPIs: Schedule Adherence, Scan Frequency, Missed Scan Count, Coverage vs Frequency.
-- Feature Reference: M18-F017 (Static Analysis Severity Triaging)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.scan_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scanner_id UUID NOT NULL,

    -- Schedule
    target VARCHAR(255) NOT NULL, -- 'all', 'payment-service'
    cron_expression VARCHAR(100) NOT NULL,

    -- State
    next_run_time TIMESTAMP WITH TIME ZONE,
    is_enabled BOOLEAN DEFAULT true
);

COMMENT ON TABLE cmmi.scan_schedules IS 'Defines the recurring schedules for automated security scans.';
CREATE INDEX idx_scan_schedules_next ON cmmi.scan_schedules (next_run_time);

-- =====================================================================================================================
-- Table: M18-T135 - ci_pipelines
-- Description: Registry of CI/CD pipelines.
-- Business Case: Managing the definition of CI/CD pipelines. This table stores metadata about pipelines (SCM URL, stages)
--                 to correlate pipeline runs (T136) with code repositories (T145).
-- KPIs: Pipeline Count, Pipeline Complexity, Stage Failure Distribution, Pipeline Update Frequency.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ci_pipelines (
    pipeline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    scm_url TEXT,

    -- Definition
    stages_json JSONB, -- ['build', 'test', 'deploy']

    -- Config
    is_active BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ci_pipelines IS 'Registry of CI/CD pipelines and their stage definitions.';

-- =====================================================================================================================
-- Table: M18-T136 - pipeline_runs
-- Description: Execution history of pipelines.
-- Business Case: The history of what ran when. This table stores every execution of a pipeline, linking it to the trigger
--                 (Manual, Webhook, Scheduled) and the outcome.
-- KPIs: Pipeline Success Rate, Average Run Duration, Trigger Source Distribution, Flake Rate.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pipeline_runs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id UUID NOT NULL,

    -- Execution
    status VARCHAR(20) NOT NULL, -- 'Success', 'Failed', 'Running'
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,

    -- Trigger
    trigger_source VARCHAR(50), -- 'Webhook', 'Manual', 'Schedule'
    trigger_source_id VARCHAR(100)
);

COMMENT ON TABLE cmmi.pipeline_runs IS 'Logs the execution history of CI/CD pipelines.';
CREATE INDEX idx_pipeline_runs_pipeline ON cmmi.pipeline_runs (pipeline_id, start_time DESC);
CREATE INDEX idx_pipeline_runs_status ON cmmi.pipeline_runs (status);

-- =====================================================================================================================
-- Table: M18-T137 - test_suites
-- Description: Test suites definitions.
-- Business Case: Organizing tests. This table defines test suites (e.g., "Smoke Tests", "Regression") and their types
--                 (Unit, Integration, E2E) to aggregate results in T138.
-- KPIs: Suite Coverage, Suite Execution Time, Test Count per Suite, Flakiness per Suite.
-- Feature Reference: M18-F009 (Automated Test Coverage Gate)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.test_suites (
    suite_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('Unit', 'Integration', 'E2E', 'Performance')),

    -- Metrics
    execution_time_ms INTEGER,

    last_run TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.test_suites IS 'Defines groups of tests (suites) for execution and reporting.';

-- =====================================================================================================================
-- Table: M18-T138 - test_results
-- Description: Results of test executions.
-- Business Case: The core of testing metrics. This table stores the result of every test case execution, enabling
--                 calculation of pass rates, flaky tests (T016), and coverage trends.
-- KPIs: Pass Rate (%), Test Execution Time, Flaky Test Count, New Failures, Regression Detection.
-- Feature Reference: M18-F009 (Automated Test Coverage Gate)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.test_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    suite_id UUID NOT NULL,
    run_id UUID NOT NULL, -- Link to pipeline run

    -- Test Details
    test_name VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('Pass', 'Fail', 'Skip', 'Flaky')),

    -- Metrics
    duration_ms INTEGER,
    error_message TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.test_results IS 'Stores detailed results of individual test case executions.';
CREATE INDEX idx_test_results_run ON cmmi.test_results (run_id, status);
CREATE INDEX idx_test_results_name ON cmmi.test_results (test_name);

-- =====================================================================================================================
-- Table: M18-T139 - code_reviews_comments
-- Description: Comments on code reviews.
-- Business Case: Understanding review quality requires looking at the content. This table stores the text of comments
--                 on Pull Requests, enabling sentiment analysis (T008) and identifying blockers.
-- KPIs: Avg Comments per PR, Review Depth, Sentiment Score, Resolution Time for Comments, Reviewer Participation.
-- Feature Reference: M18-F011 (Peer Review Depth Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.code_reviews_comments (
    comment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    review_id UUID NOT NULL,

    -- Content
    author_id UUID NOT NULL,
    text TEXT NOT NULL,

    -- Context
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN DEFAULT false
);

COMMENT ON TABLE cmmi.code_reviews_comments IS 'Stores the textual comments made during code reviews.';
CREATE INDEX idx_code_reviews_review ON cmmi.code_reviews_comments (review_id);

-- =====================================================================================================================
-- Table: M18-T140 - issue_tracker_config
-- Description: Config for Jira/Bugzilla integration.
-- Business Case: Connecting M18 to external trackers. This table stores the API keys and project keys required to
--                 sync issues from Jira (T141).
-- KPIs: Sync Success Rate, Sync Latency, Connection Error Count, Issue Mapping Accuracy.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.issue_tracker_config (
    tracker_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(50) NOT NULL, -- 'JIRA', 'GITHUB_ISSUES'

    -- Config
    url TEXT NOT NULL,
    project_key VARCHAR(50),

    -- Auth
    auth_token_hash CHAR(64),
    is_active BOOLEAN DEFAULT true
);

COMMENT ON TABLE cmmi.issue_tracker_config IS 'Configuration for integrating with external issue tracking systems.';

-- =====================================================================================================================
-- Table: M18-T141 - external_issues
-- Description: Imported issues from external trackers.
-- Business Case: Centralizing issue data. This table mirrors the state of tickets from external systems (Jira) into
--                 M18 so they can be analyzed alongside code metrics and deployment data.
-- KPIs: Import Success Rate, Data Freshness, Issue Mapping Coverage, Sync Error Rate.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.external_issues (
    external_id VARCHAR(100) PRIMARY KEY,
    tracker_id UUID NOT NULL,

    -- Details
    summary TEXT,
    status VARCHAR(50),
    severity VARCHAR(20),

    -- Dates
    created_date DATE,
    updated_date DATE,

    last_synced_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.external_issues IS 'Stores synchronized data from external issue tracking systems.';
CREATE INDEX idx_external_issues_tracker ON cmmi.external_issues (tracker_id);

-- =====================================================================================================================
-- Table: M18-T142 - sprint_backlog
-- Description: Items in a sprint backlog.
-- Business Case: Velocity calculation (M18-F005) requires knowing what is in the sprint. This table links work items (T144)
--                 to sprints (via sprint_id), tracking story points and status.
-- KPIs: Story Point Accuracy, Sprint Completion %, Scope Creep, Work Item Distribution.
-- Feature Reference: M18-F022 (Sprint Burndown Variance Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sprint_backlog (
    item_id UUID NOT NULL, -- Ref T143/144
    sprint_id VARCHAR(100) NOT NULL,

    -- Metrics
    story_points INTEGER,
    status VARCHAR(50) DEFAULT 'Todo',

    PRIMARY KEY (item_id, sprint_id)
);

COMMENT ON TABLE cmmi.sprint_backlog IS 'Links work items to sprints to track progress and burndown.';
CREATE INDEX idx_sprint_backlog_sprint ON cmmi.sprint_backlog (sprint_id);

-- =====================================================================================================================
-- Table: M18-T143 - team_members
-- Description: Mapping of users to teams.
-- Business Case: Organizational structure is needed for RLS (Row Level Security) and reporting. This table maps users
--                 to teams and roles.
-- KPIs: Team Size, Role Distribution, Member Churn, Manager Assignment Coverage.
-- Feature Reference: M18-F142 (Team Members) - implied
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.team_members (
    user_id UUID NOT NULL,
    team_id UUID NOT NULL, -- Ref T173
    role VARCHAR(50) DEFAULT 'Member',

    -- Lifecycle
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN GENERATED ALWAYS AS (left_at IS NULL) STORED,

    PRIMARY KEY (user_id, team_id)
);

COMMENT ON TABLE cmmi.team_members IS 'Maps users to organizational teams for access control and reporting.';
CREATE INDEX idx_team_members_team ON cmmi.team_members (team_id) WHERE is_active = true;

-- =====================================================================================================================
-- Table: M18-T144 - work_items
-- Description: Generic work items (Features/Bugs/Debt).
-- Business Case: The backlog. This table is the master list of work, regardless of whether it is a Feature, Bug, or
--                 Technical Debt, feeding into velocity calculations and planning.
-- KPIs: Cycle Time, Lead Time, Backlog Size, Item Type Distribution, Aging Work Items.
-- Feature Reference: M18-F045 (Requirement Traceability)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.work_items (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(50) NOT NULL, -- 'Feature', 'Bug', 'Debt', 'Refactor'

    -- Details
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Assignment
    assignee_id UUID,
    status VARCHAR(50) DEFAULT 'Backlog',

    -- Dates
    created_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_date TIMESTAMP WITH TIME ZONE,

    priority INTEGER
);

COMMENT ON TABLE cmmi.work_items IS 'The central repository for all work items (features, bugs, tasks).';
CREATE INDEX idx_work_items_assignee ON cmmi.work_items (assignee_id);
CREATE INDEX idx_work_items_status ON cmmi.work_items (status);

-- =====================================================================================================================
-- Table: M18-T145 - repositories
-- Description: Git repositories metadata.
-- Business Case: Tracking code sources. This table stores metadata for all repositories managed by M18, linking
--                 commits (T146) and Pull Requests.
-- KPIs: Repository Count, Commit Frequency per Repo, Repo Size, Language Distribution.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.repositories (
    repo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url TEXT NOT NULL,
    language VARCHAR(50),
    main_branch VARCHAR(50) DEFAULT 'main',

    -- Config
    is_monitored BOOLEAN DEFAULT true,

    last_commit_date TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.repositories IS 'Metadata for Git repositories under analysis.';
CREATE INDEX idx_repositories_url ON cmmi.repositories (url);

-- =====================================================================================================================
-- Table: M18-T146 - commits
-- Description: Git commit metadata.
-- Business Case: The atomic unit of code change. This table captures every commit analyzed by M18, linking author,
--                 timestamp, and repo, which feeds into churn (T007), sentiment (T008), and blame analysis.
-- KPIs: Commit Count, Commit Frequency, Commit Size, Author Distribution, Invalid Commit Rate.
-- Feature Reference: M18-F001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.commits (
    commit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    repo_id UUID NOT NULL,

    -- Git Details
    hash CHAR(40) NOT NULL,
    author_id UUID,

    -- Content
    message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metrics (Cached)
    files_changed INTEGER DEFAULT 0,
    lines_added INTEGER DEFAULT 0,
    lines_deleted INTEGER DEFAULT 0
);

COMMENT ON TABLE cmmi.commits IS 'Detailed log of git commits analyzed for quality metrics.';
CREATE INDEX idx_commits_repo ON cmmi.commits (repo_id, timestamp DESC);
CREATE INDEX idx_commits_author ON cmmi.commits (author_id);

-- =====================================================================================================================
-- Table: M18-T147 - pr_commits
-- Description: Link PR to Commits.
-- Business Case: Associating commits with the PR that merged them. This table establishes the many-to-many relationship
--                 between PRs (T148/T052) and Commits (T146).
-- KPIs: Commit per PR Ratio, PR Size Consistency, Commit Granularity.
-- Feature Reference: M18-F057 (PR Size Validator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pr_commits (
    pr_id UUID NOT NULL,
    commit_id UUID NOT NULL,

    PRIMARY KEY (pr_id, commit_id)
);

COMMENT ON TABLE cmmi.pr_commits IS 'Junction table linking Pull Requests to their constituent commits.';

-- =====================================================================================================================
-- Table: M18-T148 - pr_files
-- Description: Files changed in a PR.
-- Business Case: Analyzing scope at the file level. This table lists every file touched by a PR, enabling complexity
--                 analysis and risk scoring (T036, T014).
-- KPIs: Files Changed per PR, File Churn Frequency, Risk File Touch Count.
-- Feature Reference: M18-F057 (PR Size Validator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pr_files (
    pr_file_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id UUID NOT NULL,
    file_path TEXT NOT NULL,

    added_lines INTEGER DEFAULT 0,
    deleted_lines INTEGER DEFAULT 0,

    change_type VARCHAR(20) CHECK (change_type IN ('Added', 'Modified', 'Deleted', 'Renamed'))
);

COMMENT ON TABLE cmmi.pr_files IS 'Details the specific files changed within a Pull Request.';
CREATE INDEX idx_pr_files_pr ON cmmi.pr_files (pr_id);

-- =====================================================================================================================
-- Table: M18-T149 - incidents
-- Description: Operational incidents.
-- Business Case: The core of SRE work. This table tracks operational outages and incidents, triggering the RCA process
--                 (T012) and feeding into MTTR predictions (T026).
-- KPIs: MTTR, MTTD (Mean Time To Detect), Incident Frequency, Severity Distribution, Recurring Incident Rate.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Sev1', 'Sev2', 'Sev3', 'Sev4')),
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Investigating', 'Resolved', 'Closed'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Links
    assignee_id UUID,
    RCA_id UUID -- Link to T012
);

COMMENT ON TABLE cmmi.incidents IS 'Master record of operational incidents.';
CREATE INDEX idx_incidents_severity ON cmmi.incidents (severity);
CREATE INDEX idx_incidents_status ON cmmi.incidents (status);
CREATE INDEX idx_incidents_created ON cmmi.incidents (created_at DESC);

-- =====================================================================================================================
-- Table: M18-T150 - incident_updates
-- Description: Timeline updates for incidents.
-- Business Case: An incident audit trail. This table stores every status update, comment, or action taken on an incident,
--                 providing the timeline required for postmortems (T277) and stakeholder communication.
-- KPIs: Update Frequency, Time to First Update, Communication Latency, Stakeholder Notification Time.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.incident_updates (
    update_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    author_id UUID,
    message TEXT NOT NULL,

    -- Change
    old_status VARCHAR(50),
    new_status VARCHAR(50),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.incident_updates IS 'Chronological log of updates and actions taken during an incident.';
CREATE INDEX idx_incident_updates_incident ON cmmi.incident_updates (incident_id, timestamp DESC);

-- =====================================================================================================================
-- Triggers for Timestamp Updates (Part 3 Tables)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_config_drift
    BEFORE UPDATE ON cmmi.config_drift
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_secret_rotation
    BEFORE UPDATE ON cmmi.secret_rotation
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_waf_rules
    BEFORE UPDATE ON cmmi.waf_rules
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_sod_violations
    BEFORE UPDATE ON cmmi.sod_violations
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_capacity_recommendations
    BEFORE UPDATE ON cmmi.capacity_recommendations
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_runbook_definitions
    BEFORE UPDATE ON cmmi.runbook_definitions
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_throttling_policies
    BEFORE UPDATE ON cmmi.throttling_policies
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_dns_records
    BEFORE UPDATE ON cmmi.dns_records
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_ci_pipelines
    BEFORE UPDATE ON cmmi.ci_pipelines
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_work_items
    BEFORE UPDATE ON cmmi.work_items
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_repositories
    BEFORE UPDATE ON cmmi.repositories
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_incidents
    BEFORE UPDATE ON cmmi.incidents
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Foreign Key Constraints (Part 3)
-- =====================================================================================================================
ALTER TABLE cmmi.sast_false_positives ADD CONSTRAINT fk_sast_feedback_finding
    FOREIGN KEY (finding_id) REFERENCES cmmi.sast_findings(finding_id);

ALTER TABLE cmmi.canary_releases ADD CONSTRAINT fk_canary_release
    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id);

ALTER TABLE cmmi.blue_green_switches ADD CONSTRAINT fk_blue_green_env
    FOREIGN KEY (env) REFERENCES cmmi.environments(env_id); -- Assuming T178 exists

ALTER TABLE cmmi.deployment_impacts ADD CONSTRAINT fk_deploy_impact_deployment
    FOREIGN KEY (deployment_id) REFERENCES cmmi.deployments(deployment_id);

ALTER TABLE cmmi.rollback_impacts ADD CONSTRAINT fk_rollback_impact_deployment
    FOREIGN KEY (deployment_id) REFERENCES cmmi.deployments(deployment_id);

ALTER TABLE cmmi.security_scanners ADD CONSTRAINT fk_scanner_active
    FOREIGN KEY (scanner_id) REFERENCES cmmi.sast_findings(scanner_id); -- Cross reference

ALTER TABLE cmmi.scan_schedules ADD CONSTRAINT fk_scan_scanner
    FOREIGN KEY (scanner_id) REFERENCES cmmi.security_scanners(scanner_id);

ALTER TABLE cmmi.pipeline_runs ADD CONSTRAINT fk_pipeline_run_pipeline
    FOREIGN KEY (pipeline_id) REFERENCES cmmi.ci_pipelines(pipeline_id);

ALTER TABLE cmmi.test_results ADD CONSTRAINT fk_test_result_suite
    FOREIGN KEY (suite_id) REFERENCES cmmi.test_suites(suite_id);

ALTER TABLE cmmi.code_reviews_comments ADD CONSTRAINT fk_review_comment_review
    FOREIGN KEY (review_id) REFERENCES cmmi.peer_reviews(review_id);

ALTER TABLE cmmi.external_issues ADD CONSTRAINT fk_ext_issue_tracker
    FOREIGN KEY (tracker_id) REFERENCES cmmi.issue_tracker_config(tracker_id);

ALTER TABLE cmmi.commits ADD CONSTRAINT fk_commit_repo
    FOREIGN KEY (repo_id) REFERENCES cmmi.repositories(repo_id);

ALTER TABLE cmmi.pr_commits ADD CONSTRAINT fk_pr_commit_pr
    FOREIGN KEY (pr_id) REFERENCES cmmi.pull_requests(pr_id); -- Ref T146 in list, but logically PR table

ALTER TABLE cmmi.pr_commits ADD CONSTRAINT fk_pr_commit_commit
    FOREIGN KEY (commit_id) REFERENCES cmmi.commits(commit_id);

ALTER TABLE cmmi.pr_files ADD CONSTRAINT fk_pr_file_pr
    FOREIGN KEY (pr_id) REFERENCES cmmi.pull_requests(pr_id);

ALTER TABLE cmmi.incidents ADD CONSTRAINT fk_incident_rca
    FOREIGN KEY (RCA_id) REFERENCES cmmi.five_why_analyses(analysis_id);

ALTER TABLE cmmi.incident_updates ADD CONSTRAINT fk_inc_update_incident
    FOREIGN KEY (incident_id) REFERENCES cmmi.incidents(incident_id);

-- =====================================================================================================================
-- End of Script Segment (Tables 101-150)
-- =====================================================================================================================
-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 4
-- Tables DB151 - DB200
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T151 - incident_tags
-- Description: Many-to-many relationship linking incidents to tags for categorization.
-- Business Case: Incidents need to be categorized for trending analysis (e.g., "Database", "Network", "Security").
--                 Tags allow for flexible, ad-hoc categorization without rigid schema changes. They enable the creation of
--                 dashboards that show, for example, "All Sev1 incidents tagged 'Payment-Gateway' in Q3," which is critical
--                 for identifying systemic product weaknesses.
-- KPIs: Tag Usage Frequency, Untagged Incident %, Tag Consistency, Search Efficiency, Categorization Accuracy.
-- Feature Reference: M18-T149 (Incidents)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.incident_tags (
    incident_id UUID NOT NULL,
    tag_name VARCHAR(100) NOT NULL,

    -- Metadata
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID,

    PRIMARY KEY (incident_id, tag_name)
);

COMMENT ON TABLE cmmi.incident_tags IS 'Junction table assigning categorical tags to operational incidents.';

CREATE INDEX idx_incident_tags_tag ON cmmi.incident_tags (tag_name);

-- =====================================================================================================================
-- Table: M18-T159 - change_requests
-- Description: Formal change requests for production modifications.
-- Business Case: In a high-maturity organization (CMMI L5), changes to production cannot be ad-hoc. This table implements
--                 a formal change advisory board (CAB) workflow. It tracks the request, justification, and CAB decision
--                 (Approved/Rejected), ensuring that every production modification is reviewed for risk and business impact.
-- KPIs: Change Approval Rate, Change Request Lead Time, Emergency Change %, CAB Meeting Frequency, Change Success Rate.
-- Feature Reference: M18-T027 (Deployments) - Governance
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.change_requests (
    change_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    change_type VARCHAR(50) CHECK (change_type IN ('Standard', 'Normal', 'Emergency')),

    -- People
    requester_id UUID NOT NULL,
    reviewer_id UUID,

    -- Decision
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Approved', 'Rejected', 'Cancelled'
    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Impact
    risk_score INTEGER CHECK (risk_score >= 1 AND risk_score <= 10),
    impact_score INTEGER CHECK (impact_score >= 1 AND impact_score <= 10),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE cmmi.change_requests IS 'Manages the workflow for requesting and approving changes to production infrastructure.';

CREATE INDEX idx_change_requests_status ON cmmi.change_requests (status);
CREATE INDEX idx_change_requests_requester ON cmmi.change_requests (requester_id);

-- =====================================================================================================================
-- Table: M18-T160 - change_approvals
-- Description: Approval records for change requests.
-- Business Case: Compliance often requires multiple levels of approval (e.g., Tech Lead + Manager + Ops). This table
--                 stores the individual votes/approvals for a single change request, creating a full audit trail of who
--                 authorized what and when.
-- KPIs: Approval Cycle Time, Single-Point-of-Failure Risk, Approval Coverage, Rejection Justification Quality.
-- Feature Reference: M18-T159 (Change Requests)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.change_approvals (
    approval_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    change_id UUID NOT NULL,

    -- Approver
    approver_id UUID NOT NULL,
    role VARCHAR(50), -- 'Manager', 'Ops', 'Security'

    -- Decision
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Approved', 'Rejected', 'Abstained')),
    comments TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.change_approvals IS 'Stores individual approval decisions associated with a change request.';

CREATE INDEX idx_change_approvals_change ON cmmi.change_approvals (change_id);

-- =====================================================================================================================
-- Table: M18-T161 - change_risk_assessments
-- Description: Risk assessment linked to change request.
-- Business Case: Risk assessment is a core component of change management. This table stores the detailed analysis—
--                 identifying potential failure modes, impact on SLOs, and mitigation steps. It forces the requester to
--                 think through "What could go wrong?" before approval is granted.
-- KPIs: Risk Assessment Depth, Mitigation Effectiveness, Identified Risk Count vs. Actual Incidents, Assessment Time.
-- Feature Reference: M18-T014 (Release Risk Scoring)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.change_risk_assessments (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    change_id UUID NOT NULL,

    -- Assessment
    risk_score INTEGER NOT NULL CHECK (risk_score >= 1 AND risk_score <= 10),
    risk_factors TEXT[], -- ['Database Migration', 'High Traffic']
    mitigations JSONB NOT NULL, -- [{"risk": "Downtime", "mitigation": "Blue-Green Deploy"}]

    -- Assessor
    assessed_by UUID NOT NULL,
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.change_risk_assessments IS 'Detailed risk analysis and mitigation plans for specific change requests.';

CREATE INDEX idx_change_risk_change ON cmmi.change_risk_assessments (change_id);

-- =====================================================================================================================
-- Table: M18-T162 - compliance_frameworks
-- Description: Compliance standards (SOC2, ISO, PCI-DSS).
-- Business Case: PARI operates in a regulated fintech environment. This table defines the frameworks against which
--                 the organization is audited (e.g., SOC2 Type II, ISO 27001). It serves as the parent for controls and
--                 evidence collection, structuring the compliance program.
-- KPIs: Framework Coverage, Control Implementation %, Evidence Availability, Audit Readiness Score, Gap Count.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_frameworks (
    framework_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL, -- 'SOC 2 Type II'
    version VARCHAR(20), -- '2017'
    description TEXT,

    -- Schedule
    active BOOLEAN DEFAULT true,
    next_audit_date DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.compliance_frameworks IS 'Registry of regulatory and compliance frameworks applicable to the organization.';

-- =====================================================================================================================
-- Table: M18-T163 - compliance_controls
-- Description: Controls within frameworks.
-- Business Case: Frameworks are implemented via controls (e.g., "Access Control Policy"). This table maps specific
--                 controls to frameworks (e.g., ISO Control A.9 maps to SOC2 CC6.1). It allows the organization to demonstrate
--                 that a single technical implementation satisfies multiple compliance requirements.
-- KPIs: Control Maturity, Control Test Coverage, Control Failure Rate, Automation Level, Owner Assignment.
-- Feature Reference: M18-T164 (Control Mappings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_controls (
    control_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL,

    -- Details
    control_code VARCHAR(50) NOT NULL, -- 'A.9.1.1'
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Status
    implementation_status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Implemented', 'Testing', 'Operational'

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id)
);

COMMENT ON TABLE cmmi.compliance_controls IS 'Defines specific controls required to satisfy a compliance framework.';

CREATE INDEX idx_compliance_controls_framework ON cmmi.compliance_controls (framework_id);

-- =====================================================================================================================
-- Table: M18-T164 - control_mappings
-- Description: Maps technical controls to compliance controls.
-- Business Case: "Continuous Compliance" requires linking automated checks (e.g., "AWS S3 Bucket is encrypted") to
--                 compliance requirements. This table links technical assets (policies, scripts) to controls, enabling automated
--                 evidence gathering where possible.
-- KPIs: Automated Control %, Mapping Accuracy, Evidence Generation Rate, Control Validity.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.control_mappings (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    technical_control_id UUID NOT NULL, -- e.g., a script ID or policy ID
    compliance_control_id UUID NOT NULL,

    -- Metadata
    mapping_type VARCHAR(50), -- 'Automated Check', 'Manual Process', 'Evidence Upload'
    notes TEXT,

    FOREIGN KEY (compliance_control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.control_mappings IS 'Links technical implementations (scripts, configs) to compliance requirements.';

CREATE INDEX idx_control_mappings_compliance ON cmmi.control_mappings (compliance_control_id);

-- =====================================================================================================================
-- Table: M18-T165 - compliance_evidence
-- Description: Evidence files for compliance.
-- Business Case: Auditors require proof. This table stores references to evidence artifacts (screenshots, logs, reports)
--                 that prove a control is operating effectively. It manages the lifecycle of these files, ensuring they
--                 are retained for the required period.
-- KPIs: Evidence Collection Latency, Missing Evidence %, Evidence Expiry Alerts, Storage Cost, Retrieval Speed.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_evidence (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id UUID NOT NULL,

    -- File Details
    file_path TEXT NOT NULL, -- S3 URL
    file_type VARCHAR(50), -- 'PDF', 'Screenshot', 'Log'
    description TEXT,

    -- Lifecycle
    upload_date DATE NOT NULL,
    expiry_date DATE, -- When it can be archived/deleted
    uploaded_by UUID,

    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.compliance_evidence IS 'Stores metadata for evidence files supporting compliance controls.';

CREATE INDEX idx_compliance_evidence_control ON cmmi.compliance_evidence (control_id);
CREATE INDEX idx_compliance_evidence_expiry ON cmmi.compliance_evidence (expiry_date);

-- =====================================================================================================================
-- Table: M18-T166 - audit_logs
-- Description: General audit trail for system.
-- Business Case: A comprehensive audit log is mandatory for security forensics and compliance (who changed what).
--                 This table provides a centralized, immutable record of significant state changes in the M18 system,
--                 separate from detailed event logs.
-- KPIs: Log Completeness, Log Integrity (Hash Check), Query Performance, Retention Policy Adherence.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    actor_id UUID NOT NULL,

    -- Action
    action VARCHAR(100) NOT NULL, -- 'UPDATE_USER', 'DELETE_DEPLOYMENT'
    resource_type VARCHAR(50) NOT NULL, -- 'User', 'Release'
    resource_id UUID,

    -- Context
    ip_address INET,
    details JSONB,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.audit_logs IS 'Immutable audit trail of critical system actions.';

CREATE INDEX idx_audit_logs_actor ON cmmi.audit_logs (actor_id, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON cmmi.audit_logs (resource_type, resource_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T167 - users
-- Description: System users.
-- Business Case: The user directory is the foundation of Identity and Access Management (IAM). This table stores employee
--                 data, status, and departmental mapping. It enables role-based access control (RBAC) and ensures that
--                 access is revoked immediately when employment ends.
-- KPIs: User Count, Active vs Inactive Ratio, Department Distribution, Provisioning Time, Deprovisioning Speed.
-- Feature Reference: M18-T168 (Roles), M18-T171 (User Roles)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.users (
    user_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identity
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,

    -- Org
    department VARCHAR(100),
    manager_id UUID, -- Self-referencing FK

    -- Status
    is_active BOOLEAN DEFAULT true,
    is_super_user BOOLEAN DEFAULT false, -- Can bypass RBAC

    -- Security
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.users IS 'Central directory of user accounts and their organizational status.';

CREATE INDEX idx_users_email ON cmmi.users (email);
CREATE INDEX idx_users_active ON cmmi.users (is_active);
ALTER TABLE cmmi.users ADD CONSTRAINT fk_users_manager FOREIGN KEY (manager_id) REFERENCES cmmi.users(user_id);

-- =====================================================================================================================
-- Table: M18-T168 - roles
-- Description: User roles.
-- Business Case: Roles (e.g., "Developer", "QA", "Auditor") group permissions to simplify administration. Instead of
--                 managing 100 permissions per user, admins manage 5 roles. This table defines the available roles and their
--                 hierarchical structure.
-- KPIs: Role Count, User per Role Distribution, Role Inheritance Depth, Unused Role %.
-- Feature Reference: M18-T170 (Role Permissions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.roles (
    role_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    -- Hierarchy
    parent_role_id UUID, -- Role inheritance

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.roles IS 'Defines roles used for grouping permissions in Role-Based Access Control (RBAC).';

CREATE INDEX idx_roles_parent ON cmmi.roles (parent_role_id);

-- =====================================================================================================================
-- Table: M18-T169 - permissions
-- Description: Granular permissions.
-- Business Case: Permissions define fine-grained access (e.g., " deployments:read", " incidents:resolve"). This table
--                 is the bottom layer of the security model, defining exactly what actions are possible within the system.
-- KPIs: Permission Count, Permission Usage %, Orphaned Permission Count, Permission Granularity.
-- Feature Reference: M18-T170 (Role Permissions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.permissions (
    permission_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource VARCHAR(100) NOT NULL, -- 'deployments'
    action VARCHAR(100) NOT NULL, -- 'read'

    -- Description
    description TEXT,

    CONSTRAINT permissions_unique UNIQUE (resource, action)
);

COMMENT ON TABLE cmmi.permissions IS 'Defines granular permissions for system resources and actions.';

-- =====================================================================================================================
-- Table: M18-T170 - role_permissions
-- Description: Granting permissions to roles.
-- Business Case: This junction table implements the RBAC policy. It links roles to permissions. Changing this table
--                 immediately alters what thousands of users can do, making it a high-security table with strict audit requirements.
-- KPIs: Permission Change Frequency, Role Permission Count, Audit Trigger Count, Privilege Escalation Attempts.
-- Feature Reference: M18-T168 (Roles)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.role_permissions (
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,

    granted_by UUID,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (role_id, permission_id),

    FOREIGN KEY (role_id) REFERENCES cmmi.roles(role_id),
    FOREIGN KEY (permission_id) REFERENCES cmmi.permissions(permission_id)
);

COMMENT ON TABLE cmmi.role_permissions IS 'Maps permissions to roles to define access rights.';

-- =====================================================================================================================
-- Table: M18-T171 - user_roles
-- Description: Assigning roles to users.
-- Business Case: This table grants users their actual access rights. It supports time-bound assignments (expires_at),
--                 which is crucial for contractors or temporary project access. It ensures that access is automatically revoked
--                 when the contract ends.
-- KPIs: User Role Count, Role Assignment Latency, Expiring Role Count, Orphaned User (No Roles) Count.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,

    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID,
    expires_at TIMESTAMP WITH TIME ZONE, -- NULL for permanent

    is_active BOOLEAN GENERATED ALWAYS AS (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) STORED,

    PRIMARY KEY (user_id, role_id),

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (role_id) REFERENCES cmmi.roles(role_id)
);

COMMENT ON TABLE cmmi.user_roles IS 'Assigns roles to users, supporting time-based access expiry.';

CREATE INDEX idx_user_roles_user ON cmmi.user_roles (user_id);
CREATE INDEX idx_user_roles_active ON cmmi.user_roles (is_active) WHERE is_active = false; -- For cleanup of expired

-- =====================================================================================================================
-- Table: M18-T172 - sessions
-- Description: Active user sessions.
-- Business Case: Managing active sessions is critical for security (revoking access) and UX (single sign-on). This table
--                 stores the session token (hashed) and metadata, allowing the system to validate requests and force-logoff
--                 users if needed.
-- KPIs: Active Session Count, Average Session Duration, Concurrent Login Count, Session Revocation Time, Failed Session Validation.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Session
    token_hash CHAR(64) NOT NULL, -- Hashed session token
    ip_address INET,
    user_agent TEXT,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    is_active BOOLEAN GENERATED ALWAYS AS (expires_at > CURRENT_TIMESTAMP) STORED,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.sessions IS 'Manages active user authentication sessions.';

CREATE INDEX idx_sessions_user ON cmmi.sessions (user_id);
CREATE INDEX idx_sessions_token ON cmmi.sessions (token_hash);
CREATE INDEX idx_sessions_expiry ON cmmi.sessions (expires_at) WHERE is_active = true; -- For cleanup

-- =====================================================================================================================
-- Table: M18-T173 - teams
-- Description: Engineering teams.
-- Business Case: Metrics are often rolled up by team (Velocity, Burnup, Quality). This table defines teams, linking them
--                 to managers and communication channels (Slack). It is essential for organizational reporting and RLS policies.
-- KPIs: Team Size, Manager Assignment, Velocity per Team, Team Churn.
-- Feature Reference: M18-T143 (Team Members)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.teams (
    team_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    manager_id UUID,

    -- Communication
    slack_channel_id VARCHAR(100),
    email_list TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.teams IS 'Defines organizational engineering teams for reporting and access control.';

CREATE INDEX idx_teams_manager ON cmmi.teams (manager_id);

-- =====================================================================================================================
-- Table: M18-T174 - projects
-- Description: Projects or Products.
-- Business Case: Work is done within the context of a project (e.g., "Mobile Wallet v2"). This table links codebases,
--                 teams, and milestones. It provides the "Project View" in dashboards, aggregating data across all services
--                 belonging to a product.
-- KPIs: Project Count, Active Projects, Project On-Time Delivery %, Resource Allocation per Project.
-- Feature Reference: M18-T175 (Milestones)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.projects (
    project_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Links
    repo_id UUID, -- Link to T145
    owner_id UUID,

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Planning', 'Active', 'On Hold', 'Completed'

    start_date DATE,
    target_end_date DATE,
    actual_end_date DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.projects IS 'Defines high-level projects or products that encapsulate codebases and teams.';

CREATE INDEX idx_projects_owner ON cmmi.projects (owner_id);
CREATE INDEX idx_projects_status ON cmmi.projects (status);

-- =====================================================================================================================
-- Table: M18-T175 - milestones
-- Description: Project milestones.
-- Business Case: Tracking progress toward major releases or goals. Milestones aggregate sprints and work items, providing
--                 a higher-level view of delivery. Missing a milestone often triggers a risk review.
-- KPIs: Milestone Completion Rate, Milestone Slip (Days), Milestone Accuracy, Critical Milestone Count.
-- Feature Reference: M18-T174 (Projects)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.milestones (
    milestone_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    target_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed', 'Missed'

    completed_date DATE,

    FOREIGN KEY (project_id) REFERENCES cmmi.projects(project_id)
);

COMMENT ON TABLE cmmi.milestones IS 'Tracks major delivery targets and goals within a project.';

CREATE INDEX idx_milestones_project ON cmmi.milestones (project_id);
CREATE INDEX idx_milestones_date ON cmmi.milestones (target_date);

-- =====================================================================================================================
-- Table: M18-T176 - releases
-- Description: Product releases.
-- Business Case: The Release entity ties together deployments, risk scores (T014), and release notes (T048).
--                 It represents a version of the software delivered to customers. Tracking releases independently of deployments
--                 allows for multi-environment rollouts (e.g., one Release deployed to Dev, Stage, then Prod).
-- KPIs: Release Frequency, Release Lead Time, Release Success Rate, Release Note Completeness, Release Risk Score.
-- Feature Reference: M18-F050 (Release Notes Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.releases (
    release_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL, -- Semantic Versioning

    release_date DATE,
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Released', 'Deprecated'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (project_id) REFERENCES cmmi.projects(project_id)
);

COMMENT ON TABLE cmmi.releases IS 'Tracks formal software releases and their versions.';

CREATE INDEX idx_releases_project ON cmmi.releases (project_id, release_date DESC);

-- =====================================================================================================================
-- Table: M18-T177 - release_items
-- Description: Items included in a release.
-- Business Case: Traceability. This table links specific Work Items (T144 - Features/Bugs) to a Release. It answers
--                 "What features are in Release 1.2?" and ensures that all intended work is actually delivered.
-- KPIs: Items per Release, Item Inclusion Accuracy, Defect Leakage per Release, Sprint-to-Release Mapping.
-- Feature Reference: M18-T176 (Releases)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.release_items (
    release_id UUID NOT NULL,
    item_id UUID NOT NULL,

    included_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (release_id, item_id),

    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id),
    FOREIGN KEY (item_id) REFERENCES cmmi.work_items(item_id)
);

COMMENT ON TABLE cmmi.release_items IS 'Maps work items (features, fixes) to the release they are delivered in.';

-- =====================================================================================================================
-- Table: M18-T178 - environments
-- Description: Deployment environments.
-- Business Case: Promoting code through environments (Dev -> QA -> Stage -> Prod) is a core quality gate. This table
--                 defines these environments, their types (Persistent vs Ephemeral), and region, allowing for strict governance
--                 of where code runs.
-- KPIs: Environment Count, Environment Uptime, Environment Parity Score, Deployment per Env, Cost per Env.
-- Feature Reference: M18-T027 (Deployments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.environments (
    env_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL, -- 'Production-USEast'
    type VARCHAR(50) NOT NULL CHECK (type IN ('Development', 'Testing', 'Staging', 'Production')),
    region VARCHAR(50),

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Constraints
    requires_approval BOOLEAN DEFAULT false, -- Does deployment to here require CAB?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.environments IS 'Defines deployment environments and their governance policies.';

-- =====================================================================================================================
-- Table: M18-T179 - config_vars
-- Description: Configuration variables.
-- Business Case: 12-Factor App methodology separates config from code. This table stores key-value pairs for services.
--                 It supports versioning (T180) and secrets flagging (is_secret), allowing for centralized config management
--                 across environments.
-- KPIs: Config Change Frequency, Secret Config %, Missing Config Errors, Config Drift Count, Config Coverage.
-- Feature Reference: M18-F140 (Config Drift Detection)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.config_vars (
    var_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    env_id UUID NOT NULL,
    key TEXT NOT NULL,
    value TEXT, -- Encrypted if is_secret is true
    is_secret BOOLEAN DEFAULT false,

    -- Ownership
    service_name VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID,

    FOREIGN KEY (env_id) REFERENCES cmmi.environments(env_id)
);

COMMENT ON TABLE cmmi.config_vars IS 'Stores configuration variables for applications across environments.';

CREATE INDEX idx_config_vars_env ON cmmi.config_vars (env_id, key);
CREATE UNIQUE INDEX idx_config_vars_unique ON cmmi.config_vars (env_id, service_name, key) WHERE service_name IS NOT NULL;

-- =====================================================================================================================
-- Table: M18-T180 - config_history
-- Description: History of config changes.
-- Business Case: Debugging issues often requires knowing "What changed and when?". This table provides an audit trail of
--                 configuration changes, allowing for rollbacks to previous values and identifying config changes that caused incidents.
-- KPIs: Config Change Volume, Rollback Frequency, Time to Detect Bad Config, Config Update Latency.
-- Feature Reference: M18-F140 (Config Drift Detection)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.config_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    var_id UUID NOT NULL,

    -- Change
    old_value TEXT,
    new_value TEXT,

    -- Who
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (var_id) REFERENCES cmmi.config_vars(var_id)
);

COMMENT ON TABLE cmmi.config_history IS 'Audits changes made to configuration variables.';

CREATE INDEX idx_config_history_var ON cmmi.config_history (var_id, changed_at DESC);

-- =====================================================================================================================
-- Table: M18-T181 - secrets
-- Description: Encrypted secrets storage.
-- Business Case: Hard-coding secrets is forbidden. This table acts as a vault reference, storing the encrypted blob
--                 or pointer to the external vault (HashiCorp/AWS Secrets Manager). It manages metadata like rotation schedule
--                 and access control.
-- KPIs: Secret Rotation Compliance, Secret Access Audits, Secret Leak Count, Encryption Status, Secret Retrieval Latency.
-- Feature Reference: M18-F141 (Secret Rotation Verifier)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.secrets (
    secret_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Content
    encrypted_value TEXT, -- Or pointer
    version INTEGER DEFAULT 1,

    -- Lifecycle
    rotation_interval INTERVAL,
    next_rotation TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.secrets IS 'Stores metadata and references to encrypted secrets.';

CREATE INDEX idx_secrets_rotation ON cmmi.secrets (next_rotation) WHERE next_rotation IS NOT NULL;

-- =====================================================================================================================
-- Table: M18-T182 - secret_versions
-- Description: Versions of secrets.
-- Business Case: Secrets are versioned to support rolling updates without breaking existing connections. This table
--                 tracks older versions of a secret, allowing systems to still use the previous version while they pick up
--                 the new one.
-- KPIs: Version Retention, Active Version Count, Version Retrieval Speed, Rollback Success Rate.
-- Feature Reference: M18-T181 (Secrets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.secret_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL,
    version_number INTEGER NOT NULL,

    encrypted_value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (secret_id) REFERENCES cmmi.secrets(secret_id)
);

COMMENT ON TABLE cmmi.secret_versions IS 'Stores historical versions of secrets to support rolling updates.';

CREATE INDEX idx_secret_versions_secret ON cmmi.secret_versions (secret_id, version_number DESC);

-- =====================================================================================================================
-- Table: M18-T183 - assets
-- Description: Digital assets (Images, Docs).
-- Business Case: Compliance requires archiving specific artifacts (e.g., Architecture diagrams). This table stores metadata
--                 for these digital assets, linking them to projects or compliance requirements.
-- KPIs: Asset Storage Size, Asset Retrieval Speed, Asset Access Count, Duplicate Asset Detection, Retention Policy Adherence.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.assets (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'PDF', 'PNG', 'DOCX'
    storage_path TEXT NOT NULL, -- S3 URL

    -- Context
    project_id UUID,
    compliance_control_id UUID, -- If used as evidence

    uploaded_by UUID,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.assets IS 'Registry of digital assets and documents.';

CREATE INDEX idx_assets_project ON cmmi.assets (project_id);

-- =====================================================================================================================
-- Table: M18-T184 - tasks
-- Description: Background task queue.
-- Business Case: Asynchronous processing is vital for performance (e.g., generating PDF reports, sending emails).
--                 This table acts as a durable queue for background jobs, tracking their status (Pending, Running, Success, Failed).
-- KPIs: Task Throughput, Task Failure Rate, Task Latency, Queue Depth, Worker Utilization.
-- Feature Reference: M18-T188 (Reports)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tasks (
    task_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    type VARCHAR(100) NOT NULL, -- 'GenerateReport', 'SendEmail'
    payload JSONB,

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Running', 'Success', 'Failed'
    priority INTEGER DEFAULT 5, -- 1 is high, 10 is low
    queue_name VARCHAR(50) DEFAULT 'default',

    -- Retry Logic
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,

    -- Timing
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.tasks IS 'Durable queue for background asynchronous jobs.';

CREATE INDEX idx_tasks_status ON cmmi.tasks (status, priority) WHERE status IN ('Pending', 'Failed');
CREATE INDEX idx_tasks_queue ON cmmi.tasks (queue_name, status);

-- =====================================================================================================================
-- Table: M18-T185 - task_results
-- Description: Results of background tasks.
-- Business Case: Debugging failed jobs requires detailed logs/output. This table stores the return value and error
--                 messages of tasks, decoupling the large payload from the task queue table for performance.
-- KPIs: Result Retrieval Speed, Error Log Volume, Success/Failure Signal, Result Retention.
-- Feature Reference: M18-T184 (Tasks)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.task_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    task_id UUID NOT NULL,

    output JSONB,
    error_message TEXT,
    return_code INTEGER,

    FOREIGN KEY (task_id) REFERENCES cmmi.tasks(task_id)
);

COMMENT ON TABLE cmmi.task_results IS 'Stores execution output and error details for background tasks.';

-- =====================================================================================================================
-- Table: M18-T186 - annotations
-- Description: User annotations on metrics.
-- Business Case: Context is king in debugging. Ops engineers often leave notes on graphs (e.g., "Deployed v2.1").
--                 This table stores these annotations, which are then displayed on dashboards to explain spikes/dips in metrics.
-- KPIs: Annotation Count, Annotation Utility (viewed), Annotation Latency, User Participation.
-- Feature Reference: M18-T187 (Dashboards)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.annotations (
    annotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,

    -- Annotation
    text TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Author
    author_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.annotations IS 'Stores user notes attached to specific metrics for context.';

CREATE INDEX idx_annotations_metric_time ON cmmi.annotations (metric_name, timestamp);

-- =====================================================================================================================
-- Table: M18-T187 - dashboards
-- Description: Dashboard definitions.
-- Business Case: Dashboards are the primary UI for M18. This table stores the JSON definition of dashboard layouts
--                 (which panels, in what order, with what filters). It allows users to create custom views of the data.
-- KPIs: Dashboard Count, Dashboard Usage (Views), Load Time, User Customization Rate, Dashboard Shareability.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dashboards (
    dashboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Definition
    config_json JSONB NOT NULL, -- Panel definitions, layout

    -- Access
    owner_id UUID NOT NULL,
    is_public BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dashboards IS 'Stores visualization layouts and widget configurations for UI dashboards.';

CREATE INDEX idx_dashboards_owner ON cmmi.dashboards (owner_id);

-- =====================================================================================================================
-- Table: M18-T188 - reports
-- Description: Generated reports.
-- Business Case: Audit reports and weekly summaries are generated on demand or schedule. This table tracks the metadata
--                 of these generated files, linking them back to the parameters used to generate them.
-- KPIs: Report Generation Time, Report Download Count, Report Accuracy, Storage Usage, Schedule Adherence.
-- Feature Reference: M18-T189 (Subscriptions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'PDF', 'CSV', 'HTML'

    -- Source
    generated_by VARCHAR(50), -- 'System' or User ID
    params JSONB, -- Input parameters used

    -- File
    file_path TEXT,

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.reports IS 'Tracks generated reports and their file locations.';

CREATE INDEX idx_reports_generated_at ON cmmi.reports (generated_at DESC);

-- =====================================================================================================================
-- Table: M18-T189 - subscriptions
-- Description: Report subscriptions.
-- Business Case: Stakeholders need information pushed to them. This table manages subscriptions to reports (e.g.,
--                 "Email 'Weekly Quality Report' every Monday"). It automates the delivery of insights.
-- KPIs: Subscription Count, Delivery Success Rate, Bounce Rate, Subscription Click-through, Unsubscribe Rate.
-- Feature Reference: M18-T188 (Reports)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.subscriptions (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID NOT NULL,
    user_id UUID NOT NULL,

    -- Schedule
    schedule VARCHAR(50) NOT NULL, -- Cron expression

    -- Delivery
    channel VARCHAR(20) DEFAULT 'Email', -- 'Email', 'Slack', 'Webhook'
    destination TEXT, -- Email address or webhook URL

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_sent_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (report_id) REFERENCES cmmi.reports(report_id)
);

COMMENT ON TABLE cmmi.subscriptions IS 'Manages user preferences for automated delivery of reports.';

CREATE INDEX idx_subscriptions_user ON cmmi.subscriptions (user_id);

-- =====================================================================================================================
-- Table: M18-T190 - webhooks
-- Description: Outgoing webhook definitions.
-- Business Case: Integration with external systems (e.g., Jira, Slack, PagerDuty) is achieved via webhooks. This table
--                 defines the endpoints and events that trigger outgoing HTTP requests, enabling automation and alerting.
-- KPIs: Webhook Success Rate, Webhook Latency, Retry Volume, Destination Health, Event Delivery Consistency.
-- Feature Reference: M18-T104 (Webhook Delivery Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.webhooks (
    webhook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url TEXT NOT NULL,

    -- Events
    events TEXT[] NOT NULL, -- ['deploy.success', 'incident.created']

    -- Security
    secret VARCHAR(255), -- HMAC secret for verification

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.webhooks IS 'Configures outgoing webhooks for event notifications.';

-- =====================================================================================================================
-- Table: M18-T191 - api_keys
-- Description: API keys for external access.
-- Business Case: Partners or internal tools may need API access to M18 data. This table stores hashed API keys
--                 and scopes (permissions), allowing for secure, revocable access without user accounts.
-- KPIs: API Key Usage, API Key Validity, Revoked Key Access Attempts, Key Rotation Frequency.
-- Feature Reference: M18-F103 (API Throttling)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID, -- Optional: link to user if applicable

    -- Credentials
    hashed_key CHAR(64) NOT NULL, -- SHA-256
    scopes JSONB NOT NULL, -- ["read:metrics", "write:deployments"]

    -- Lifecycle
    name VARCHAR(100), -- Friendly name
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.api_keys IS 'Manages API keys for programmatic access to the M18 system.';

CREATE INDEX idx_api_keys_hashed ON cmmi.api_keys (hashed_key);

-- =====================================================================================================================
-- Table: M18-T192 - audit_events
-- Description: Detailed audit events.
-- Business Case: While T166 tracks high-level "actions", T192 captures detailed security events (failed logins,
--                 permission denied, access to PII). This granular log is essential for forensic analysis and meeting strict
--                 compliance logging requirements (PCI-DSS).
-- KPIs: Event Volume, Event Retention, Search Latency, Anomaly Detection Rate, Alert Trigger Count.
-- Feature Reference: M18-T166 (Audit Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Source
    actor_id UUID,
    actor_type VARCHAR(50), -- 'User', 'APIKey', 'System'

    -- Event
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,

    -- Outcome
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('Success', 'Failure', 'Partial')),

    -- Context
    ip_address INET,
    user_agent TEXT,
    details JSONB,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.audit_events IS 'Detailed security event log for forensic analysis.';

CREATE INDEX idx_audit_events_timestamp ON cmmi.audit_events (timestamp DESC);
CREATE INDEX idx_audit_events_actor ON cmmi.audit_events (actor_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T193 - threat_models
-- Description: Threat model documents.
-- Business Case: Proactive security requires Threat Modeling (STRIDE/Pastor). This table stores the results of
--                 threat modeling sessions, documenting identified threats and mitigations for specific architectures or features.
-- KPIs: Threat Model Coverage, Threat Remediation Rate, Model Age, Identified Threats Count, Review Frequency.
-- Feature Reference: M18-T241 (Threat Model Reviews)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.threat_models (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL, -- Link to Service, Repo, or Feature

    -- Content
    title VARCHAR(255) NOT NULL,
    threats_json JSONB NOT NULL, -- List of threats
    mitigations_json JSONB NOT NULL, -- List of mitigations

    -- Status
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Reviewed', 'Approved'
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.threat_models IS 'Documents structured threat models for system assets.';

CREATE INDEX idx_threat_models_asset ON cmmi.threat_models (asset_id);

-- =====================================================================================================================
-- Table: M18-T194 - pen_tests
-- Description: Penetration test records.
-- Business Case: Regular penetration testing validates security defenses. This table schedules and tracks the results of
--                 third-party pen tests, managing the lifecycle of findings from report to remediation.
-- KPIs: Pen Test Frequency, Critical Finding Count, Finding Remediation Time, Vendor Score, Recurring Findings %.
-- Feature Reference: M18-T195 (Vulnerabilities)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pen_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scheduling
    target_scope TEXT NOT NULL, -- 'Payment API', 'All Public IPs'
    scheduled_date DATE,
    tester_firm VARCHAR(255),

    -- Results
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed', 'Report Delivered'
    summary TEXT,
    findings_count INTEGER,

    -- Report
    report_path TEXT,
    uploaded_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.pen_tests IS 'Manages the schedule and results of penetration testing exercises.';

CREATE INDEX idx_pen_tests_status ON cmmi.pen_tests (status);

-- =====================================================================================================================
-- Table: M18-T195 - vulnerabilities
-- Description: General vulnerability tracking.
-- Business Case: While T018 tracks dependency CVEs and T059 container CVEs, this table tracks general application
--                 vulnerabilities discovered by any means (pen tests, bug bounty, manual review). It centralizes vulnerability management.
-- KPIs: Open Vulnerability Count, Age of Open Vulns, High Severity Vulns, Remediation Velocity, Vulnerability Recurrence.
-- Feature Reference: M18-T198 (Remediation Plans)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vulnerabilities (
    vuln_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),

    -- Source
    source VARCHAR(50), -- 'PenTest', 'Scan', 'Manual'
    source_ref_id VARCHAR(100), -- ID from external system

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Resolved', 'Mitigated'
    discovered_date DATE NOT NULL,
    resolved_date DATE,

    assignee_id UUID
);

COMMENT ON TABLE cmmi.vulnerabilities IS 'Central registry for tracking all security vulnerabilities.';

CREATE INDEX idx_vulns_severity ON cmmi.vulnerabilities (severity, status);
CREATE INDEX idx_vulns_status ON cmmi.vulnerabilities (status);

-- =====================================================================================================================
-- Table: M18-T196 - vuln_scans
-- Description: Vulnerability scan executions.
-- Business Case: Automated scanning (DAST/SAST) happens regularly. This table records the execution of these scans,
--                 linking them to the scanner tool and providing a container for the findings (T197).
-- KPIs: Scan Frequency, Scan Duration, Scan Failure Rate, Coverage %, False Positive Reduction.
-- Feature Reference: M18-T017 (SAST Findings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vuln_scans (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Context
    scanner_type VARCHAR(50) NOT NULL, -- 'DAST', 'SAST', 'DAST'
    target TEXT NOT NULL, -- URL or Repo

    -- Execution
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- 'Running', 'Completed', 'Failed'

    -- Results Summary
    total_findings INTEGER DEFAULT 0
);

COMMENT ON TABLE cmmi.vuln_scans IS 'Logs the execution history of automated vulnerability scans.';

CREATE INDEX idx_vuln_scans_target ON cmmi.vuln_scans (target, start_time DESC);

-- =====================================================================================================================
-- Table: M18-T197 - vuln_findings
-- Description: Findings from a scan.
-- Business Case: Detailed results from a scan execution. This table captures the specific location and nature of a finding
--                 generated during a specific scan (T196), linking it to the master vulnerability record (T195) for tracking.
-- KPIs: Finding per Scan, Unique Finding Ratio, Confirmation Rate, Suppression Rate.
-- Feature Reference: M18-T196 (Vuln Scans)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vuln_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_id UUID NOT NULL,
    vuln_id UUID, -- Link to master T195 if matched

    -- Details
    location TEXT, -- URL or File Path
    description TEXT,

    -- Confidence
    confidence NUMERIC(3, 2), -- 0.0 to 1.0

    FOREIGN KEY (scan_id) REFERENCES cmmi.vuln_scans(scan_id),
    FOREIGN KEY (vuln_id) REFERENCES cmmi.vulnerabilities(vuln_id)
);

COMMENT ON TABLE cmmi.vuln_findings IS 'Detailed results from a specific vulnerability scan execution.';

CREATE INDEX idx_vuln_findings_scan ON cmmi.vuln_findings (scan_id);

-- =====================================================================================================================
-- Table: M18-T198 - remediation_plans
-- Description: Plans to fix vulnerabilities.
-- Business Case: Fixing vulnerabilities requires planning (code changes, config changes, documentation). This table tracks
--                 the remediation efforts, assigning owners and due dates to open vulnerabilities (T195).
-- KPIs: Remediation Plan SLA Adherence, Plan Effectiveness, Assignee Workload, Plan Completion Rate.
-- Feature Reference: M18-T195 (Vulnerabilities)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.remediation_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vuln_id UUID NOT NULL,

    -- Plan
    description TEXT NOT NULL,
    assignee_id UUID NOT NULL,
    target_date DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed', 'Cancelled'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (vuln_id) REFERENCES cmmi.vulnerabilities(vuln_id)
);

COMMENT ON TABLE cmmi.remediation_plans IS 'Manages the remediation lifecycle for identified vulnerabilities.';

CREATE INDEX idx_remediation_vuln ON cmmi.remediation_plans (vuln_id);
CREATE INDEX idx_remediation_assignee ON cmmi.remediation_plans (assignee_id);

-- =====================================================================================================================
-- Table: M18-T199 - risk_registers
-- Description: Enterprise risk register.
-- Business Case: Risk Management extends beyond code to the enterprise (Financial, Reputational, Operational). This table
--                 acts as the Risk Register, logging identified risks, their likelihood, impact, and calculated scores.
-- KPIs: Risk Count, Average Risk Score, High Risk Count, Mitigation Coverage, Risk Review Frequency.
-- Feature Reference: M18-T200 (Risk Mitigations)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.risk_registers (
    risk_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Description
    category VARCHAR(50) NOT NULL, -- 'Operational', 'Security', 'Financial', 'Reputational'
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Scoring
    likelihood INTEGER CHECK (likelihood >= 1 AND likelihood <= 5),
    impact INTEGER CHECK (impact >= 1 AND impact <= 5),
    score INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,

    -- Owner
    owner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Mitigating', 'Accepted', 'Closed'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.risk_registers IS 'Central repository for tracking enterprise-level risks.';

CREATE INDEX idx_risk_category ON cmmi.risk_registers (category, score DESC);

-- =====================================================================================================================
-- Table: M18-T200 - risk_mitigations
-- Description: Mitigations for risks.
-- Business Case: Identification without action is useless. This table tracks the specific mitigation strategies (controls,
--                 processes, projects) put in place to reduce the likelihood or impact of risks in the register (T199).
-- KPIs: Mitigation Effectiveness, Mitigation Implementation Lag, Mitigation Cost, Risk Reduction Achievement.
-- Feature Reference: M18-T199 (Risk Registers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.risk_mitigations (
    mitigation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id UUID NOT NULL,

    description TEXT NOT NULL,
    owner_id UUID,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Implemented'

    effectiveness VARCHAR(20), -- 'High', 'Medium', 'Low', 'Unknown'

    FOREIGN KEY (risk_id) REFERENCES cmmi.risk_registers(risk_id)
);

COMMENT ON TABLE cmmi.risk_mitigations IS 'Tracks actions taken to mitigate identified enterprise risks.';

CREATE INDEX idx_mitigations_risk ON cmmi.risk_mitigations (risk_id);

-- =====================================================================================================================
-- Triggers for Timestamp Updates (Part 4 Tables)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_change_requests
    BEFORE UPDATE ON cmmi.change_requests
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_users
    BEFORE UPDATE ON cmmi.users
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_config_vars
    BEFORE UPDATE ON cmmi.config_vars
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_dashboards
    BEFORE UPDATE ON cmmi.dashboards
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_vuln_scans
    BEFORE UPDATE ON cmmi.vuln_scans
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_risk_registers
    BEFORE UPDATE ON cmmi.risk_registers
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 151-200)
-- =====================================================================================================================
-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 5
-- Tables DB201 - DB250
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T201 - process_baselines
-- Description: Historical baselines for process metrics.
-- Business Case: To measure improvement, one must know the starting point. This table stores snapshots of process
--                 baselines (e.g., "Average Cycle Time" or "Defect Density") over time. CMMI Level 5 requires
--                 quantitative management, which relies on comparing current performance against these historical baselines to
--                 calculate process capability and improvement trends. It prevents "moving the goalposts" by locking in
--                 performance targets for specific periods.
-- KPIs: Baseline Drift, Baseline Stability, Process Shifts, Re-calibration Frequency, Trend Validity.
-- Feature Reference: M18-F003 (Automated SPC Chart Generation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_baselines (
    baseline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,

    -- Values
    baseline_value NUMERIC(18, 6) NOT NULL,
    variance_allowed NUMERIC(18, 6), -- Tolerance band

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE, -- NULL implies current

    -- Metadata
    established_by UUID,
    established_method VARCHAR(100), -- 'Historical Average', 'Industry Benchmark', 'Executive Target'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_baselines IS 'Stores historical performance baselines used for trend analysis and process control.';
CREATE INDEX idx_process_baselines_metric ON cmmi.process_baselines (metric_name, valid_from DESC);

-- =====================================================================================================================
-- Table: M18-T202 - sigma_levels
-- Description: Calculated Sigma levels (DPMO) for processes.
-- Business Case: Six Sigma is a standard for process quality. This table calculates and stores the Sigma level
--                 (1 to 6) and Defects Per Million Opportunities (DPMO) for critical processes (e.g., Payment Processing).
--                 It provides a single, universally understood metric to communicate engineering quality to executive
--                 stakeholders and compare against industry benchmarks.
-- KPIs: Process Sigma (Goal > 4.5), DPMO, Opportunities Count, Defect Count, Sigma Trend.
-- Feature Reference: M18-F019 (Process Capability Cpk Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sigma_levels (
    calculation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    process_name VARCHAR(100) NOT NULL,

    -- Calculations
    sigma_score NUMERIC(3, 2) NOT NULL CHECK (sigma_score >= 0 AND sigma_score <= 6),
    dpmo NUMERIC(12, 2) NOT NULL, -- Defects Per Million Opportunities

    -- Context
    calculation_date DATE NOT NULL DEFAULT CURRENT_DATE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    CONSTRAINT sigma_levels_check CHECK (sigma_score >= 0)
);

COMMENT ON TABLE cmmi.sigma_levels IS 'Stores Six Sigma calculations and DPMO metrics for process quality assessment.';
CREATE INDEX idx_sigma_levels_process ON cmmi.sigma_levels (process_name, calculation_date DESC);

-- =====================================================================================================================
-- Table: M18-T203 - training_catalog
-- Description: Catalog of available training courses.
-- Business Case: Addressing skill gaps (T044) requires a repository of learning content. This table defines the curriculum,
--                 linking courses to specific skills or compliance requirements. It tracks delivery modes (E-learning, Classroom)
--                 and duration, enabling managers to prescribe specific training to developers based on their performance
--                 data or quality incidents.
-- KPIs: Course Availability, Training Coverage of Skills, Completion Rate, Training Cost, Relevance Score.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_catalog (
    course_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Logistics
    duration_hours NUMERIC(5, 2),
    delivery_mode VARCHAR(50) CHECK (delivery_mode IN ('Online', 'Classroom', 'Workshop', 'Video')),
    difficulty_level VARCHAR(20) CHECK (difficulty_level IN ('Beginner', 'Intermediate', 'Advanced')),

    -- Compliance/Skill Link
    required_for VARCHAR(100)[], -- Array of skills or compliance frameworks
    is_mandatory BOOLEAN DEFAULT false,

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.training_catalog IS 'Defines available training courses and their learning objectives.';
CREATE INDEX idx_training_catalog_active ON cmmi.training_catalog (is_active);

-- =====================================================================================================================
-- Table: M18-T204 - training_records
-- Description: Records of training completed by staff.
-- Business Case: Compliance mandates proof of training (e.g., PCI-DSS awareness). This table tracks who took which course
--                 and when. It feeds into compliance reporting (T146) and ensures that developers have the prerequisites
--                 before being assigned to sensitive projects (e.g., Crypto modules).
-- KPIs: Training Compliance %, Training per Employee, Certification Expiry, Skill Gap Closure, Training Cost per Capita.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    course_id UUID NOT NULL,

    -- Completion
    completion_date DATE NOT NULL,
    score NUMERIC(5, 2), -- Pass mark
    status VARCHAR(20) DEFAULT 'Completed', -- 'Completed', 'Failed', 'InProgress'

    -- Certification
    certificate_url TEXT,
    expiry_date DATE,

    FOREIGN KEY (course_id) REFERENCES cmmi.training_catalog(course_id),
    CONSTRAINT training_records_unique UNIQUE (user_id, course_id, completion_date)
);

COMMENT ON TABLE cmmi.training_records IS 'Logs the training history and certifications of employees.';
CREATE INDEX idx_training_records_user ON cmmi.training_records (user_id, completion_date DESC);
CREATE INDEX idx_training_records_course ON cmmi.training_records (course_id);

-- =====================================================================================================================
-- Table: M18-T205 - skill_inventory
-- Description: Inventory of skills per user.
-- Business Case: Dynamic team assembly requires knowing who knows what. This table captures the proficiency level
--                 (1-5) of users for specific skills. It differs from training (T204) by being a self or peer-assessed
--                 inventory of *capability*, not just *courses taken*. It is crucial for optimizing team composition.
-- KPIs: Skill Proficiency Average, Skills per User, Skill Gap Severity, Expert Identification, Redundancy Count.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.skill_inventory (
    inventory_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    skill_name VARCHAR(100) NOT NULL,

    -- Proficiency
    proficiency_level INTEGER CHECK (proficiency_level >= 1 AND proficiency_level <= 5),
    self_assessed BOOLEAN DEFAULT true,

    -- Verification
    last_verified_date DATE,
    verified_by UUID,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT skill_inventory_unique UNIQUE (user_id, skill_name)
);

COMMENT ON TABLE cmmi.skill_inventory IS 'Maps users to their specific skills and proficiency levels.';
CREATE INDEX idx_skill_inventory_user ON cmmi.skill_inventory (user_id);
CREATE INDEX idx_skill_inventory_skill ON cmmi.skill_inventory (skill_name);

-- =====================================================================================================================
-- Table: M18-T206 - process_asset_library
-- Description: Repository for process documents/templates.
-- Business Case: Standardization requires reusable assets. This table stores artifacts like templates, checklists, and
--                 guidelines. By versioning these assets, M18 ensures that everyone uses the latest approved process,
--                 reducing variation and errors caused by using outdated templates.
-- KPIs: Asset Usage Count, Asset Version Age, Template Adoption Rate, Search Success Rate, Asset Obsolescence.
-- Feature Reference: M18-F003 (Automated SPC Chart Generation) - Process definition aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_asset_library (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('Template', 'Guide', 'Policy', 'Checklist', 'Script')),

    -- Content
    version VARCHAR(20) NOT NULL,
    file_path TEXT,

    -- Lifecycle
    approval_status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Pending', 'Approved', 'Deprecated'
    approved_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_asset_library IS 'Manages the lifecycle of reusable process documents and templates.';
CREATE INDEX idx_process_asset_type ON cmmi.process_asset_library (type);

-- =====================================================================================================================
-- Table: M18-T207 - tailoring_guidelines
-- Description: Guidelines for tailoring standard processes.
-- Business Case: One size does not fit all. A small maintenance project needs less overhead than a new flagship feature.
--                 This table defines how the standard CMMI process can be tailored for different project types (e.g.,
--                 "Emergency fixes skip design review"). It ensures deviations are authorized and documented.
-- KPIs: Tailoring Exceptions, Compliance Risk from Tailoring, Project Type Coverage, Guideline Adherence.
-- Feature Reference: M18-T010 (Technical Debt Metrics) - Process Aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tailoring_guidelines (
    guideline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_type VARCHAR(100) NOT NULL,

    -- Rules
    applicable_standards TEXT[], -- 'ISO 9001', 'CMMI Level 5'
    tailoring_options JSONB NOT NULL, -- {"design_review": "skipped", "unit_test_coverage": "80%"}

    -- Governance
    approval_required BOOLEAN DEFAULT true,
    authorized_by UUID,

    valid_from DATE NOT NULL,
    valid_to DATE
);

COMMENT ON TABLE cmmi.tailoring_guidelines IS 'Defines authorized deviations from standard processes based on project classification.';
CREATE INDEX idx_tailoring_guidelines_type ON cmmi.tailoring_guidelines (project_type);

-- =====================================================================================================================
-- Table: M18-T208 - checklist_templates
-- Description: Templates for review checklists.
-- Business Case: Checklists prevent cognitive lapses during reviews. This table defines the master templates for various
--                 activities (Code Review, Deployment, Risk Assessment). It ensures that mandatory steps are never skipped
--                 and facilitates consistency across different reviewers.
-- KPIs: Checklist Usage, Checklist Completion Rate, Defect Prevention Rate, Template Accuracy, Reviewer Compliance.
-- Feature Reference: M18-T209 (Checklist Instances)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.checklist_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    review_type VARCHAR(50) NOT NULL, -- 'CodeReview', 'DeployPrep', 'RCA'

    -- Content
    section_json JSONB NOT NULL, -- Structured list of items

    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.checklist_templates IS 'Defines standard checklist templates for quality gates and reviews.';

-- =====================================================================================================================
-- Table: M18-T209 - checklist_instances
-- Description: Usage of checklists in actual reviews.
-- Business Case: Templates (T208) are static; instances are the filled-out forms attached to real work. This table
--                 records the outcome of a checklist run (e.g., PR #123 Checklist), tracking which items passed, failed, or
--                 were N/A. It provides auditable proof of review rigor.
-- KPIs: Instance Pass Rate, Checklist Item Failure Frequency, Review Consistency, Time to Complete Checklist.
-- Feature Reference: M18-F011 (Peer Review Depth Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.checklist_instances (
    instance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id UUID NOT NULL,
    pr_id VARCHAR(100), -- Or deployment_id, incident_id

    -- Execution
    item_json JSONB NOT NULL, -- [{"id": 1, "status": "Pass", "comment": "..."}]
    passed_flag BOOLEAN NOT NULL,

    -- User
    reviewer_id UUID,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (template_id) REFERENCES cmmi.checklist_templates(template_id)
);

COMMENT ON TABLE cmmi.checklist_instances IS 'Records the execution and results of checklist templates during reviews.';
CREATE INDEX idx_checklist_instances_pr ON cmmi.checklist_instances (pr_id);

-- =====================================================================================================================
-- Table: M18-T210 - gate_reviews
-- Description: Definition of Phase Gates.
-- Business Case: Phase gates (e.g., "Requirement Sign-off", "Ready for Test") control the progression of a project.
--                 This table defines the criteria for these gates. It ensures that a project cannot proceed to the next
--                 phase until quality and documentation standards are met.
-- KPIs: Gate Pass Rate, Gate Cycle Time, Critical Gate Blocking Count, Waiver Request Rate.
-- Feature Reference: M18-T211 (Gate Review Decisions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gate_reviews (
    gate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    phase_name VARCHAR(100) NOT NULL, -- 'Requirements', 'Design', 'Implementation'

    -- Criteria
    criteria_json JSONB NOT NULL, -- List of requirements
    approver_role VARCHAR(100) NOT NULL, -- Who must approve

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.gate_reviews IS 'Defines quality gate criteria for project phases.';

-- =====================================================================================================================
-- Table: M18-T211 - gate_review_decisions
-- Description: History of gate decisions.
-- Business Case: This table logs the outcome of Phase Gates (T210). It tracks whether a project Passed, Failed, or
--                 was granted a Conditional Pass (Waiver). This history is vital for analyzing which quality criteria
--                 are most frequently missed or waived.
-- KPIs: Gate Approval Latency, Fail Rate, Waiver Justification Quality, Gate Rejection Reason Distribution.
-- Feature Reference: M18-T210 (Gate Reviews)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gate_review_decisions (
    decision_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gate_id UUID NOT NULL,
    project_id UUID NOT NULL,

    -- Decision
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Pass', 'Fail', 'ConditionalPass', 'Hold')),
    comments TEXT,

    -- People
    reviewer_id UUID NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (gate_id) REFERENCES cmmi.gate_reviews(gate_id)
);

COMMENT ON TABLE cmmi.gate_review_decisions IS 'Audits decisions made at project phase gates.';
CREATE INDEX idx_gate_decisions_project ON cmmi.gate_review_decisions (project_id);

-- =====================================================================================================================
-- Table: M18-T212 - corrective_actions
-- Description: Corrective Action Requests (CAR) from Causal Analysis.
-- Business Case: RCA (T012) is useless without action. This table manages the lifecycle of Corrective Actions, assigning
--                 owners and due dates. It ensures that systemic root causes (like "Lack of Crypto Training") are
--                 actually resolved to prevent recurrence.
-- KPIs: CAR Open Age, CAR Completion Rate, CAR Effectiveness, Overdue CARs, Recurrence of Root Cause.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.corrective_actions (
    car_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_incident_id UUID NOT NULL, -- Link to T149
    description TEXT NOT NULL,

    -- Assignment
    owner_id UUID NOT NULL,
    due_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Verified', 'Closed'

    -- Outcome
    effectiveness_rating INTEGER, -- 1-5 post-implementation

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.corrective_actions IS 'Tracks remediation steps for identified root causes of incidents.';
CREATE INDEX idx_corrective_actions_incident ON cmmi.corrective_actions (source_incident_id);
CREATE INDEX idx_corrective_actions_status ON cmmi.corrective_actions (status, due_date);

-- =====================================================================================================================
-- Table: M18-T213 - preventive_actions
-- Description: Preventive actions to stop future issues.
-- Business Case: Proactive risk management. While CARs react to incidents, Preventive Actions (PA) address risks
--                 (T199) before they materialize. This table tracks proactive measures (e.g., "Upgrade firewall firmware")
--                 to demonstrate due diligence.
-- KPIs: PA Completion Rate, Risk Mitigation %, PA vs Incident Correlation, Proactive Investment ROI.
-- Feature Reference: M18-T199 (Risk Registers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.preventive_actions (
    pa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id UUID NOT NULL, -- Link to T199
    description TEXT NOT NULL,

    -- Assignment
    owner_id UUID NOT NULL,
    target_date DATE NOT NULL,
    implementation_date DATE,

    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Implemented', 'Cancelled'

    FOREIGN KEY (risk_id) REFERENCES cmmi.risk_registers(risk_id)
);

COMMENT ON TABLE cmmi.preventive_actions IS 'Tracks proactive measures implemented to mitigate identified risks.';
CREATE INDEX idx_preventive_actions_risk ON cmmi.preventive_actions (risk_id);

-- =====================================================================================================================
-- Table: M18-T214 - lessons_learned
-- Description: Repository of lessons learned.
-- Business Case: Organizational memory. Lessons learned capture tacit knowledge from retrospectives (T031) or incidents (T149).
--                 Storing them in a searchable database prevents repeating the same mistakes across different teams.
-- KPIs: Lessons Logged, Lessons Applied, Search Usage, Knowledge Base Growth, Lesson Age.
-- Feature Reference: M18-T031 (Automated Retrospective Summarizer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.lessons_learned (
    lesson_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID,

    -- Content
    context TEXT NOT NULL,
    lesson_learned TEXT NOT NULL,
    impact TEXT,

    -- Metadata
    tags TEXT[],
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.lessons_learned IS 'Repository for organizational knowledge to prevent repeated mistakes.';
CREATE INDEX idx_lessons_learned_tags ON cmmi.lessons_learned USING GIN (tags);

-- =====================================================================================================================
-- Table: M18-T215 - best_practices
-- Description: Approved best practices for reuse.
-- Business Case: Standardization of excellence. Best practices are patterns that have been proven to work (e.g.,
--                 "Circuit Breaker Pattern for APIs"). This table vets and publishes these for general adoption,
--                 accelerating development and reducing architectural debt.
-- KPIs: Best Practice Adoption Count, Practice Effectiveness, Suggestion vs Adoption Ratio, Search Frequency.
-- Feature Reference: M18-T206 (Process Asset Library)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.best_practices (
    practice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain VARCHAR(100) NOT NULL, -- 'Security', 'Scalability', 'UX'
    description TEXT NOT NULL,

    -- Evidence
    evidence_url TEXT, -- Link to case study or doc
    adoption_count INTEGER DEFAULT 0,

    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.best_practices IS 'Catalogs proven patterns and techniques recommended for adoption.';
CREATE INDEX idx_best_practices_domain ON cmmi.best_practices (domain);

-- =====================================================================================================================
-- Table: M18-T216 - process_assessments
-- Description: Internal process assessments (e.g., SCAMPI).
-- Business Case: Verifying maturity level. CMMI requires periodic formal assessments (like SCAMPI B or C). This table
--                 schedules and stores results of these appraisals, providing the official "Maturity Level" rating
--                 used for marketing and internal governance.
-- KPIs: Maturity Level (Target 5), Assessment Frequency, Weakness Count, Strength Count, Appraisal Cost.
-- Feature Reference: M18-T217 (Assessment Findings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_assessments (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    scope VARCHAR(255) NOT NULL,
    maturity_level_target VARCHAR(20), -- 'Level 4', 'Level 5'

    -- Execution
    assessor_id UUID NOT NULL,
    date DATE NOT NULL,
    result VARCHAR(20), -- 'Achieved', 'Not Achieved', 'Lapsed'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_assessments IS 'Records formal appraisals of organizational process maturity.';

-- =====================================================================================================================
-- Table: M18-T217 - assessment_findings
-- Description: Findings from process assessments.
-- Business Case: The "Why" behind the Maturity Level. This table details specific Strengths and Weaknesses found
--                 during an assessment (T216). It forms the basis for the Process Improvement Plan (PIP).
-- KPIs: Finding Severity, Finding Resolution Rate, Weakness vs Strength Ratio, Recurring Findings.
-- Feature Reference: M18-T216 (Process Assessments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.assessment_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assessment_id UUID NOT NULL,

    -- Details
    process_area VARCHAR(100) NOT NULL,
    strength_weakness VARCHAR(10) CHECK (strength_weakness IN ('Strength', 'Weakness')),
    recommendation TEXT,

    FOREIGN KEY (assessment_id) REFERENCES cmmi.process_assessments(assessment_id)
);

COMMENT ON TABLE cmmi.assessment_findings IS 'Stores detailed feedback from formal process maturity assessments.';
CREATE INDEX idx_assessment_findings_assessment ON cmmi.assessment_findings (assessment_id);

-- =====================================================================================================================
-- Table: M18-T218 - improvement_proposals
-- Description: Process Improvement Proposals (PIP).
-- Business Case: Continuous improvement requires ideas. PIPs capture suggestions from the floor (developers) on how
--                 to fix process pain points. This table manages the workflow of evaluating, approving, and scheduling
--                 these improvements.
-- KPIs: PIP Submission Rate, PIP Implementation Rate, Average Cycle Time, ROI of PIPs, Employee Engagement.
-- Feature Reference: M18-F153 (Innovation Time Tracking)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.improvement_proposals (
    pip_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proposer_id UUID NOT NULL,

    -- Content
    title VARCHAR(255) NOT NULL,
    problem_statement TEXT NOT NULL,
    proposed_solution TEXT NOT NULL,

    -- Business Case
    estimated_cost NUMERIC(15, 2),
    estimated_benefit TEXT,

    -- Workflow
    status VARCHAR(20) DEFAULT 'Submitted', -- 'Submitted', 'Approved', 'Rejected', 'Implemented'
    priority VARCHAR(20),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.improvement_proposals IS 'Manages workflow for process improvement suggestions from staff.';
CREATE INDEX idx_pip_status ON cmmi.improvement_proposals (status);

-- =====================================================================================================================
-- Table: M18-T219 - pip_status_history
-- Description: Status tracking for PIPs.
-- Business Case: Audit trail for PIP decisions. This table tracks every transition a PIP goes through (Submitted ->
--                 Review -> Approved), providing visibility into how long ideas sit in the queue and who is blocking them.
-- KPIs: Time in State, Approval Chain Length, Rejection Reason Frequency, State Transition Speed.
-- Feature Reference: M18-T218 (Improvement Proposals)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pip_status_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pip_id UUID NOT NULL,

    old_status VARCHAR(20),
    new_status VARCHAR(20) NOT NULL,

    changed_by UUID,
    comments TEXT,

    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (pip_id) REFERENCES cmmi.improvement_proposals(pip_id)
);

COMMENT ON TABLE cmmi.pip_status_history IS 'Logs state transitions of Process Improvement Proposals.';
CREATE INDEX idx_pip_history_pip ON cmmi.pip_status_history (pip_id, changed_at DESC);

-- =====================================================================================================================
-- Table: M18-T220 - pilot_projects
-- Description: Pilot projects for testing new processes.
-- Business Case: Don't bet the farm on an unproven process. Before rolling out a PIP to the whole org, run a pilot.
--                 This table defines these experiments, tracking the hypothesis, scope, and expected outcomes.
-- KPIs: Pilot Success Rate, Pilot Duration, Findings per Pilot, Rollout Decision Rate.
-- Feature Reference: M18-T221 (Pilot Results)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pilot_projects (
    pilot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pip_id UUID NOT NULL, -- Link to proposal

    -- Details
    name VARCHAR(255) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE,

    -- Metrics
    baseline_metric NUMERIC(15, 2),
    target_metric NUMERIC(15, 2),

    status VARCHAR(20) DEFAULT 'Planned',

    FOREIGN KEY (pip_id) REFERENCES cmmi.improvement_proposals(pip_id)
);

COMMENT ON TABLE cmmi.pilot_projects IS 'Manages experimental trials for new process improvements before full rollout.';
CREATE INDEX idx_pilot_projects_pip ON cmmi.pilot_projects (pip_id);

-- =====================================================================================================================
-- Table: M18-T221 - pilot_results
-- Description: Results of pilot projects.
-- Business Case: Data-driven decisions on rollout. This table captures the actual results of the pilot (Metric Before/After)
--                 and qualitative feedback. It determines if the PIP should be adopted, modified, or scrapped.
-- KPIs: Metric Improvement %, Stakeholder Satisfaction, Pilot vs Production Variance, Recommendation Confidence.
-- Feature Reference: M18-T220 (Pilot Projects)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pilot_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pilot_id UUID NOT NULL,

    -- Metrics
    metric_before NUMERIC(15, 2) NOT NULL,
    metric_after NUMERIC(15, 2) NOT NULL,
    improvement_pct NUMERIC(5, 2) GENERATED ALWAYS AS (((metric_after - metric_before) / NULLIF(metric_before, 0)) * 100) STORED,

    -- Qualitative
    qualitative_feedback TEXT,
    recommendation VARCHAR(20) CHECK (recommendation IN ('Adopt', 'Modify', 'Reject')),

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (pilot_id) REFERENCES cmmi.pilot_projects(pilot_id)
);

COMMENT ON TABLE cmmi.pilot_results IS 'Analyzes the outcome of pilot projects to decide on organizational rollout.';

-- =====================================================================================================================
-- Table: M18-T222 - org_process_metrics
-- Description: High-level organizational process performance.
-- Business Case: Executives need a dashboard of health. This table aggregates low-level metrics (Cycle Time, Defect Density)
--                 into Org-level KPIs. It simplifies reporting and highlights trends across the entire engineering organization.
-- KPIs: Productivity Index, Quality Index, Predictability Index, Organizational Velocity, Strategic Goal Alignment.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.org_process_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Calculation
    aggregation_method VARCHAR(50) CHECK (aggregation_method IN ('Average', 'Sum', 'WeightedAvg', 'Median')),
    target_value NUMERIC(15, 2),

    -- Data
    reporting_period DATE NOT NULL,
    actual_value NUMERIC(15, 2),
    variance_pct NUMERIC(5, 2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.org_process_metrics IS 'High-level aggregated metrics for executive dashboards.';
CREATE INDEX idx_org_metrics_period ON cmmi.org_process_metrics (reporting_period DESC);

-- =====================================================================================================================
-- Table: M18-T223 - quality_objectives
-- Description: Strategic Quality Objectives.
-- Business Case: W. Edwards Deming said "If you can't measure it, you can't improve it." This table sets strategic
--                 quality goals (e.g., "Achieve CMMI Level 5" or "Reduce Defect Escape to 0.05%"). It aligns
--                 engineering efforts with business strategy.
-- KPIs: Objective Progress, Objective Completion Time, Objective Alignment, Stretch Goal Achievement.
-- Feature Reference: M18-T224 (Quality Trend Analysis)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.quality_objectives (
    objective_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Measurement
    target_value NUMERIC(15, 2) NOT NULL,
    measurement_period VARCHAR(50), -- 'Quarterly', 'Annually'

    -- Ownership
    owner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Achieved', 'OnHold'

    start_date DATE NOT NULL,
    target_date DATE
);

COMMENT ON TABLE cmmi.quality_objectives IS 'Defines strategic quality goals for the engineering organization.';

-- =====================================================================================================================
-- Table: M18-T224 - quality_trend_analysis
-- Description: Trend data against quality objectives.
-- Business Case: Tracking trajectory. This table snapshots actual values against the targets set in Quality Objectives (T223).
--                 It visualizes whether the organization is improving, stagnating, or regressing over time.
-- KPIs: Trend Slope, Variance from Target, Consistency Score, Predictability, Alert Threshold Breach.
-- Feature Reference: M18-T223 (Quality Objectives)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.quality_trend_analysis (
    trend_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    objective_id UUID NOT NULL,

    -- Data
    date DATE NOT NULL,
    actual_value NUMERIC(15, 2) NOT NULL,
    target_value NUMERIC(15, 2),
    variance NUMERIC(15, 2),

    -- Trend
    moving_avg_3_periods NUMERIC(15, 2),

    FOREIGN KEY (objective_id) REFERENCES cmmi.quality_objectives(objective_id)
);

COMMENT ON TABLE cmmi.quality_trend_analysis IS 'Tracks historical performance data to visualize progress against strategic quality objectives.';
CREATE INDEX idx_quality_trend_objective ON cmmi.quality_trend_analysis (objective_id, date DESC);

-- =====================================================================================================================
-- Table: M18-T225 - audit_schedules
-- Description: Schedule of internal/external audits.
-- Business Case: Audits are inevitable. This table schedules upcoming audits (SOC2, ISO, PCI), assigning scope,
--                 auditors, and target dates. It triggers workflows for evidence collection (T165) well in advance
--                 to avoid last-minute panic.
-- KPIs: Audit Readiness Score, Audit On-Time Delivery, Audit Finding Severity, Preparation Duration.
-- Feature Reference: M18-T226 (Audit Reports)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Audit Details
    audit_type VARCHAR(50) NOT NULL, -- 'SOC2 Type II', 'ISO 27001'
    auditor_id UUID, -- Internal or External Firm ref
    target_date DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed'

    -- Scope
    scope_description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.audit_schedules IS 'Schedules and tracks preparations for compliance audits.';

-- =====================================================================================================================
-- Table: M18-T226 - audit_reports
-- Description: Final audit reports.
-- Business Case: The outcome. This table stores the final deliverables from auditors, including the rating (Pass/Fail),
--                 major non-conformities, and evidence of closure. It serves as the historical record for certification
--                 renewals.
-- KPIs: Pass Rate, Major Non-Conformity Count, Corrective Action Load, Auditor Satisfaction.
-- Feature Reference: M18-T225 (Audit Schedules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schedule_id UUID NOT NULL,

    -- Report Details
    findings_json JSONB NOT NULL,
    rating VARCHAR(20), -- 'Pass', 'Pass with Observations', 'Fail'

    -- Documents
    report_path TEXT,
    submitted_date DATE,

    FOREIGN KEY (schedule_id) REFERENCES cmmi.audit_schedules(schedule_id)
);

COMMENT ON TABLE cmmi.audit_reports IS 'Stores the final results and reports of compliance audits.';

-- =====================================================================================================================
-- Table: M18-T227 - compliance_gaps
-- Description: Identified gaps in compliance.
-- Business Case: The difference between "Where we are" and "Where we need to be". Compliance Gaps represent missing
--                 controls or evidence. This table logs these gaps, assigning severity and due dates for closure to maintain
--                 certification.
-- KPIs: Gap Count, Gap Age, Critical Gap %, Closure Rate, Gap Recurrence.
-- Feature Reference: M18-T228 (Gap Remediation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_gaps (
    gap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL, -- Link to T162
    control_id UUID NOT NULL, -- Link to T163

    -- Gap Details
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Closed'
    target_date DATE,

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id),
    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.compliance_gaps IS 'Identifies deficiencies in compliance controls that require remediation.';
CREATE INDEX idx_compliance_gaps_framework ON cmmi.compliance_gaps (framework_id);

-- =====================================================================================================================
-- Table: M18-T228 - gap_remediation
-- Description: Remediation plans for gaps.
-- Business Case: Closing the gap. This table manages the plan to fix compliance gaps (T227). It tracks the specific
--                 actions, owners, and evidence of proof, ensuring the auditor sees progress.
-- KPIs: Remediation Timeliness, Evidence Quality, Remediation Cost, Residual Risk.
-- Feature Reference: M18-T227 (Compliance Gaps)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gap_remediation (
    remediation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gap_id UUID NOT NULL,

    -- Action
    action_plan TEXT NOT NULL,
    owner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed'
    completed_date DATE,

    -- Evidence
    evidence_path TEXT,

    FOREIGN KEY (gap_id) REFERENCES cmmi.compliance_gaps(gap_id)
);

COMMENT ON TABLE cmmi.gap_remediation IS 'Manages the execution of plans to resolve compliance gaps.';
CREATE INDEX idx_gap_remediation_gap ON cmmi.gap_remediation (gap_id);

-- =====================================================================================================================
-- Table: M18-T229 - vendor_contract_terms
-- Description: Terms of vendor contracts related to SLA/Security.
-- Business Case: Managing vendor risk (T110) requires knowing what we signed for. This table extracts key terms (SLAs,
--                 security requirements, penalties) from vendor contracts. It is essential for enforcing accountability
--                 and calculating penalties (T232).
-- KPIs: Contract Coverage, SLA Terms vs. Reality, Penalty Enforced, Security Clause Compliance.
-- Feature Reference: M18-T230 (Vendor Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_contract_terms (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL, -- Link to T110

    -- Terms
    sla_terms TEXT, -- Detailed SLA description
    security_requirements TEXT,
    penalty_clause TEXT,

    -- Lifecycle
    start_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    is_active BOOLEAN DEFAULT true,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id) -- Note: T110 is 'vendor_risks' table in previous parts
);

COMMENT ON TABLE cmmi.vendor_contract_terms IS 'Tracks critical SLA and security terms in vendor contracts.';
CREATE INDEX idx_vendor_contract_vendor ON cmmi.vendor_contract_terms (vendor_id);

-- =====================================================================================================================
-- Table: M18-T230 - vendor_performance
-- Description: Vendor performance tracking.
-- Business Case: Vendors must be held to account. This table scores vendor performance against the terms (T229)
--                 across availability, quality, and cost. It drives decisions on contract renewal or termination.
-- KPIs: Vendor Availability Score, Quality Score, Cost Score, Overall Rating, SLA Breach %.
-- Feature Reference: M18-T110 (Vendor Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_performance (
    perf_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Metrics
    period VARCHAR(20) NOT NULL, -- 'Q1 2023'
    availability_score NUMERIC(3, 2),
    quality_score NUMERIC(3, 2),
    cost_score NUMERIC(3, 2),

    -- Outcome
    overall_score NUMERIC(3, 2),
    comments TEXT,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id)
);

COMMENT ON TABLE cmmi.vendor_performance IS 'Tracks quarterly scorecards for third-party vendors.';

-- =====================================================================================================================
-- Table: M18-T231 - sla_definitions
-- Description: Service Level Agreements (Internal/External).
-- Business Case: Defining "Good Service". This table stores SLA definitions for internal services (e.g., "API Latency < 200ms")
--                 and external vendors. It provides the target values for SLO error budget calculations (T049) and breach
--                 detection (T232).
-- KPIs: SLA Count, SLA Coverage, Breach Tolerance, Business Hours Configured.
-- Feature Reference: M18-T049 (SLO Error Budgets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_definitions (
    sla_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    metric VARCHAR(50) NOT NULL, -- 'latency', 'uptime', 'accuracy'

    -- The Agreement
    threshold NUMERIC(15, 2) NOT NULL,
    unit VARCHAR(20) NOT NULL, -- 'ms', '%'

    -- Window
    period_hours INTEGER NOT NULL, -- Rolling window (e.g., 24h, 30d)

    -- Penalties
    penalty_clause TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sla_definitions IS 'Stores agreed-upon service levels and penalties.';

-- =====================================================================================================================
-- Table: M18-T232 - sla_breaches
-- Description: Records of SLA breaches.
-- Business Case: When we fail the SLA. This table logs every instance where performance dipped below the threshold (T231).
--                 It is critical for financial reconciliation (penalties owed) and driving process improvements to reduce
--                 recurrence.
-- KPIs: Breach Count, Breach Severity (Duration), Breach Frequency, Financial Impact, MTTR per Breach.
-- Feature Reference: M18-T231 (SLA Definitions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_breaches (
    breach_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sla_id UUID NOT NULL,

    -- Details
    breach_date TIMESTAMP WITH TIME ZONE NOT NULL,
    actual_value NUMERIC(15, 2),
    threshold_value NUMERIC(15, 2),

    -- Impact
    duration_seconds INTEGER,
    financial_impact NUMERIC(15, 2),

    -- Analysis
    root_cause TEXT,

    FOREIGN KEY (sla_id) REFERENCES cmmi.sla_definitions(sla_id)
);

COMMENT ON TABLE cmmi.sla_breaches IS 'Logs failures to meet Service Level Agreements.';
CREATE INDEX idx_sla_breaches_sla ON cmmi.sla_breaches (sla_id, breach_date DESC);

-- =====================================================================================================================
-- Table: M18-T233 - capacity_plans
-- Description: Forward-looking capacity plans.
-- Business Case: Scaling proactively. This table documents forecasts for resource needs (Servers, Storage, Licenses)
--                 based on growth projections. It ensures infrastructure is procured and ready before traffic spikes.
-- KPIs: Forecast Accuracy, Capacity Headroom, Procurement Lead Time, Over-provisioning Waste, Under-provisioning Incidents.
-- Feature Reference: M18-T116 (Capacity Planning Recommender) - Plan storage
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.capacity_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    resource_type VARCHAR(50) NOT NULL, -- 'Compute', 'Storage', 'Bandwidth'
    forecasted_demand NUMERIC(15, 2),

    -- Action
    proposed_action TEXT NOT NULL, -- 'Purchase 50 servers', 'Upgrade 10Gbps'
    target_date DATE,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Approved', 'Procured'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.capacity_plans IS 'Stores strategic plans for infrastructure scaling.';

-- =====================================================================================================================
-- Table: M18-T234 - technology_radar
-- Description: Tracking emerging technologies.
-- Business Case: Innovation management. The "Technology Radar" helps the org decide what to Adopt, Trial, Assess, or Hold.
--                 This table tracks the status of technologies, providing a structured view of the tech landscape and
--                 guiding R&D investment.
-- KPIs: Radar Update Frequency, Adoption Success Rate, Tech Debt from Trial, Retrospective Accuracy.
-- Feature Reference: M18-T234 (Technology Radar) - Feature ID
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.technology_radar (
    tech_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(20) NOT NULL CHECK (category IN ('Adopt', 'Trial', 'Assess', 'Hold')),

    -- Justification
    rationale TEXT NOT NULL,

    -- Metadata
    date_added DATE NOT NULL,
    suggested_by UUID,
    quadrant VARCHAR(20) -- 'Tools', 'Languages', 'Frameworks', 'Platforms'
);

COMMENT ON TABLE cmmi.technology_radar IS 'Visualizes and manages the adoption status of emerging technologies.';
CREATE INDEX idx_tech_radar_category ON cmmi.technology_radar (category);

-- =====================================================================================================================
-- Table: M18-T235 - deprecation_notices
-- Description: Notices for deprecated libs/tools.
-- Business Case: Managing technical debt and security. When a library is deprecated (e.g., OpenSSL 1.0), it must be removed.
--                 This table tracks deprecation notices from libraries (T018) or tools, triggering remediation tickets.
-- KPIs: Deprecation Count, Remediation Speed, Compliance with Deprecation, Security Exposure Time.
-- Feature Reference: M18-T018 (Dependency Vulnerabilities)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.deprecation_notices (
    notice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),

    -- Dates
    deprecation_date DATE NOT NULL,
    end_of_life_date DATE,

    -- Action
    replacement_suggestion TEXT,
    jira_ticket_id VARCHAR(100), -- Link to work item

    status VARCHAR(20) DEFAULT 'Open'
);

COMMENT ON TABLE cmmi.deprecation_notices IS 'Alerts on upcoming end-of-life for software components.';
CREATE INDEX idx_deprecation_date ON cmmi.deprecation_notices (deprecation_date);

-- =====================================================================================================================
-- Table: M18-T236 - cost_allocation_rules
-- Description: Rules for allocating costs to cost centers.
-- Business Case: FinOps transparency. Cloud spend (T061) needs to be billed back to business units. This table defines
--                 the logic (e.g., "Tag 'Team:Payments' -> Cost Center 101") to automate monthly chargebacks (T237).
-- KPIs: Allocation Accuracy, Unallocated Cost %, Rule Complexity, Processing Time, Chargeback Dispute Rate.
-- Feature Reference: M18-T237 (Chargeback Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cost_allocation_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Matching Criteria
    tag_key VARCHAR(100) NOT NULL,
    tag_value VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50), -- Optional: 'EC2', 'S3'

    -- Allocation
    cost_center_id VARCHAR(50) NOT NULL,
    allocation_percentage NUMERIC(5, 2) CHECK (allocation_percentage > 0 AND allocation_percentage <= 100),

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cost_allocation_rules IS 'Defines logic for assigning cloud infrastructure costs to internal departments.';
CREATE INDEX idx_cost_allocation_tags ON cmmi.cost_allocation_rules (tag_key, tag_value);

-- =====================================================================================================================
-- Table: M18-T237 - chargeback_records
-- Description: Records of costs charged back to teams.
-- Business Case: Show me the money. This table generates monthly invoices for teams based on their cloud usage. It drives
--                 cost-aware behavior among developers.
-- KPIs: Bill Accuracy, Bill Generation Time, Payment Timeliness, Cost Reduction Post-Billing, Query Volume.
-- Feature Reference: M18-T236 (Cost Allocation Rules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.chargeback_records (
    charge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Billing Period
    cost_center_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Financials
    amount_usd NUMERIC(15, 2) NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Generated', -- 'Generated', 'Disputed', 'Paid'
    invoice_path TEXT,

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.chargeback_records IS 'Stores generated cost allocation reports for internal billing.';
CREATE INDEX idx_chargeback_center ON cmmi.chargeback_records (cost_center_id, period_start DESC);

-- =====================================================================================================================
-- Table: M18-T238 - carbon_emission_metrics
-- Description: Green IT metrics (CO2e).
-- Business Case: Sustainability is a KPI. This table estimates CO2 equivalent emissions based on compute usage and region
--                 (carbon intensity of the grid). It helps PARI achieve its "Green FinTech" goals.
-- KPIs: CO2e Emissions (kg), Emission Reduction Rate, Green Energy Usage %, Compute Efficiency (CO2 per $ revenue).
-- Feature Reference: M18-T239 (Sustainability Targets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.carbon_emission_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Context
    resource_id VARCHAR(100),
    region VARCHAR(50), -- Different regions have different carbon intensity

    -- Measurement
    emission_kg_co2e NUMERIC(15, 6) NOT NULL,
    energy_kwh NUMERIC(15, 6),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.carbon_emission_metrics IS 'Tracks environmental impact of cloud computing resources.';
CREATE INDEX idx_carbon_emissions_time ON cmmi.carbon_emission_metrics (timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T239 - sustainability_targets
-- Description: Green IT targets.
-- Business Case: Committing to improvement. This table sets targets for reducing carbon footprint (e.g., "Reduce emissions
--                 by 20% YoY"). It allows M18 to track progress against these environmental goals alongside engineering goals.
-- KPIs: Target Achievement %, Emission Trend, Offset Purchases, Renewable Energy Adoption.
-- Feature Reference: M18-T238 (Carbon Emission Metrics)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sustainability_targets (
    target_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    year INTEGER NOT NULL,

    -- Goal
    emission_target_kg NUMERIC(15, 2) NOT NULL,
    reduction_target_pct NUMERIC(5, 2),

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Achieved', 'Missed'

    owner_id UUID
);

COMMENT ON TABLE cmmi.sustainability_targets IS 'Defines and tracks organizational goals for environmental sustainability.';

-- =====================================================================================================================
-- Table: M18-T240 - security_incidents
-- Description: Detailed security incident records.
-- Business Case: Separate from Operational Incidents (T149), Security Incidents (Hacks, Data Leaks) require specific forensic
--                 workflows and legal reporting. This table details the nature of the breach, attacker methods, and data impact.
-- KPIs: Mean Time to Identify (MTTI), Mean Time to Contain (MTTC), Data Loss Quantity, Regulatory Notification Timeliness.
-- Feature Reference: M18-T143 (Brute Force Attack Detector) - Escalation
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.security_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    type VARCHAR(50) NOT NULL, -- 'Malware', 'Phishing', 'Insider', 'DDoS'
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Impact
    data_compromised BOOLEAN DEFAULT false,
    records_affected INTEGER,

    -- Lifecycle
    containment_status VARCHAR(20), -- 'Not Contained', 'Contaminated', 'Eradicated'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.security_incidents IS 'Detailed log of security breaches and cyber attacks.';
CREATE INDEX idx_security_incidents_severity ON cmmi.security_incidents (severity);
CREATE INDEX idx_security_incidents_type ON cmmi.security_incidents (type);

-- =====================================================================================================================
-- Table: M18-T241 - threat_model_reviews
-- Description: Reviews of threat models.
-- Business Case: Threat Models (T193) must be reviewed regularly. This table logs the approval process, ensuring that
--                 the threat landscape is re-evaluated and mitigations remain effective as the architecture evolves.
-- KPIs: Model Review Frequency, Reviewer Availability, Finding Accuracy, Model Completeness.
-- Feature Reference: M18-T193 (Threat Models)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.threat_model_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,

    -- Review
    reviewer_id UUID NOT NULL,
    findings TEXT,
    approval_status VARCHAR(20) NOT NULL, -- 'Approved', 'Rejected', 'Needs Revision'

    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (model_id) REFERENCES cmmi.threat_models(model_id)
);

COMMENT ON TABLE cmmi.threat_model_reviews IS 'Tracks approval reviews for threat model documents.';

-- =====================================================================================================================
-- Table: M18-T242 - pen_test_schedule
-- Description: Schedule of penetration tests.
-- Business Case: Continuous security validation. This table manages the recurring schedule of Pen Tests (T194), ensuring
--                 that critical assets are tested at mandated frequencies (e.g., Quarterly for external facing APIs).
-- KPIs: Test Adherence Rate, Test Coverage % (Assets), Delayed Test Count, Vendor Availability.
-- Feature Reference: M18-T194 (Pen Tests)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pen_test_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_scope TEXT NOT NULL, -- IP ranges, App names

    -- Timing
    frequency VARCHAR(50) NOT NULL, -- 'Quarterly', 'Annual', 'Ad-hoc'
    next_scheduled_date DATE NOT NULL,

    -- Execution
    tester_firm VARCHAR(255),
    status VARCHAR(20) DEFAULT 'Scheduled' -- 'Scheduled', 'In Progress', 'Completed', 'Cancelled'
);

COMMENT ON TABLE cmmi.pen_test_schedule IS 'Manages the calendar for recurring penetration testing exercises.';

-- =====================================================================================================================
-- Table: M18-T243 - compliance_mapping_matrix
-- Description: Mapping controls to laws/regs.
-- Business Case: One control, many laws. This table maps organizational controls (T163) to external regulations (GDPR Article 32,
--                 PCI-DSS Requirement 8). It simplifies compliance reporting by showing how a single test covers
--                 multiple legal obligations.
-- KPIs: Mapping Completeness, Control Reusability, Coverage per Regulation, Audit Preparation Time.
-- Feature Reference: M18-T164 (Control Mappings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_mapping_matrix (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Links
    regulation VARCHAR(100) NOT NULL, -- 'GDPR', 'PCI-DSS', 'SOX'
    requirement_text TEXT, -- The specific clause
    control_id UUID NOT NULL,

    -- Mapping Status
    mapping_status VARCHAR(20) DEFAULT 'Mapped', -- 'Mapped', 'Partial', 'Gap'

    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.compliance_mapping_matrix IS 'Connects internal controls to external legal and regulatory requirements.';

-- =====================================================================================================================
-- Table: M18-T244 - data_classification
-- Description: Classification of data assets.
-- Business Case: Data Governance. Not all data is equal. This table classifies assets (DB tables, S3 buckets) by sensitivity
--                 (Public, Internal, Confidential, Restricted). It drives encryption policies (T179) and access control
--                 enforcement.
-- KPIs: Asset Classification Coverage, Restricted Asset Count, Policy Violation Count, Re-classification Frequency.
-- Feature Reference: M18-T064 (PII Access Logs) - Context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_classification (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50), -- 'Database', 'File', 'API'

    -- Classification
    classification_level VARCHAR(20) NOT NULL CHECK (classification_level IN ('Public', 'Internal', 'Confidential', 'Restricted')),

    -- Governance
    owner_id UUID,
    retention_period_days INTEGER,

    last_reviewed DATE
);

COMMENT ON TABLE cmmi.data_classification IS 'Assigns sensitivity levels to data assets for security governance.';

-- =====================================================================================================================
-- Table: M18-T245 - privacy_impact_assessments
-- Description: DPIA records.
-- Business Case: GDPR requires Data Protection Impact Assessments (DPIA) for high-risk processing. This table tracks the
--                 lifecycle of DPIAs, documenting necessity, proportionality, and safeguards for data processing activities.
-- KPIs: DPIA Completion Rate, DPIA Findings, Risk Mitigation Score, Data Subject Rights Impact.
-- Feature Reference: M18-T064 (PII Access Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.privacy_impact_assessments (
    dpia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,

    -- Assessment
    assessed_by UUID NOT NULL,
    risk_score NUMERIC(5, 2), -- 0 to 100

    -- Details
    processing_purpose TEXT,
    safeguards TEXT,
    recommendation TEXT,

    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Approved', 'Rejected'
);

COMMENT ON TABLE cmmi.privacy_impact_assessments IS 'Documents Data Protection Impact Assessments required for compliance with GDPR.';

-- =====================================================================================================================
-- Table: M18-T246 - data_subject_requests
-- Description: GDPR DSAR tracking.
-- Business Case: The "Right to be Forgotten". This table manages workflow for Data Subject Access Requests (DSAR) and
--                 Erasure Requests. It tracks the clock (SLA) to respond and the actions taken (deletion logs from T064).
-- KPIs: Request Response Time (< 30 days), Request Volume, Erasure Verification Rate, Denied Request Count, Automation %.
-- Feature Reference: M18-T064 (PII Access Logs), M18-T081 (Right to be Forgotten)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_subject_requests (
    dsar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Requester
    requester_id UUID, -- Or external email
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('Access', 'Portability', 'Erasure', 'Rectification')),

    -- Workflow
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Processing', 'Completed', 'Rejected'
    received_date DATE NOT NULL,
    due_date DATE,

    -- Outcome
    completion_date DATE,
    notes TEXT
);

COMMENT ON TABLE cmmi.data_subject_requests IS 'Tracks Data Subject Access Rights (DSAR) workflows for privacy compliance.';
CREATE INDEX idx_dsar_status ON cmmi.data_subject_requests (status, due_date);

-- =====================================================================================================================
-- Table: M18-T247 - consent_logs
-- Description: Detailed audit of consents.
-- Business Case: Granular audit trail. While T065 tracks the state of consent, this table logs every event—Grant,
--                 Revoke, Withdraw. It provides the immutable proof required in case of legal disputes over data usage.
-- KPIs: Consent Volume, Withdrawal Rate, Consent Change Frequency, Audit Query Latency, Compliance Validity.
-- Feature Reference: M18-T065 (Consent Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.consent_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    consent_point VARCHAR(100) NOT NULL, -- e.g., 'Marketing', 'Analytics'

    -- Event
    action VARCHAR(20) NOT NULL CHECK (action IN ('Grant', 'Revoke', 'Withdraw')),

    -- Context
    ip_address INET,
    user_agent TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.consent_logs IS 'Immutable audit log of changes to user consent permissions.';
CREATE INDEX idx_consent_logs_user ON cmmi.consent_logs (user_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T248 - model_features
-- Description: Features used in ML models.
-- Business Case: Managing Model Lineage. This table defines the inputs (features) used by models. It is crucial for
--                 debugging model drift—if a feature becomes stale or distribution changes, the model performance degrades.
-- KPIs: Feature Count per Model, Feature Importance, Feature Staleness, Feature Drift, Missing Value %.
-- Feature Reference: M18-T068 (Training Data Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_features (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,

    -- Characteristics
    importance_score NUMERIC(5, 4),
    data_type VARCHAR(50), -- 'Numerical', 'Categorical', 'Text'

    -- Stats
    missing_value_strategy VARCHAR(50) -- 'Mean', 'Median', 'Drop'
);

COMMENT ON TABLE cmmi.model_features IS 'Catalogs input features and their relative importance for machine learning models.';
CREATE INDEX idx_model_features_model ON cmmi.model_features (model_id);

-- =====================================================================================================================
-- Table: M18-T249 - model_predictions
-- Description: Logged predictions for audit.
-- Business Case: Explainable AI and Auditability. For critical decisions (e.g., Fraud Decline), PARI must be able to
--                 explain why. This table logs the prediction, the input hash, and the outcome, allowing for historical
--                 analysis of model bias and accuracy.
-- KPIs: Prediction Volume, Prediction Latency, Explainability Score, Audit Retrieval Speed, Bias Alerts.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_predictions (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Input/Output
    input_data_hash CHAR(64), -- Fingerprint of input (PII redacted)
    output VARCHAR(100) NOT NULL,
    confidence NUMERIC(3, 2),

    -- Outcome
    actual_outcome VARCHAR(100), -- True label (delayed update)

    -- Audit
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_context VARCHAR(100) -- e.g., Merchant ID
);

COMMENT ON TABLE cmmi.model_predictions IS 'Logs predictions for audit and regulatory purposes.';

-- =====================================================================================================================
-- Table: M18-T250 - feature_importance_history
-- Description: History of feature importance changes.
-- Business Case: Detecting subtle drift. If the importance of a feature changes drastically (e.g., "Device Type" becomes
--                 top predictor), it indicates a shift in the underlying data distribution (Concept Drift). This table
--                 tracks feature importance over time to catch these shifts early.
-- KPIs: Importance Variance, Drift Detection Latency, Model Retraining Trigger, Feature Stability Score.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_importance_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_id UUID NOT NULL, -- Link to T248

    -- Data
    importance_score NUMERIC(5, 4) NOT NULL,
    training_run_id UUID NOT NULL, -- Link to T118

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (feature_id) REFERENCES cmmi.model_features(feature_id)
);

COMMENT ON TABLE cmmi.feature_importance_history IS 'Tracks changes in feature importance over time to detect model concept drift.';
CREATE INDEX idx_feature_importance_feature ON cmmi.feature_importance_history (feature_id, measured_at DESC);

-- =====================================================================================================================
-- Triggers for Timestamp Updates (Part 5 Tables)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_process_baselines
    BEFORE UPDATE ON cmmi.process_baselines
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_skill_inventory
    BEFORE UPDATE ON cmmi.skill_inventory
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_process_asset_library
    BEFORE UPDATE ON cmmi.process_asset_library
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_improvement_proposals
    BEFORE UPDATE ON cmmi.improvement_proposals
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_quality_trend_analysis
    BEFORE UPDATE ON cmmi.quality_trend_analysis
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_cost_allocation_rules
    BEFORE UPDATE ON cmmi.cost_allocation_rules
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_data_classification
    BEFORE UPDATE ON cmmi.data_classification
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 201-250)
-- =====================================================================================================================

-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 5
-- Tables DB201 - DB250
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T201 - process_baselines
-- Description: Historical baselines for process metrics.
-- Business Case: To measure improvement, one must know the starting point. This table stores snapshots of process
--                 baselines (e.g., "Average Cycle Time" or "Defect Density") over time. CMMI Level 5 requires
--                 quantitative management, which relies on comparing current performance against these historical baselines to
--                 calculate process capability and improvement trends. It prevents "moving the goalposts" by locking in
--                 performance targets for specific periods.
-- KPIs: Baseline Drift, Baseline Stability, Process Shifts, Re-calibration Frequency, Trend Validity.
-- Feature Reference: M18-F003 (Automated SPC Chart Generation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_baselines (
    baseline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(255) NOT NULL,

    -- Values
    baseline_value NUMERIC(18, 6) NOT NULL,
    variance_allowed NUMERIC(18, 6), -- Tolerance band

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE, -- NULL implies current

    -- Metadata
    established_by UUID,
    established_method VARCHAR(100), -- 'Historical Average', 'Industry Benchmark', 'Executive Target'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_baselines IS 'Stores historical performance baselines used for trend analysis and process control.';
CREATE INDEX idx_process_baselines_metric ON cmmi.process_baselines (metric_name, valid_from DESC);

-- =====================================================================================================================
-- Table: M18-T202 - sigma_levels
-- Description: Calculated Sigma levels (DPMO) for processes.
-- Business Case: Six Sigma is a standard for process quality. This table calculates and stores the Sigma level
--                 (1 to 6) and Defects Per Million Opportunities (DPMO) for critical processes (e.g., Payment Processing).
--                 It provides a single, universally understood metric to communicate engineering quality to executive
--                 stakeholders and compare against industry benchmarks.
-- KPIs: Process Sigma (Goal > 4.5), DPMO, Opportunities Count, Defect Count, Sigma Trend.
-- Feature Reference: M18-F019 (Process Capability Cpk Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sigma_levels (
    calculation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    process_name VARCHAR(100) NOT NULL,

    -- Calculations
    sigma_score NUMERIC(3, 2) NOT NULL CHECK (sigma_score >= 0 AND sigma_score <= 6),
    dpmo NUMERIC(12, 2) NOT NULL, -- Defects Per Million Opportunities

    -- Context
    calculation_date DATE NOT NULL DEFAULT CURRENT_DATE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    CONSTRAINT sigma_levels_check CHECK (sigma_score >= 0)
);

COMMENT ON TABLE cmmi.sigma_levels IS 'Stores Six Sigma calculations and DPMO metrics for process quality assessment.';
CREATE INDEX idx_sigma_levels_process ON cmmi.sigma_levels (process_name, calculation_date DESC);

-- =====================================================================================================================
-- Table: M18-T203 - training_catalog
-- Description: Catalog of available training courses.
-- Business Case: Addressing skill gaps (T044) requires a repository of learning content. This table defines the curriculum,
--                 linking courses to specific skills or compliance requirements. It tracks delivery modes (E-learning, Classroom)
--                 and duration, enabling managers to prescribe specific training to developers based on their performance
--                 data or quality incidents.
-- KPIs: Course Availability, Training Coverage of Skills, Completion Rate, Training Cost, Relevance Score.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_catalog (
    course_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Logistics
    duration_hours NUMERIC(5, 2),
    delivery_mode VARCHAR(50) CHECK (delivery_mode IN ('Online', 'Classroom', 'Workshop', 'Video')),
    difficulty_level VARCHAR(20) CHECK (difficulty_level IN ('Beginner', 'Intermediate', 'Advanced')),

    -- Compliance/Skill Link
    required_for VARCHAR(100)[], -- Array of skills or compliance frameworks
    is_mandatory BOOLEAN DEFAULT false,

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.training_catalog IS 'Defines available training courses and their learning objectives.';
CREATE INDEX idx_training_catalog_active ON cmmi.training_catalog (is_active);

-- =====================================================================================================================
-- Table: M18-T204 - training_records
-- Description: Records of training completed by staff.
-- Business Case: Compliance mandates proof of training (e.g., PCI-DSS awareness). This table tracks who took which course
--                 and when. It feeds into compliance reporting (T146) and ensures that developers have the prerequisites
--                 before being assigned to sensitive projects (e.g., Crypto modules).
-- KPIs: Training Compliance %, Training per Employee, Certification Expiry, Skill Gap Closure, Training Cost per Capita.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    course_id UUID NOT NULL,

    -- Completion
    completion_date DATE NOT NULL,
    score NUMERIC(5, 2), -- Pass mark
    status VARCHAR(20) DEFAULT 'Completed', -- 'Completed', 'Failed', 'InProgress'

    -- Certification
    certificate_url TEXT,
    expiry_date DATE,

    FOREIGN KEY (course_id) REFERENCES cmmi.training_catalog(course_id),
    CONSTRAINT training_records_unique UNIQUE (user_id, course_id, completion_date)
);

COMMENT ON TABLE cmmi.training_records IS 'Logs the training history and certifications of employees.';
CREATE INDEX idx_training_records_user ON cmmi.training_records (user_id, completion_date DESC);
CREATE INDEX idx_training_records_course ON cmmi.training_records (course_id);

-- =====================================================================================================================
-- Table: M18-T205 - skill_inventory
-- Description: Inventory of skills per user.
-- Business Case: Dynamic team assembly requires knowing who knows what. This table captures the proficiency level
--                 (1-5) of users for specific skills. It differs from training (T204) by being a self or peer-assessed
--                 inventory of *capability*, not just *courses taken*. It is crucial for optimizing team composition.
-- KPIs: Skill Proficiency Average, Skills per User, Skill Gap Severity, Expert Identification, Redundancy Count.
-- Feature Reference: M18-F046 (Skill Gap Analysis Engine)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.skill_inventory (
    inventory_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    skill_name VARCHAR(100) NOT NULL,

    -- Proficiency
    proficiency_level INTEGER CHECK (proficiency_level >= 1 AND proficiency_level <= 5),
    self_assessed BOOLEAN DEFAULT true,

    -- Verification
    last_verified_date DATE,
    verified_by UUID,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT skill_inventory_unique UNIQUE (user_id, skill_name)
);

COMMENT ON TABLE cmmi.skill_inventory IS 'Maps users to their specific skills and proficiency levels.';
CREATE INDEX idx_skill_inventory_user ON cmmi.skill_inventory (user_id);
CREATE INDEX idx_skill_inventory_skill ON cmmi.skill_inventory (skill_name);

-- =====================================================================================================================
-- Table: M18-T206 - process_asset_library
-- Description: Repository for process documents/templates.
-- Business Case: Standardization requires reusable assets. This table stores artifacts like templates, checklists, and
--                 guidelines. By versioning these assets, M18 ensures that everyone uses the latest approved process,
--                 reducing variation and errors caused by using outdated templates.
-- KPIs: Asset Usage Count, Asset Version Age, Template Adoption Rate, Search Success Rate, Asset Obsolescence.
-- Feature Reference: M18-F003 (Automated SPC Chart Generation) - Process definition aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_asset_library (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('Template', 'Guide', 'Policy', 'Checklist', 'Script')),

    -- Content
    version VARCHAR(20) NOT NULL,
    file_path TEXT,

    -- Lifecycle
    approval_status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Pending', 'Approved', 'Deprecated'
    approved_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_asset_library IS 'Manages the lifecycle of reusable process documents and templates.';
CREATE INDEX idx_process_asset_type ON cmmi.process_asset_library (type);

-- =====================================================================================================================
-- Table: M18-T207 - tailoring_guidelines
-- Description: Guidelines for tailoring standard processes.
-- Business Case: One size does not fit all. A small maintenance project needs less overhead than a new flagship feature.
--                 This table defines how the standard CMMI process can be tailored for different project types (e.g.,
--                 "Emergency fixes skip design review"). It ensures deviations are authorized and documented.
-- KPIs: Tailoring Exceptions, Compliance Risk from Tailoring, Project Type Coverage, Guideline Adherence.
-- Feature Reference: M18-T010 (Technical Debt Metrics) - Process Aspect
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tailoring_guidelines (
    guideline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_type VARCHAR(100) NOT NULL,

    -- Rules
    applicable_standards TEXT[], -- 'ISO 9001', 'CMMI Level 5'
    tailoring_options JSONB NOT NULL, -- {"design_review": "skipped", "unit_test_coverage": "80%"}

    -- Governance
    approval_required BOOLEAN DEFAULT true,
    authorized_by UUID,

    valid_from DATE NOT NULL,
    valid_to DATE
);

COMMENT ON TABLE cmmi.tailoring_guidelines IS 'Defines authorized deviations from standard processes based on project classification.';
CREATE INDEX idx_tailoring_guidelines_type ON cmmi.tailoring_guidelines (project_type);

-- =====================================================================================================================
-- Table: M18-T208 - checklist_templates
-- Description: Templates for review checklists.
-- Business Case: Checklists prevent cognitive lapses during reviews. This table defines the master templates for various
--                 activities (Code Review, Deployment, Risk Assessment). It ensures that mandatory steps are never skipped
--                 and facilitates consistency across different reviewers.
-- KPIs: Checklist Usage, Checklist Completion Rate, Defect Prevention Rate, Template Accuracy, Reviewer Compliance.
-- Feature Reference: M18-T209 (Checklist Instances)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.checklist_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    review_type VARCHAR(50) NOT NULL, -- 'CodeReview', 'DeployPrep', 'RCA'

    -- Content
    section_json JSONB NOT NULL, -- Structured list of items

    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.checklist_templates IS 'Defines standard checklist templates for quality gates and reviews.';

-- =====================================================================================================================
-- Table: M18-T209 - checklist_instances
-- Description: Usage of checklists in actual reviews.
-- Business Case: Templates (T208) are static; instances are the filled-out forms attached to real work. This table
--                 records the outcome of a checklist run (e.g., PR #123 Checklist), tracking which items passed, failed, or
--                 were N/A. It provides auditable proof of review rigor.
-- KPIs: Instance Pass Rate, Checklist Item Failure Frequency, Review Consistency, Time to Complete Checklist.
-- Feature Reference: M18-F011 (Peer Review Depth Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.checklist_instances (
    instance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    template_id UUID NOT NULL,
    pr_id VARCHAR(100), -- Or deployment_id, incident_id

    -- Execution
    item_json JSONB NOT NULL, -- [{"id": 1, "status": "Pass", "comment": "..."}]
    passed_flag BOOLEAN NOT NULL,

    -- User
    reviewer_id UUID,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (template_id) REFERENCES cmmi.checklist_templates(template_id)
);

COMMENT ON TABLE cmmi.checklist_instances IS 'Records the execution and results of checklist templates during reviews.';
CREATE INDEX idx_checklist_instances_pr ON cmmi.checklist_instances (pr_id);

-- =====================================================================================================================
-- Table: M18-T210 - gate_reviews
-- Description: Definition of Phase Gates.
-- Business Case: Phase gates (e.g., "Requirement Sign-off", "Ready for Test") control the progression of a project.
--                 This table defines the criteria for these gates. It ensures that a project cannot proceed to the next
--                 phase until quality and documentation standards are met.
-- KPIs: Gate Pass Rate, Gate Cycle Time, Critical Gate Blocking Count, Waiver Request Rate.
-- Feature Reference: M18-T211 (Gate Review Decisions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gate_reviews (
    gate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    phase_name VARCHAR(100) NOT NULL, -- 'Requirements', 'Design', 'Implementation'

    -- Criteria
    criteria_json JSONB NOT NULL, -- List of requirements
    approver_role VARCHAR(100) NOT NULL, -- Who must approve

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.gate_reviews IS 'Defines quality gate criteria for project phases.';

-- =====================================================================================================================
-- Table: M18-T211 - gate_review_decisions
-- Description: History of gate decisions.
-- Business Case: This table logs the outcome of Phase Gates (T210). It tracks whether a project Passed, Failed, or
--                 was granted a Conditional Pass (Waiver). This history is vital for analyzing which quality criteria
--                 are most frequently missed or waived.
-- KPIs: Gate Approval Latency, Fail Rate, Waiver Justification Quality, Gate Rejection Reason Distribution.
-- Feature Reference: M18-T210 (Gate Reviews)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gate_review_decisions (
    decision_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gate_id UUID NOT NULL,
    project_id UUID NOT NULL,

    -- Decision
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('Pass', 'Fail', 'ConditionalPass', 'Hold')),
    comments TEXT,

    -- People
    reviewer_id UUID NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (gate_id) REFERENCES cmmi.gate_reviews(gate_id)
);

COMMENT ON TABLE cmmi.gate_review_decisions IS 'Audits decisions made at project phase gates.';
CREATE INDEX idx_gate_decisions_project ON cmmi.gate_review_decisions (project_id);

-- =====================================================================================================================
-- Table: M18-T212 - corrective_actions
-- Description: Corrective Action Requests (CAR) from Causal Analysis.
-- Business Case: RCA (T012) is useless without action. This table manages the lifecycle of Corrective Actions, assigning
--                 owners and due dates. It ensures that systemic root causes (like "Lack of Crypto Training") are
--                 actually resolved to prevent recurrence.
-- KPIs: CAR Open Age, CAR Completion Rate, CAR Effectiveness, Overdue CARs, Recurrence of Root Cause.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.corrective_actions (
    car_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_incident_id UUID NOT NULL, -- Link to T149
    description TEXT NOT NULL,

    -- Assignment
    owner_id UUID NOT NULL,
    due_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Verified', 'Closed'

    -- Outcome
    effectiveness_rating INTEGER, -- 1-5 post-implementation

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.corrective_actions IS 'Tracks remediation steps for identified root causes of incidents.';
CREATE INDEX idx_corrective_actions_incident ON cmmi.corrective_actions (source_incident_id);
CREATE INDEX idx_corrective_actions_status ON cmmi.corrective_actions (status, due_date);

-- =====================================================================================================================
-- Table: M18-T213 - preventive_actions
-- Description: Preventive actions to stop future issues.
-- Business Case: Proactive risk management. While CARs react to incidents, Preventive Actions (PA) address risks
--                 (T199) before they materialize. This table tracks proactive measures (e.g., "Upgrade firewall firmware")
--                 to demonstrate due diligence.
-- KPIs: PA Completion Rate, Risk Mitigation %, PA vs Incident Correlation, Proactive Investment ROI.
-- Feature Reference: M18-T199 (Risk Registers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.preventive_actions (
    pa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id UUID NOT NULL, -- Link to T199
    description TEXT NOT NULL,

    -- Assignment
    owner_id UUID NOT NULL,
    target_date DATE NOT NULL,
    implementation_date DATE,

    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Implemented', 'Cancelled'

    FOREIGN KEY (risk_id) REFERENCES cmmi.risk_registers(risk_id)
);

COMMENT ON TABLE cmmi.preventive_actions IS 'Tracks proactive measures implemented to mitigate identified risks.';
CREATE INDEX idx_preventive_actions_risk ON cmmi.preventive_actions (risk_id);

-- =====================================================================================================================
-- Table: M18-T214 - lessons_learned
-- Description: Repository of lessons learned.
-- Business Case: Organizational memory. Lessons learned capture tacit knowledge from retrospectives (T031) or incidents (T149).
--                 Storing them in a searchable database prevents repeating the same mistakes across different teams.
-- KPIs: Lessons Logged, Lessons Applied, Search Usage, Knowledge Base Growth, Lesson Age.
-- Feature Reference: M18-T031 (Automated Retrospective Summarizer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.lessons_learned (
    lesson_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID,

    -- Content
    context TEXT NOT NULL,
    lesson_learned TEXT NOT NULL,
    impact TEXT,

    -- Metadata
    tags TEXT[],
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.lessons_learned IS 'Repository for organizational knowledge to prevent repeated mistakes.';
CREATE INDEX idx_lessons_learned_tags ON cmmi.lessons_learned USING GIN (tags);

-- =====================================================================================================================
-- Table: M18-T215 - best_practices
-- Description: Approved best practices for reuse.
-- Business Case: Standardization of excellence. Best practices are patterns that have been proven to work (e.g.,
--                 "Circuit Breaker Pattern for APIs"). This table vets and publishes these for general adoption,
--                 accelerating development and reducing architectural debt.
-- KPIs: Best Practice Adoption Count, Practice Effectiveness, Suggestion vs Adoption Ratio, Search Frequency.
-- Feature Reference: M18-T206 (Process Asset Library)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.best_practices (
    practice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain VARCHAR(100) NOT NULL, -- 'Security', 'Scalability', 'UX'
    description TEXT NOT NULL,

    -- Evidence
    evidence_url TEXT, -- Link to case study or doc
    adoption_count INTEGER DEFAULT 0,

    approved_by UUID,
    approved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.best_practices IS 'Catalogs proven patterns and techniques recommended for adoption.';
CREATE INDEX idx_best_practices_domain ON cmmi.best_practices (domain);

-- =====================================================================================================================
-- Table: M18-T216 - process_assessments
-- Description: Internal process assessments (e.g., SCAMPI).
-- Business Case: Verifying maturity level. CMMI requires periodic formal assessments (like SCAMPI B or C). This table
--                 schedules and stores results of these appraisals, providing the official "Maturity Level" rating
--                 used for marketing and internal governance.
-- KPIs: Maturity Level (Target 5), Assessment Frequency, Weakness Count, Strength Count, Appraisal Cost.
-- Feature Reference: M18-T217 (Assessment Findings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.process_assessments (
    assessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    scope VARCHAR(255) NOT NULL,
    maturity_level_target VARCHAR(20), -- 'Level 4', 'Level 5'

    -- Execution
    assessor_id UUID NOT NULL,
    date DATE NOT NULL,
    result VARCHAR(20), -- 'Achieved', 'Not Achieved', 'Lapsed'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.process_assessments IS 'Records formal appraisals of organizational process maturity.';

-- =====================================================================================================================
-- Table: M18-T217 - assessment_findings
-- Description: Findings from process assessments.
-- Business Case: The "Why" behind the Maturity Level. This table details specific Strengths and Weaknesses found
--                 during an assessment (T216). It forms the basis for the Process Improvement Plan (PIP).
-- KPIs: Finding Severity, Finding Resolution Rate, Weakness vs Strength Ratio, Recurring Findings.
-- Feature Reference: M18-T216 (Process Assessments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.assessment_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    assessment_id UUID NOT NULL,

    -- Details
    process_area VARCHAR(100) NOT NULL,
    strength_weakness VARCHAR(10) CHECK (strength_weakness IN ('Strength', 'Weakness')),
    recommendation TEXT,

    FOREIGN KEY (assessment_id) REFERENCES cmmi.process_assessments(assessment_id)
);

COMMENT ON TABLE cmmi.assessment_findings IS 'Stores detailed feedback from formal process maturity assessments.';
CREATE INDEX idx_assessment_findings_assessment ON cmmi.assessment_findings (assessment_id);

-- =====================================================================================================================
-- Table: M18-T218 - improvement_proposals
-- Description: Process Improvement Proposals (PIP).
-- Business Case: Continuous improvement requires ideas. PIPs capture suggestions from the floor (developers) on how
--                 to fix process pain points. This table manages the workflow of evaluating, approving, and scheduling
--                 these improvements.
-- KPIs: PIP Submission Rate, PIP Implementation Rate, Average Cycle Time, ROI of PIPs, Employee Engagement.
-- Feature Reference: M18-F153 (Innovation Time Tracking)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.improvement_proposals (
    pip_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    proposer_id UUID NOT NULL,

    -- Content
    title VARCHAR(255) NOT NULL,
    problem_statement TEXT NOT NULL,
    proposed_solution TEXT NOT NULL,

    -- Business Case
    estimated_cost NUMERIC(15, 2),
    estimated_benefit TEXT,

    -- Workflow
    status VARCHAR(20) DEFAULT 'Submitted', -- 'Submitted', 'Approved', 'Rejected', 'Implemented'
    priority VARCHAR(20),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.improvement_proposals IS 'Manages workflow for process improvement suggestions from staff.';
CREATE INDEX idx_pip_status ON cmmi.improvement_proposals (status);

-- =====================================================================================================================
-- Table: M18-T219 - pip_status_history
-- Description: Status tracking for PIPs.
-- Business Case: Audit trail for PIP decisions. This table tracks every transition a PIP goes through (Submitted ->
--                 Review -> Approved), providing visibility into how long ideas sit in the queue and who is blocking them.
-- KPIs: Time in State, Approval Chain Length, Rejection Reason Frequency, State Transition Speed.
-- Feature Reference: M18-T218 (Improvement Proposals)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pip_status_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pip_id UUID NOT NULL,

    old_status VARCHAR(20),
    new_status VARCHAR(20) NOT NULL,

    changed_by UUID,
    comments TEXT,

    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (pip_id) REFERENCES cmmi.improvement_proposals(pip_id)
);

COMMENT ON TABLE cmmi.pip_status_history IS 'Logs state transitions of Process Improvement Proposals.';
CREATE INDEX idx_pip_history_pip ON cmmi.pip_status_history (pip_id, changed_at DESC);

-- =====================================================================================================================
-- Table: M18-T220 - pilot_projects
-- Description: Pilot projects for testing new processes.
-- Business Case: Don't bet the farm on an unproven process. Before rolling out a PIP to the whole org, run a pilot.
--                 This table defines these experiments, tracking the hypothesis, scope, and expected outcomes.
-- KPIs: Pilot Success Rate, Pilot Duration, Findings per Pilot, Rollout Decision Rate.
-- Feature Reference: M18-T221 (Pilot Results)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pilot_projects (
    pilot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pip_id UUID NOT NULL, -- Link to proposal

    -- Details
    name VARCHAR(255) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE,

    -- Metrics
    baseline_metric NUMERIC(15, 2),
    target_metric NUMERIC(15, 2),

    status VARCHAR(20) DEFAULT 'Planned',

    FOREIGN KEY (pip_id) REFERENCES cmmi.improvement_proposals(pip_id)
);

COMMENT ON TABLE cmmi.pilot_projects IS 'Manages experimental trials for new process improvements before full rollout.';
CREATE INDEX idx_pilot_projects_pip ON cmmi.pilot_projects (pip_id);

-- =====================================================================================================================
-- Table: M18-T221 - pilot_results
-- Description: Results of pilot projects.
-- Business Case: Data-driven decisions on rollout. This table captures the actual results of the pilot (Metric Before/After)
--                 and qualitative feedback. It determines if the PIP should be adopted, modified, or scrapped.
-- KPIs: Metric Improvement %, Stakeholder Satisfaction, Pilot vs Production Variance, Recommendation Confidence.
-- Feature Reference: M18-T220 (Pilot Projects)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pilot_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pilot_id UUID NOT NULL,

    -- Metrics
    metric_before NUMERIC(15, 2) NOT NULL,
    metric_after NUMERIC(15, 2) NOT NULL,
    improvement_pct NUMERIC(5, 2) GENERATED ALWAYS AS (((metric_after - metric_before) / NULLIF(metric_before, 0)) * 100) STORED,

    -- Qualitative
    qualitative_feedback TEXT,
    recommendation VARCHAR(20) CHECK (recommendation IN ('Adopt', 'Modify', 'Reject')),

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (pilot_id) REFERENCES cmmi.pilot_projects(pilot_id)
);

COMMENT ON TABLE cmmi.pilot_results IS 'Analyzes the outcome of pilot projects to decide on organizational rollout.';

-- =====================================================================================================================
-- Table: M18-T222 - org_process_metrics
-- Description: High-level organizational process performance.
-- Business Case: Executives need a dashboard of health. This table aggregates low-level metrics (Cycle Time, Defect Density)
--                 into Org-level KPIs. It simplifies reporting and highlights trends across the entire engineering organization.
-- KPIs: Productivity Index, Quality Index, Predictability Index, Organizational Velocity, Strategic Goal Alignment.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.org_process_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Calculation
    aggregation_method VARCHAR(50) CHECK (aggregation_method IN ('Average', 'Sum', 'WeightedAvg', 'Median')),
    target_value NUMERIC(15, 2),

    -- Data
    reporting_period DATE NOT NULL,
    actual_value NUMERIC(15, 2),
    variance_pct NUMERIC(5, 2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.org_process_metrics IS 'High-level aggregated metrics for executive dashboards.';
CREATE INDEX idx_org_metrics_period ON cmmi.org_process_metrics (reporting_period DESC);

-- =====================================================================================================================
-- Table: M18-T223 - quality_objectives
-- Description: Strategic Quality Objectives.
-- Business Case: W. Edwards Deming said "If you can't measure it, you can't improve it." This table sets strategic
--                 quality goals (e.g., "Achieve CMMI Level 5" or "Reduce Defect Escape to 0.05%"). It aligns
--                 engineering efforts with business strategy.
-- KPIs: Objective Progress, Objective Completion Time, Objective Alignment, Stretch Goal Achievement.
-- Feature Reference: M18-T224 (Quality Trend Analysis)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.quality_objectives (
    objective_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Measurement
    target_value NUMERIC(15, 2) NOT NULL,
    measurement_period VARCHAR(50), -- 'Quarterly', 'Annually'

    -- Ownership
    owner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Achieved', 'OnHold'

    start_date DATE NOT NULL,
    target_date DATE
);

COMMENT ON TABLE cmmi.quality_objectives IS 'Defines strategic quality goals for the engineering organization.';

-- =====================================================================================================================
-- Table: M18-T224 - quality_trend_analysis
-- Description: Trend data against quality objectives.
-- Business Case: Tracking trajectory. This table snapshots actual values against the targets set in Quality Objectives (T223).
--                 It visualizes whether the organization is improving, stagnating, or regressing over time.
-- KPIs: Trend Slope, Variance from Target, Consistency Score, Predictability, Alert Threshold Breach.
-- Feature Reference: M18-T223 (Quality Objectives)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.quality_trend_analysis (
    trend_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    objective_id UUID NOT NULL,

    -- Data
    date DATE NOT NULL,
    actual_value NUMERIC(15, 2) NOT NULL,
    target_value NUMERIC(15, 2),
    variance NUMERIC(15, 2),

    -- Trend
    moving_avg_3_periods NUMERIC(15, 2),

    FOREIGN KEY (objective_id) REFERENCES cmmi.quality_objectives(objective_id)
);

COMMENT ON TABLE cmmi.quality_trend_analysis IS 'Tracks historical performance data to visualize progress against strategic quality objectives.';
CREATE INDEX idx_quality_trend_objective ON cmmi.quality_trend_analysis (objective_id, date DESC);

-- =====================================================================================================================
-- Table: M18-T225 - audit_schedules
-- Description: Schedule of internal/external audits.
-- Business Case: Audits are inevitable. This table schedules upcoming audits (SOC2, ISO, PCI), assigning scope,
--                 auditors, and target dates. It triggers workflows for evidence collection (T165) well in advance
--                 to avoid last-minute panic.
-- KPIs: Audit Readiness Score, Audit On-Time Delivery, Audit Finding Severity, Preparation Duration.
-- Feature Reference: M18-T226 (Audit Reports)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Audit Details
    audit_type VARCHAR(50) NOT NULL, -- 'SOC2 Type II', 'ISO 27001'
    auditor_id UUID, -- Internal or External Firm ref
    target_date DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed'

    -- Scope
    scope_description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.audit_schedules IS 'Schedules and tracks preparations for compliance audits.';

-- =====================================================================================================================
-- Table: M18-T226 - audit_reports
-- Description: Final audit reports.
-- Business Case: The outcome. This table stores the final deliverables from auditors, including the rating (Pass/Fail),
--                 major non-conformities, and evidence of closure. It serves as the historical record for certification
--                 renewals.
-- KPIs: Pass Rate, Major Non-Conformity Count, Corrective Action Load, Auditor Satisfaction.
-- Feature Reference: M18-T225 (Audit Schedules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.audit_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schedule_id UUID NOT NULL,

    -- Report Details
    findings_json JSONB NOT NULL,
    rating VARCHAR(20), -- 'Pass', 'Pass with Observations', 'Fail'

    -- Documents
    report_path TEXT,
    submitted_date DATE,

    FOREIGN KEY (schedule_id) REFERENCES cmmi.audit_schedules(schedule_id)
);

COMMENT ON TABLE cmmi.audit_reports IS 'Stores the final results and reports of compliance audits.';

-- =====================================================================================================================
-- Table: M18-T227 - compliance_gaps
-- Description: Identified gaps in compliance.
-- Business Case: The difference between "Where we are" and "Where we need to be". Compliance Gaps represent missing
--                 controls or evidence. This table logs these gaps, assigning severity and due dates for closure to maintain
--                 certification.
-- KPIs: Gap Count, Gap Age, Critical Gap %, Closure Rate, Gap Recurrence.
-- Feature Reference: M18-T228 (Gap Remediation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_gaps (
    gap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL, -- Link to T162
    control_id UUID NOT NULL, -- Link to T163

    -- Gap Details
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'In Progress', 'Closed'
    target_date DATE,

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id),
    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.compliance_gaps IS 'Identifies deficiencies in compliance controls that require remediation.';
CREATE INDEX idx_compliance_gaps_framework ON cmmi.compliance_gaps (framework_id);

-- =====================================================================================================================
-- Table: M18-T228 - gap_remediation
-- Description: Remediation plans for gaps.
-- Business Case: Closing the gap. This table manages the plan to fix compliance gaps (T227). It tracks the specific
--                 actions, owners, and evidence of proof, ensuring the auditor sees progress.
-- KPIs: Remediation Timeliness, Evidence Quality, Remediation Cost, Residual Risk.
-- Feature Reference: M18-T227 (Compliance Gaps)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.gap_remediation (
    remediation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    gap_id UUID NOT NULL,

    -- Action
    action_plan TEXT NOT NULL,
    owner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'In Progress', 'Completed'
    completed_date DATE,

    -- Evidence
    evidence_path TEXT,

    FOREIGN KEY (gap_id) REFERENCES cmmi.compliance_gaps(gap_id)
);

COMMENT ON TABLE cmmi.gap_remediation IS 'Manages the execution of plans to resolve compliance gaps.';
CREATE INDEX idx_gap_remediation_gap ON cmmi.gap_remediation (gap_id);

-- =====================================================================================================================
-- Table: M18-T229 - vendor_contract_terms
-- Description: Terms of vendor contracts related to SLA/Security.
-- Business Case: Managing vendor risk (T110) requires knowing what we signed for. This table extracts key terms (SLAs,
--                 security requirements, penalties) from vendor contracts. It is essential for enforcing accountability
--                 and calculating penalties (T232).
-- KPIs: Contract Coverage, SLA Terms vs. Reality, Penalty Enforced, Security Clause Compliance.
-- Feature Reference: M18-T230 (Vendor Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_contract_terms (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL, -- Link to T110

    -- Terms
    sla_terms TEXT, -- Detailed SLA description
    security_requirements TEXT,
    penalty_clause TEXT,

    -- Lifecycle
    start_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    is_active BOOLEAN DEFAULT true,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id) -- Note: T110 is 'vendor_risks' table in previous parts
);

COMMENT ON TABLE cmmi.vendor_contract_terms IS 'Tracks critical SLA and security terms in vendor contracts.';
CREATE INDEX idx_vendor_contract_vendor ON cmmi.vendor_contract_terms (vendor_id);

-- =====================================================================================================================
-- Table: M18-T230 - vendor_performance
-- Description: Vendor performance tracking.
-- Business Case: Vendors must be held to account. This table scores vendor performance against the terms (T229)
--                 across availability, quality, and cost. It drives decisions on contract renewal or termination.
-- KPIs: Vendor Availability Score, Quality Score, Cost Score, Overall Rating, SLA Breach %.
-- Feature Reference: M18-T110 (Vendor Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_performance (
    perf_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Metrics
    period VARCHAR(20) NOT NULL, -- 'Q1 2023'
    availability_score NUMERIC(3, 2),
    quality_score NUMERIC(3, 2),
    cost_score NUMERIC(3, 2),

    -- Outcome
    overall_score NUMERIC(3, 2),
    comments TEXT,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id)
);

COMMENT ON TABLE cmmi.vendor_performance IS 'Tracks quarterly scorecards for third-party vendors.';

-- =====================================================================================================================
-- Table: M18-T231 - sla_definitions
-- Description: Service Level Agreements (Internal/External).
-- Business Case: Defining "Good Service". This table stores SLA definitions for internal services (e.g., "API Latency < 200ms")
--                 and external vendors. It provides the target values for SLO error budget calculations (T049) and breach
--                 detection (T232).
-- KPIs: SLA Count, SLA Coverage, Breach Tolerance, Business Hours Configured.
-- Feature Reference: M18-T049 (SLO Error Budgets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_definitions (
    sla_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    metric VARCHAR(50) NOT NULL, -- 'latency', 'uptime', 'accuracy'

    -- The Agreement
    threshold NUMERIC(15, 2) NOT NULL,
    unit VARCHAR(20) NOT NULL, -- 'ms', '%'

    -- Window
    period_hours INTEGER NOT NULL, -- Rolling window (e.g., 24h, 30d)

    -- Penalties
    penalty_clause TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sla_definitions IS 'Stores agreed-upon service levels and penalties.';

-- =====================================================================================================================
-- Table: M18-T232 - sla_breaches
-- Description: Records of SLA breaches.
-- Business Case: When we fail the SLA. This table logs every instance where performance dipped below the threshold (T231).
--                 It is critical for financial reconciliation (penalties owed) and driving process improvements to reduce
--                 recurrence.
-- KPIs: Breach Count, Breach Severity (Duration), Breach Frequency, Financial Impact, MTTR per Breach.
-- Feature Reference: M18-T231 (SLA Definitions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_breaches (
    breach_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sla_id UUID NOT NULL,

    -- Details
    breach_date TIMESTAMP WITH TIME ZONE NOT NULL,
    actual_value NUMERIC(15, 2),
    threshold_value NUMERIC(15, 2),

    -- Impact
    duration_seconds INTEGER,
    financial_impact NUMERIC(15, 2),

    -- Analysis
    root_cause TEXT,

    FOREIGN KEY (sla_id) REFERENCES cmmi.sla_definitions(sla_id)
);

COMMENT ON TABLE cmmi.sla_breaches IS 'Logs failures to meet Service Level Agreements.';
CREATE INDEX idx_sla_breaches_sla ON cmmi.sla_breaches (sla_id, breach_date DESC);

-- =====================================================================================================================
-- Table: M18-T233 - capacity_plans
-- Description: Forward-looking capacity plans.
-- Business Case: Scaling proactively. This table documents forecasts for resource needs (Servers, Storage, Licenses)
--                 based on growth projections. It ensures infrastructure is procured and ready before traffic spikes.
-- KPIs: Forecast Accuracy, Capacity Headroom, Procurement Lead Time, Over-provisioning Waste, Under-provisioning Incidents.
-- Feature Reference: M18-T116 (Capacity Planning Recommender) - Plan storage
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.capacity_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    resource_type VARCHAR(50) NOT NULL, -- 'Compute', 'Storage', 'Bandwidth'
    forecasted_demand NUMERIC(15, 2),

    -- Action
    proposed_action TEXT NOT NULL, -- 'Purchase 50 servers', 'Upgrade 10Gbps'
    target_date DATE,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Approved', 'Procured'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.capacity_plans IS 'Stores strategic plans for infrastructure scaling.';

-- =====================================================================================================================
-- Table: M18-T234 - technology_radar
-- Description: Tracking emerging technologies.
-- Business Case: Innovation management. The "Technology Radar" helps the org decide what to Adopt, Trial, Assess, or Hold.
--                 This table tracks the status of technologies, providing a structured view of the tech landscape and
--                 guiding R&D investment.
-- KPIs: Radar Update Frequency, Adoption Success Rate, Tech Debt from Trial, Retrospective Accuracy.
-- Feature Reference: M18-T234 (Technology Radar) - Feature ID
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.technology_radar (
    tech_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(20) NOT NULL CHECK (category IN ('Adopt', 'Trial', 'Assess', 'Hold')),

    -- Justification
    rationale TEXT NOT NULL,

    -- Metadata
    date_added DATE NOT NULL,
    suggested_by UUID,
    quadrant VARCHAR(20) -- 'Tools', 'Languages', 'Frameworks', 'Platforms'
);

COMMENT ON TABLE cmmi.technology_radar IS 'Visualizes and manages the adoption status of emerging technologies.';
CREATE INDEX idx_tech_radar_category ON cmmi.technology_radar (category);

-- =====================================================================================================================
-- Table: M18-T235 - deprecation_notices
-- Description: Notices for deprecated libs/tools.
-- Business Case: Managing technical debt and security. When a library is deprecated (e.g., OpenSSL 1.0), it must be removed.
--                 This table tracks deprecation notices from libraries (T018) or tools, triggering remediation tickets.
-- KPIs: Deprecation Count, Remediation Speed, Compliance with Deprecation, Security Exposure Time.
-- Feature Reference: M18-T018 (Dependency Vulnerabilities)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.deprecation_notices (
    notice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(100),

    -- Dates
    deprecation_date DATE NOT NULL,
    end_of_life_date DATE,

    -- Action
    replacement_suggestion TEXT,
    jira_ticket_id VARCHAR(100), -- Link to work item

    status VARCHAR(20) DEFAULT 'Open'
);

COMMENT ON TABLE cmmi.deprecation_notices IS 'Alerts on upcoming end-of-life for software components.';
CREATE INDEX idx_deprecation_date ON cmmi.deprecation_notices (deprecation_date);

-- =====================================================================================================================
-- Table: M18-T236 - cost_allocation_rules
-- Description: Rules for allocating costs to cost centers.
-- Business Case: FinOps transparency. Cloud spend (T061) needs to be billed back to business units. This table defines
--                 the logic (e.g., "Tag 'Team:Payments' -> Cost Center 101") to automate monthly chargebacks (T237).
-- KPIs: Allocation Accuracy, Unallocated Cost %, Rule Complexity, Processing Time, Chargeback Dispute Rate.
-- Feature Reference: M18-T237 (Chargeback Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cost_allocation_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Matching Criteria
    tag_key VARCHAR(100) NOT NULL,
    tag_value VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50), -- Optional: 'EC2', 'S3'

    -- Allocation
    cost_center_id VARCHAR(50) NOT NULL,
    allocation_percentage NUMERIC(5, 2) CHECK (allocation_percentage > 0 AND allocation_percentage <= 100),

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cost_allocation_rules IS 'Defines logic for assigning cloud infrastructure costs to internal departments.';
CREATE INDEX idx_cost_allocation_tags ON cmmi.cost_allocation_rules (tag_key, tag_value);

-- =====================================================================================================================
-- Table: M18-T237 - chargeback_records
-- Description: Records of costs charged back to teams.
-- Business Case: Show me the money. This table generates monthly invoices for teams based on their cloud usage. It drives
--                 cost-aware behavior among developers.
-- KPIs: Bill Accuracy, Bill Generation Time, Payment Timeliness, Cost Reduction Post-Billing, Query Volume.
-- Feature Reference: M18-T236 (Cost Allocation Rules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.chargeback_records (
    charge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Billing Period
    cost_center_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Financials
    amount_usd NUMERIC(15, 2) NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Generated', -- 'Generated', 'Disputed', 'Paid'
    invoice_path TEXT,

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.chargeback_records IS 'Stores generated cost allocation reports for internal billing.';
CREATE INDEX idx_chargeback_center ON cmmi.chargeback_records (cost_center_id, period_start DESC);

-- =====================================================================================================================
-- Table: M18-T238 - carbon_emission_metrics
-- Description: Green IT metrics (CO2e).
-- Business Case: Sustainability is a KPI. This table estimates CO2 equivalent emissions based on compute usage and region
--                 (carbon intensity of the grid). It helps PARI achieve its "Green FinTech" goals.
-- KPIs: CO2e Emissions (kg), Emission Reduction Rate, Green Energy Usage %, Compute Efficiency (CO2 per $ revenue).
-- Feature Reference: M18-T239 (Sustainability Targets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.carbon_emission_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Context
    resource_id VARCHAR(100),
    region VARCHAR(50), -- Different regions have different carbon intensity

    -- Measurement
    emission_kg_co2e NUMERIC(15, 6) NOT NULL,
    energy_kwh NUMERIC(15, 6),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.carbon_emission_metrics IS 'Tracks environmental impact of cloud computing resources.';
CREATE INDEX idx_carbon_emissions_time ON cmmi.carbon_emission_metrics (timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T239 - sustainability_targets
-- Description: Green IT targets.
-- Business Case: Committing to improvement. This table sets targets for reducing carbon footprint (e.g., "Reduce emissions
--                 by 20% YoY"). It allows M18 to track progress against these environmental goals alongside engineering goals.
-- KPIs: Target Achievement %, Emission Trend, Offset Purchases, Renewable Energy Adoption.
-- Feature Reference: M18-T238 (Carbon Emission Metrics)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sustainability_targets (
    target_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    year INTEGER NOT NULL,

    -- Goal
    emission_target_kg NUMERIC(15, 2) NOT NULL,
    reduction_target_pct NUMERIC(5, 2),

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Achieved', 'Missed'

    owner_id UUID
);

COMMENT ON TABLE cmmi.sustainability_targets IS 'Defines and tracks organizational goals for environmental sustainability.';

-- =====================================================================================================================
-- Table: M18-T240 - security_incidents
-- Description: Detailed security incident records.
-- Business Case: Separate from Operational Incidents (T149), Security Incidents (Hacks, Data Leaks) require specific forensic
--                 workflows and legal reporting. This table details the nature of the breach, attacker methods, and data impact.
-- KPIs: Mean Time to Identify (MTTI), Mean Time to Contain (MTTC), Data Loss Quantity, Regulatory Notification Timeliness.
-- Feature Reference: M18-T143 (Brute Force Attack Detector) - Escalation
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.security_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    type VARCHAR(50) NOT NULL, -- 'Malware', 'Phishing', 'Insider', 'DDoS'
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Impact
    data_compromised BOOLEAN DEFAULT false,
    records_affected INTEGER,

    -- Lifecycle
    containment_status VARCHAR(20), -- 'Not Contained', 'Contaminated', 'Eradicated'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.security_incidents IS 'Detailed log of security breaches and cyber attacks.';
CREATE INDEX idx_security_incidents_severity ON cmmi.security_incidents (severity);
CREATE INDEX idx_security_incidents_type ON cmmi.security_incidents (type);

-- =====================================================================================================================
-- Table: M18-T241 - threat_model_reviews
-- Description: Reviews of threat models.
-- Business Case: Threat Models (T193) must be reviewed regularly. This table logs the approval process, ensuring that
--                 the threat landscape is re-evaluated and mitigations remain effective as the architecture evolves.
-- KPIs: Model Review Frequency, Reviewer Availability, Finding Accuracy, Model Completeness.
-- Feature Reference: M18-T193 (Threat Models)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.threat_model_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,

    -- Review
    reviewer_id UUID NOT NULL,
    findings TEXT,
    approval_status VARCHAR(20) NOT NULL, -- 'Approved', 'Rejected', 'Needs Revision'

    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (model_id) REFERENCES cmmi.threat_models(model_id)
);

COMMENT ON TABLE cmmi.threat_model_reviews IS 'Tracks approval reviews for threat model documents.';

-- =====================================================================================================================
-- Table: M18-T242 - pen_test_schedule
-- Description: Schedule of penetration tests.
-- Business Case: Continuous security validation. This table manages the recurring schedule of Pen Tests (T194), ensuring
--                 that critical assets are tested at mandated frequencies (e.g., Quarterly for external facing APIs).
-- KPIs: Test Adherence Rate, Test Coverage % (Assets), Delayed Test Count, Vendor Availability.
-- Feature Reference: M18-T194 (Pen Tests)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pen_test_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    target_scope TEXT NOT NULL, -- IP ranges, App names

    -- Timing
    frequency VARCHAR(50) NOT NULL, -- 'Quarterly', 'Annual', 'Ad-hoc'
    next_scheduled_date DATE NOT NULL,

    -- Execution
    tester_firm VARCHAR(255),
    status VARCHAR(20) DEFAULT 'Scheduled' -- 'Scheduled', 'In Progress', 'Completed', 'Cancelled'
);

COMMENT ON TABLE cmmi.pen_test_schedule IS 'Manages the calendar for recurring penetration testing exercises.';

-- =====================================================================================================================
-- Table: M18-T243 - compliance_mapping_matrix
-- Description: Mapping controls to laws/regs.
-- Business Case: One control, many laws. This table maps organizational controls (T163) to external regulations (GDPR Article 32,
--                 PCI-DSS Requirement 8). It simplifies compliance reporting by showing how a single test covers
--                 multiple legal obligations.
-- KPIs: Mapping Completeness, Control Reusability, Coverage per Regulation, Audit Preparation Time.
-- Feature Reference: M18-T164 (Control Mappings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_mapping_matrix (
    map_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Links
    regulation VARCHAR(100) NOT NULL, -- 'GDPR', 'PCI-DSS', 'SOX'
    requirement_text TEXT, -- The specific clause
    control_id UUID NOT NULL,

    -- Mapping Status
    mapping_status VARCHAR(20) DEFAULT 'Mapped', -- 'Mapped', 'Partial', 'Gap'

    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.compliance_mapping_matrix IS 'Connects internal controls to external legal and regulatory requirements.';

-- =====================================================================================================================
-- Table: M18-T244 - data_classification
-- Description: Classification of data assets.
-- Business Case: Data Governance. Not all data is equal. This table classifies assets (DB tables, S3 buckets) by sensitivity
--                 (Public, Internal, Confidential, Restricted). It drives encryption policies (T179) and access control
--                 enforcement.
-- KPIs: Asset Classification Coverage, Restricted Asset Count, Policy Violation Count, Re-classification Frequency.
-- Feature Reference: M18-T064 (PII Access Logs) - Context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_classification (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50), -- 'Database', 'File', 'API'

    -- Classification
    classification_level VARCHAR(20) NOT NULL CHECK (classification_level IN ('Public', 'Internal', 'Confidential', 'Restricted')),

    -- Governance
    owner_id UUID,
    retention_period_days INTEGER,

    last_reviewed DATE
);

COMMENT ON TABLE cmmi.data_classification IS 'Assigns sensitivity levels to data assets for security governance.';

-- =====================================================================================================================
-- Table: M18-T245 - privacy_impact_assessments
-- Description: DPIA records.
-- Business Case: GDPR requires Data Protection Impact Assessments (DPIA) for high-risk processing. This table tracks the
--                 lifecycle of DPIAs, documenting necessity, proportionality, and safeguards for data processing activities.
-- KPIs: DPIA Completion Rate, DPIA Findings, Risk Mitigation Score, Data Subject Rights Impact.
-- Feature Reference: M18-T064 (PII Access Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.privacy_impact_assessments (
    dpia_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,

    -- Assessment
    assessed_by UUID NOT NULL,
    risk_score NUMERIC(5, 2), -- 0 to 100

    -- Details
    processing_purpose TEXT,
    safeguards TEXT,
    recommendation TEXT,

    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Approved', 'Rejected'
);

COMMENT ON TABLE cmmi.privacy_impact_assessments IS 'Documents Data Protection Impact Assessments required for compliance with GDPR.';

-- =====================================================================================================================
-- Table: M18-T246 - data_subject_requests
-- Description: GDPR DSAR tracking.
-- Business Case: The "Right to be Forgotten". This table manages workflow for Data Subject Access Requests (DSAR) and
--                 Erasure Requests. It tracks the clock (SLA) to respond and the actions taken (deletion logs from T064).
-- KPIs: Request Response Time (< 30 days), Request Volume, Erasure Verification Rate, Denied Request Count, Automation %.
-- Feature Reference: M18-T064 (PII Access Logs), M18-T081 (Right to be Forgotten)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_subject_requests (
    dsar_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Requester
    requester_id UUID, -- Or external email
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('Access', 'Portability', 'Erasure', 'Rectification')),

    -- Workflow
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Processing', 'Completed', 'Rejected'
    received_date DATE NOT NULL,
    due_date DATE,

    -- Outcome
    completion_date DATE,
    notes TEXT
);

COMMENT ON TABLE cmmi.data_subject_requests IS 'Tracks Data Subject Access Rights (DSAR) workflows for privacy compliance.';
CREATE INDEX idx_dsar_status ON cmmi.data_subject_requests (status, due_date);

-- =====================================================================================================================
-- Table: M18-T247 - consent_logs
-- Description: Detailed audit of consents.
-- Business Case: Granular audit trail. While T065 tracks the state of consent, this table logs every event—Grant,
--                 Revoke, Withdraw. It provides the immutable proof required in case of legal disputes over data usage.
-- KPIs: Consent Volume, Withdrawal Rate, Consent Change Frequency, Audit Query Latency, Compliance Validity.
-- Feature Reference: M18-T065 (Consent Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.consent_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    consent_point VARCHAR(100) NOT NULL, -- e.g., 'Marketing', 'Analytics'

    -- Event
    action VARCHAR(20) NOT NULL CHECK (action IN ('Grant', 'Revoke', 'Withdraw')),

    -- Context
    ip_address INET,
    user_agent TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.consent_logs IS 'Immutable audit log of changes to user consent permissions.';
CREATE INDEX idx_consent_logs_user ON cmmi.consent_logs (user_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T248 - model_features
-- Description: Features used in ML models.
-- Business Case: Managing Model Lineage. This table defines the inputs (features) used by models. It is crucial for
--                 debugging model drift—if a feature becomes stale or distribution changes, the model performance degrades.
-- KPIs: Feature Count per Model, Feature Importance, Feature Staleness, Feature Drift, Missing Value %.
-- Feature Reference: M18-T068 (Training Data Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_features (
    feature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,

    -- Characteristics
    importance_score NUMERIC(5, 4),
    data_type VARCHAR(50), -- 'Numerical', 'Categorical', 'Text'

    -- Stats
    missing_value_strategy VARCHAR(50) -- 'Mean', 'Median', 'Drop'
);

COMMENT ON TABLE cmmi.model_features IS 'Catalogs input features and their relative importance for machine learning models.';
CREATE INDEX idx_model_features_model ON cmmi.model_features (model_id);

-- =====================================================================================================================
-- Table: M18-T249 - model_predictions
-- Description: Logged predictions for audit.
-- Business Case: Explainable AI and Auditability. For critical decisions (e.g., Fraud Decline), PARI must be able to
--                 explain why. This table logs the prediction, the input hash, and the outcome, allowing for historical
--                 analysis of model bias and accuracy.
-- KPIs: Prediction Volume, Prediction Latency, Explainability Score, Audit Retrieval Speed, Bias Alerts.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_predictions (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Input/Output
    input_data_hash CHAR(64), -- Fingerprint of input (PII redacted)
    output VARCHAR(100) NOT NULL,
    confidence NUMERIC(3, 2),

    -- Outcome
    actual_outcome VARCHAR(100), -- True label (delayed update)

    -- Audit
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_context VARCHAR(100) -- e.g., Merchant ID
);

COMMENT ON TABLE cmmi.model_predictions IS 'Logs predictions for audit and regulatory purposes.';

-- =====================================================================================================================
-- Table: M18-T250 - feature_importance_history
-- Description: History of feature importance changes.
-- Business Case: Detecting subtle drift. If the importance of a feature changes drastically (e.g., "Device Type" becomes
--                 top predictor), it indicates a shift in the underlying data distribution (Concept Drift). This table
--                 tracks feature importance over time to catch these shifts early.
-- KPIs: Importance Variance, Drift Detection Latency, Model Retraining Trigger, Feature Stability Score.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_importance_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_id UUID NOT NULL, -- Link to T248

    -- Data
    importance_score NUMERIC(5, 4) NOT NULL,
    training_run_id UUID NOT NULL, -- Link to T118

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (feature_id) REFERENCES cmmi.model_features(feature_id)
);

COMMENT ON TABLE cmmi.feature_importance_history IS 'Tracks changes in feature importance over time to detect model concept drift.';
CREATE INDEX idx_feature_importance_feature ON cmmi.feature_importance_history (feature_id, measured_at DESC);

-- =====================================================================================================================
-- Triggers for Timestamp Updates (Part 5 Tables)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_process_baselines
    BEFORE UPDATE ON cmmi.process_baselines
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_skill_inventory
    BEFORE UPDATE ON cmmi.skill_inventory
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_process_asset_library
    BEFORE UPDATE ON cmmi.process_asset_library
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_improvement_proposals
    BEFORE UPDATE ON cmmi.improvement_proposals
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_quality_trend_analysis
    BEFORE UPDATE ON cmmi.quality_trend_analysis
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_cost_allocation_rules
    BEFORE UPDATE ON cmmi.cost_allocation_rules
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_data_classification
    BEFORE UPDATE ON cmmi.data_classification
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 201-250)
-- =====================================================================================================================
-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 6
-- Tables DB251 - DB350
-- =====================================================================================================================

-- Note: Tables M18-T251 through M18-T280 are derived from the provided feature list.
-- Tables M18-T281 through M18-T350 are identified via Gap Analysis and Exhaustive Research to meet the requirement for Tables DB250-DB350,
-- covering Advanced ML Ops, Security Intelligence, Fintech Operations, and Organizational Governance.

-- =====================================================================================================================
-- Table: M18-T251 - retraining_triggers
-- Description: Events triggering model retraining.
-- Business Case: Model performance degrades over time due to concept drift or data changes. This table defines events or thresholds
--                 (e.g., "Accuracy drops below 90%", "New Data Detected") that trigger the automated retraining pipeline (M18-F087).
--                 Automating this trigger ensures models remain effective without constant manual monitoring, critical for fraud detection accuracy
--                 in the PARI ecosystem.
-- KPIs: Retraining Frequency, Trigger Accuracy, False Positive Retrains, Time from Trigger to Retrain, Model Stability Post-Retrain.
-- Feature Reference: M18-F084 (Model Drift Monitor), M18-F087 (Automated Hyperparameter Tuning)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.retraining_triggers (
    trigger_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Trigger Conditions
    trigger_type VARCHAR(50) NOT NULL CHECK (trigger_type IN ('Drift', 'AccuracyDrop', 'DataAvailability', 'Schedule')),
    threshold_value NUMERIC(10, 6),

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Paused', 'Triggered'
    last_triggered_at TIMESTAMP WITH TIME ZONE,

    -- Config
    priority INTEGER DEFAULT 5,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.retraining_triggers IS 'Defines conditions under which machine learning models are automatically queued for retraining.';

CREATE INDEX idx_retraining_model ON cmmi.retraining_triggers (model_id);
CREATE INDEX idx_retraining_status ON cmmi.retraining_triggers (status);

-- =====================================================================================================================
-- Table: M18-T252 - communication_logs
-- Description: Logs of notifications sent (Slack/Email).
-- Business Case: Stakeholders need timely alerts. This table logs the delivery of critical system messages (alerts, reports, approvals).
--                 It provides a detailed audit trail of who received what information and when, which is essential for incident reviews
--                 and confirming that notification channels (Slack, Email) are functioning correctly.
-- KPIs: Delivery Success Rate (>99.5%), Channel Latency, Failed Delivery Reasons, User Engagement (Click Rate), Notification Volume.
-- Feature Reference: M18-F155 (Notification Channels)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.communication_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    channel_id UUID NOT NULL, -- Ref T155

    -- Message
    recipient VARCHAR(255) NOT NULL, -- Email, User ID, or Channel Name
    subject TEXT,
    message_body TEXT,

    -- Status
    status VARCHAR(20) NOT NULL CHECK (status IN ('Sent', 'Delivered', 'Failed', 'Bounced')),
    error_message TEXT,

    -- Context
    correlation_id UUID, -- Link to Incident/Release
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.communication_logs IS 'Audit trail for outgoing notifications sent to users or systems.';

CREATE INDEX idx_comm_logs_channel ON cmmi.communication_logs (channel_id, sent_at DESC);
CREATE INDEX idx_comm_logs_status ON cmmi.communication_logs (status);

-- =====================================================================================================================
-- Table: M18-T253 - survey_questions
-- Description: Bank of questions for surveys.
-- Business Case: Standardizing data collection. This table defines the repository of questions used in surveys (T152, T254).
--                 Storing questions centrally allows for reuse across different survey types (Satisfaction, 360 review) and ensures consistency
--                 in data analysis over time.
-- KPIs: Question Usage Frequency, Response Rate per Question, Question Clarity Score, Category Coverage, Update Frequency.
-- Feature Reference: M18-F152 (Developer Satisfaction Survey)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.survey_questions (
    question_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    text TEXT NOT NULL,
    category VARCHAR(50) NOT NULL, -- 'Process', 'Tooling', 'Culture'
    scale_type VARCHAR(20) CHECK (scale_type IN ('Likert1-5', 'Likert1-10', 'YesNo', 'OpenText')),

    -- Metadata
    is_active BOOLEAN DEFAULT true,
    created_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.survey_questions IS 'Central repository of standardized questions for organizational surveys.';

-- =====================================================================================================================
-- Table: M18-T254 - survey_responses
-- Description: Individual responses to surveys.
-- Business Case: The raw data for sentiment analysis. This table stores every answer provided by a user to a survey question.
--                 It allows for granular analysis of trends (e.g., "Satisfaction with Tooling decreased in Q3") and correlation with
--                 other metrics (Defect Rate, Deployment Velocity).
-- KPIs: Survey Participation Rate, Response Completeness, Sentiment Trend, NPS Score, Correlation with Performance.
-- Feature Reference: M18-F152 (Developer Satisfaction Survey)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.survey_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    survey_id UUID NOT NULL, -- Ref T112
    user_id UUID NOT NULL,

    question_id UUID NOT NULL, -- Ref T253
    answer TEXT, -- String or Number stored as text for flexibility

    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (question_id) REFERENCES cmmi.survey_questions(question_id)
);

COMMENT ON TABLE cmmi.survey_responses IS 'Stores individual answers to survey questions for trend analysis.';

CREATE INDEX idx_survey_responses_survey ON cmmi.survey_responses (survey_id);
CREATE INDEX idx_survey_responses_user ON cmmi.survey_responses (user_id);

-- =====================================================================================================================
-- Table: M18-T255 - dashboard_subscriptions
-- Description: User subscriptions to dashboard updates.
-- Business Case: Pushing insights to stakeholders. Instead of users checking dashboards, they subscribe to updates. This table
--                 manages those subscriptions, determining when and how often a PDF report or dashboard snapshot is emailed to them.
-- KPIs: Subscription Count, Open Rate, Click-Through Rate, Unsubscribe Rate, Digest Engagement.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dashboard_subscriptions (
    sub_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dashboard_id UUID NOT NULL, -- Ref T187
    user_id UUID NOT NULL,

    -- Schedule
    frequency VARCHAR(20) NOT NULL CHECK (frequency IN ('Daily', 'Weekly', 'Monthly', 'OnTrigger')),

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_sent_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (dashboard_id) REFERENCES cmmi.dashboards(dashboard_id)
);

COMMENT ON TABLE cmmi.dashboard_subscriptions IS 'Manages user preferences for receiving automated dashboard updates.';

-- =====================================================================================================================
-- Table: M18-T256 - api_rate_limits
-- Description: Per-client rate limits.
-- Business Case: Fair usage and abuse prevention. While global throttling (T103) protects the system, client-specific limits
--                 (T256) enforce contract tiers (e.g., Gold vs Silver partners). This table enforces quotas per client ID.
-- KPIs: Limit Hits per Client, Limit Violations, Client Tier Compliance, Revenue per Tier, Limit Adjustment Frequency.
-- Feature Reference: M18-F103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_rate_limits (
    client_id VARCHAR(100) NOT NULL,
    endpoint_id VARCHAR(100),

    -- Limits
    requests_per_second INTEGER NOT NULL,
    window_seconds INTEGER DEFAULT 1,

    -- Metadata
    tier VARCHAR(20), -- 'Gold', 'Silver', 'Bronze'
    is_active BOOLEAN DEFAULT true,

    PRIMARY KEY (client_id, endpoint_id)
);

COMMENT ON TABLE cmmi.api_rate_limits IS 'Defines granular rate limits for specific API clients.';

-- =====================================================================================================================
-- Table: M18-T257 - quota_usage
-- Description: Usage of quotas per client.
-- Business Case: Tracking consumption. This table logs actual usage against the defined limits (T256), providing data
--                 for billing (based on usage overages) and detecting clients attempting to abuse their allocation.
-- KPIs: Quota Utilization (%), Overage Count, Usage Patterns, Denied Request Count, Billing Adjustment Events.
-- Feature Reference: M18-F103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.quota_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL,

    -- Metrics
    request_count BIGINT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.quota_usage IS 'Tracks actual API usage volume per client for quota enforcement and billing.';

CREATE INDEX idx_quota_usage_client ON cmmi.quota_usage (client_id, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T258 - geo_fencing_rules
-- Description: Rules for restricting access by region.
-- Business Case: Regulatory and security compliance. PARI might need to block access from sanctioned countries or restrict
--                 certain operations to specific regions (e.g., EU data only processed in EU). This table manages these geofencing rules.
-- KPIs: Blocked Requests per Region, Policy Violations, Legitimate User Impact, Rule Update Latency, Enforcement Accuracy.
-- Feature Reference: M18-F132 (GeoIP Traffic Distribution)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.geo_fencing_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Rule
    country_code CHAR(2) NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('Allow', 'Deny', 'Challenge')),
    service_name VARCHAR(100), -- Optional: Apply to specific service only

    -- Metadata
    reason TEXT, -- 'Sanctioned Country', 'GDPR Restriction'
    is_active BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.geo_fencing_rules IS 'Manages rules to block or allow traffic based on geographic origin.';

-- =====================================================================================================================
-- Table: M18-T259 - ip_reputations
-- Description: Reputation scores of IP addresses.
-- Business Case: Crowd-sourced security. This table aggregates reputation data (spam lists, botnets) for IP addresses.
--                 If an IP has a low reputation score, M18 can preemptively block it or force extra authentication before
--                 allowing a transaction.
-- KPIs: Low Reputation IP Count, Blocked Attack Volume, False Positive Rate, Reputation Source Accuracy, List Refresh Rate.
-- Feature Reference: M18-F143 (Brute Force Attack Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ip_reputations (
    ip_address INET PRIMARY KEY,

    -- Score
    reputation_score INTEGER NOT NULL CHECK (reputation_score >= 0 AND reputation_score <= 100),
    risk_level VARCHAR(20) GENERATED ALWAYS AS (
        CASE
            WHEN reputation_score < 20 THEN 'Critical'
            WHEN reputation_score < 50 THEN 'High'
            WHEN reputation_score < 80 THEN 'Medium'
            ELSE 'Low'
        END
    ) STORED,

    -- Sources
    sources TEXT[], -- ['SpamHaus', 'ProjectHoneypot', 'Internal']

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ip_reputations IS 'Caches reputation scores for IP addresses to identify malicious actors early.';

-- =====================================================================================================================
-- Table: M18-T260 - malware_signatures
-- Description: Known malware signatures/files.
-- Business Case: Scanning uploads. If PARI accepts file uploads (e.g., documents, invoices), this table stores
--                 hashes (MD5, SHA1) of known malware to block them instantly at the upload gateway.
-- KPIs: Malware Blocked Count, Signature Age, False Positive Block, Signature Update Latency, Upload Scan Time.
-- Feature Reference: M18-F024 (Security Policy Violation Auto-Check)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.malware_signatures (
    signature_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identification
    hash_md5 CHAR(32),
    hash_sha1 CHAR(40),
    threat_name VARCHAR(255),

    -- Classification
    malware_family VARCHAR(100),

    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.malware_signatures IS 'Stores file hashes of known malware for upload scanning.';

-- =====================================================================================================================
-- Table: M18-T261 - firewall_rules
-- Description: Configuration of firewall rules.
-- Business Case: Network security hygiene. This table stores the state of firewall rules (AWS Security Groups, On-prem Firewalls).
--                 Drift here (T102) is critical. It enables auditing of who allowed what traffic to where.
-- KPIs: Rule Count, Open Port Risk, Policy Violations, Change Frequency, Orphaned Rules.
-- Feature Reference: M18-F145 (WAF Rule Update Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.firewall_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Rule Def
    source VARCHAR(100), -- CIDR, IP, Tag
    destination VARCHAR(100),
    port VARCHAR(20),
    protocol VARCHAR(10),

    -- Action
    action VARCHAR(10) NOT NULL CHECK (action IN ('allow', 'deny')),

    -- Lifecycle
    rule_number INTEGER, -- Rule order priority
    enabled BOOLEAN DEFAULT true,

    changed_by UUID,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.firewall_rules IS 'Configures network firewall access control lists.';

-- =====================================================================================================================
-- Table: M18-T262 - firewall_audits
-- Description: Audit trail of firewall changes.
-- Business Case: Security compliance. Every change to a firewall rule (T261) creates a risk. This table logs the "Before"
--                 and "After" state and the authorizer, providing a forensic trail in case of a breach.
-- KPIs: Audit Completeness, Change Justification Capture, Risk Acceptance Rate, Approval Latency.
-- Feature Reference: M18-T261 (Firewall Rules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.firewall_audits (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL,

    -- Change
    change_type VARCHAR(20) NOT NULL, -- 'Created', 'Modified', 'Deleted'
    old_state JSONB,
    new_state JSONB,

    -- Approval
    changed_by UUID NOT NULL,
    approved_by UUID,

    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.firewall_audits IS 'Logs changes to firewall rules for security auditing.';

-- =====================================================================================================================
-- Table: M18-T263 - dns_blacklists
-- Description: Domains on DNS blacklists.
-- Business Case: Preventing C2 callbacks. This table contains lists of domains known to be malicious (Botnet Command & Control).
--                 DNS resolvers can use this to block resolution, preventing infected internal hosts from phoning home.
-- KPIs: Blocked Domains Count, List Freshness, Resolution Failure Count, False Positives.
-- Feature Reference: M18-F145 (WAF Rule Update Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dns_blacklists (
    list_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,

    -- Source
    source_feed VARCHAR(100), -- 'ThreatIntelligenceProvider'
    added_date DATE NOT NULL,

    is_active BOOLEAN DEFAULT true
);

COMMENT ON TABLE cmmi.dns_blacklists IS 'Aggregates known malicious domains for DNS filtering.';

-- =====================================================================================================================
-- Table: M18-T264 - backup_policies
-- Description: Policies for data backups.
-- Business Case: Data retention and RPO/RTO. This table defines what gets backed up, how often (Frequency), and where
--                 (Storage Class). It is the master configuration for the Backup Jobs (T265).
-- KPIs: Backup Compliance, RPO Achievement, Retention Adherence, Cost vs Policy, Coverage %.
-- Feature Reference: M18-F097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.backup_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL, -- 'Database', 'FileSystem', 'ObjectStorage'

    -- Scheduling
    frequency VARCHAR(50) NOT NULL, -- 'Hourly', 'Daily', 'Weekly'
    retention_days INTEGER NOT NULL,

    -- Storage
    storage_class VARCHAR(50), -- 'Glacier', 'Standard', 'ReducedRedundancy'
    region VARCHAR(50),

    is_active BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.backup_policies IS 'Defines the scope and retention settings for backup jobs.';

-- =====================================================================================================================
-- Table: M18-T265 - backup_jobs
-- Description: Execution of backup jobs.
-- Business Case: Operational execution. This table records the actual execution of the policies (T264). It tracks success/failure
--                 and size, ensuring that the "Safety Net" is actually being woven.
-- KPIs: Job Success Rate, Backup Duration, Storage Used, Missed Backups, Verification Status.
-- Feature Reference: M18-F097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.backup_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,

    -- Execution
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- 'Running', 'Success', 'Failed', 'Partial'

    -- Metrics
    size_gb NUMERIC(10, 2),
    duration_seconds INTEGER,

    FOREIGN KEY (policy_id) REFERENCES cmmi.backup_policies(policy_id)
);

COMMENT ON TABLE cmmi.backup_jobs IS 'Tracks the execution history of data backup processes.';

CREATE INDEX idx_backup_jobs_policy ON cmmi.backup_jobs (policy_id, start_time DESC);

-- =====================================================================================================================
-- Table: M18-T266 - restore_jobs
-- Description: Execution of restore jobs.
-- Business Case: The ultimate test of a backup. This table logs restore attempts (drills or real disasters).
--                 It tracks if a restore was successful and how long it took, validating RTO claims.
-- KPIs: Restore Success Rate, RTO Compliance, Restore Speed, Data Integrity Checks, Drill Frequency.
-- Feature Reference: M18-F097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.restore_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id UUID NOT NULL, -- Ref T076 or link to T265

    target_location TEXT NOT NULL,

    -- Execution
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- 'Running', 'Success', 'Failed'

    -- Integrity
    verification_checksum CHAR(64),

    FOREIGN KEY (backup_id) REFERENCES cmmi.backup_integrity(check_id)
);

COMMENT ON TABLE cmmi.restore_jobs IS 'Tracks the execution and verification of data restore operations.';

-- =====================================================================================================================
-- Table: M18-T267 - patch_management
-- Description: OS and application patch status.
-- Business Case: Vulnerability window. Unpatched systems are low-hanging fruit for attackers. This table tracks the patch status
--                 of all servers (OS level) and libraries (App level), prioritizing critical CVEs (T018).
-- KPIs: Patch Compliance %, Critical Patch Latency, Vulnerability Window, Out-of-Date Servers, Patch Failure Rate.
-- Feature Reference: M18-F018 (Dependency Vulnerability Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.patch_management (
    server_id VARCHAR(100) NOT NULL,
    patch_id VARCHAR(100) NOT NULL, -- CVE or Package Version

    -- Status
    current_version VARCHAR(50),
    target_version VARCHAR(50),

    installed_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Installed', 'Failed', 'Superseded'

    PRIMARY KEY (server_id, patch_id)
);

COMMENT ON TABLE cmmi.patch_management IS 'Tracks the application status of security and OS patches across infrastructure.';

CREATE INDEX idx_patch_management_status ON cmmi.patch_management (status);

-- =====================================================================================================================
-- Table: M18-T268 - vulnerability_scans
-- Description: Scheduled vulnerability scans.
-- Business Case: Continuous scanning. This table defines the schedule and scope of automated scans (T269), ensuring
--                 regular security health checks of the internal and external footprint.
-- KPIs: Scan Frequency, Scan Coverage % (Assets), Scan Duration, New Vuln Discovery Rate.
-- Feature Reference: M18-T017 (SAST Findings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vulnerability_scans (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    scan_type VARCHAR(50) NOT NULL, -- 'Network', 'Auth', 'App', 'Container'
    target VARCHAR(255) NOT NULL, -- IP Range, URL, Repo

    -- Schedule
    schedule VARCHAR(100), -- Cron or 'Ad-hoc'

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Running', 'Completed', 'Failed'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.vulnerability_scans IS 'Defines and tracks the execution of vulnerability assessment scans.';

-- =====================================================================================================================
-- Table: M18-T269 - scan_results
-- Description: Detailed results of scans.
-- Business Case: Triage and Remediation. This table stores the specific findings (Host, Port, CVE) from a scan (T268).
--                 It feeds into the Vulnerability (T195) and Remediation (T198) workflows.
-- KPIs: Vulns per Scan, Severity Distribution, False Positive % (after triage), Triage Time.
-- Feature Reference: M18-T017 (SAST Findings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.scan_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_id UUID NOT NULL,

    -- Finding
    hostname VARCHAR(255),
    ip_address INET,
    port INTEGER,
    vulnerability_id VARCHAR(100), -- CVE ID

    -- Context
    description TEXT,
    solution TEXT,

    FOREIGN KEY (scan_id) REFERENCES cmmi.vulnerability_scans(scan_id)
);

COMMENT ON TABLE cmmi.scan_results IS 'Stores detailed findings from vulnerability assessment scans.';

CREATE INDEX idx_scan_results_scan ON cmmi.scan_results (scan_id);
CREATE INDEX idx_scan_results_host ON cmmi.scan_results (hostname);

-- =====================================================================================================================
-- Table: M18-T270 - compliance_questionnaires
-- Description: Third-party questionnaires.
-- Business Case: Supply chain compliance. Vendors and partners must prove their security posture. This table manages the incoming
--                 questionnaires (e.g., CAIQ for Cloud), tracking receipt, assignment, and due dates.
-- KPIs: Questionnaire Response Time, Completion Rate, Vendor Risk Score from Questionnaire, Pending Questionnaires.
-- Feature Reference: M18-T150 (Vendor Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_questionnaires (
    questionnaire_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Details
    type VARCHAR(100) NOT NULL, -- 'CAIQ', 'SIG', 'Custom'
    received_date DATE NOT NULL,
    due_date DATE NOT NULL,

    -- Workflow
    status VARCHAR(20) DEFAULT 'Received', -- 'Received', 'In Progress', 'Submitted', 'Approved'

    assigned_to UUID,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id)
);

COMMENT ON TABLE cmmi.compliance_questionnaires IS 'Manages the lifecycle of third-party compliance assessment questionnaires.';

-- =====================================================================================================================
-- Table: M18-T271 - questionnaire_responses
-- Description: Responses to compliance questionnaires.
-- Business Case: Detail of evidence. This table stores the actual answers provided by the vendor in the questionnaire (T270).
--                 It creates a structured record of their security controls for auditor review.
-- KPIs: Evidence Completeness, Answer Accuracy (Spot Check), Review Time, Discrepancy Count.
-- Feature Reference: M18-T270 (Compliance Questionnaires)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.questionnaire_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    questionnaire_id UUID NOT NULL,

    question_ref VARCHAR(100) NOT NULL, -- ID or Text of question
    answer TEXT NOT NULL,
    evidence_link TEXT, -- URL to document

    FOREIGN KEY (questionnaire_id) REFERENCES cmmi.compliance_questionnaires(questionnaire_id)
);

COMMENT ON TABLE cmmi.questionnaire_responses IS 'Stores structured answers and evidence for compliance questionnaires.';

-- =====================================================================================================================
-- Table: M18-T272 - knowledge_base
-- Description: Organizational knowledge base.
-- Business Case: Avoiding rework. This table stores Wiki/KB articles (Runbooks, SOPs, Solutions). It centralizes tribal
--                 knowledge, making it searchable for new hires and during incidents.
-- KPIs: KB Article Count, Search Success Rate, Article Freshness, Contribution Rate, Readership.
-- Feature Reference: M18-T206 (Process Asset Library)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.knowledge_base (
    article_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Content
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    category VARCHAR(100),

    -- Metadata
    author_id UUID,
    tags TEXT[],

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID
);

COMMENT ON TABLE cmmi.knowledge_base IS 'Central repository for documentation and runbooks.';

CREATE INDEX idx_kb_tags ON cmmi.knowledge_base USING GIN (tags);
CREATE TRIGGER trigger_update_knowledge_base
    BEFORE UPDATE ON cmmi.knowledge_base
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Table: M18-T273 - kb_feedback
-- Description: User feedback on KB articles.
-- Business Case: Knowledge Quality Control. If a KB article is confusing or wrong, users flag it. This table tracks feedback
--                 to drive updates and ensure the knowledge base remains accurate and helpful.
-- KPIs: Helpful Rating (%), Flagged Article Count, Update Rate based on Feedback, User Engagement.
-- Feature Reference: M18-T272 (Knowledge Base)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.kb_feedback (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    article_id UUID NOT NULL,

    user_id UUID,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (article_id) REFERENCES cmmi.knowledge_base(article_id)
);

COMMENT ON TABLE cmmi.kb_feedback IS 'Captures user ratings and comments on knowledge base articles.';

-- =====================================================================================================================
-- Table: M18-T274 - code_refactors
-- Description: Tracking of code refactoring efforts.
-- Business Case: Paying down debt. Technical debt (T010) needs to be serviced. This table tracks refactoring tasks
--                 (T275 decisions), linking them to specific code files and measuring the improvement (complexity reduction).
-- KPIs: Refactoring Velocity, Complexity Reduction %, Regression Rate, Debt Paydown Ratio, Files Refactored.
-- Feature Reference: M18-F010 (Technical Debt Ratio Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.code_refactors (
    refactor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    file_path TEXT NOT NULL,
    reason VARCHAR(100), -- 'Complexity', 'DeadCode', 'Optimization'
    adr_id UUID, -- Link to Architecture Decision

    -- Metrics
    complexity_before INTEGER,
    complexity_after INTEGER,
    improvement_pct NUMERIC(5, 2),

    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (adr_id) REFERENCES cmmi.architecture_decisions(adr_id)
);

COMMENT ON TABLE cmmi.code_refactors IS 'Tracks specific refactoring tasks to reduce technical debt.';

-- =====================================================================================================================
-- Table: M18-T275 - architecture_decisions
-- Description: Architectural Decision Records (ADR).
-- Business Case: Documenting "Why". ADRs capture the context and consequences of major architectural choices.
--                 This table stores these records, ensuring future devs understand the tradeoffs made.
-- KPIs: ADR Creation Rate, ADR Consultation Rate, Obsolete ADR Count, Decision Reversal Frequency.
-- Feature Reference: M18-F034 (Architecture Compliance Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.architecture_decisions (
    adr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Content
    title VARCHAR(255) NOT NULL,
    context TEXT NOT NULL,
    decision TEXT NOT NULL,
    consequences TEXT NOT NULL,

    -- Metadata
    status VARCHAR(20) DEFAULT 'Proposed', -- 'Proposed', 'Accepted', 'Superseded', 'Rejected'
    date DATE NOT NULL,

    author_id UUID
);

COMMENT ON TABLE cmmi.architecture_decisions IS 'Stores Architectural Decision Records (ADRs) to document design rationale.';

-- =====================================================================================================================
-- Table: M18-T276 - tech_debt_payments
-- Description: Sprints dedicated to paying tech debt.
-- Business Case: Balancing feature work with maintenance. This table tracks the outcome of sprints specifically
--                 designated for "paying down debt" (T010), ensuring resources are actually allocated to this strategic goal.
-- KPIs: Debt Paid Down (Complexity Points), Debt Reduction Velocity, Bug Fix % during Debt Sprints, Planned vs Actual.
-- Feature Reference: M18-F010 (Technical Debt Ratio Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tech_debt_payments (
    payment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sprint_id VARCHAR(100) NOT NULL,

    -- Plan
    targeted_debt_score NUMERIC(10, 2),
    debt_items_addressed INTEGER,

    -- Result
    actual_score_reduction NUMERIC(10, 2),

    start_date DATE NOT NULL,
    end_date DATE NOT NULL
);

COMMENT ON TABLE cmmi.tech_debt_payments IS 'Tracks sprints dedicated to reducing technical debt.';

-- =====================================================================================================================
-- Table: M18-T277 - incident_postmortems
-- Description: Storage of postmortem documents.
-- Business Case: Learning from failure. This table links incidents (T149) to detailed postmortem documents, storing the
--                 timeline, root cause, and action items. It ensures that "Postmortem" isn't just a meeting but a recorded artifact.
-- KPIs: Postmortem Completion Time, Action Item Closure Rate, Postmortem Readability, Incident Recurrence Rate.
-- Feature Reference: M18-F012 (Automated 5-Why Root Cause Trigger)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.incident_postmortems (
    postmortem_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    -- Content
    document_url TEXT NOT NULL,
    summary TEXT,
    action_items JSONB, -- [{"task": "...", "owner": "..."}]

    -- Metadata
    author_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (incident_id) REFERENCES cmmi.incidents(incident_id)
);

COMMENT ON TABLE cmmi.incident_postmortems IS 'Stores detailed analysis and artifacts from incident postmortems.';

-- =====================================================================================================================
-- Table: M18-T278 - meeting_notes
-- Description: Notes from engineering meetings.
-- Business Case: Institutional Memory. Decisions made in meetings (T278) often get lost. This table stores notes and attendees,
--                 allowing for searchability and accountability for action items discussed.
-- KPIs: Meeting Note Volume, Action Item Capture Rate, Search Access, Note Completeness.
-- Feature Reference: M18-F047 (Meeting Load Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.meeting_notes (
    meeting_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    date TIMESTAMP WITH TIME ZONE NOT NULL,
    attendees TEXT[], -- List of User IDs or Names

    -- Content
    notes_url TEXT, -- Link to doc
    action_items TEXT,

    recorded_by UUID
);

COMMENT ON TABLE cmmi.meeting_notes IS 'Stores metadata and links to notes from engineering meetings.';

-- =====================================================================================================================
-- Table: M18-T279 - okrs
-- Description: Objectives and Key Results.
-- Business Case: Strategic alignment. OKRs (Objectives and Key Results) align individual/team goals with company strategy.
--                 This table manages the quarterly cadence of OKRs.
-- KPIs: OKR Achievement Rate, Key Result Progress, Alignment Score, Stretch Goal vs Committed.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.okrs (
    okr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Objective
    period VARCHAR(20) NOT NULL, -- 'Q1 2023'
    objective TEXT NOT NULL,

    -- Owner
    owner_id UUID,

    -- Status
    progress NUMERIC(5, 2) CHECK (progress >= 0 AND progress <= 100),
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Closed'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.okrs IS 'Manages Objectives and Key Results for strategic alignment.';

-- =====================================================================================================================
-- Table: M18-T280 - key_results
-- Description: Key results linked to OKRs.
-- Business Case: Measuring OKR success. This table breaks down an Objective (T279) into measurable Key Results, tracking
--                 their specific progress (Target vs Current).
-- KPIs: KR Completion, Confidence Level, KR Updates, Attainment Percentage.
-- Feature Reference: M18-T279 (OKRs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.key_results (
    kr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    okr_id UUID NOT NULL,

    -- Details
    description TEXT NOT NULL,
    target_value NUMERIC(10, 2),
    current_value NUMERIC(10, 2),

    -- Status
    progress NUMERIC(5, 2) GENERATED ALWAYS AS ((current_value / NULLIF(target_value, 1)) * 100) STORED,

    FOREIGN KEY (okr_id) REFERENCES cmmi.okrs(okr_id)
);

COMMENT ON TABLE cmmi.key_results IS 'Tracks measurable Key Results associated with strategic Objectives.';


-- =====================================================================================================================
-- GAP ANALYSIS & EXTENSIONS (Tables M18-T281 to M18-T350)
-- These tables were identified as necessary for a CMMI Level 5 system to bridge gaps in Advanced ML Ops,
-- Deep Security, Fintech Operations, and Organizational Governance.
-- =====================================================================================================================

-- =====================================================================================================================
-- Table: M18-T281 - model_shapley_values
-- Description: SHAP values for model explainability.
-- Business Case: Explainable AI (XAI). SHAP (SHapley Additive exPlanations) values explain the contribution of each feature to
--                 a specific prediction. In fintech, explaining why a loan or transaction was declined is often a regulatory requirement.
--                 This table stores these values for audit and compliance.
-- KPIs: Explainability Coverage, SHAP Calculation Latency, Feature Contribution Distribution, Compliance Explainability %.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_shapley_values (
    shap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prediction_id UUID NOT NULL, -- Ref T249

    feature_name VARCHAR(100) NOT NULL,
    shap_value NUMERIC(10, 6) NOT NULL,

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.model_shapley_values IS 'Stores SHAP values to explain individual model predictions.';

-- =====================================================================================================================
-- Table: M18-T290 - model_deployment_strategies
-- Description: Strategy for deploying ML models.
-- Business Case: Deployment risk management. This table defines *how* a model is deployed (Canary, Blue/Green, Shadow).
--                 It links the model ID (T118) to the deployment strategy parameters, ensuring the rollout is safe.
-- KPIs: Deployment Failure Rate, Rollback Frequency, Traffic Shift Success, Canary Accuracy.
-- Feature Reference: M18-T089 (Canary Release Automation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_deployment_strategies (
    strategy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    strategy_type VARCHAR(20) NOT NULL CHECK (strategy_type IN ('Canary', 'BlueGreen', 'Shadow', 'Full')),
    traffic_percentage INTEGER DEFAULT 100, -- For Canary
    environment VARCHAR(50) NOT NULL,

    status VARCHAR(20) DEFAULT 'Active'
);

COMMENT ON TABLE cmmi.model_deployment_strategies IS 'Defines the rollout strategy for machine learning models.';

-- =====================================================================================================================
-- Table: M18-T299 - saml_assertion_logs
-- Description: Logs of SAML SSO assertions.
-- Business Case: Identity federation audit. For SSO (Single Sign-On), this table logs every SAML assertion received,
--                 tracking user login times and attributes for security auditing and troubleshooting.
-- KPIs: Login Success Rate, SAML Validation Errors, IdP Latency, User Access Logs.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.saml_assertion_logs (
    assertion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    idp VARCHAR(100) NOT NULL, -- Identity Provider

    response_id VARCHAR(255), -- SAML Response ID
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attributes JSONB
);

COMMENT ON TABLE cmmi.saml_assertion_logs IS 'Audits SAML SSO assertions for security and compliance.';

-- =====================================================================================================================
-- Table: M18-T301 - payment_transaction_logs
-- Description: Core logs for payment transactions.
-- Business Case: The heart of PARI. This table logs every payment transaction for audit trails, reconciliation,
--                 and fraud detection. It is the primary source of truth for financial integrity.
-- KPIs: Transaction Volume, Success Rate, Latency, Fraud Rate, Reconciliation Match %.
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.payment_transaction_logs (
    transaction_id UUID PRIMARY KEY, -- Assume external ID or UUID
    amount NUMERIC(19, 4) NOT NULL,
    currency CHAR(3) NOT NULL,

    status VARCHAR(20) NOT NULL, -- 'Pending', 'Success', 'Failed', 'Reversed'

    source_account VARCHAR(100),
    destination_account VARCHAR(100),

    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Fraud/Security
    fraud_flag BOOLEAN DEFAULT false
);

COMMENT ON TABLE cmmi.payment_transaction_logs IS 'Core log of financial transactions processed by the system.';

-- =====================================================================================================================
-- Table: M18-T305 - fraud_detection_signals
-- Description: Signals generated by fraud models.
-- Business Case: Real-time fraud prevention. This table stores signals generated by fraud models (e.g., "High Velocity",
--                 "Device Fingerprint Mismatch") linked to transactions (T301). It feeds into review queues.
-- KPIs: Signal Accuracy, Fraud Detection Rate, False Positive Rate, Review Queue Depth, Manual Intervention %.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.fraud_detection_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    model_id VARCHAR(100) NOT NULL,
    signal_type VARCHAR(50) NOT NULL, -- 'Velocity', 'Geolocation', 'Identity'
    score NUMERIC(5, 2) NOT NULL,

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (transaction_id) REFERENCES cmmi.payment_transaction_logs(transaction_id)
);

COMMENT ON TABLE cmmi.fraud_detection_signals IS 'Stores fraud risk scores and signals for transactions.';

-- =====================================================================================================================
-- Table: M18-T311 - user_session_analytics
-- Description: Detailed analytics of user sessions.
-- Business Case: Product/UX improvement. This table tracks user journeys (clicks, time spent) to optimize the UI and
--                 identify friction points in the payment flow.
-- KPIs: Session Duration, Bounce Rate, Conversion Funnel Drop-off, Page Views, Error Rate per Session.
-- Feature Reference: M18-T156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.user_session_analytics (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,

    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    pages_visited INTEGER,
    errors_encountered INTEGER,

    conversion_flag BOOLEAN DEFAULT false
);

COMMENT ON TABLE cmmi.user_session_analytics IS 'Tracks detailed user behavior and session metrics.';

-- =====================================================================================================================
-- Table: M18-T321 - kubernetes_pod_metrics
-- Description: Metrics for K8s pods.
-- Business Case: Container orchestration health. This table stores granular metrics for K8s pods (CPU/Memory limits vs usage),
--                 used for autoscaling decisions (T117) and right-sizing recommendations.
-- KPIs: Pod Restart Count, Resource Limit Throttles, OOM Kills, Pod Availability, Density per Node.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.kubernetes_pod_metrics (
    pod_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pod_name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100) NOT NULL,

    cpu_limit_cores NUMERIC(5, 2),
    cpu_usage_cores NUMERIC(5, 2),
    memory_limit_mb INTEGER,
    memory_usage_mb INTEGER,

    restart_count INTEGER,
    phase VARCHAR(20), -- 'Pending', 'Running', 'Succeeded', 'Failed'

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.kubernetes_pod_metrics IS 'Granular resource metrics for Kubernetes pods.';

-- =====================================================================================================================
-- Table: M18-T331 - policy_version_history
-- Description: History of policy changes.
-- Business Case: Regulatory traceability. Compliance policies change. This table versions the policy documents (or rules),
--                 ensuring that we can prove which policy was in effect at the time of an audit or incident.
-- KPIs: Policy Change Frequency, Version Rollback Count, Policy Audit Trail, Governance Review Trigger.
-- Feature Reference: M18-T162 (Compliance Frameworks)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.policy_version_history (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id VARCHAR(100) NOT NULL, -- ID of the policy

    version_number INTEGER NOT NULL,
    policy_text TEXT,

    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
    effective_to TIMESTAMP WITH TIME ZONE, -- Null implies current

    approved_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.policy_version_history IS 'Tracks version history of governance and security policies.';

-- =====================================================================================================================
-- Table: M18-T332 - control_effectiveness_tests
-- Description: Tests of control effectiveness.
-- Business Case: Controls must work. This table records results of testing internal controls (e.g., "Does Access Control
--                 actually block unauthorized users?"). It moves beyond "implementation" to "verification".
-- KPIs: Control Pass Rate, Test Coverage, Gap Identification, Control Weakness Trends, Auditor Satisfaction.
-- Feature Reference: M18-T163 (Compliance Controls)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.control_effectiveness_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id UUID NOT NULL,

    test_method VARCHAR(50), -- 'Automated', 'Manual', 'PenTest'
    test_date DATE NOT NULL,

    result VARCHAR(20) NOT NULL, -- 'Effective', 'Partially Effective', 'Ineffective'
    findings TEXT,

    tested_by UUID,

    FOREIGN KEY (control_id) REFERENCES cmmi.compliance_controls(control_id)
);

COMMENT ON TABLE cmmi.control_effectiveness_tests IS 'Records results of testing the effectiveness of compliance controls.';

-- =====================================================================================================================
-- Table: M18-T341 - database_connection_pool_metrics
-- Description: Detailed metrics for DB connection pools.
-- Business Case: Database contention. Beyond basic usage (T078), this table tracks wait times, failed checkouts, and
--                 creation rates to tune connection pool settings (HikariCP, PgBouncer) for optimal throughput.
-- KPIs: Wait Time Avg, Failed Checkout Rate, Active Connection Peak, Pool Utilization %.
-- Feature Reference: M18-T099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.database_connection_pool_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,

    -- Detailed Metrics
    active_connections INTEGER,
    idle_connections INTEGER,
    waiting_threads INTEGER,

    -- Performance
    checkout_time_avg_ms NUMERIC(10, 2),
    checkout_time_max_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.database_connection_pool_metrics IS 'Detailed statistics on database connection pool performance.';

-- =====================================================================================================================
-- Table: M18-T346 - api_gateway_error_codes
-- Description: Aggregation of API Gateway error codes.
-- Business Case: Product reliability. This table aggregates errors by code (400, 401, 403, 404, 500) at the gateway level,
--                 identifying systemic issues (e.g., spike in 403s suggesting throttling or auth failures).
-- KPIs: Error Code Distribution, Error Rate Trend, Specific Endpoint Failure Rate, 5xx vs 4xx Ratio.
-- Feature Reference: M18-T124 (API Endpoints)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_gateway_error_codes (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id VARCHAR(100) NOT NULL,
    error_code INTEGER NOT NULL,

    count INTEGER NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.api_gateway_error_codes IS 'Aggregates error codes from the API gateway for reliability monitoring.';

-- =====================================================================================================================
-- Table: M18-T350 - system_announcements
-- Description: Admin announcements for users.
-- Business Case: Communication. This table stores announcements (Maintenance, Outage, Feature Launch) displayed to users
--                 within the application or portal.
-- KPIs: Announcement View Count, Announcement Click-through, Engagement Rate, Targeting Accuracy.
-- Feature Reference: M18-T156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.system_announcements (
    announcement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,

    -- Targeting
    target_audience TEXT[], -- ['admins', 'developers', 'all']
    severity VARCHAR(20) CHECK (severity IN ('Info', 'Warning', 'Critical')),

    -- Lifecycle
    publish_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN DEFAULT true,

    created_by UUID
);

COMMENT ON TABLE cmmi.system_announcements IS 'Manages announcements broadcasted to platform users.';

-- =====================================================================================================================
-- Triggers for Part 6 (T251-T350)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_retraining_triggers
    BEFORE UPDATE ON cmmi.retraining_triggers
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_knowledge_base
    BEFORE UPDATE ON cmmi.knowledge_base
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_api_rate_limits
    BEFORE UPDATE ON cmmi.api_rate_limits
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_vulnerability_scans
    BEFORE UPDATE ON cmmi.vulnerability_scans
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_compliance_questionnaires
    BEFORE UPDATE ON cmmi.compliance_questionnaires
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_okrs
    BEFORE UPDATE ON cmmi.okrs
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_system_announcements
    BEFORE UPDATE ON cmmi.system_announcements
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 251-350)
-- =====================================================================================================================

-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 7
-- Tables DB351 - DB450
-- =====================================================================================================================

-- Note: Tables M18-T351 through M18-T450 are derived from Gap Analysis and Exhaustive Research to cover
-- Advanced Supply Chain Security (SBOM), Fintech Operations (KYC/AML), Deep Database Observability,
-- Network Telemetry, and Advanced Governance required for Tables DB351-DB450.

-- =====================================================================================================================
-- Table: M18-T351 - sbom_entries
-- Description: Software Bill of Materials (SBOM) entries.
-- Business Case: Supply chain transparency is critical for security (Executive Order). This table stores granular components
--                 (libraries, modules) used in production artifacts. It links specific versions to Vulnerabilities (T018)
--                 and Licenses (T037), allowing for immediate identification of "Log4j" style risks across the fleet.
-- KPIs: SBOM Coverage %, Known Vuln in SBOM, License Compliance in SBOM, Component Age, SBOM Freshness.
-- Feature Reference: M18-F018 (Dependency Vulnerability Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sbom_entries (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identity
    purl VARCHAR(500) NOT NULL, -- Package URL (pkg:npm/react@16.0.0)
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,

    -- Integrity
    hash_sha256 CHAR(64),
    hash_sha1 CHAR(40),

    -- Source
    upstream_supplier VARCHAR(255), -- Vendor/Author
    download_location TEXT,

    -- Context
    artifact_id UUID, -- Link to specific build/release

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sbom_entries IS 'Inventory of software components (SBOM) for supply chain security transparency.';
CREATE INDEX idx_sbom_purl_version ON cmmi.sbom_entries (purl, version);
CREATE INDEX idx_sbom_component ON cmmi.sbom_entries (component_name);

-- =====================================================================================================================
-- Table: M18-T352 - sbom_vulnerabilities
-- Description: Links SBOM entries to specific vulnerabilities.
-- Business Case: Not all versions of a library are vulnerable. This table links a specific SBOM entry (T351) to
--                 a specific CVE (T018), confirming that the exact version running in PARI is affected by a known exploit.
-- KPIs: Affected Component Count, SBOM Scan Accuracy, Critical Vuln in Dependency, Remediation Trigger Rate.
-- Feature Reference: M18-F018 (Dependency Vulnerability Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sbom_vulnerabilities (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_entry_id UUID NOT NULL,
    cve_id VARCHAR(50) NOT NULL,

    -- Details
    severity VARCHAR(20) NOT NULL,
    published_date DATE,

    FOREIGN KEY (sbom_entry_id) REFERENCES cmmi.sbom_entries(entry_id)
);

COMMENT ON TABLE cmmi.sbom_vulnerabilities IS 'Maps specific component versions to known security vulnerabilities.';

CREATE INDEX idx_sbom_vulns_cve ON cmmi.sbom_vulnerabilities (cve_id);

-- =====================================================================================================================
-- Table: M18-T353 - service_mesh_topology
-- Description: Real-time snapshot of service mesh topology.
-- Business Case: Service Mesh (Istio/Linkerd) topology changes dynamically. This table stores a snapshot of services,
--                 endpoints, and their relationships, used for visualizing dependency graphs (T101) and identifying
--                 split-brain scenarios.
-- KPIs: Service Count, Endpoint Count, Topology Change Frequency, Mesh Health Score, Latency P95.
-- Feature Reference: M18-T101 (Dependency Graph)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.service_mesh_topology (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    service_name VARCHAR(100) NOT NULL,
    namespace VARCHAR(100) NOT NULL,

    -- Topology
    upstream_services TEXT[], -- Array of dependency names
    endpoint_ips TEXT[],

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.service_mesh_topology IS 'Stores snapshots of service mesh topology for visualization and analysis.';
CREATE INDEX idx_mesh_topology_service ON cmmi.service_mesh_topology (service_name);

-- =====================================================================================================================
-- Table: M18-T354 - feature_flags_metadata
-- Description: Advanced metadata for feature flags.
-- Business Case: Feature flags (T056) often have complex rules (percentage rollout, whitelist users). This table stores
--                 the configuration and rollout strategy metadata, enabling automated traffic shifting.
-- KPIs: Flag Complexity, Rollout Velocity, Whitelist Size, Kill Switch Usage, Flag Adoption Rate.
-- Feature Reference: M18-F063 (Feature Flag Adoption Tracker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_flags_metadata (
    flag_id UUID NOT NULL, -- Ref T056 (Composite key or FK)

    -- Strategy
    rollout_strategy VARCHAR(50) NOT NULL, -- 'Percentage', 'Whitelist', 'Gradual'
    rules_json JSONB NOT NULL, -- {"percentage": 10, "whitelist_users": [...]}

    -- Governance
    owner_email VARCHAR(255),
    expiration_action VARCHAR(20), -- 'RemoveFlag', 'Retain', 'Notify'

    -- Status
    stale BOOLEAN DEFAULT false,
    last_evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (flag_id)
);

COMMENT ON TABLE cmmi.feature_flags_metadata IS 'Stores detailed configuration and rollout strategies for feature flags.';
CREATE INDEX idx_flags_metadata_stale ON cmmi.feature_flags_metadata (stale) WHERE stale = true;

-- =====================================================================================================================
-- Table: M18-T355 - customer_journey_analytics
-- Description: Tracking of customer flows (Funnels).
-- Business Case: Optimizing conversion in Fintech apps. This table tracks user steps through flows (e.g., "Onboarding",
--                 "Add Money"), identifying drop-off points to optimize UI/UX.
-- KPIs: Conversion Rate per Step, Drop-off Rate, Journey Duration, Abandonment Reason, Funnel Leakage.
-- Feature Reference: M18-F064 (A/B Test Statistical Significance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.customer_journey_analytics (
    journey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    session_id UUID,

    -- Journey
    flow_name VARCHAR(100) NOT NULL, -- e.g., "KYC_Flow"
    step_name VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,

    -- Outcome
    status VARCHAR(20) NOT NULL, -- 'Entered', 'Completed', 'Dropped', 'Error'
    duration_seconds NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.customer_journey_analytics IS 'Tracks user steps through application flows to identify UX bottlenecks.';
CREATE INDEX idx_journey_flow ON cmmi.customer_journey_analytics (flow_name, user_id);

-- =====================================================================================================================
-- Table: M18-T356 - aml_screening_records
-- Description: Anti-Money Laundering screening results.
-- Business Case: Financial compliance. This table logs results of AML screening engines checking transactions against watchlists.
--                 It is critical for regulatory reporting (SARs - Suspicious Activity Reports).
-- KPIs: Screening Latency, Hit Rate, False Positive Rate, SAR Generation Time, Watchlist Coverage.
-- Feature Reference: M18-F083 (Algorithmic Bias Detector) - Fairness/Audit context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.aml_screening_records (
    screening_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL, -- Ref T301

    -- Screening
    provider VARCHAR(50), -- 'LexisNexis', 'ComplyAdvantage'
    watchlist_hit BOOLEAN NOT NULL,
    match_score NUMERIC(5, 2),

    -- Result
    action_taken VARCHAR(50), -- 'Pass', 'Block', 'ManualReview'
    sar_filed BOOLEAN DEFAULT false, -- Suspicious Activity Report

    screened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.aml_screening_records IS 'Logs AML screening results for financial transactions.';
CREATE INDEX idx_aml_transaction ON cmmi.aml_screening_records (transaction_id);
CREATE INDEX idx_aml_hit ON cmmi.aml_screening_records (watchlist_hit) WHERE watchlist_hit = true;

-- =====================================================================================================================
-- Table: M18-T357 - kyc_verification_records
-- Description: Know Your Customer (KYC) verification logs.
-- Business Case: Regulatory requirement for onboarding. This table tracks verification status of user identity documents,
--                 linking user ID to verification provider and outcome.
-- KPIs: Verification Success Rate, Verification Latency, Provider Failure Rate, Document Quality Score, Reject Reasons.
-- Feature Reference: M18-F145 (WAF Rule Update Automator) - Security context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.kyc_verification_records (
    verification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Verification
    provider VARCHAR(50) NOT NULL,
    document_type VARCHAR(50), -- 'Passport', 'DriversLicense', 'IDCard'

    -- Result
    status VARCHAR(20) NOT NULL, -- 'Pending', 'Verified', 'Rejected'
    confidence_score NUMERIC(3, 2),

    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at DATE
);

COMMENT ON TABLE cmmi.kyc_verification_records IS 'Tracks KYC verification lifecycle for user onboarding.';
CREATE INDEX idx_kyc_user ON cmmi.kyc_verification_records (user_id);

-- =====================================================================================================================
-- Table: M18-T358 - sanction_list_hits
-- Description: Matches against global sanction lists (OFAC, UN, EU).
-- Business Case: Preventing illegal transactions. This table logs when an entity (User or Merchant) matches a sanction
--                 list, triggering immediate compliance review or blocking.
-- KPIs: Sanction Hit Count, False Positive Rate, List Freshness, Blocking Accuracy, Resolution Time.
-- Feature Reference: M18-F145 (WAF Rule Update Automator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sanction_list_hits (
    hit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Matched Entity
    entity_type VARCHAR(20) NOT NULL, -- 'User', 'Merchant'
    entity_id UUID,
    matched_name TEXT,

    -- List Data
    list_name VARCHAR(100) NOT NULL, -- 'OFAC_SDN', 'UN_Consolidated'
    list_reference_id VARCHAR(100),

    -- Action
    action_taken VARCHAR(50) NOT NULL, -- 'Blocked', 'FlaggedForReview'

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sanction_list_hits IS 'Logs matches against global political and financial sanction lists.';
CREATE INDEX idx_sanction_entity ON cmmi.sanction_list_hits (entity_id);

-- =====================================================================================================================
-- Table: M18-T359 - ledger_integrity_hashes
-- Description: Hash chain for ledger integrity.
-- Business Case: Immutable audit trail. In Fintech, ensuring transaction logs haven't been tampered with is critical.
--                 This table stores cryptographic hashes of batches or blocks to detect篡改 (tampering).
-- KPIs: Hash Chain Integrity, Block Validation Time, Hash Computation Speed, Tamper Alerts, Chain Height.
-- Feature Reference: M18-T183 (Assets) - Ledger Context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ledger_integrity_hashes (
    hash_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Chain
    block_height BIGINT NOT NULL,
    previous_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL,

    -- Content
    data_range_start TIMESTAMP WITH TIME ZONE,
    data_range_end TIMESTAMP WITH TIME ZONE,

    -- Validation
    is_valid BOOLEAN DEFAULT true,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ledger_integrity_hashes IS 'Stores cryptographic hash chain for verifying ledger immutability.';
CREATE INDEX idx_ledger_height ON cmmi.ledger_integrity_hashes (block_height DESC);

-- =====================================================================================================================
-- Table: M18-T360 - settlement_batch_jobs
-- Description: Batching of payment settlements.
-- Business Case: Efficient clearing. Payments are often settled in batches (e.g., to banks). This table tracks
--                 the lifecycle of these settlement jobs, ensuring reconciliation and auditing of fund movement.
-- KPIs: Settlement Latency, Batch Success Rate, Reconciliation Variance, Batch Size Optimization, Banking Partner Response Time.
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.settlement_batch_jobs (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Batch Definition
    batch_reference VARCHAR(100) NOT NULL, -- External Ref
    payment_count INTEGER NOT NULL,
    total_amount NUMERIC(19, 4) NOT NULL,
    currency CHAR(3) NOT NULL,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Submitted', 'Accepted', 'Rejected'
    submitted_at TIMESTAMP WITH TIME ZONE,
    settled_at TIMESTAMP WITH TIME ZONE,

    -- Partner
    partner_bank VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.settlement_batch_jobs IS 'Tracks batch processing of payment settlements to banking partners.';
CREATE INDEX idx_settlement_status ON cmmi.settlement_batch_jobs (status);
CREATE INDEX idx_settlement_ref ON cmmi.settlement_batch_jobs (batch_reference);

-- =====================================================================================================================
-- Table: M18-T361 - regulatory_reporting_runs
-- Description: Specific runs of regulatory reports (e.g., SAR, STR).
-- Business Case: Fintech reporting. Regulators require specific formats (e.g., FinCEN 114, STR). This table logs
--                 generation and submission of these reports, tracking status (Draft, Filed, Accepted).
-- KPIs: Reporting Accuracy, Submission Latency, Reject Rate, Data Completeness, Automation %.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.regulatory_reporting_runs (
    report_run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_type VARCHAR(50) NOT NULL, -- 'SAR', 'CTR', 'STR'

    -- Scope
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Generated', -- 'Generated', 'Filed', 'Accepted', 'Rejected'
    filing_reference VARCHAR(100), -- Ack number from regulator

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    filed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.regulatory_reporting_runs IS 'Tracks generation and submission of mandatory regulatory reports.';
CREATE INDEX idx_reg_report_type ON cmmi.regulatory_reporting_runs (report_type, period_end DESC);

-- =====================================================================================================================
-- Table: M18-T362 - data_retention_schedules
-- Description: Schedules for data deletion/archival.
-- Business Case: GDPR/Privacy "Right to be Forgotten" and minimization. This table defines retention schedules for
--                 different data types (Transactions, Logs, Profiles), triggering automated archival or deletion (T011).
-- KPIs: Retention Compliance, Data Volume Reduction, Deletion Accuracy, Archive Retrieval Success.
-- Feature Reference: M18-F096 (Log Retention Policy Enforcer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_retention_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    data_type VARCHAR(100) NOT NULL, -- 'TransactionLogs', 'UserProfiles', 'PIIData'

    -- Policy
    retention_period_days INTEGER NOT NULL,
    archival_action VARCHAR(50), -- 'Delete', 'ArchiveToColdStorage'

    -- Status
    last_run_date DATE,
    next_run_date DATE,

    is_active BOOLEAN DEFAULT true
);

COMMENT ON TABLE cmmi.data_retention_schedules IS 'Defines data lifecycle policies for compliance and storage management.';

-- =====================================================================================================================
-- Table: M18-T363 - employee_offboarding
-- Description: Checklist and status for employee offboarding.
-- Business Case: Security perimeter management. When employees leave, access must be revoked systematically. This table
--                 tracks the offboarding checklist (Git access, DB access, Tokens), ensuring no zombie accounts remain.
-- KPIs: Offboarding Completion Time, Access Revocation Speed, Asset Recovery Rate, Checklist Adherence.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.employee_offboarding (
    offboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Timeline
    last_day DATE NOT NULL,

    -- Checklist
    git_access_revoked BOOLEAN DEFAULT false,
    db_access_revoked BOOLEAN DEFAULT false,
    tokens_revoked BOOLEAN DEFAULT false,
    assets_returned BOOLEAN DEFAULT false,

    -- Status
    status VARCHAR(20) DEFAULT 'InProgress', -- 'InProgress', 'Completed'

    completed_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.employee_offboarding IS 'Manages the security checklist for departing employees.';
CREATE INDEX idx_offboard_user ON cmmi.employee_offboarding (user_id);

-- =====================================================================================================================
-- Table: M18-T364 - third_party_api_usage
-- Description: Detailed usage stats for external APIs.
-- Business Case: Managing external costs and limits. This table tracks usage of paid APIs (e.g., Credit Checks, Tax Validation)
--                 at a granular level, informing budget planning (T237) and vendor negotiations.
-- KPIs: API Call Volume, Cost per Call, Success Rate, Latency vs. Cost, Budget Utilization.
-- Feature Reference: M18-F060 (Third-Party API Latency Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.third_party_api_usage (
    usage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_name VARCHAR(100) NOT NULL,

    -- Usage
    call_count BIGINT NOT NULL,
    cost_usd NUMERIC(15, 4),

    -- Metrics
    avg_latency_ms NUMERIC(10, 2),
    error_rate NUMERIC(5, 2),

    period_start DATE NOT NULL,
    period_end DATE NOT NULL
);

COMMENT ON TABLE cmmi.third_party_api_usage IS 'Tracks usage and cost metrics for external third-party APIs.';

-- =====================================================================================================================
-- Table: M18-T365 - microservice_choreography
-- Description: Detailed dependency and latency matrix.
-- Business Case: Understanding service interaction beyond topology. This table stores latency metrics between specific
--                 pairs of services, identifying slow communication paths (Service A -> Service B).
-- KPIs: Inter-service Latency P95, Critical Path Latency, Hotspot Identification, Dependency Coupling.
-- Feature Reference: M18-T101 (Dependency Graph)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.microservice_choreography (
    choreo_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    caller_service VARCHAR(100) NOT NULL,
    callee_service VARCHAR(100) NOT NULL,

    -- Metrics
    latency_p50 NUMERIC(10, 2),
    latency_p95 NUMERIC(10, 2),
    error_rate NUMERIC(5, 2),
    request_rate NUMERIC(10, 2), -- RPS

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.microservice_choreography IS 'Detailed performance matrix between microservice pairs.';

CREATE INDEX idx_choreo_pair ON cmmi.microservice_choreography (caller_service, callee_service);

-- =====================================================================================================================
-- Table: M18-T366 - chaos_engineering_scenarios
-- Description: Library of chaos experiment scenarios.
-- Business Case: Reusable failure modes. This table defines templates for chaos experiments (e.g., "Kill Pod",
--                 "Inject Latency") so they can be easily executed via M18-T071.
-- KPIs: Scenario Coverage, Execution Frequency, Fault Impact Score, Scenario Complexity.
-- Feature Reference: M18-F091 (Chaos Engineering Integration)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.chaos_engineering_scenarios (
    scenario_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Definition
    fault_type VARCHAR(50) NOT NULL, -- 'PodKill', 'Latency', 'DiskFull'
    parameters JSONB NOT NULL, -- {"latency_ms": 5000}

    -- Classification
    severity VARCHAR(20),
    blast_radius TEXT, -- e.g., "payments-service"

    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.chaos_engineering_scenarios IS 'Library of templates for chaos engineering experiments.';

-- =====================================================================================================================
-- Table: M18-T367 - git_commit_signatures
-- Description: Verification of signed git commits.
-- Business Case: Supply chain integrity. Ensuring that code is signed and verified prevents injection of malicious code.
--                 This table logs signature validation results for every commit.
-- KPIs: Signature Coverage, Validity Rate, Key Expiry Issues, Signing Key ID.
-- Feature Reference: M18-T146 (Commits)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.git_commit_signatures (
    commit_id UUID PRIMARY KEY, -- Ref T146

    -- Signature
    signing_key_id VARCHAR(100),
    signature_status VARCHAR(20) NOT NULL, -- 'Valid', 'Invalid', 'Missing', 'Expired'

    -- Details
    signer_name TEXT,
    signature_date TIMESTAMP WITH TIME ZONE,

    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.git_commit_signatures IS 'Tracks GPG signature validation for git commits.';

-- =====================================================================================================================
-- Table: M18-T368 - code_ownership_history
-- Description: Historical tracking of code ownership.
-- Business Case: "Bus Factor" analysis over time. This table snapshots code ownership (who touched what file most recently)
--                 to create a time-series of risk, identifying periods where critical code became siloed.
-- KPIs: Ownership Turnover Rate, Bus Factor Trends, Concentration History, Team Expansion Impact.
-- Feature Reference: M18-F049 (Code Ownership Distribution)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.code_ownership_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_path TEXT NOT NULL,

    -- Snapshot
    primary_owner_id UUID,
    bus_factor INTEGER,
    ownership_concentration NUMERIC(3, 2),

    snapshot_date DATE NOT NULL
);

COMMENT ON TABLE cmmi.code_ownership_history IS 'Historical time-series of code ownership to track bus factor evolution.';
CREATE INDEX idx_ownership_history_path ON cmmi.code_ownership_history (file_path, snapshot_date DESC);

-- =====================================================================================================================
-- Table: M18-T369 - deployment_rollback_history
-- Description: Complete history of rollback actions.
-- Business Case: Learning from failure. This table logs detailed reasoning and execution of rollbacks (T021, T139),
--                 providing data to analyze "What went wrong?" and improve deployment strategies.
-- KPIs: Rollback Frequency, Rollback Success, Root Cause Categories, Time-to-Recovery (Rollback).
-- Feature Reference: M18-F090 (Blue-Green Deployment Manager)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.deployment_rollback_history (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL, -- Ref T027

    -- Context
    reason_code VARCHAR(50) NOT NULL, -- 'LatencySpike', 'ErrorRate', 'DataCorruption'
    description TEXT,

    -- Execution
    triggered_by UUID, -- 'System' or User
    execution_time_seconds INTEGER,
    success BOOLEAN NOT NULL,

    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.deployment_rollback_history IS 'Detailed audit trail of deployment rollbacks.';

-- =====================================================================================================================
-- Table: M18-T370 - sli_error_budget_details
-- Description: Granular breakdown of error budget consumption.
-- Business Case: "Where did the budget go?". While T049 tracks current status, this table logs individual
--                 "burn" events (e.g., "5 mins of outage due to DB latency") to attribute budget loss to specific causes.
-- KPIs: Burn Rate per Cause, Budget Recovery Rate, Burn Event Frequency, Critical Incident Impact.
-- Feature Reference: M18-F051 (Latency SLO Error Budget Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sli_error_budget_details (
    burn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_name VARCHAR(100) NOT NULL,

    -- Event
    incident_id UUID, -- Ref T149
    cause_category VARCHAR(100), -- 'Database', 'Network', 'Deployment'

    -- Consumption
    budget_burned_minutes NUMERIC(10, 2) NOT NULL,
    budget_remaining_minutes NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sli_error_budget_details IS 'Logs individual events that consume SLO error budgets.';
CREATE INDEX idx_slo_burn_slo ON cmmi.sli_error_budget_details (slo_name, timestamp DESC);

-- =====================================================================================================================
-- Table: M18-T371 - latency_distribution_histograms
-- Description: Detailed histograms of request latency.
-- Business Case: Tail latency analysis. Knowing P95 is good, but knowing the whole distribution curve is better.
--                 This table stores histogram buckets (e.g., 0-10ms: 100 reqs, 10-20ms: 50 reqs) for deep analysis.
-- KPIs: Tail Latency Percent, Distribution Mode, Skewness, Kurtosis, P99.9.
-- Feature Reference: M18-F051 (Latency SLO Error Budget Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.latency_distribution_histograms (
    histogram_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,

    -- Buckets
    bucket_min_ms INTEGER NOT NULL,
    bucket_max_ms INTEGER NOT NULL,
    request_count BIGINT NOT NULL,

    sampled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.latency_distribution_histograms IS 'Stores detailed latency histograms for tail latency analysis.';
CREATE INDEX idx_latency_hist_service ON cmmi.latency_distribution_histograms (service_name, sampled_at DESC);

-- =====================================================================================================================
-- Table: M18-T372 - throughput_metrics
-- Description: Requests per second (RPS/TPS) metrics.
-- Business Case: Capacity planning requires knowing max throughput. This table tracks sustained RPS/TPS per service,
--                 used for sizing (T117) and detecting throughput drops (DDoS or upstream issues).
-- KPIs: Max Throughput, Avg Throughput, Throughput Variance, Saturation %.
-- Feature Reference: M18-F099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.throughput_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,

    -- Metrics
    requests_per_second NUMERIC(10, 2) NOT NULL,
    bytes_per_second NUMERIC(15, 2),

    -- Context
    error_rate NUMERIC(5, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.throughput_metrics IS 'Tracks request and byte throughput for capacity planning.';

-- =====================================================================================================================
-- Table: M18-T373 - error_budget_consumption
-- Description: Real-time consumption stream.
-- Business Case: Automation trigger. This table is a high-frequency log of error budget burn, updated by monitoring,
--                 to trigger automated circuit breakers (T085) or throttling.
-- KPIs: Consumption Rate, Budget Remaining %, Burn Velocity, Recovery Velocity.
-- Feature Reference: M18-F051 (Latency SLO Error Budget Calculator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.error_budget_consumption (
    consumption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slo_name VARCHAR(100) NOT NULL,

    -- State
    budget_remaining_pct NUMERIC(5, 2) NOT NULL,
    burn_rate_pct_per_min NUMERIC(5, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.error_budget_consumption IS 'Real-time stream of SLO error budget burn rates.';

-- =====================================================================================================================
-- Table: M18-T374 - incident_commander_logs
-- Description: Chat logs during incidents.
-- Business Case: "The chat is the record." This table aggregates messages from Slack/Teams during an incident,
--                 providing context for post-mortems (T277) and analyzing communication efficiency.
-- KPIs: Message Volume, Response Time, Participant Count, Command Sentiment, Resolution Correlation.
-- Feature Reference: M18-T149 (Incidents)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.incident_commander_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    -- Message
    user_id UUID,
    username VARCHAR(100),
    message TEXT NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.incident_commander_logs IS 'Stores chat room messages associated with incident response.';
CREATE INDEX idx_commander_incident ON cmmi.incident_commander_logs (incident_id, timestamp ASC);

-- =====================================================================================================================
-- Table: M18-T375 - on_call_rotations
-- Description: SRE on-call scheduling.
-- Business Case: Who is responding? This table manages the on-call rotation, tracking who is primary, secondary,
--                 and when handovers occur, ensuring accountability for incident response.
-- KPIs: Rotation Adherence, Coverage Gaps, Escalation Handoff Time, Primary Response SLA.
-- Feature Reference: M18-T157 (On-Call Schedules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.on_call_rotations (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_name VARCHAR(100) NOT NULL,

    -- Schedule
    primary_user_id UUID,
    secondary_user_id UUID,

    -- Timeline
    rotation_start TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_end TIMESTAMP WITH TIME ZONE NOT NULL,

    timezone VARCHAR(50) NOT NULL,

    FOREIGN KEY (primary_user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (secondary_user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.on_call_rotations IS 'Manages scheduling of on-call engineering rotations.';

-- =====================================================================================================================
-- Table: M18-T376 - escalation_policies
-- Description: Rules for escalating alerts.
-- Business Case: Waking up the VP shouldn't happen accidentally. This table defines escalation policies (e.g., "If not
--                 acknowledged in 15 mins, ping secondary"), automating the escalation ladder.
-- KPIs: Escalation Frequency, Policy Accuracy, Time to Engage Higher Management, False Escalations.
-- Feature Reference: M18-T158 (Escalation Policies)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.escalation_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schedule_id UUID NOT NULL, -- Ref T157

    -- Rules
    level INTEGER NOT NULL, -- 1 (Primary), 2 (Secondary), 3 (Manager)
    wait_minutes INTEGER NOT NULL,
    notify_user_id UUID,

    FOREIGN KEY (schedule_id) REFERENCES cmmi.on_call_rotations(rotation_id)
);

COMMENT ON TABLE cmmi.escalation_policies IS 'Defines automated escalation rules for unacknowledged alerts.';

-- =====================================================================================================================
-- Table: M18-T377 - run_time_policy_enforcement
-- Description: Enforcement of operational policies.
-- Business Case: Policy as Code. This table checks/records if resources adhere to policies (e.g., "Pods must have limits",
--                 "DBs must be encrypted"). It automates governance guardrails.
-- KPIs: Policy Violation Count, Enforcement Success Rate, Policy Coverage, Auto-Remediation Rate.
-- Feature Reference: M18-T024 (Security Policy Violation Auto-Check)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.run_time_policy_enforcement (
    enforcement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id UUID NOT NULL,
    policy_name VARCHAR(100) NOT NULL,

    -- Check
    status VARCHAR(20) NOT NULL, -- 'Compliant', 'Violation', 'Error'
    details JSONB,

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.run_time_policy_enforcement IS 'Results of policy checks against running infrastructure resources.';

-- =====================================================================================================================
-- Table: M18-T378 - infrastructure_cost_breakdown
-- Description: Detailed cloud bill breakdown.
-- Business Case: FinOps optimization. This table normalizes raw cloud billing data into a clean schema, breaking down
--                 costs by Service, Environment, and Tag to enable accurate chargeback (T237).
-- KPIs: Cost per Service, Cost per Environment, Unallocated Cost, Discount Utilization, Currency Rate.
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.infrastructure_cost_breakdown (
    cost_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Dimensions
    service_name VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    environment VARCHAR(50) NOT NULL,

    -- Financials
    cost_amount NUMERIC(15, 4) NOT NULL,
    currency CHAR(3) DEFAULT 'USD',

    -- Time
    billing_period_start DATE NOT NULL,
    billing_period_end DATE NOT NULL
);

COMMENT ON TABLE cmmi.infrastructure_cost_breakdown IS 'Normalized breakdown of cloud infrastructure costs.';

-- =====================================================================================================================
-- Table: M18-T379 - carbon_footprint_calculations
-- Description: Detailed Green IT metrics.
-- Business Case: Sustainability reporting. This table calculates CO2e emissions based on compute hours and region
--                 carbon intensity, providing data for ESG (Environmental, Social, Governance) reporting.
-- KPIs: kgCO2e per Compute Hour, Energy Efficiency, Renewable Energy % (by region), Emissions Reduction.
-- Feature Reference: M18-T238 (Carbon Emission Metrics)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.carbon_footprint_calculations (
    calculation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_id VARCHAR(100),

    -- Calculation
    compute_hours NUMERIC(10, 2),
    region VARCHAR(50) NOT NULL,
    grid_carbon_intensity_gco2_kwh NUMERIC(10, 6), -- Grid emission factor

    -- Result
    estimated_emissions_kg NUMERIC(15, 6),

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.carbon_footprint_calculations IS 'Detailed calculation of carbon emissions for IT resources.';

-- =====================================================================================================================
-- Table: M18-T380 - open_source_contribution_logs
-- Description: Contributions to external open source.
-- Business Case: Innovation and branding. PARI contributing to OS (Open Source) improves reputation. This table
--                 tracks commits/PRs to external repos, measuring engineering impact on the wider community.
-- KPIs: Contributions per Quarter, External PR Acceptance Rate, Community Engagement, Follower Growth.
-- Feature Reference: M18-F154 (Open Source Contribution Health)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.open_source_contribution_logs (
    contribution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    platform VARCHAR(50) NOT NULL, -- 'GitHub', 'GitLab'
    repo_name VARCHAR(255) NOT NULL,

    -- Contribution
    type VARCHAR(20) NOT NULL, -- 'Commit', 'Issue', 'PR', 'Comment'
    url TEXT NOT NULL,
    author_id UUID,

    -- Outcome
    status VARCHAR(20), -- 'Open', 'Merged', 'Closed'
    merged_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.open_source_contribution_logs IS 'Tracks engineering contributions to external open source projects.';

-- =====================================================================================================================
-- Table: M18-T381 - patent_ip_assets
-- Description: Management of patents and IP.
-- Business Case: Intellectual Property protection. This table tracks patent applications, status, and linkage to
--                 internal innovations/products.
-- KPIs: Patents Filed, Patents Granted, IP Maintenance Cost, Patent Rejection Rate, Time to Grant.
-- Feature Reference: M18-F153 (Innovation Time Tracking)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.patent_ip_assets (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    title VARCHAR(255) NOT NULL,
    patent_number VARCHAR(100),

    -- Status
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Filed', 'Granted', 'Rejected', 'Expired'
    filed_date DATE,
    expiry_date DATE,

    -- Linkage
    internal_project_id UUID, -- Link to Project
    inventors TEXT[], -- List of User IDs or Names

    created_by UUID
);

COMMENT ON TABLE cmmi.patent_ip_assets IS 'Manages intellectual property and patent lifecycle.';

-- =====================================================================================================================
-- Table: M18-T382 - competitive_intelligence_analysis
-- Description: Market research data.
-- Business Case: Strategic planning. This table stores analysis of competitor features, pricing, or tech stack,
--                 informing product roadmap decisions.
-- KPIs: Analysis Freshness, Coverage % of Market, Insight Accuracy, Strategic Alignment Score.
-- Feature Reference: M18-T234 (Technology Radar)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.competitive_intelligence_analysis (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    competitor_name VARCHAR(100) NOT NULL,
    feature_name VARCHAR(255),

    -- Analysis
    description TEXT,
    advantage_type VARCHAR(50), -- 'FeatureParity', 'Superiority', 'Inferiority'

    impact_score INTEGER, -- 1-5

    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    analyst_id UUID
);

COMMENT ON TABLE cmmi.competitive_intelligence_analysis IS 'Stores strategic analysis of competitor products and features.';

-- =====================================================================================================================
-- Table: M18-T383 - roadmap_progress_tracking
-- Description: High-level roadmap metrics.
-- Business Case: Strategic delivery tracking. This table monitors progress on strategic initiatives (e.g., "Expand to Asia"),
--                 distinct from feature delivery.
-- KPIs: Strategic Initiative Completion, Roadmap Variance, Milestone Velocity, Strategic Value Delivered.
-- Feature Reference: M18-F156 (KPI Dashboard)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.roadmap_progress_tracking (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Planning
    planned_quarter VARCHAR(20) NOT NULL, -- 'Q1 2023'
    target_outcome TEXT,

    -- Progress
    completion_percentage NUMERIC(5, 2) DEFAULT 0,
    status VARCHAR(20) DEFAULT 'OnTrack', -- 'OnTrack', 'AtRisk', 'Delayed'

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    owner_id UUID
);

COMMENT ON TABLE cmmi.roadmap_progress_tracking IS 'Tracks progress of high-level strategic roadmap items.';

-- =====================================================================================================================
-- Table: M18-T384 - product_market_fit_metrics
-- Description: Product/Market Fit metrics (PMF).
-- Business Case: Measuring success. This table tracks metrics like Net Promoter Score (NPS), Churn, and Monthly Recurring
--                 Revenue (MRR) to validate product market fit.
-- KPIs: NPS Score, Churn Rate, LTV (Lifetime Value), CAC (Customer Acquisition Cost), Viral Coefficient.
-- Feature Reference: M18-F065 (Customer Feedback Sentiment Correlation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.product_market_fit_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Segment
    customer_segment VARCHAR(100),

    -- Metrics
    nps_score NUMERIC(3, 2),
    churn_rate NUMERIC(5, 2),
    mrr NUMERIC(15, 2),

    period_start DATE NOT NULL,
    period_end DATE NOT NULL
);

COMMENT ON TABLE cmmi.product_market_fit_metrics IS 'Tracks strategic product metrics indicating market fit.';

-- =====================================================================================================================
-- Table: M18-T385 - customer_feedback_loops
-- Description: Mapping feedback to engineering work.
-- Business Case: Closing the loop. This table links customer support tickets (or feedback) to specific features or bugs
--                 addressed by engineering, quantifying the impact of development on customer satisfaction.
-- KPIs: Feedback Resolution Time, Issues Addressed %, Customer Satisfaction Lift, Engineering-Feedback Correlation.
-- Feature Reference: M18-F065 (Customer Feedback Sentiment Correlation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.customer_feedback_loops (
    loop_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Feedback
    feedback_id VARCHAR(100) NOT NULL, -- Ticket ID or Review ID
    sentiment_score NUMERIC(3, 2),

    -- Engineering Action
    linked_work_item_id UUID, -- Ref T144
    linked_release_id UUID, -- Ref T176

    -- Outcome
    resolution_status VARCHAR(20), -- 'Resolved', 'Ignored', 'Planned'

    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.customer_feedback_loops IS 'Links customer feedback to engineering work items to track impact.';

-- =====================================================================================================================
-- Table: M18-T386 - ux_a_b_testing_results
-- Description: Frontend A/B testing data.
-- Business Case: Optimizing UI/UX. This table stores results of frontend A/B tests (Layouts, Colors, Copy),
--                 distinct from backend feature flags.
-- KPIs: Conversion Lift, Click-Through Rate, Engagement Time, Statistical Significance.
-- Feature Reference: M18-F064 (A/B Test Statistical Significance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ux_a_b_testing_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id VARCHAR(100) NOT NULL,
    variant VARCHAR(50) NOT NULL, -- 'A', 'B', 'Control'

    -- Metrics
    views INTEGER NOT NULL,
    conversions INTEGER NOT NULL,
    clicks INTEGER NOT NULL,

    -- Stats
    conversion_rate NUMERIC(5, 4),
    p_value NUMERIC(10, 6),
    is_winner BOOLEAN,

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ux_a_b_testing_results IS 'Stores results of UX/UI A/B experiments.';

-- =====================================================================================================================
-- Table: M18-T387 - performance_budget_compliance
-- Description: Checking adherence to performance budgets.
-- Business Case: Budgets are useless if not enforced. This table checks if specific metrics (like Font Load Time)
--                 are within the defined "Performance Budget" for a page or feature.
-- KPIs: Budget Compliance Rate, Budget Breach Severity, Performance Trend vs Budget.
-- Feature Reference: M18-F071 (Automated Accessibility Audit) - Context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.performance_budget_compliance (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    page_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(50) NOT NULL, -- 'SpeedIndex', 'LCP', 'CLS'

    -- Budget
    budget_value_ms NUMERIC(10, 2) NOT NULL,
    actual_value_ms NUMERIC(10, 2) NOT NULL,

    -- Result
    is_compliant BOOLEAN NOT NULL,
    over_budget_ms NUMERIC(10, 2) GENERATED ALWAYS AS (actual_value_ms - budget_value_ms) STORED,

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.performance_budget_compliance IS 'Checks if frontend performance metrics adhere to defined budgets.';

-- =====================================================================================================================
-- Table: M18-T388 - resource_efficiency_metrics
-- Description: CPU/RAM efficiency per request.
-- Business Case: Cost efficiency. It's not just about raw load, but how much work is done per unit of CPU/RAM.
--                 This table tracks cost-efficiency (e.g., $ per transaction vs CPU cost).
-- KPIs: CPU per Transaction, Memory per Request, Efficiency Trend, Cost per Request, Resource Waste.
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.resource_efficiency_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,

    -- Resource Usage
    cpu_cycles_per_req BIGINT,
    memory_bytes_per_req BIGINT,

    -- Work
    requests_handled BIGINT,

    -- Efficiency
    cost_per_request_usd NUMERIC(10, 6),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.resource_efficiency_metrics IS 'Measures compute efficiency relative to traffic volume.';

-- =====================================================================================================================
-- Table: M18-T389 - cache_invalidation_events
-- Description: When and why cache was cleared.
-- Business Case: Debugging staleness. If cache is invalidated too often, it defeats the purpose. This table logs
--                 invalidation events (Manual, Time-based, Write-through) to tune TTL strategies.
-- KPIs: Invalidation Frequency, Cache Hit Ratio Post-Invalidation, Manual Invalidation %.
-- Feature Reference: M18-T079 (Cache Stats)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cache_invalidation_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cache_key VARCHAR(255) NOT NULL,

    -- Action
    trigger_reason VARCHAR(50) NOT NULL, -- 'TimeExpiry', 'Manual', 'WriteUpdate'
    triggered_by VARCHAR(100), -- 'System' or User

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cache_invalidation_events IS 'Logs cache invalidation events to analyze efficiency.';

-- =====================================================================================================================
-- Table: M18-T390 - database_query_plans
-- Description: Analysis of execution plans.
-- Business Case: Identifying slow queries often involves looking at the plan. This table stores snapshots of query
--                 execution plans (Seq Scans, Nested Loops) to identify performance regressions.
-- KPIs: Plan Cost (Total Cost), Scan Count, Buffer Usage, Plan Stability, Join Method Changes.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.database_query_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_hash CHAR(64) NOT NULL,

    -- Plan Metrics
    total_cost NUMERIC(10, 2) NOT NULL,
    plan_rows NUMERIC(15, 2),
    plan_width INTEGER, -- Width of plan tree

    -- Details
    plan_text TEXT, -- Full explain output

    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.database_query_plans IS 'Analyzes database execution plan costs for query tuning.';

-- =====================================================================================================================
-- Table: M18-T391 - index_usage_stats
-- Description: Detailed stats on index usage.
-- Business Case: Index maintenance. Knowing which indexes are used (scans) vs. which are dead is critical for DB
--                 performance. This table tracks index scan counts.
-- KPIs: Index Scan Count, Index Read Ratio, Unused Indexes, Index Size vs Utility.
-- Feature Reference: M18-T110 (Index Usage Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.index_usage_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,
    index_name VARCHAR(255) NOT NULL,

    -- Usage
    idx_scan BIGINT NOT NULL,
    idx_tup_read BIGINT NOT NULL,
    idx_tup_fetch BIGINT NOT NULL,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.index_usage_stats IS 'Tracks usage statistics of database indexes.';

-- =====================================================================================================================
-- Table: M18-T392 - table_partition_stats
-- Description: Partition pruning/maintenance.
-- Business Case: Large tables are partitioned. This table tracks partition size, last analyzed, and pruning stats
--                 to maintain query performance.
-- KPIs: Partition Size, Pruning Speed, Inactive Partitions, Maintenance Overhead.
-- Feature Reference: M18-T099 (Connection Pool Usage Monitor) - General DB context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.table_partition_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,
    partition_value TEXT NOT NULL, -- e.g., '2023_10'

    -- Stats
    row_count BIGINT NOT NULL,
    size_bytes BIGINT,

    -- Maintenance
    last_analyzed TIMESTAMP WITH TIME ZONE,
    is_prunable BOOLEAN,

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.table_partition_stats IS 'Monitors size and usage of table partitions.';

-- =====================================================================================================================
-- Table: M18-T393 - replication_lag_stats
-- Description: Lag per DB shard/replica.
-- Business Case: Data consistency. Replication lag can cause data loss during failover. This table tracks lag bytes
--                 and time for every replica/shard.
-- KPIs: Lag Seconds, Lag Bytes, Lag Trends, Failover Data Loss Risk.
-- Feature Reference: M18-T098 (Follower Lag Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.replication_lag_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_db VARCHAR(100) NOT NULL,
    replica_name VARCHAR(100) NOT NULL,

    -- Lag
    lag_bytes BIGINT,
    lag_seconds NUMERIC(10, 2),
    replay_lag_seconds NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.replication_lag_stats IS 'Detailed metrics on database replication lag.';

-- =====================================================================================================================
-- Table: M18-T394 - connection_pool_stats
-- Description: Connection pool utilization details.
-- Business Case: Tuning pools. This table tracks active, idle, and waiting connections in high resolution,
--                 helping configure optimal pool sizes.
-- KPIs: Pool Utilization %, Wait Time, Failed Connections, Pool Stalls.
-- Feature Reference: M18-T099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.connection_pool_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,

    -- Counts
    active_connections INTEGER NOT NULL,
    idle_connections INTEGER NOT NULL,
    waiting_connections INTEGER NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.connection_pool_stats IS 'Detailed statistics on database connection pools.';

-- =====================================================================================================================
-- Table: M18-T395 - cursor_fetch_stats
-- Description: Fetch performance for cursors.
-- Business Case: Application efficiency. Poor fetching (fetching 1M rows instead of 10) kills performance.
--                 This table tracks fetch counts and durations to identify inefficient code.
-- KPIs: Avg Fetch Time, Fetch Count per Query, Data Volume Fetched, Cursor Abortion Rate.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cursor_fetch_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,

    -- Fetch
    total_fetches INTEGER NOT NULL,
    total_rows_fetched BIGINT NOT NULL,
    avg_duration_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cursor_fetch_stats IS 'Monitors cursor fetch performance to detect inefficient data access patterns.';

-- =====================================================================================================================
-- Table: M18-T396 - database_lock_stats
-- Description: Database lock wait details.
-- Business Case: Concurrency issues. Lock waits serialize transactions, reducing throughput. This table tracks
--                 lock types, wait times, and deadlocks.
-- KPIs: Lock Wait %, Deadlock Count, Lock Duration, Blocking Queries.
-- Feature Reference: M18-T112 (Lock Contention Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.database_lock_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Lock Details
    lock_type VARCHAR(50) NOT NULL,
    relation_name VARCHAR(255) NOT NULL,
    mode VARCHAR(20) NOT NULL, -- 'AccessShare', 'Exclusive'

    -- Wait
    wait_count BIGINT,
    total_wait_time_ms NUMERIC(15, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.database_lock_stats IS 'Aggregates database lock contention statistics.';

-- =====================================================================================================================
-- Table: M18-T397 - transaction_rollback_stats
-- Description: Reasons for transaction rollbacks.
-- Business Case: Application logic errors. Transactions roll back due to deadlocks, logic errors, or timeouts.
--                 This table categorizes rollbacks to fix the underlying code.
-- KPIs: Rollback Rate, Rollback Reasons, Deadlock Rollback %, Timeout Rollback %.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.transaction_rollback_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Reason
    rollback_reason VARCHAR(50) NOT NULL, -- 'Deadlock', 'Timeout', 'LogicError', 'SerializationFailure'

    count BIGINT NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.transaction_rollback_stats IS 'Categorizes and tracks database transaction rollbacks.';

-- =====================================================================================================================
-- Table: M18-T398 - bloat_analysis_stats
-- Description: Table and index bloat.
-- Business Case: Storage efficiency. Bloated tables waste disk space and slow down scans. This table monitors
--                 bloat percentage to schedule vacuums.
-- KPIs: Bloat % (>20% is bad), Bloat Size, Vacuum Frequency, Autovacuum Effectiveness.
-- Feature Reference: M18-T111 (Table Bloat Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bloat_analysis_stats (
    analysis_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,

    -- Bloat
    bloat_bytes BIGINT NOT NULL,
    bloat_pct NUMERIC(5, 2) NOT NULL,

    -- Action
    recommended_action VARCHAR(50), -- 'Vacuum', 'Reindex', 'None'

    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.bloat_analysis_stats IS 'Tracks storage bloat in database tables and indexes.';

-- =====================================================================================================================
-- Table: M18-T399 - autovacuum_statistics
-- Description: Autovacuum config and ops.
-- Business Case: Maintenance automation. Autovacuum prevents transaction ID wraparound. This table tracks autovacuum
--                 operations and configuration health.
-- KPIs: Wraparound Protection Days, Autovacuum Duration, Dead Tuples Count, Avv Scan Effectiveness.
-- Feature Reference: M18-T097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.autovacuum_statistics (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,

    -- Metrics
    num_dead_tuples BIGINT,
    autovacuum_count BIGINT,
    last_autovacuum TIMESTAMP WITH TIME ZONE,

    -- Protection
    xid_wraparound_protection_days NUMERIC(5, 1),

    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.autovacuum_statistics IS 'Monitors the health and operation of the autovacuum process.';

-- =====================================================================================================================
-- Table: M18-T400 - analyze_statistics
-- Description: Statistics table analysis.
-- Business Case: System health of `pg_statistic`. The stats collector itself can have issues (stuck). This table
--                 monitors the freshness of the stats tables used by the monitoring system.
-- KPIs: Stats Freshness (seconds), Collector Lag, Stats Table Size.
-- Feature Reference: M18-T001 (Real-time Metric Ingestion)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.analyze_statistics (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schemaname VARCHAR(100) NOT NULL,
    tablename VARCHAR(255),

    -- Counts
    seq_scan BIGINT,
    idx_scan BIGINT,
    n_tup_ins BIGINT,
    n_tup_upd BIGINT,
    n_tup_del BIGINT,

    last_analyzed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.analyze_statistics IS 'System tables monitoring for database performance statistics.';

-- =====================================================================================================================
-- Table: M18-T401 - pg_stat_statements
-- Description: Normalized statement execution stats.
-- Business Case: Top N queries. This table (snapshot of pg_stat_statements) identifies the most time-consuming queries
--                 in the system for optimization.
-- KPIs: Total Exec Time, Calls, Rows, Avg Exec Time per Query.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pg_stat_statements (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    queryid BIGINT NOT NULL,
    query_text TEXT,

    -- Metrics
    calls BIGINT,
    total_exec_time_ms NUMERIC(20, 2),
    rows BIGINT,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pg_stat_statements IS 'Stores normalized execution statistics for SQL queries.';

-- =====================================================================================================================
-- Table: M18-T402 - pg_stat_activity
-- Description: Database activity stats.
-- Business Case: Load analysis. This table tracks active sessions, DDL actions, and cache hits to understand
--                 what the DB is doing right now.
-- KPIs: Active Sessions, Cache Hit Ratio, DDL Count, Checkpoint Count.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pg_stat_activity (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    datid NUMERIC(10, 2), -- Database OID
    active_connections INTEGER,
    xact_commit BIGINT,
    xact_rollback BIGINT,
    blks_hit BIGINT,
    blks_read BIGINT,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pg_stat_activity IS 'High-level database activity metrics.';

-- =====================================================================================================================
-- Table: M18-T403 - pg_stat_replication
-- Description: Replication specific stats.
-- Business Case: HA health. This table monitors replication slot lag, WAL file size, and sync state,
--                 essential for disaster recovery readiness.
-- KPIs: WAL Size, Slot Lag, Sync Commit Time, Replay Location Lag.
-- Feature Reference: M18-T098 (Follower Lag Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pg_stat_replication (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    pid INTEGER, -- WAL Sender Process ID
    application_name VARCHAR(100),

    -- Stats
    sync_lag_bytes BIGINT,
    replay_lag_bytes BIGINT,
    flushed_lag_bytes BIGINT,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pg_stat_replication IS 'Detailed metrics for streaming replication processes.';

-- =====================================================================================================================
-- Table: M18-T404 - pg_stat_database
-- Description: Per-database stats.
-- Business Case: Multi-tenant DB monitoring. This table aggregates stats (commits, rollbacks, cache hits) per
--                 database instance within a cluster.
-- KPIs: Transactions per DB, Cache Hit Ratio per DB, DB Size, Temp File Size.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pg_stat_database (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    datid NUMERIC(10, 2) NOT NULL,
    datname VARCHAR(100) NOT NULL,

    -- Stats
    numbackends BIGINT,
    xact_commit BIGINT,
    xact_rollback BIGINT,
    blks_read BIGINT,
    tup_returned BIGINT,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pg_stat_database IS 'Aggregates performance statistics per database.';

-- =====================================================================================================================
-- Table: M18-T405 - wal_statistics
-- Description: Write Ahead Log metrics.
-- Business Case: WAL throughput is the bottleneck. This table tracks WAL size, generation rate, and archival status.
-- KPIs: WAL Size, WAL Generation Rate, Archival Success Rate, WAL Sync Latency.
-- Feature Reference: M18-T097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.wal_statistics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Location/Stats
    wal_location TEXT,
    wal_size_bytes BIGINT,
    wal_generation_rate_mb_sec NUMERIC(10, 2),

    -- Archival
    is_archiving BOOLEAN,
    archival_lag_files INTEGER,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.wal_statistics IS 'Monitors Write Ahead Log (WAL) throughput and status.';

-- =====================================================================================================================
-- Table: M18-T406 - checkpoint_stats
-- Description: Checkpoint operation metrics.
-- Business Case: Checkpoint spikes cause I/O bursts. This table tracks checkpoint duration and sync time to ensure
--                 they don't degrade performance.
-- KPIs: Checkpoint Duration, Checkpoint Interval, Sync Duration, Buffer Usage.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.checkpoint_stats (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Type
    checkpoint_type VARCHAR(20), -- 'spread', 'fast'

    -- Stats
    duration_seconds NUMERIC(10, 2),
    buffers_written BIGINT,
    seconds_since_start NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.checkpoint_stats IS 'Monitors database checkpoint operations.';

-- =====================================================================================================================
-- Table: M18-T407 - background_worker_stats
-- Description: PgBouncer or connection pooler stats.
-- Business Case: Pooler efficiency. If the pooler (PgBouncer) is the bottleneck, the DB looks slow. This table
--                 tracks queue times and pool wait times for the connection proxy.
-- KPIs: Client Wait Time, Server Wait Time, Query Count, Max Connection Count.
-- Feature Reference: M18-T099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.background_worker_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    worker_name VARCHAR(100) NOT NULL, -- e.g., 'pgbouncer', 'pgpool'

    -- Pool Stats
    max_connections INTEGER NOT NULL,
    active_connections INTEGER NOT NULL,
    waiting_clients INTEGER NOT NULL,

    -- Performance
    average_wait_time_ms NUMERIC(10, 2),

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.background_worker_stats IS 'Tracks metrics for connection pooler background workers.';

-- =====================================================================================================================
-- Table: M18-T408 - extension_versions
-- Description: Installed DB extensions and versions.
-- Business Case: Dependency management. Upgrading extensions (e.g., PostGIS, pg_stat_statements) can break queries.
--                 This table logs versions to manage upgrades safely.
-- KPIs: Extension Count, Version Uniformity, Extension Updates, Deprecated Extensions.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.extension_versions (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    extname VARCHAR(100) NOT NULL,
    version VARCHAR(50),

    -- Status
    installed_schema VARCHAR(100),
    default_version BOOLEAN,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.extension_versions IS 'Inventory of installed database extensions and their versions.';

-- =====================================================================================================================
-- Table: M18-T409 - custom_function_metrics
-- Description: Performance of User Defined Functions (UDF).
-- Business Case: Custom code in DB (Triggers/Functions) can be slow. This table tracks execution time of functions
--                 to identify performance regressions in PL/pgSQL.
-- KPIs: Function Call Time, Call Count, Error Rate, Function Self-Time.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.custom_function_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    function_name VARCHAR(255) NOT NULL,

    -- Metrics
    total_call_time_ms NUMERIC(15, 2),
    self_time_ms NUMERIC(15, 2),
    calls BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.custom_function_metrics IS 'Monitors execution performance of custom database functions.';

-- =====================================================================================================================
-- Table: M18-T410 - trigger_execution_stats
-- Description: Trigger performance metrics.
-- Business Case: Triggers add overhead. This table tracks how often triggers fire and how long they take,
--                 ensuring they don't silently kill performance.
-- KPIs: Trigger Fire Count, Trigger Duration, Trigger Latency Impact.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.trigger_execution_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tgname VARCHAR(100) NOT NULL,

    calls BIGINT,
    total_time_ms NUMERIC(15, 2),
    avg_time_ms NUMERIC(10, 2),

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.trigger_execution_stats IS 'Tracks execution frequency and overhead of database triggers.';

-- =====================================================================================================================
-- Table: M18-T411 - rule_based_performance
-- Description: Row Level Security (RLS) performance.
-- Business Case: RLS adds a layer of filtering. If poorly implemented, it causes full table scans. This table
--                 tracks performance of RLS policies to ensure they are optimized.
-- KPIs: RLS Query Overhead %, Denied Queries, Full Scans due to RLS.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.rule_based_performance (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    schemaname VARCHAR(100) NOT NULL,
    tablename VARCHAR(100) NOT NULL,

    -- RLS Stats
    rls_calls BIGINT,
    rls_consequential_checks BIGINT,
    rls_predicate_checks BIGINT,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.rule_based_performance IS 'Analyzes overhead and usage of Row Level Security policies.';

-- =====================================================================================================================
-- Table: M18-T412 - partition_pruning_stats
-- Description: Partition pruning performance.
-- Business Case: Pruning removes old partitions instantly. If pruning fails or is slow, it might affect `DROP`
--                 commands. This table tracks pruning efficiency.
-- KPIs: Partitions Pruned, Pruning Duration, Scan Overhead, Maintenance Workload.
-- Feature Reference: M18-T392 (Table Partition Stats)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.partition_pruning_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_table VARCHAR(255) NOT NULL,

    -- Stats
    partitions_pruned INTEGER,
    scan_time_ms NUMERIC(10, 2),

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.partition_pruning_stats IS 'Monitors the efficiency of partition pruning operations.';

-- =====================================================================================================================
-- Table: M18-T413 - async_notification_logs
-- Description: Logs for LISTEN/NOTIFY.
-- Business Case: Async messaging within DB. `LISTEN/NOTIFY` is used for cache invalidation or app signaling.
--                 This table logs these events to debug notification delivery failures.
-- KPIs: Notification Throughput, Delivery Failures, Listener Lag, Notification Payload Size.
-- Feature Reference: M18-T389 (Cache Invalidation Events)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.async_notification_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    channel VARCHAR(100) NOT NULL,
    payload TEXT,

    -- Delivery
    pid INTEGER, -- Process ID of listener
    delivered BOOLEAN,
    delivery_latency_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.async_notification_logs IS 'Audits PostgreSQL LISTEN/NOTIFY async messaging events.';

-- =====================================================================================================================
-- Table: M18-T414 - logical_decoding_stats
-- Description: Logical replication decoding stats.
-- Business Case: Logical replication (Wal2Json) applies changes. If decoding is slow, replicas lag. This table
--                 tracks decoding throughput.
-- KPIs: Decode Lag, Decode Throughput, Errors, Transaction Size.
-- Feature Reference: M18-T403 (pg_stat_replication)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.logical_decoding_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slot_name VARCHAR(100) NOT NULL,

    -- Stats
    transactions_decoded BIGINT,
    decode_lag_bytes BIGINT,
    error_count BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.logical_decoding_stats IS 'Monitors decoding lag and throughput for logical replication slots.';

-- =====================================================================================================================
-- Table: M18-T415 - physical_replication_stats
-- Description: Physical replication streaming stats.
-- Business Case: High availability. This table tracks the raw WAL streaming rate to standbys, ensuring
--                 sync replication is healthy.
-- KPIs: Streaming Rate (MB/s), Sync Latency, Sender/Receiver Lag, Network Throughput.
-- Feature Reference: M18-T403 (pg_stat_replication)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.physical_replication_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    application_name VARCHAR(100) NOT NULL,

    -- Streaming
    sent_lsn NUMERIC(20, 2),
    write_lsn NUMERIC(20, 2),
    flush_lsn NUMERIC(20, 2),

    -- Lag
    replay_lag NUMERIC(20, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.physical_replication_stats IS 'Monitors LSN positions and lag for physical replication.';

-- =====================================================================================================================
-- Table: M18-T416 - backup_label_stats
-- Description: Metadata attached to backups.
-- Business Case: Organizing backups. This table stores labels/tags applied to backups (e.g., "Pre-Release", "Critical"),
--                 aiding in retention and selection for PITR (Point in Time Recovery).
-- KPIs: Labeled Backup %, Retention Policy Compliance, Label Usage Frequency.
-- Feature Reference: M18-T097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.backup_label_stats (
    label_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    backup_id UUID NOT NULL,
    label_key VARCHAR(100) NOT NULL,
    label_value VARCHAR(100) NOT NULL,

    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (backup_id) REFERENCES cmmi.backup_integrity(check_id)
);

COMMENT ON TABLE cmmi.backup_label_stats IS 'Manages tags and labels applied to database backups.';

-- =====================================================================================================================
-- Table: M18-T417 - recovery_point_objective_stats
-- Description: RPO targets vs actuals.
-- Business Case: Disaster Recovery metrics. This table compares the target RPO (Data Loss allowed) with the
--                 actual data loss calculated based on backup/recovery logs.
-- KPIs: RPO Compliance, Data Loss Minutes, RPO Breach Count, Recovery Target Delta.
-- Feature Reference: M18-T097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.recovery_point_objective_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    target_rpo_minutes INTEGER NOT NULL,
    actual_rpo_minutes NUMERIC(10, 2),

    is_compliant BOOLEAN GENERATED ALWAYS AS (actual_rpo_minutes <= target_rpo_minutes) STORED,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.recovery_point_objective_stats IS 'Tracks adherence to Recovery Point Objective (RPO) targets.';

-- =====================================================================================================================
-- Table: M18-T418 - failover_simulation_results
-- Description: Results of HA failover tests.
-- Business Case: Validating DR plans. This table stores results of automated failover drills (Primary -> Standby),
--                 measuring time to switch and data consistency.
-- KPIs: Failover Time, Data Loss, Service Downtime, Failover Success Rate.
-- Feature Reference: M18-T097 (Backup Integrity Checker)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.failover_simulation_results (
    sim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scenario
    primary_node VARCHAR(100) NOT NULL,
    standby_node VARCHAR(100) NOT NULL,

    -- Results
    failover_time_seconds NUMERIC(10, 2),
    data_loss_records BIGINT,
    success BOOLEAN NOT NULL,

    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.failover_simulation_results IS 'Logs results of high availability failover drills.';

-- =====================================================================================================================
-- Table: M18-T419 - high_availability_cluster_status
-- Description: State of HA cluster nodes.
-- Business Case: Cluster health. This table monitors the status of all nodes in a cluster (Primary, Standby, Streaming).
-- KPIs: Node Availability, Quorum Status, Split-Brain Detection, Cluster Health Score.
-- Feature Reference: M18-T415 (Physical Replication Stats)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.high_availability_cluster_status (
    status_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    node_name VARCHAR(100) NOT NULL,

    -- State
    role VARCHAR(20) NOT NULL, -- 'Primary', 'Standby', 'Witness'
    status VARCHAR(20) NOT NULL, -- 'Up', 'Down', 'Unreachable'
    current_lsn NUMERIC(20, 2),

    timeline_lag NUMERIC(10, 2),

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.high_availability_cluster_status IS 'Monitors the status and replication lag of HA cluster nodes.';

-- =====================================================================================================================
-- Table: M18-T420 - synchronous_replication_lag
-- Description: Critical lag for sync commits.
-- Business Case: Real-time data requirement. Synchronous replication (sync commit) adds a hard dependency on the
--                 replica. Any lag here pauses the whole primary. This table tracks this critical metric.
-- KPIs: Sync Commit Lag, Network RTT to Replica, Sync Commit Timeout Count, Primary Impact.
-- Feature Reference: M18-T403 (pg_stat_replication)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.synchronous_replication_lag (
    lag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    standby_name VARCHAR(100) NOT NULL,

    -- Metrics
    lag_bytes BIGINT,
    lag_seconds NUMERIC(10, 2),

    -- Status
    is_blocking BOOLEAN, -- True if lag > timeout
    warning_threshold_sec INTEGER,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.synchronous_replication_lag IS 'Monitors lag for synchronous replication, which can block primary transactions.';

-- =====================================================================================================================
-- Table: M18-T421 - connection_proxy_metrics
-- Description: Metrics for connection proxy (PgBouncer).
-- Business Case: Proxy bottleneck. The pooler sits between app and DB. Monitoring its internal queues (waiting clients)
--                 is crucial to see if the pool is big enough.
-- KPIs: Client Wait Time, Server Wait Time, Pool Utilization %.
-- Feature Reference: M18-T099 (Connection Pool Usage Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.connection_proxy_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    database VARCHAR(100) NOT NULL,

    -- Queues
    cl_active INTEGER NOT NULL,
    cl_waiting INTEGER NOT NULL,
    sv_active INTEGER NOT NULL,
    sv_idle INTEGER NOT NULL,
    sv_used INTEGER NOT NULL,
    sv_tested INTEGER NOT NULL,
    max_conn INTEGER NOT NULL,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.connection_proxy_metrics IS 'Detailed internal stats for database connection proxy software.';

-- =====================================================================================================================
-- Table: M18-T422 - dns_resolution_latency
-- Description: DNS lookup performance.
-- Business Case: Slow DNS kills everything. This table tracks the time taken to resolve hostnames used by the app,
--                 identifying network issues or slow DNS servers.
-- KPIs: Lookup Latency (p95), Cache Hit % (resolver), DNS Error Rate.
-- Feature Reference: M18-T115 (DNS Resolution Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dns_resolution_latency (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    hostname TEXT NOT NULL,
    lookup_time_ms NUMERIC(10, 2) NOT NULL,
    resolver_ip INET,
    dns_server VARCHAR(100),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dns_resolution_latency IS 'Measures latency of DNS resolutions for application hosts.';

-- =====================================================================================================================
-- Table: M18-T423 - tls_handshake_metrics
-- Description: TLS/SSL handshake performance.
-- Business Case: Secure connections cost time. This table tracks the time taken to complete the TLS handshake,
--                 measuring the overhead of encryption.
-- KPIs: Handshake Duration, Handshake Failures, Session Resumption Rate.
-- Feature Reference: M18-T090 (SSL/TLS Certificate Expiry Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tls_handshake_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    service_name VARCHAR(100) NOT NULL,

    -- Metrics
    handshake_duration_ms NUMERIC(10, 2) NOT NULL,
    session_resumed BOOLEAN,

    -- Status
    success BOOLEAN NOT NULL,
    failure_reason TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.tls_handshake_metrics IS 'Monitors the performance overhead of secure TLS handshakes.';

-- =====================================================================================================================
-- Table: M18-T424 - http_header_size_metrics
-- Description: Analysis of HTTP header sizes.
-- Business Case: Huge headers (cookies, auth tokens) hit limits. This table tracks header sizes to prevent
--                 HTTP 431 errors or proxy failures.
-- KPIs: Avg Header Size, Max Header Size, Requests Rejected for Size.
-- Feature Reference: M18-T124 (API Endpoints)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.http_header_size_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    endpoint_id VARCHAR(100),
    header_size_bytes INTEGER NOT NULL,
    request_count INTEGER NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.http_header_size_metrics IS 'Analyzes HTTP header sizes to prevent limit errors.';

-- =====================================================================================================================
-- Table: M18-T425 - http_body_compression_metrics
-- Description: Gzip/Brotli compression savings.
-- Business Case: Bandwidth costs. This table tracks the compression ratio of HTTP bodies, validating the effectiveness
--                 of compression settings on the LB or API Gateway.
-- KPIs: Compression Ratio, Bandwidth Saved, Compression CPU Overhead.
-- Feature Reference: M18-T092 (Disk IOPS Latency) - General Performance context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.http_body_compression_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    content_type VARCHAR(100) NOT NULL,
    original_size_bytes BIGINT NOT NULL,
    compressed_size_bytes BIGINT NOT NULL,

    compression_ratio NUMERIC(5, 2) GENERATED ALWAYS AS (1.0 - (compressed_size_bytes::NUMERIC / NULLIF(original_size_bytes, 1))) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.http_body_compression_metrics IS 'Tracks efficiency and savings of HTTP body compression.';

-- =====================================================================================================================
-- Table: M18-T426 - protocol_upgrade_stats
-- Description: HTTP/1.1 to HTTP/2 upgrades.
-- Business Case: Performance migration. Tracking how many connections upgrade to HTTP/2 or HTTP/3 helps measure
--                 modern protocol adoption and performance gains.
-- KPIs: Protocol Split, Upgrade Success Rate, H2 Push Usage, H3 Connection Count.
-- Feature Reference: M18-T124 (API Endpoints)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.protocol_upgrade_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    protocol VARCHAR(10) NOT NULL, -- 'h2', 'http/1.1', 'h3'

    -- Metrics
    connection_count BIGINT NOT NULL,
    bytes_transferred BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.protocol_upgrade_stats IS 'Tracks usage of modern HTTP protocols (HTTP/2, HTTP/3).';

-- =====================================================================================================================
-- Table: M18-T427 - keepalive_stats
-- Description: TCP Keepalive metrics.
-- Business Case: Connection reuse. Keepalives reduce latency. This table tracks how often connections are reused
--                 vs. closed.
-- KPIs: Keepalive Hit Rate, Connection Duration, Time to First Byte (TTFB) with Keepalive.
-- Feature Reference: M18-T092 (Disk IOPS Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.keepalive_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    host_ip INET NOT NULL,

    -- Metrics
    connections_kept_alive BIGINT,
    connections_closed BIGINT,
    avg_lifetime_sec NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.keepalive_stats IS 'Monitors effectiveness of TCP Keepalive settings.';

-- =====================================================================================================================
-- Table: M18-T428 - tcp_connection_establishment_metrics
-- Description: Time to establish TCP connections.
-- Business Case: Network setup time. High SYN/SYN-ACK latency adds to total request latency. This table tracks
--                 the time taken to perform the TCP 3-way handshake.
-- KPIs: Handshake Duration, Retransmission Rate, SYN Drop Rate.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tcp_connection_establishment_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    destination_ip INET NOT NULL,
    destination_port INTEGER NOT NULL,

    -- Metrics
    connect_time_ms NUMERIC(10, 2),
    retransmissions INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.tcp_connection_establishment_metrics IS 'Tracks latency of TCP connection establishment.';

-- =====================================================================================================================
-- Table: M18-T429 - bandwidth_limiting_stats
-- Description: QoS / Throttling impact.
-- Business Case: Fairness. If bandwidth is limited (QoS), apps slow down. This table tracks when bandwidth
--                 throttling activates and its impact on throughput.
-- KPIs: Throttle Activation Count, Bandwidth Limit vs Usage, Throughput Drop %.
-- Feature Reference: M18-F092 (Disk IOPS Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bandwidth_limiting_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    interface VARCHAR(100),

    -- Limits
    max_bandwidth_mbps NUMERIC(10, 2),
    current_bandwidth_mbps NUMERIC(10, 2),
    is_throttled BOOLEAN,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.bandwidth_limiting_stats IS 'Monitors bandwidth throttling and its impact on performance.';

-- =====================================================================================================================
-- Table: M18-T430 - packet_reordering_stats
-- Description: Packet reordering metrics.
-- Business Case: TCP reordering. Some networks (satellite, specific VPNs) reorder packets. This can confuse
--                 some implementations. This table tracks reordering events.
-- KPIs: Reorder % (DupAcks), Duplicate ACKs, Out of Order Packets.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.packet_reordering_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    link_id VARCHAR(100) NOT NULL,

    -- Stats
    total_packets BIGINT,
    reordered_packets BIGINT,
    duplicate_packets BIGINT,

    reorder_rate NUMERIC(5, 2) GENERATED ALWAYS AS ((reordered_packets::NUMERIC / NULLIF(total_packets, 1)) * 100) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.packet_reordering_stats IS 'Tracks packet reordering and duplication on network links.';

-- =====================================================================================================================
-- Table: M18-T431 - jitter_stats
-- Description: Network jitter (latency variance).
-- Business Case: Real-time (VoIP, Gaming) or DB replication hates jitter. This table measures variance in latency
--                 (Jitter), which is as bad as high latency.
-- KPIs: Jitter (ms), Jitter Buffer Overflow, Packet Loss due to Jitter.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.jitter_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    flow_id VARCHAR(100) NOT NULL,

    -- Stats
    avg_latency_ms NUMERIC(10, 2),
    jitter_ms NUMERIC(10, 2), -- Standard deviation of latency
    worst_latency_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.jitter_stats IS 'Calculates network jitter (variance in latency).';

-- =====================================================================================================================
-- Table: M18-T432 - packet_loss_stats
-- Description: Packet loss monitoring.
-- Business Case: TCP recovery. Loss causes retransmissions, which are slow. This table tracks loss rates, helping
--                 identify unstable network segments.
-- KPIs: Packet Loss % (Input/Output), Retransmission Rate, TCP Backoff.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.packet_loss_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    interface VARCHAR(100) NOT NULL,

    -- Loss
    in_loss_pct NUMERIC(5, 2),
    out_loss_pct NUMERIC(5, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.packet_loss_stats IS 'Monitors packet loss rates on network interfaces.';

-- =====================================================================================================================
-- Table: M18-T433 - mtu_discovery_stats
-- Description: Path MTU detection.
-- Business Case: Fragmentation. If MTU is too small, packets fragment. If too big, they get dropped.
--                 This table tracks detected Path MTU to optimize connection settings.
-- KPIs: MTU Size, Fragmentation Count, MTU Changes, Packet Drop due to MTU.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.mtu_discovery_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    destination_ip INET NOT NULL,

    -- Stats
    mtu_bytes INTEGER NOT NULL,
    fragmentation_count INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.mtu_discovery_stats IS 'Tracks detected Path MTU for network connections.';

-- =====================================================================================================================
-- Table: M18-T434 - bgp_peering_metrics
-- Description: BGP peering status.
-- Business Case: Network routing. BGP peering status (Up/Down) determines if traffic takes optimal path.
--                 This table tracks BGP state for multi-homed deployments.
-- KPIs: Peer Availability, Route Propagation Time, ASN Count, Route Flaps.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bgp_peering_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    peer_asn NUMERIC(10) NOT NULL,

    -- State
    status VARCHAR(20) NOT NULL, -- 'Established', 'Idle', 'Active'
    uptime_pct NUMERIC(5, 2),

    prefix_count INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.bgp_peering_metrics IS 'Monitors BGP peering status for network connectivity.';

-- =====================================================================================================================
-- Table: M18-T435 - load_balancer_metrics
-- Description: LB distribution metrics.
-- Business Case: Load balancing efficiency. This table ensures traffic is distributed evenly across backend
--                 servers and that no backend is overwhelmed.
-- KPIs: Backend Request Count, Backend Error Rate, Backend Latency, Max Connections.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.load_balancer_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    lb_name VARCHAR(100) NOT NULL,
    backend_address TEXT NOT NULL,

    -- Metrics
    request_count BIGINT NOT NULL,
    avg_latency_ms NUMERIC(10, 2),
    active_connections INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.load_balancer_metrics IS 'Tracks traffic distribution to backend targets.';

-- =====================================================================================================================
-- Table: M18-T436 - cdn_cache_hit_ratios
-- Description: CDN performance.
-- Business Case: Offloading origin. This table tracks hit ratios for static assets served via CDN,
--                 determining cost savings and performance gains.
-- KPIs: Cache Hit %, Origin Offload %, Edge Latency vs Origin Latency, Bandwidth Saved.
-- Feature Reference: M18-T091 (Network Latency)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cdn_cache_hit_ratios (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    cdn_provider VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50), -- 'Image', 'Script', 'API'

    -- Metrics
    hits BIGINT,
    misses BIGINT,
    hit_ratio NUMERIC(5, 2) GENERATED ALWAYS AS ((hits::NUMERIC / NULLIF((hits+misses), 1)) * 100) STORED,

    bandwidth_saving_gb NUMERIC(15, 4),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.cdn_cache_hit_ratios IS 'Measures cache hit ratios for Content Delivery Networks.';

-- =====================================================================================================================
-- Table: M18-T437 - origin_server_health
-- Description: Health of origin servers behind CDN/LB.
-- Business Case: The root. If the origin server (where the app runs) is slow, the CDN doesn't matter.
--                 This table monitors the health of PARI origin servers from the edge perspective.
-- KPIs: Origin Availability, Origin Latency, 5xx Error Rate at Origin.
-- Feature Reference: M18-T027 (Deployments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.origin_server_health (
    health_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    origin_name VARCHAR(100) NOT NULL,

    -- Health
    is_up BOOLEAN NOT NULL,
    health_check_latency_ms NUMERIC(10, 2),

    -- Errors
    error_rate NUMERIC(5, 2),

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.origin_server_health IS 'Health checks for origin servers from CDN/Proxy perspective.';

-- =====================================================================================================================
-- Table: M18-T438 - edge_function_metrics
-- Description: Edge computing (Cloudflare Workers, Lambda@Edge) stats.
-- Business Case: Offloading logic. Edge functions run at the PoP. This table tracks their execution time and success.
-- KPIs: Edge Request Count, Execution Duration, Cold Start Latency, Error Rate.
-- Feature Reference: M18-T027 (Deployments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.edge_function_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    function_name VARCHAR(100) NOT NULL,

    -- Metrics
    invocation_count BIGINT,
    avg_exec_time_ms NUMERIC(10, 2),
    error_count BIGINT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.edge_function_metrics IS 'Tracks performance of edge computing functions.';

-- =====================================================================================================================
-- Table: M18-T439 - waf_rule_execution_stats
-- Description: Performance of WAF rules.
-- Business Case: Security overhead. Complex Regex rules in WAF can be slow. This table tracks time spent in each
--                 rule to identify performance bottlenecks in the security layer.
-- KPIs: Rule Execution Time, Rule Trigger Count, Blocked Requests, Rule CPU %.
-- Feature Reference: M18-T107 (WAF Rules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.waf_rule_execution_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    rule_id VARCHAR(100) NOT NULL,

    -- Metrics
    total_time_ms NUMERIC(10, 2),
    triggered_count BIGINT,
    blocked_count BIGINT,

    avg_time_ms NUMERIC(10, 2) GENERATED ALWAYS AS (total_time_ms / NULLIF(triggered_count, 1)) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.waf_rule_execution_stats IS 'Monitors execution time and impact of specific WAF rules.';

-- =====================================================================================================================
-- Table: M18-T440 - ddos_mitigation_stats
-- Description: Effectiveness of DDoS mitigation.
-- Business Case: Survival under attack. When under DDoS, mitigation rules trigger. This table tracks if they
--                 successfully blocked the bad traffic and let the good traffic through.
-- KPIs: Attack Volume, Blocked Volume, Legitimate Traffic Preservation, Mitigation Latency.
-- Feature Reference: M18-T144 (DDoS Signatures)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ddos_mitigation_stats (
    mitigation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    attack_signature VARCHAR(100) NOT NULL,

    -- Stats
    packets_blocked BIGINT,
    packets_allowed BIGINT,
    mitigation_mode VARCHAR(50), -- 'Challenge', 'Blackhole', 'RateLimit'

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ddos_mitigation_stats IS 'Evaluates the effectiveness of DDoS mitigation strategies.';

-- =====================================================================================================================
-- Table: M18-T441 - bot_detection_signals
-- Description: Bot traffic analysis.
-- Business Case: Good vs Bad bots. Not all bots are bad (Google bot). This table classifies traffic,
--                 distinguishing friendly crawlers from malicious scrapers.
-- KPIs: Bot Traffic %, Malicious Bot Count, Whitelisted Bot Hits, User-Agent Spoofing.
-- Feature Reference: M18-T131 (User Agent Parser)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bot_detection_signals (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    ip_address INET NOT NULL,
    user_agent TEXT,

    -- Classification
    bot_category VARCHAR(50) NOT NULL, -- 'SearchEngine', 'Scraper', 'Malicious', 'Verified'
    confidence_score NUMERIC(3, 2),

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.bot_detection_signals IS 'Stores signals from bot detection analysis.';

-- =====================================================================================================================
-- Table: M18-T442 - credential_stuffing_attempts
-- Description: Credential stuffing attack logs.
-- Business Case: Stolen passwords. Attackers test leaked username/password combos. This table logs detected
--                 stuffing attempts to block them or force MFA.
-- KPIs: Stuffing Attempts, Blocked Requests, Compromised Account Count, Source IPs.
-- Feature Reference: M18-T143 (Brute Force Attack Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.credential_stuffing_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    username VARCHAR(100) NOT NULL,

    -- Source
    ip_address INET NOT NULL,
    user_agent TEXT,

    -- Status
    success BOOLEAN, -- Successful login
    blocked BOOLEAN NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.credential_stuffing_attempts IS 'Logs credential stuffing attempts on authentication endpoints.';

-- =====================================================================================================================
-- Table: M18-T443 - api_abuse_detection
-- Description: Patterns of API abuse.
-- Business Case: Reselling access or scraping. This table detects patterns like one account making 10,000 API calls
--                 per hour, indicating reselling or scraping.
-- KPIs: Abuse Case Count, Abusive Volume, Rule Trigger Count, Abuse Prevention Success.
-- Feature Reference: M18-T103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_abuse_detection (
    detection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    api_key_hash CHAR(64) NOT NULL,

    -- Abuse Pattern
    pattern_type VARCHAR(50) NOT NULL, -- 'HighVelocity', 'GeoAnomaly', 'UnusualHours'
    violation_count BIGINT,

    -- Action
    action_taken VARCHAR(20), -- 'Blocked', 'RateLimited', 'Warned'

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.api_abuse_detection IS 'Detects and logs API abuse patterns for API keys.';

-- =====================================================================================================================
-- Table: M18-T444 - scraping_detection
-- Description: Web scraping detection.
-- Business Case: Content protection. Scrapers steal proprietary data (prices, lists). This table logs detection
--                 of scraping behavior (ignoring robots.txt, high velocity, linear navigation).
-- KPIs: Scraper IPs Blocked, Content Protected, False Positive Rate, Scraping Volume.
-- Feature Reference: M18-T103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.scraping_detection (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    ip_address INET NOT NULL,

    -- Indicators
    request_count INTEGER NOT NULL,
    accessed_unique_items INTEGER,
    linear_navigation_score NUMERIC(5, 2),

    -- Action
    blocked BOOLEAN DEFAULT true,
    reason TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.scraping_detection IS 'Logs detection of web scraping activity.';

-- =====================================================================================================================
-- Table: M18-T445 - account_takeover_attempts
-- Description: ATO pattern detection.
-- Business Case: Account Security. ATO often involves failed logins from new locations, followed by a success.
--                 This table logs anomalies in login behavior.
-- KPIs: ATO Score, Suspicious Login Count, New Location Logins, Velocity Changes.
-- Feature Reference: M18-T143 (Brute Force Attack Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.account_takeover_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,

    -- Login Details
    success BOOLEAN NOT NULL,
    ip_address INET,
    device_fingerprint CHAR(64),

    -- Anomaly Score
    anomaly_score NUMERIC(3, 2), -- 0 to 1
    reason VARCHAR(100), -- 'NewCity', 'NewDevice', 'ImprobableVelocity'

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.account_takeover_attempts IS 'Logs anomalies indicating potential account takeover.';

-- =====================================================================================================================
-- Table: M18-T446 - identity_resolution_latency
-- Description: Time to resolve identity.
-- Business Case: UX bottleneck. If fetching user profile (Identity) takes 1 second, the page loads slow.
--                 This table tracks latency of identity resolution from IDP or Auth Provider.
-- KPIs: Resolution Time (p95), Cache Hit Rate for Identity, Resolution Error Rate.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.identity_resolution_latency (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    provider VARCHAR(100) NOT NULL,
    operation VARCHAR(50) NOT NULL, -- 'Auth', 'UserProfile', 'MFA'

    -- Metrics
    duration_ms NUMERIC(10, 2) NOT NULL,
    success BOOLEAN NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.identity_resolution_latency IS 'Tracks latency of identity provider operations.';

-- =====================================================================================================================
-- Table: M18-T447 - mfa_factor_usage_stats
-- Description: Usage stats for MFA factors.
-- Business Case: Security vs UX. This table tracks which MFA methods (SMS, TOTP, YubiKey) are used and their
--                 failure rates, to optimize the security experience.
-- KPIs: Factor Usage %, Factor Success Rate, SMS Delivery Failures, TOTP Drift.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.mfa_factor_usage_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    factor_type VARCHAR(50) NOT NULL, -- 'Sms', 'Totp', 'HardwareKey', 'Biometric'

    -- Stats
    attempts BIGINT NOT NULL,
    successes BIGINT NOT NULL,
    failures BIGINT NOT NULL,

    success_rate NUMERIC(5, 2) GENERATED ALWAYS AS ((successes::NUMERIC / NULLIF(attempts, 1)) * 100) STORED,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.mfa_factor_usage_stats IS 'Analyzes usage and success rates of Multi-Factor Authentication methods.';

-- =====================================================================================================================
-- Table: M18-T448 - biometric_verification_logs
-- Description: Biometric authentication logs.
-- Business Case: High security, High UX. Biometrics (Face, Fingerprint) are sensitive. This table logs
--                 verification results (Match, No Match, Error), ensuring auditability.
-- KPIs: Verification Accuracy, False Rejection Rate, Template Creation Rate, Verification Speed.
-- Feature Reference: M18-T357 (KYC Verification Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.biometric_verification_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Biometric Data
    template_id VARCHAR(100), -- Reference to stored template
    match_score NUMERIC(5, 2), -- Similarity Score

    -- Result
    status VARCHAR(20) NOT NULL, -- 'Match', 'NoMatch', 'Error'
    verification_time_ms NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.biometric_verification_logs IS 'Stores results of biometric verification attempts.';

-- =====================================================================================================================
-- Table: M18-T449 - privilege_escalation_attempts
-- Description: Logs of PAM (Privileged Access Management) escalation.
-- Business Case: Controlling power. Escalation to root or admin is risky. This table logs who requested escalation,
--                 why, and if it was approved.
-- KPIs: Escalation Frequency, Denial Rate, Justification Capture, Session Duration for Privileged Access.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.privilege_escalation_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Request
    requested_role VARCHAR(100) NOT NULL,
    justification TEXT NOT NULL,

    -- Approval
    approver_id UUID,
    approved BOOLEAN NOT NULL,

    -- Session
    granted_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.privilege_escalation_attempts IS 'Audits requests for temporary privilege escalation.';

-- =====================================================================================================================
-- Table: M18-T450 - session_hijacking_alerts
-- Description: Alerts for session hijacking.
-- Business Case: Detecting "Session Fixation" or ID side-jacking. This table logs alerts triggered by
--                 anomalies in session behavior (IP change, impossible travel).
-- KPIs: Hijack Alerts, True Positive Rate, Account Recovery Time, Blocked Sessions.
-- Feature Reference: M18-T172 (Sessions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.session_hijacking_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    user_id UUID NOT NULL,

    -- Trigger
    reason_code VARCHAR(50) NOT NULL, -- 'IPChange', 'ImpossibleTravel', 'DeviceFingerprintMismatch'

    -- Details
    old_ip INET,
    new_ip INET,

    -- Action
    action_taken VARCHAR(20) DEFAULT 'Terminate', -- 'Terminate', 'NotifyUser', 'Ignore'

    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (session_id) REFERENCES cmmi.sessions(session_id)
);

COMMENT ON TABLE cmmi.session_hijacking_alerts IS 'Logs security alerts triggered by session anomaly detection.';

-- =====================================================================================================================
-- Triggers for Part 7 (T351-T450)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_sbom_metadata
    BEFORE UPDATE ON cmmi.sbom_entries
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_feature_flags_metadata
    BEFORE UPDATE ON cmmi.feature_flags_metadata
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_kyc_verification_records
    BEFORE UPDATE ON cmmi.kyc_verification_records
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_patent_ip_assets
    BEFORE UPDATE ON cmmi.patent_ip_assets
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_roadmap_progress_tracking
    BEFORE UPDATE ON cmmi.roadmap_progress_tracking
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_connection_proxy_metrics
    BEFORE UPDATE ON cmmi.connection_proxy_metrics
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 351-450)
-- =====================================================================================================================

-- =====================================================================================================================
-- MODULE M18: CMMI Level 5 Process Automation - Part 8
-- Tables DB451 - DB550
-- =====================================================================================================================

-- Note: Tables M18-T451 through M18-T550 are derived from Gap Analysis and Exhaustive Research to cover
-- Advanced Governance (Signatures), Talent Management (Attributes/Onboarding), MLOps (Lineage/Experiments),
-- Financial Operations (Settlement/Invoicing), and System Notification/Auditing.

-- =====================================================================================================================
-- Table: M18-T451 - compliance_framework_signing
-- Description: Signing off on compliance frameworks.
-- Business Case: Accountability and legal liability. Executives and compliance officers must formally sign off on the
--                 organization's adherence to frameworks like SOC2, ISO 27001, and PCI-DSS. This table stores the
--                 digital signatures or acknowledgments of these sign-offs, providing an immutable record of responsibility
--                 during audits.
-- KPIs: Signature Coverage %, Signature Freshness, Executory Participation Rate, Audit Readiness Score, Sign-off Latency.
-- Feature Reference: M18-T162 (Compliance Frameworks)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_framework_signing (
    signing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL, -- Ref T162

    -- The Signatory
    signatory_name VARCHAR(255) NOT NULL,
    signatory_role VARCHAR(100) NOT NULL,
    signatory_title VARCHAR(100),

    -- The Action
    signature_type VARCHAR(50) NOT NULL CHECK (signature_type IN ('Digital', 'WetInk', 'Delegated')),
    statement_text TEXT NOT NULL,

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE, -- NULL implies indefinite until revoked
    is_revoked BOOLEAN DEFAULT false,

    -- Audit
    ip_address INET,
    user_agent TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id)
);

COMMENT ON TABLE cmmi.compliance_framework_signing IS 'Stores digital acknowledgments and signatures for compliance frameworks.';

CREATE INDEX idx_framework_signing_framework ON cmmi.compliance_framework_signing (framework_id);
CREATE INDEX idx_framework_signing_signatory ON cmmi.compliance_framework_signing (signatory_name);

-- =====================================================================================================================
-- Table: M18-T452 - framework_review_history
-- Description: History of reviews for compliance frameworks.
-- Business Case: Continuous improvement of compliance posture. Compliance isn't static; it requires regular reviews (quarterly/annually).
--                 This table records the outcomes of these reviews, noting new gaps identified, remediation plans accepted,
--                 and maturity level targets.
-- KPIs: Review Frequency, Remediation Velocity, Gap Reduction Rate, Reviewer Participation, Compliance Trend Score.
-- Feature Reference: M18-T216 (Process Assessments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.framework_review_history (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL,

    -- Details
    review_date DATE NOT NULL,
    reviewer_id UUID,

    -- Outcomes
    maturity_level_achieved VARCHAR(20), -- e.g., 'Level 4', 'Level 5'
    summary TEXT,
    action_plan_link TEXT, -- Link to document

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id)
);

COMMENT ON TABLE cmmi.framework_review_history IS 'Tracks periodic reviews of compliance frameworks and maturity levels.';

CREATE INDEX idx_framework_review_framework ON cmmi.framework_review_history (framework_id);

-- =====================================================================================================================
-- Table: M18-T453 - compliance_framework_signatory
-- Description: Stores details of individuals authorized to sign.
-- Business Case: Governance. Not everyone can sign off on behalf of the company. This table defines the authorized signatories
--                 for each framework, ensuring that digital signatures in T451 come from recognized roles.
-- KPIs: Authorized Signatory Count, Role Coverage, Delegated Signatory %.
-- Feature Reference: M18-T162 (Compliance Frameworks)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_framework_signatory (
    signatory_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    framework_id UUID NOT NULL,

    -- Identity
    user_id UUID NOT NULL,
    role VARCHAR(100) NOT NULL, -- 'CISO', 'CTO', 'VP Engineering'

    -- Authorization
    is_primary BOOLEAN DEFAULT false, -- Primary vs Backup signer
    delegation_chain TEXT, -- If delegated, who delegated it to this user?

    valid_from DATE NOT NULL,
    valid_until DATE,

    FOREIGN KEY (framework_id) REFERENCES cmmi.compliance_frameworks(framework_id),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.compliance_framework_signatory IS 'Defines authorized personnel for signing off on compliance frameworks.';

-- =====================================================================================================================
-- Table: M18-T454 - governance_policy_versions
-- Description: Versioning of governance documents.
-- Business Case: Regulatory compliance requires proving what policy was in effect when. This table versions internal policies
--                 (e.g., "Access Control Policy", "Data Retention Policy"), storing diffs and effective dates.
-- KPIs: Policy Version Count, Policy Update Frequency, Version Access Count, Policy Age.
-- Feature Reference: M18-T331 (Policy Version History)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.governance_policy_versions (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Identity
    policy_name VARCHAR(255) NOT NULL,
    version_number VARCHAR(20) NOT NULL,

    -- Content
    document_url TEXT NOT NULL,
    hash_sha256 CHAR(64), -- Integrity of the policy doc

    -- Lifecycle
    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
    effective_until TIMESTAMP WITH TIME ZONE, -- NULL implies current
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Published', 'Archived'

    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.governance_policy_versions IS 'Manages lifecycle and versioning of internal governance policies.';

-- =====================================================================================================================
-- Table: M18-T455 - policy_review_cycle
-- Description: Workflow for reviewing policies.
-- Business Case: Stale policies are a risk. This table manages the workflow for mandatory policy reviews (e.g., annual review
--                 of the Information Security Policy), tracking reminders, assignments, and review outcomes.
-- KPIs: Review Cycle Adherence %, Review Completion Time, Policy Revision Rate, Reminder Effectiveness.
-- Feature Reference: M18-T206 (Process Asset Library)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.policy_review_cycle (
    cycle_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL, -- Ref T454

    -- Schedule
    last_review_date DATE,
    next_review_date DATE NOT NULL,
    review_frequency_days INTEGER NOT NULL, -- e.g., 365

    -- Workflow
    assigned_reviewer_id UUID,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'In Progress', 'Completed', 'Overdue'

    -- Outcome
    revision_required BOOLEAN DEFAULT false,
    revision_summary TEXT,

    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES cmmi.governance_policy_versions(policy_id)
);

COMMENT ON TABLE cmmi.policy_review_cycle IS 'Schedules and tracks the mandatory review cycle for governance policies.';

-- =====================================================================================================================
-- Table: M18-T456 - developer_attributes
-- Description: Extended attributes for developers.
-- Business Case: Capacity planning and engagement. Standard user tables (T167) don't capture HR-specific data like office location,
--                 employment type (Contractor/Full-time), or tenure. This table enriches user profiles to optimize team
--                 composition and support remote work policies.
-- KPIs: Remote Work %, Contractor Ratio, Tenure Distribution, Skill Density, Engagement Score.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.developer_attributes (
    user_id UUID NOT NULL, -- Ref T167
    attribute_type VARCHAR(50) NOT NULL, -- 'Location', 'EmploymentType', 'Grade'
    attribute_value TEXT NOT NULL,

    is_active BOOLEAN DEFAULT true,
    effective_from DATE,
    effective_until DATE,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, attribute_type),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.developer_attributes IS 'Stores extended HR and organizational attributes for developers.';

-- =====================================================================================================================
-- Table: M18-T457 - employment_status_history
-- Description: History of status changes.
-- Business Case: Security and Asset Return. Tracking when employees go on leave, probation, or resignation is vital for
--                 access revocation (T363) and asset return (T463).
-- KPIs: Status Change Volume, Active vs Inactive Ratio, Return Rate (Boomerang), Probation Failure Rate.
-- Feature Reference: M18-T363 (Employee Offboarding)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.employment_status_history (
    history_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Status
    status VARCHAR(50) NOT NULL, -- 'Active', 'Probation', 'Leave', 'Resigned', 'Terminated'
    status_date DATE NOT NULL,
    reason TEXT,

    -- Context
    notified_hr BOOLEAN DEFAULT false,
    access_revoked BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.employment_status_history IS 'Tracks lifecycle status changes for employees.';

-- =====================================================================================================================
-- Table: M18-T458 - performance_review_history
-- Description: Annual/Quarterly review history.
-- Business Case: Talent Development. Performance reviews are the primary feedback loop. This table stores ratings and
--                 goals, allowing HR and management to track growth and identify low performers who need training
--                 (T203/T204).
-- KPIs: Review Completion Rate, Average Rating, Rating Trend, Goal Achievement %, Promotion Rate.
-- Feature Reference: M18-T046 (Skill Gap Analysis)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.performance_review_history (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    reviewer_id UUID,

    -- Review Details
    review_period VARCHAR(50) NOT NULL, -- 'Q1 2023', 'Annual'
    overall_rating NUMERIC(3, 1), -- 1 to 5
    comments TEXT,

    -- Goals
    goals_met VARCHAR(20), -- 'Exceeded', 'Met', 'Partially Met', 'Missed'
    promotion_flag BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (reviewer_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.performance_review_history IS 'Stores historical performance reviews for developers.';

-- =====================================================================================================================
-- Table: M18-T459 - learning_path_progress
-- Description: Tracking a dev's progress through a learning path.
-- Business Case: Structured upskilling. Instead of random courses, devs follow "Paths" (e.g., "Cloud Native Dev").
--                 This table tracks completion of courses (T203) within a path, ensuring all prerequisites are met.
-- KPIs: Path Completion Rate, Time to Complete Path, Drop-off Rate, Certification Rate, Path Relevance.
-- Feature Reference: M18-T203 (Training Catalog)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.learning_path_progress (
    progress_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    learning_path_id UUID NOT NULL, -- Logical ID for the path

    -- Progress
    total_modules INTEGER,
    completed_modules INTEGER DEFAULT 0,
    completion_pct NUMERIC(5, 2) GENERATED ALWAYS AS (
        CASE WHEN total_modules > 0 THEN (completed_modules::NUMERIC / total_modules) * 100 ELSE 0 END
    ) STORED,

    -- Status
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Completed', 'On Hold'
    target_completion_date DATE,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.learning_path_progress IS 'Tracks developer progress through structured learning paths.';

-- =====================================================================================================================
-- Table: M18-T460 - mentoring_relationships
-- Description: Mentor-Mentee tracking.
-- Business Case: Knowledge transfer. Ensuring knowledge transfer (T277) requires tracking who is mentoring whom.
--                 This table links mentors to mentees, tracking the relationship duration and outcomes.
-- KPIs: Mentee Growth Rate, Mentee Retention, Mentor Capacity, Relationship Duration, Promotion Rate of Mentees.
-- Feature Reference: M18-T277 (Knowledge Base)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.mentoring_relationships (
    relationship_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mentor_id UUID NOT NULL,
    mentee_id UUID NOT NULL,

    -- Details
    start_date DATE NOT NULL,
    end_date DATE,

    goals TEXT,
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Completed', 'Terminated'

    FOREIGN KEY (mentor_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (mentee_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.mentoring_relationships IS 'Manages mentor-mentee assignments and progress.';

-- =====================================================================================================================
-- Table: M18-T461 - onboarding_checklist
-- Description: Tasks for new hires.
-- Business Case: Standardizing onboarding. Ensures every new hire gets their laptop, accounts, and badges.
--                 This table defines the checklist items and tracks completion status.
-- KPIs: Checklist Completion % (Day 1/7), Asset Ready Time, Account Provisioning Time, Manager Checklist Sign-off.
-- Feature Reference: M18-T363 (Employee Offboarding)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.onboarding_checklist (
    checklist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Task
    item_name VARCHAR(255) NOT NULL,
    item_category VARCHAR(50), -- 'Hardware', 'Accounts', 'Training'

    -- Status
    owner_id UUID,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'In Progress', 'Completed', 'Blocked'
    completed_at TIMESTAMP WITH TIME ZONE,

    notes TEXT,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.onboarding_checklist IS 'Defines and tracks mandatory onboarding tasks for new hires.';

-- =====================================================================================================================
-- Table: M18-T462 - offboarding_checklist
-- Description: Tasks for leaving employees.
-- Business Case: Security and Asset Recovery. Offboarding is security-critical (revoking access, recovering hardware).
--                 This table ensures T363 is comprehensive, with sign-offs from IT, HR, and Finance.
-- KPIs: Access Revocation Speed, Asset Return Rate, Account Deletion Latency, Checklist Completion Time.
-- Feature Reference: M18-T363 (Employee Offboarding)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.offboarding_checklist (
    checklist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Task
    item_name VARCHAR(255) NOT NULL,
    item_category VARCHAR(50), -- 'Access', 'Hardware', 'Finance', 'Documentation'

    -- Status
    owner_id UUID,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'In Progress', 'Completed', 'Escalated'
    completed_at TIMESTAMP WITH TIME ZONE,

    notes TEXT,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.offboarding_checklist IS 'Defines and tracks tasks for employee separation.';

-- =====================================================================================================================
-- Table: M18-T463 - equipment_inventory
-- Description: Laptops, monitors assigned.
-- Business Case: Asset Management. Tracking the lifecycle of IT assets (Procurement -> Assignment -> Decommission).
--                 This table stores inventory data, linking hardware to users (T464).
-- KPIs: Asset Utilization %, Asset Age, Maintenance Overhead, Lost/Stolen Asset Count, Inventory Accuracy.
-- Feature Reference: M18-T116 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.equipment_inventory (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Asset Details
    asset_tag VARCHAR(50) UNIQUE NOT NULL, -- "MAC00123"
    asset_type VARCHAR(50) NOT NULL, -- 'Laptop', 'Monitor', 'Server'
    make VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),

    -- Lifecycle
    purchase_date DATE,
    purchase_cost NUMERIC(10, 2),
    status VARCHAR(20) DEFAULT 'InStock', -- 'InStock', 'Assigned', 'InRepair', 'Retired'

    current_user_id UUID, -- Ref T167
    assigned_date DATE,

    FOREIGN KEY (current_user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.equipment_inventory IS 'Inventory database for IT hardware assets.';

-- =====================================================================================================================
-- Table: M18-T464 - equipment_allocation
-- Description: Assignment history of assets.
-- Business Case: Audit trail. Knowing who had what device and when is crucial for data breaches (e.g., "Who had
--                 the laptop that was lost?"). This table tracks the movement of assets between users.
-- KPIs: Swap Frequency, Asset Utilization Rate, Assignment Accuracy, Unassigned Asset Count.
-- Feature Reference: M18-T463 (Equipment Inventory)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.equipment_allocation (
    allocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL,
    user_id UUID,

    -- Timeline
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    returned_at TIMESTAMP WITH TIME ZONE,

    -- Status
    condition_on_return TEXT,

    FOREIGN KEY (asset_id) REFERENCES cmmi.equipment_inventory(asset_id),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.equipment_allocation IS 'Tracks the history of equipment assignments to users.';

-- =====================================================================================================================
-- Table: M18-T465 - software_licenses
-- Description: Managing tool licenses (JetBrains, Datadog).
-- Business Case: Cost Optimization. SaaS (Software as a Service) licenses are expensive. This table tracks seat counts,
--                 vendors, and costs, enabling FinOps to identify unused licenses (T466).
-- KPIs: License Utilization %, Cost per Seat, Expiring License Count, Vendor Spend, License Compliance.
-- Feature Reference: M18-F157 (Cost Anomaly Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.software_licenses (
    license_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    vendor_name VARCHAR(100) NOT NULL,
    product_name VARCHAR(100) NOT NULL,
    license_key VARCHAR(255), -- Product Key or Enterprise Agreement ID

    -- Terms
    total_seats INTEGER NOT NULL,
    used_seats INTEGER DEFAULT 0,
    cost_per_seat NUMERIC(10, 2),
    billing_currency CHAR(3) DEFAULT 'USD',

    -- Lifecycle
    renewal_date DATE,
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'Suspended', 'Expired'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.software_licenses IS 'Tracks usage and cost of software subscriptions and licenses.';

CREATE INDEX idx_licenses_vendor ON cmmi.software_licenses (vendor_name);

-- =====================================================================================================================
-- Table: M18-T466 - seat_usage_metrics
-- Description: Are they using the licenses?
-- Business Case: Justifying spend. If a tool has 100 seats but only 20 active users, we should downgrade.
--                 This table logs daily active user counts to optimize licensing costs.
-- KPIs: Utilization % (Target >80%), Seat Efficiency, Cost Reduction Opportunity, Active User Trends.
-- Feature Reference: M18-T465 (Software Licenses)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.seat_usage_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    license_id UUID NOT NULL,

    -- Metrics
    active_users INTEGER NOT NULL,
    unique_logins INTEGER NOT NULL,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (license_id) REFERENCES cmmi.software_licenses(license_id)
);

COMMENT ON TABLE cmmi.seat_usage_metrics IS 'Tracks actual usage metrics for software licenses to optimize spend.';

-- =====================================================================================================================
-- Table: M18-T467 - access_request_workflow
-- Description: Requesting access (Ticket based).
-- Business Case: Auditable access grants. Instead of direct assignment, users request access via Jira ticket (T140).
--                 This table tracks the workflow (Request -> Approval -> Provisioning).
-- KPIs: Request Approval Time, Request Denial Rate, Access Request Volume, Provisioning Accuracy.
-- Feature Reference: M18-T168 (Roles)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.access_request_workflow (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id VARCHAR(100) NOT NULL, -- Ref T140 (External Issues)
    requester_id UUID NOT NULL,

    -- Request Details
    resource_type VARCHAR(100) NOT NULL, -- 'Database', 'Server', 'Repo'
    access_level VARCHAR(50) NOT NULL, -- 'Read', 'Write', 'Admin'
    justification TEXT NOT NULL,

    -- Decision
    approver_id UUID,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending', -- 'Pending', 'Approved', 'Rejected'

    -- Execution
    provisioned_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (requester_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (approver_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.access_request_workflow IS 'Manages ticket-based access request workflow.';

CREATE TRIGGER trigger_update_access_request_workflow
    BEFORE UPDATE ON cmmi.access_request_workflow
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Table: M18-T468 - access_revocation_log
-- Description: Detailed log of revoked access.
-- Business Case: Security Audit. Simply removing a row from a table isn't an audit trail. This table explicitly logs
--                 "Access revoked for User X on Resource Y", providing forensic data for security incidents.
-- KPIs: Revocation Accuracy, Revocation Latency, Revocation Volume, Revocation Due to Offboarding %.
-- Feature Reference: M18-T467 (Access Request Workflow)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.access_revocation_log (
    revocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    user_id UUID NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(100), -- Specific DB ID, Server Name, etc.

    -- Reason
    reason_code VARCHAR(50) NOT NULL, -- 'Offboarding', 'PolicyViolation', 'RoleChange'
    reason_text TEXT,

    -- Execution
    revoked_by UUID NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (revoked_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.access_revocation_log IS 'Immutable audit log of access revocations.';

-- =====================================================================================================================
-- Table: M18-T469 - session_termination_log
-- Description: Why a session was killed.
-- Business Case: User Experience and Security. Sessions can be killed by admin, token expiry, or security (T108).
--                 This table logs termination events to debug login issues or detect suspicious admin actions.
-- KPIs: Termination Rate, Termination Reason Distribution, Average Session Duration, Admin Termination %.
-- Feature Reference: M18-T172 (Sessions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.session_termination_log (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL, -- Ref T172

    user_id UUID,
    termination_reason VARCHAR(100) NOT NULL, -- 'AdminKill', 'TokenExpiry', 'PasswordChange'
    terminated_by UUID, -- NULL if system (expiry)

    terminated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (session_id) REFERENCES cmmi.sessions(session_id)
);

COMMENT ON TABLE cmmi.session_termination_log IS 'Logs details of forced session terminations.';

-- =====================================================================================================================
-- Table: M18-T470 - data_lineage
-- Description: Input -> Transformation -> Output tracking.
-- Business Case: AI/ML Reproducibility and Debugging. In complex data pipelines, it is hard to trace where a specific
--                 data point came from. This table tracks data lineage (Source -> Transformation -> Target), enabling
--                 impact analysis when source data is corrupt.
-- KPIs: Lineage Completeness, Transformation Traceability, Data Source Quality, Dependency Depth.
-- Feature Reference: M18-T085 (Training Data Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_lineage (
    lineage_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Source
    source_id VARCHAR(255) NOT NULL, -- Table/File/API
    source_type VARCHAR(50) NOT NULL,
    source_hash CHAR(64), -- Hash of source data for change detection

    -- Transformation
    transformation_id VARCHAR(255),
    transformation_desc TEXT,

    -- Target
    target_id VARCHAR(255) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_hash CHAR(64),

    -- Context
    pipeline_id VARCHAR(255),
    execution_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.data_lineage IS 'Tracks the flow and transformation of data through pipelines.';

-- =====================================================================================================================
-- Table: M18-T471 - ml_experiments
-- Description: Tracking ML experiment runs.
-- Business Case: Scientific Methodology for ML. Developing models requires rigorous experiment tracking (Hypothesis, Variables,
--                 Outcome). This table stores the metadata of experiments, ensuring that winning models can be reproducible.
-- KPIs: Experiment Success Rate, Model Lift vs Baseline, Experiment Duration, Repeatability Score, Cost per Experiment.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ml_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,

    -- Hypothesis
    hypothesis TEXT NOT NULL,
    baseline_metric NUMERIC(10, 2), -- e.g., baseline F1 score
    target_metric NUMERIC(10, 2),

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Running', 'Completed', 'Aborted'
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,

    -- Result
    outcome_metric NUMERIC(10, 2), -- e.g., final F1 score
    is_significant BOOLEAN, -- Statistically significant?

    owner_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.ml_experiments IS 'Stores metadata and results of machine learning experiments.';

CREATE TRIGGER trigger_update_ml_experiments
    BEFORE UPDATE ON cmmi.ml_experiments
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Table: M18-T472 - experiment_parameters
-- Description: Hyperparams for an experiment.
-- Business Case: Reproducibility. To reproduce an experiment (T471), one must know exactly which hyperparameters
--                 (learning rate, tree depth) were used. This table stores these parameters.
-- KPIs: Parameter Search Space, Parameter Tuning Efficiency, Best Parameter Convergence.
-- Feature Reference: M18-T069 (Hyperparameters)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.experiment_parameters (
    param_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id UUID NOT NULL,

    -- Parameters
    parameter_name VARCHAR(100) NOT NULL,
    parameter_value JSONB NOT NULL,

    data_type VARCHAR(50), -- 'Float', 'Int', 'String', 'Array'

    FOREIGN KEY (experiment_id) REFERENCES cmmi.ml_experiments(experiment_id)
);

COMMENT ON TABLE cmmi.experiment_parameters IS 'Stores hyperparameter configurations for ML experiments.';

-- =====================================================================================================================
-- Table: M18-T473 - experiment_artifacts
-- Description: Links to models/data for an experiment.
-- Business Case: Audit Trail. Linking the experiment to the resulting Model ID (T176/Model Version) and Training Data ID (T068)
--                 creates a permanent record of what produced the deployed model.
-- KPIs: Artifact Linkage, Model Retention, Data Retention, Experiment Artifacts Size.
-- Feature Reference: M18-T118 (Model Training Runs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.experiment_artifacts (
    artifact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id UUID NOT NULL,

    -- Artifacts
    artifact_type VARCHAR(50) NOT NULL, -- 'Model', 'Dataset', 'DockerImage'
    artifact_reference_id VARCHAR(255) NOT NULL, -- UUID or Path
    artifact_version VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (experiment_id) REFERENCES cmmi.ml_experiments(experiment_id)
);

COMMENT ON TABLE cmmi.experiment_artifacts IS 'Links generated artifacts (models/data) to their source experiment.';

-- =====================================================================================================================
-- Table: M18-T474 - model_version_history
-- Description: Timeline of model deployments.
-- Business Case: Model Rollback. ML models degrade. This table tracks the history of which model version (e.g.,
--                 Fraud Detection v3.2) was deployed when, allowing for instant rollback if a new model performs worse.
-- KPIs: Model Deployment Frequency, Model Rollback Rate, Version Age, A/B Test Promotion Rate.
-- Feature Reference: M18-T290 (Model Deployment Strategies)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_version_history (
    deployment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,

    -- Deployment Details
    environment VARCHAR(50) NOT NULL, -- 'Production', 'Staging'
    deployment_strategy VARCHAR(50) NOT NULL, -- 'Canary', 'BlueGreen', 'Full'

    -- Performance
    baseline_accuracy NUMERIC(5, 4),
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE cmmi.model_version_history IS 'Tracks the lifecycle and performance history of ML model versions.';

-- =====================================================================================================================
-- Table: M18-T475 - feature_store_versions
-- Description: Versions of feature definitions.
-- Business Case: Data Consistency. In MLOps, the definition of a feature (calculation) used for training must match
--                 the one used in serving. This table versions the feature definition code/config.
-- KPIs: Version Mismatch Count, Feature Deployment Latency, Feature Version History.
-- Feature Reference: M18-T119 (Feature Store Syncs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.feature_store_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(255) NOT NULL,

    -- Details
    version_number VARCHAR(50) NOT NULL,
    feature_definition_url TEXT NOT NULL, -- Link to code/config
    schema_hash CHAR(64),

    -- Status
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'InTraining', 'Live', 'Archived'
    live_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.feature_store_versions IS 'Tracks versions of features used in ML model training and serving.';

-- =====================================================================================================================
-- Table: M18-T476 - training_data_sources
-- Description: Origins of data.
-- Business Case: Data Governance. Knowing where training data comes from is vital for compliance and bias detection.
--                 This table logs the source of data batches.
-- KPIs: Source Diversity, Data Freshness, Source Quality Score, Consent Verification %.
-- Feature Reference: M18-T085 (Training Data Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.training_data_sources (
    source_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Source
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50), -- 'Production', 'Synthetic', 'ThirdParty'
    location_uri TEXT,

    -- Quality
    data_quality_score NUMERIC(3, 2),
    consent_verified BOOLEAN DEFAULT false,

    -- Metadata
    capture_date DATE NOT NULL,
    data_volume_gb NUMERIC(10, 2)
);

COMMENT ON TABLE cmmi.training_data_sources IS 'Inventory and quality tracking for ML training data sources.';

-- =====================================================================================================================
-- Table: M18-T477 - data_quality_metrics
-- Description: Quality of ML data.
-- Business Case: Garbage In, Garbage Out. Poor data quality leads to bad models. This table tracks metrics like
--                 Missing Values % and Duplicate Rate for training datasets.
-- KPIs: Missing Value %, Duplicate Record %, Null Imbalance, Outlier Count, Drift in Quality.
-- Feature Reference: M18-T085 (Training Data Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_quality_metrics (
    quality_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_id UUID NOT NULL,

    -- Metrics
    missing_value_pct NUMERIC(5, 2),
    duplicate_record_pct NUMERIC(5, 2),
    outlier_count BIGINT,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.data_quality_metrics IS 'Monitors data quality metrics for machine learning datasets.';

-- =====================================================================================================================
-- Table: M18-T478 - model_performance_history
-- Description: Performance over time (AUC, F1).
-- Business Case: Model Decay. Model performance (AUC, Precision, Recall) must be tracked over time to detect
--                 drift (T084) or market changes.
-- KPIs: AUC Trend, Precision Trend, Recall Trend, F1 Score, Confusion Matrix Changes.
-- Feature Reference: M18-T084 (Model Drift Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.model_performance_history (
    performance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),

    -- Metrics
    metric_name VARCHAR(50) NOT NULL, -- 'AUC', 'Precision', 'Recall'
    metric_value NUMERIC(10, 6) NOT NULL,

    -- Context
    evaluation_set VARCHAR(100), -- 'Validation', 'Test', 'Production'
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.model_performance_history IS 'Time-series tracking of ML model performance metrics.';

-- =====================================================================================================================
-- Table: M18-T479 - a_b_test_experiments
-- Description: Tracking A/B test experiments.
-- Business Case: Statistical Rigor. Beyond "Results" (T386), managing the *experiment* lifecycle
--                 (Hypothesis: "Red button increases clicks") is distinct. This table manages that.
-- KPIs: Experiment Duration, Statistical Significance, Sample Size Ratio, Conversion Lift.
-- Feature Reference: M18-F064 (A/B Test Statistical Significance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.a_b_test_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    -- Hypothesis
    hypothesis TEXT,
    target_metric VARCHAR(50) NOT NULL, -- 'ClickRate', 'ConversionRate'

    -- Config
    variant_a_description TEXT,
    variant_b_description TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'Draft', -- 'Draft', 'Running', 'Completed'
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,

    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.a_b_test_experiments IS 'Manages the lifecycle of A/B testing experiments.';

-- =====================================================================================================================
-- Table: M18-T480 - experiment_segments
-- Description: Who is in A vs B.
-- Business Case: Cohort Analysis. For valid A/B tests, we must ensure random sampling. This table tracks
--                 which user ID falls into which bucket (A or B) for a specific experiment.
-- KPIs: Sample Ratio (A/B), Segment Imbalance, Segment Size, Bucket Consistency.
-- Feature Reference: M18-T479 (A/B Test Experiments)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.experiment_segments (
    segment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id UUID NOT NULL,

    -- Assignment
    user_id UUID NOT NULL,
    variant VARCHAR(10) NOT NULL, -- 'A', 'B', 'Control'

    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (experiment_id) REFERENCES cmmi.a_b_test_experiments(experiment_id),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.experiment_segments IS 'Maps users to specific variants in A/B tests.';

-- =====================================================================================================================
-- Table: M18-T481 - sla_maintenance_windows
-- Description: Scheduled downtime windows.
-- Business Case: Realistic SLAs. SLAs cannot be met if the system is down for scheduled maintenance.
--                 This table defines maintenance windows which are excluded from SLA availability calculations (T231).
-- KPIs: Window Adherence, Emergency Maintenance %, Window Notification Rate, SLA Impact Calculation Accuracy.
-- Feature Reference: M18-T231 (SLA Definitions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_maintenance_windows (
    window_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    service_name VARCHAR(100) NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',

    -- Details
    day_of_week INTEGER CHECK (day_of_week >= 1 AND day_of_week <= 7),
    reason TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'Planned', -- 'Planned', 'Active', 'Completed', 'Cancelled'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sla_maintenance_windows IS 'Defines scheduled maintenance windows excluded from SLA uptime calculations.';

-- =====================================================================================================================
-- Table: M18-T482 - sla_exception_requests
-- Description: Asking for a waiver on an SLA.
-- Business Case: Customer Relations. Sometimes strict SLA enforcement harms business (e.g., VIP merchant).
--                 This table tracks requests to waive SLA penalties or extend deadlines.
-- KPIs: Exception Approval Rate, Business Impact of Waiver, Request Turnaround Time, Cost of Waiver.
-- Feature Reference: M18-T232 (SLA Breaches)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_exception_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sla_id UUID NOT NULL, -- Ref T231

    -- Request
    customer_id UUID,
    reason TEXT NOT NULL,
    requested_expiration DATE NOT NULL,

    -- Decision
    approver_id UUID,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Approved', 'Rejected'
    notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (sla_id) REFERENCES cmmi.sla_definitions(sla_id)
);

COMMENT ON TABLE cmmi.sla_exception_requests IS 'Manages requests for waivers or exceptions to Service Level Agreements.';

-- =====================================================================================================================
-- Table: M18-T483 - sla_escalation_matrix
-- Description: Who to call when SLA is missed.
-- Business Case: Escalation procedures. When an SLA breach occurs, who needs to be notified? This table maps
--                 Severity Levels + Service -> Notification Lists (Executives, PR Team).
-- KPIs: Notification Latency, Escalation Trigger Accuracy, Notification Readiness.
-- Feature Reference: M18-T232 (SLA Breaches)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_escalation_matrix (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    service_name VARCHAR(100) NOT NULL,
    breach_severity VARCHAR(20) NOT NULL, -- 'Warning', 'Critical'

    -- Action
    notify_roles TEXT[], -- ['CTO', 'VP Engineering', 'PR Manager']
    notify_channels TEXT[], -- ['Slack', 'Email', 'PagerDuty']
    notify_within_minutes INTEGER NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.sla_escalation_matrix IS 'Defines escalation rules based on SLA breach severity.';

-- =====================================================================================================================
-- Table: M18-T484 - sla_notification_history
-- Description: History of alerts sent.
-- Business Case: Proof of Notification. If PARI is penalized for a breach, we must prove we notified the customer.
--                 This table logs every SLA alert sent, including timestamp and method.
-- KPIs: Notification Delivery Success Rate, Alert Volume, False Alarm Rate.
-- Feature Reference: M18-T483 (SLA Escalation Matrix)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sla_notification_history (
    notification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    breach_id UUID NOT NULL, -- Ref T232 (SLA Breaches)

    -- Details
    sent_to_role VARCHAR(100),
    sent_via VARCHAR(50), -- 'Email', 'Slack', 'SMS'
    sent_at TIMESTAMP WITH TIME ZONE NOT NULL,

    delivery_status VARCHAR(20) CHECK (delivery_status IN ('Sent', 'Delivered', 'Failed')),

    FOREIGN KEY (breach_id) REFERENCES cmmi.sla_breaches(breach_id)
);

COMMENT ON TABLE cmmi.sla_notification_history IS 'Logs outgoing SLA breach notifications to stakeholders.';

-- =====================================================================================================================
-- Table: M18-T485 - retry_storm_log
-- Description: Detailed log of retry spikes.
-- Business Case: System Stability. A "Thundering Herd" of retries (retrying a failed request thousands of times/sec)
--                 can bring down databases. This table logs the metrics of the storm to tune circuit breakers.
-- KPIs: Storm Duration, Peak Retry Rate, Origin Service Impact, Circuit Breaker Trigger Time.
-- Feature Reference: M18-T108 (Retry Storm Detector)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.retry_storm_log (
    storm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Origin
    service_name VARCHAR(100) NOT NULL,
    endpoint VARCHAR(255),

    -- Metrics
    peak_retries_per_sec NUMERIC(10, 2),
    avg_latency_ms NUMERIC(10, 2),
    error_rate_pct NUMERIC(5, 2),

    -- Impact
    duration_seconds INTEGER,
    circuit_breaker_triggered BOOLEAN DEFAULT false,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.retry_storm_log IS 'Detailed logs of retry storm events for system stability analysis.';

-- =====================================================================================================================
-- Table: M18-T486 - circuit_breaker_state_transitions
-- Description: Every time a breaker trips (Open/Closed).
-- Business Case: Debugging Flapping. A circuit breaker that constantly opens/closes ("flapping") is unhealthy.
--                 This table logs every state transition to identify instability patterns.
-- KPIs: Transition Frequency, Time in Open State, Flap Count, Reset Success Rate.
-- Feature Reference: M18-T085 (Circuit Breakers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.circuit_breaker_state_transitions (
    transition_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    breaker_id UUID NOT NULL, -- Ref T085
    service_name VARCHAR(100) NOT NULL,

    -- State Change
    from_state VARCHAR(20) NOT NULL,
    to_state VARCHAR(20) NOT NULL,
    reason_code VARCHAR(100),

    triggered_by VARCHAR(50), -- 'System', 'Manual'
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (breaker_id) REFERENCES cmmi.circuit_breakers(breaker_id) -- Ref M18-T085 assumed based on ID
);

COMMENT ON TABLE cmmi.circuit_breaker_state_transitions IS 'Audits state changes in circuit breakers to identify flapping patterns.';

-- =====================================================================================================================
-- Table: M18-T487 - bulkhead_isolation_status
-- Description: Status of thread pools/isolation.
-- Business Case: Fault Isolation. Bulkheads prevent cascading failures. This table tracks the status of
--                 thread pools (e.g., "HikariCP", custom executors) ensuring they remain isolated and don't share memory.
-- KPIs: Isolation Violation Count, Pool Saturation, Pool Exhaustion Incidents.
-- Feature Reference: M18-T107 (Bulkhead Isolation Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bulkhead_isolation_status (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    pool_name VARCHAR(100) NOT NULL,
    service_name VARCHAR(100) NOT NULL,

    -- Status
    is_isolated BOOLEAN NOT NULL,
    isolation_pattern VARCHAR(50), -- 'ThreadLocal', 'ProcessIsolation'

    -- Metrics
    shared_memory_bytes BIGINT,
    max_threads INTEGER,

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.bulkhead_isolation_status IS 'Verifies that bulkhead thread pools maintain proper isolation.';

-- =====================================================================================================================
-- Table: M18-T488 - system_message_queue
-- Description: Internal system messages.
-- Business Case: Decoupled Communication. Microservices communicate via queues (Kafka/RabbitMQ) internally.
--                 This table logs messages flowing between services for debugging.
-- KPIs: Message Throughput, Message Latency, Error Rate, Queue Depth, Consumer Lag.
-- Feature Reference: M18-T080 (Queue Depth Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.system_message_queue (
    message_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL,
    producer_service VARCHAR(100) NOT NULL,
    consumer_service VARCHAR(100) NOT NULL,

    -- Content
    message_key VARCHAR(255),
    payload_size_bytes INTEGER,

    -- Lifecycle
    produced_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Processed', 'Failed'

    error_message TEXT
);

COMMENT ON TABLE cmmi.system_message_queue IS 'Logs internal system-to-system message flow for debugging.';

-- =====================================================================================================================
-- Table: M18-T489 - api_gateway_config_history
-- Description: History of gateway config changes.
-- Business Case: Configuration Drift. Changing gateway rules (routes, plugins) can break apps. This table logs
--                 history of API Gateway configuration (Kong/NGINX) changes for rollback and audit.
-- KPIs: Config Change Frequency, Rollback Count, Config Drift Severity, Change Impact.
-- Feature Reference: M18-T124 (API Endpoints)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_gateway_config_history (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    service_name VARCHAR(100) NOT NULL,
    config_type VARCHAR(50), -- 'Route', 'Plugin', 'Upstream'
    resource_id VARCHAR(255), -- The route or plugin name

    -- Changes
    old_config JSONB,
    new_config JSONB,

    -- Metadata
    changed_by UUID NOT NULL,
    reason TEXT,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (changed_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.api_gateway_config_history IS 'Tracks history of API Gateway configuration changes.';

-- =====================================================================================================================
-- Table: M18-T490 - api_rate_limit_adjustments
-- Description: Changes to limits.
-- Business Case: Dynamic Rate Limiting. Rate limits (T256) are not static. This table logs adjustments made to
--                 limits for specific clients or globally in response to load or abuse.
-- KPIs: Adjustment Frequency, Limit Tightening/Loosening, Abuse Reduction vs User Impact.
-- Feature Reference: M18-T103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.api_rate_limit_adjustments (
    adjustment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    client_id VARCHAR(100),
    endpoint_id VARCHAR(100),

    -- Change
    old_rps INTEGER,
    new_rps INTEGER,

    -- Reason
    reason_code VARCHAR(50) NOT NULL, -- 'Scaling', 'Abuse', 'SubscriptionUpgrade'
    effective_until TIMESTAMP WITH TIME ZONE,

    changed_by UUID,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (changed_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.api_rate_limit_adjustments IS 'Logs manual and automated adjustments to API rate limits.';

-- =====================================================================================================================
-- Table: M18-T491 - client_blacklist
-- Description: Specific IPs or Clients blocked.
-- Business Case: Hard Blocking. Beyond dynamic rate limiting (T256), some actors are blacklisted permanently.
--                 This table manages the blacklist (IP, Client ID, API Key).
-- KPIs: Blacklist Size, Blacklist Hit Count, Removal Rate, False Positive Rate.
-- Feature Reference: M18-T103 (API Throttling Impact Analyzer)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.client_blacklist (
    blacklist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    blacklist_type VARCHAR(20) NOT NULL CHECK (blacklist_type IN ('IP', 'ClientID', 'APIKey')),
    value VARCHAR(255) NOT NULL, -- The IP or Key

    -- Reason
    reason TEXT NOT NULL,

    -- Lifecycle
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_by UUID,
    expires_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN DEFAULT true,

    FOREIGN KEY (blocked_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.client_blacklist IS 'Manages permanently blocked clients and IP addresses.';

-- =====================================================================================================================
-- Table: M18-T492 - geo_location_anomalies
-- Description: Anomalies in location (impossible travel).
-- Business Case: Fraud Detection. A user logging in from New York and London 5 minutes apart is suspicious.
--                 This table flags geo-location anomalies for review (T493).
-- KPIs: Anomaly Detection Rate, Fraud Confirmation Rate, Legitimate Travel %, Geo-Lock Trigger Rate.
-- Feature Reference: M18-T132 (GeoIP Traffic Distribution)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.geo_location_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Anomaly
    location_1 VARCHAR(100),
    location_2 VARCHAR(100),
    time_difference_minutes INTEGER,
    distance_km NUMERIC(10, 2),

    -- Status
    risk_score NUMERIC(3, 2),
    is_confirmed_fraud BOOLEAN DEFAULT false,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.geo_location_anomalies IS 'Flags impossible travel patterns for fraud review.';

-- =====================================================================================================================
-- Table: M18-T493 - user_risk_profile
-- Description: Risky user behavior.
-- Business Case: Behavioral Biometrics. Creating a risk profile for each user based on login times, transaction amounts,
--                 and typing speed helps detect account takeover or fraud.
-- KPIs: Risk Score Distribution, High Risk User Count, False Positive Profile Count, Dynamic Risk Adaptation.
-- Feature Reference: M18-T492 (Geo Location Anomalies)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.user_risk_profile (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Metrics
    overall_risk_score NUMERIC(3, 2) GENERATED ALWAYS AS (
        (0.4 * login_anomaly_score + 0.3 * transaction_anomaly_score + 0.3 * behavioral_anomaly_score)
    ) STORED,
    login_anomaly_score NUMERIC(3, 2) DEFAULT 0,
    transaction_anomaly_score NUMERIC(3, 2) DEFAULT 0,
    behavioral_anomaly_score NUMERIC(3, 2) DEFAULT 0,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.user_risk_profile IS 'Aggregates behavioral data into a single user risk score.';

-- =====================================================================================================================
-- Table: M18-T494 - behavioral_biometric_profile
-- Description: Normal user behavior vs current.
-- Business Case: Continuous Auth. Users have habits (login times, typical IP ranges). This table stores the
--                 "baseline" behavior and flags deviations for T493.
-- KPIs: Baseline Stability, Deviation Trigger Count, Baseline Update Frequency.
-- Feature Reference: M18-T493 (User Risk Profile)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.behavioral_biometric_profile (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Baseline Stats
    typical_login_hours NUMERIC(4, 2)[]; -- e.g., [9.0, 9.5, 10.0]
    typical_geo_regions TEXT[],
    typical_device_ids CHAR(64)[],

    -- Profile Strength
    profile_strength INTEGER DEFAULT 0, -- How much data points we have
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.behavioral_biometric_profile IS 'Stores baseline behavioral patterns for fraud detection.';

-- =====================================================================================================================
-- Table: M18-T495 - biometric_template_enrollment
-- Description: User enrolls in a template.
-- Business Case: Biometric Setup. Before a user can use FaceID/Fingerprint, they must enroll. This table tracks
--                 the enrollment event and the resulting template ID.
-- KPIs: Enrollment Success Rate, Enrollment Time, Template Quality Score, Spoofed Enrollments.
-- Feature Reference: M18-T494 (Behavioral Biometric Profile)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.biometric_template_enrollment (
    enrollment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Template
    template_id UUID NOT NULL, -- Reference to the bio config
    modality VARCHAR(50), -- 'Face', 'Voice', 'Fingerprint'

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Active', 'Failed'
    quality_score NUMERIC(3, 2), -- Match Quality 0-1

    enrolled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.biometric_template_enrollment IS 'Tracks the enrollment of users in biometric authentication templates.';

-- =====================================================================================================================
-- Table: M18-T496 - biometric_scan_logs
-- Description: Scans against watchlists.
-- Business Case: Identity Verification. Biometrics (Fingerprints) are matched against watchlists (e.g., known terrorist
--                 prints). This table logs the results of these external scans.
-- KPIs: Watchlist Match Count, False Positive Rate, Scan Latency, Watchlist Update Frequency.
-- Feature Reference: M18-T145 (Malware Signatures)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.biometric_scan_logs (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    template_id UUID,

    -- Scan Details
    provider VARCHAR(50) NOT NULL, -- e.g., 'Onfido', 'IDemia'
    scan_reference_id VARCHAR(255), -- Transaction ID at provider

    -- Result
    match_found BOOLEAN NOT NULL,
    risk_score NUMERIC(3, 2),
    action_taken VARCHAR(50), -- 'Allow', 'ManualReview', 'Block'

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.biometric_scan_logs IS 'Logs results of biometric scans against watchlists.';

-- =====================================================================================================================
-- Table: M18-T497 - hardware_inventory
-- Description: Servers, Racks, Switches.
-- Business Case: Data Center Management. Tracking physical infrastructure assets (Racks, Switches, Power) is vital
--                 for capacity planning (T117) and disaster recovery.
-- KPIs: Asset Utilization, Power Usage, Cooling Efficiency, Failure Rate, Maintenance Overhead.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.hardware_inventory (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    asset_type VARCHAR(50) NOT NULL, -- 'Server', 'Switch', 'Router', 'Rack'
    serial_number VARCHAR(100),
    manufacturer VARCHAR(100),
    model VARCHAR(100),

    -- Location
    datacenter VARCHAR(100),
    rack VARCHAR(50),
    u_location VARCHAR(50),

    -- Status
    status VARCHAR(20) DEFAULT 'Operational', -- 'Operational', 'Maintenance', 'Decommissioned'
    capacity_utilization_pct NUMERIC(5, 2),

    purchase_date DATE,
    warranty_expiry DATE
);

COMMENT ON TABLE cmmi.hardware_inventory IS 'Physical inventory of data center hardware assets.';

-- =====================================================================================================================
-- Table: M18-T498 - hardware_maintenance_schedule
-- Description: Preventive maintenance.
-- Business Case: Reducing Failures. Preventive maintenance (Patching firmware, cleaning dust) prevents outages.
--                 This table schedules these tasks to ensure hardware reliability.
-- KPIs: Maintenance Compliance %, Maintenance Lead Time, Failure Prevention Rate, MTBF (Mean Time Between Failures).
-- Feature Reference: M18-T497 (Hardware Inventory)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.hardware_maintenance_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL,

    -- Task
    task_type VARCHAR(50) NOT NULL, -- 'FirmwareUpgrade', 'PhysicalInspection'
    frequency_days INTEGER NOT NULL,
    description TEXT,

    -- Execution
    last_completed_date DATE,
    next_due_date DATE,

    status VARCHAR(20) DEFAULT 'Scheduled', -- 'Scheduled', 'Completed', 'Missed'

    FOREIGN KEY (asset_id) REFERENCES cmmi.hardware_inventory(asset_id)
);

COMMENT ON TABLE cmmi.hardware_maintenance_schedule IS 'Schedules preventive maintenance for hardware infrastructure.';

-- =====================================================================================================================
-- Table: M18-T499 - hardware_failure_log
-- Description: When hardware died.
-- Business Case: MTBF Calculation. Tracking hardware failures allows calculation of Mean Time Between Failures,
--                 a critical metric for infrastructure reliability.
-- KPIs: MTBF (Days), Failure Count by Type, Mean Time To Repair (MTTR), Part Replacement Cost.
-- Feature Reference: M18-T497 (Hardware Inventory)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.hardware_failure_log (
    failure_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL,

    -- Incident
    failure_date TIMESTAMP WITH TIME ZONE NOT NULL,
    failure_mode VARCHAR(100) NOT NULL, -- 'PowerSupply', 'HardDisk', 'NetworkCard'

    -- Resolution
    repaired_date TIMESTAMP WITH TIME ZONE,
    repair_cost NUMERIC(10, 2),

    root_cause TEXT,

    FOREIGN KEY (asset_id) REFERENCES cmmi.hardware_inventory(asset_id)
);

COMMENT ON TABLE cmmi.hardware_failure_log IS 'Logs hardware failure incidents and repairs.';

-- =====================================================================================================================
-- Table: M18-T500 - software_deployment_history
-- Description: History of software on hardware.
-- Business Case: Configuration Management. Knowing what software version runs on which server is crucial for support
--                 and debugging. This table links software releases (T176) to hardware (T497).
-- KPIs: Deployment Coverage %, Drift Status, Rollback Speed, Compliance Score per Asset.
-- Feature Reference: M18-T176 (Releases)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.software_deployment_history (
    deployment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_id UUID NOT NULL, -- Ref T497
    release_id UUID NOT NULL, -- Ref T176

    -- Details
    deployed_version VARCHAR(50) NOT NULL,
    environment VARCHAR(50) NOT NULL, -- 'Production', 'Staging'

    deployed_by UUID,
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'Active', -- 'Active', 'RolledBack'

    FOREIGN KEY (asset_id) REFERENCES cmmi.hardware_inventory(asset_id),
    FOREIGN KEY (release_id) REFERENCES cmmi.releases(release_id)
);

COMMENT ON TABLE cmmi.software_deployment_history IS 'Maps software releases to physical hardware assets.';

-- =====================================================================================================================
-- Table: M18-T501 - capacity_reservation
-- Description: Reserved capacity for critical events.
-- Business Case: Event Scaling. For major events (Black Friday), PARI reserves extra capacity (servers/bandwidth).
--                 This table tracks these reservations to ensure resources are available when needed.
-- KPIs: Reservation Utilization, Reservation Accuracy, Overhead Cost, Capacity Availability %.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.capacity_reservation (
    reservation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Target
    resource_type VARCHAR(50) NOT NULL, -- 'Compute', 'Bandwidth', 'Storage'
    resource_id VARCHAR(100) NOT NULL,

    -- Schedule
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Business Context
    event_name VARCHAR(255),
    owner_id UUID,

    status VARCHAR(20) DEFAULT 'Reserved', -- 'Reserved', 'InUse', 'Released'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.capacity_reservation IS 'Tracks reservations of infrastructure capacity for critical events.';

-- =====================================================================================================================
-- Table: M18-T502 - resource_pooling
-- Description: Pooled resources (IPs, VIPs).
-- Business Case: High Availability. Some resources (Static IPs, VIP Gateway endpoints) are "pooled" and shared
--                 across services or tenants. This table manages their allocation.
-- KPIs: Pool Utilization %, Contention Count, Allocation Latency, Idle Resource Count.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.resource_pooling (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Resource
    resource_type VARCHAR(50) NOT NULL,
    resource_identifier VARCHAR(100) NOT NULL,

    -- Allocation
    assigned_to VARCHAR(100), -- Service or Project
    tenant_id VARCHAR(100),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'Available', -- 'Available', 'Allocated', 'Maintenance'

    allocated_at TIMESTAMP WITH TIME ZONE,

    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.resource_pooling IS 'Manages the allocation of shared infrastructure resources.';

-- =====================================================================================================================
-- Table: M18-T503 - dynamic_scaling_events
-- Description: Log of scale-up/scale-down events.
-- Business Case: Cloud Cost Optimization. Auto-scaling (Kubernetes HPA) is great but can be expensive.
--                 This table logs scaling events to analyze costs and tune thresholds.
-- KPIs: Scale Up Frequency, Scale Down Frequency, Scale Event Cost, Underutilization Post-Scale, Scale Success Rate.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.dynamic_scaling_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    service_name VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50), -- 'CPU', 'Memory', 'Pods'

    -- Action
    action VARCHAR(20) NOT NULL, -- 'ScaleUp', 'ScaleDown'
    current_value INTEGER,
    previous_value integer,
    trigger_reason VARCHAR(100), -- 'CPU > 80%', 'Cron'

    -- Cost
    estimated_cost_impact NUMERIC(10, 2),

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.dynamic_scaling_events IS 'Logs infrastructure auto-scaling events for cost analysis.';

-- =====================================================================================================================
-- Table: M18-T504 - autoscaling_policies
-- Description: Rules for scaling.
-- Business Case: Defining "When to Scale". This table stores the configuration for auto-scaling (HPA),
--                 defining targets (e.g., "Scale up if CPU > 70%").
-- KPIs: Policy Efficiency (Over-scaling vs Under-scaling), Policy Volatility, Scale Time Reduction.
-- Feature Reference: M18-T117 (Capacity Planning Recommender)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.autoscaling_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    target_service VARCHAR(100) NOT NULL,

    -- Triggers
    metric_name VARCHAR(50) NOT NULL, -- 'cpu_percent', 'memory_percent'
    lower_threshold NUMERIC(5, 2),
    upper_threshold NUMERIC(5, 2),

    -- Scaling Action
    scale_up_percent INTEGER NOT NULL,
    scale_down_percent INTEGER,

    min_replicas INTEGER,
    max_replicas INTEGER,

    cooldown_seconds INTEGER NOT NULL,

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.autoscaling_policies IS 'Stores configuration rules for infrastructure auto-scaling.';

-- =====================================================================================================================
-- Table: M18-T505 - cost_allocation_adjustments
-- Description: Manual overrides to billing.
-- Business Case: Fair Billing. Sometimes cost allocation rules (T236) need exceptions (e.g., "R&D spent more time
--                 than usual"). This table logs manual adjustments to the billing ledger.
-- KPIs: Adjustment Volume, Adjustment Value, Audit Frequency, Dispute Reduction.
-- Feature Reference: M18-T236 (Cost Allocation Rules)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.cost_allocation_adjustments (
    adjustment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Source
    resource_id VARCHAR(100) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Change
    original_cost_usd NUMERIC(10, 2) NOT NULL,
    adjusted_cost_usd NUMERIC(10, 2) NOT NULL,

    -- Justification
    reason TEXT NOT NULL,

    approved_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (approved_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.cost_allocation_adjustments IS 'Logs manual adjustments to automated cost allocations.';

-- =====================================================================================================================
-- Table: M18-T506 - invoice_reconciliation_queue
-- Description: Queue for billing disputes.
-- Business Case: Resolving Billing Conflicts. If a customer disputes a charge, it enters a queue. This table
--                 tracks the investigation and resolution.
-- KPIs: Queue Depth, Resolution Time, Write-off Amount, Dispute Win Rate.
-- Feature Reference: M18-T237 (Chargeback Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.invoice_reconciliation_queue (
    dispute_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Invoice Details
    invoice_id VARCHAR(100) NOT NULL,
    amount_disputed NUMERIC(10, 2) NOT NULL,

    -- Workflow
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'UnderReview', 'Resolved', 'WriteOff'
    assigned_to UUID,

    -- Outcome
    resolution_notes TEXT,
    write_off_amount NUMERIC(10, 2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (assigned_to) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.invoice_reconciliation_queue IS 'Manages disputes and reconciliation of billing charges.';

CREATE TRIGGER trigger_update_invoice_reconciliation_queue
    BEFORE UPDATE ON cmmi.invoice_reconciliation_queue
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

-- =====================================================================================================================
-- Table: M18-T507 - subscription_management
-- Description: Customer subscriptions (if PARI sold as SaaS).
-- Business Case: Recurring Revenue. Managing subscription lifecycle (Trial -> Active -> Churn) is key to B2B SaaS revenue.
--                 This table tracks subscription details.
-- KPIs: Churn Rate, Monthly Recurring Revenue (MRR), Trial Conversion Rate, Customer Lifetime Value (LTV).
-- Feature Reference: M18-F069 (Cost per Transaction Monitor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.subscription_management (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    customer_id UUID NOT NULL,
    plan_id VARCHAR(50) NOT NULL, -- 'Basic', 'Pro'

    -- Terms
    billing_cycle VARCHAR(20) NOT NULL, -- 'Monthly', 'Quarterly'
    amount_usd NUMERIC(10, 2) NOT NULL,

    -- Lifecycle
    start_date DATE NOT NULL,
    end_date DATE, -- NULL implies auto-renew
    status VARCHAR(20) DEFAULT 'Active', -- 'Trial', 'Active', 'PastDue', 'Cancelled'

    FOREIGN KEY (customer_id) REFERENCES cmmi.users(user_id) -- Assuming customer is a user type or separate table.
);

COMMENT ON TABLE cmmi.subscription_management IS 'Manages customer subscription lifecycles for SaaS offerings.';

-- =====================================================================================================================
-- Table: M18-T508 - billing_dispute_records
-- Description: Details of disputes.
-- Business Case: Financial Audit. This table links disputes (T506) to specific transaction line items or invoices
--                 to prove/disprove the discrepancy.
-- KPIs: Dispute Count per Month, Dispute Value, Evidence Availability, Resolution Bias.
-- Feature Reference: M18-T506 (Invoice Reconciliation Queue)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.billing_dispute_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dispute_id UUID NOT NULL,

    -- Evidence
    transaction_id VARCHAR(100),
    evidence_urls TEXT[],

    -- Analysis
    analysis_result TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dispute_id) REFERENCES cmmi.invoice_reconciliation_queue(dispute_id)
);

COMMENT ON TABLE cmmi.billing_dispute_records IS 'Stores evidence and analysis for billing disputes.';

-- =====================================================================================================================
-- Table: M18-T509 - payment_gateway_logs
-- Description: Interactions with payment providers (Stripe/Adyen).
-- Business Case: Payment Integration Debugging. Transactions fail at the gateway. This table logs the raw request/response
--                 (sanitized) to debug integration issues.
-- KPIs: Gateway Success Rate, Gateway Latency, Retry Rate, Provider Response Time.
-- Feature Reference: M18-T360 (Settlement Batch Jobs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.payment_gateway_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Provider
    provider_name VARCHAR(50) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,

    -- Transaction
    internal_ref_id VARCHAR(100), -- PARI Transaction ID
    gateway_ref_id VARCHAR(100), -- Provider Transaction ID

    -- Status
    http_status_code INTEGER,
    latency_ms NUMERIC(10, 2),
    error_code VARCHAR(50),
    raw_response_body_preview TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.payment_gateway_logs IS 'Logs interaction details with external payment gateway providers.';

-- =====================================================================================================================
-- Table: M18-T510 - settlement_reconciliation
-- Description: Matching internal ledger to bank statement.
-- Business Case: Financial Reconciliation. Ensuring the money PARI thinks it has matches the money the bank confirms.
--                 This table records the match status of batches.
-- KPIs: Reconciliation Variance, Auto-Match Rate, Breakdown %, Reconciliation Speed, Write-off Amount.
-- Feature Reference: M18-T360 (Settlement Batch Jobs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.settlement_reconciliation (
    recon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    batch_id UUID NOT NULL, -- Ref T360

    -- Stats
    expected_txns NUMERIC(10, 2),
    matched_txns NUMERIC(10, 2),
    variance_amount NUMERIC(15, 2),

    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Matched', 'Exception'

    exception_reason TEXT,

    reconciled_by UUID,
    reconciled_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (batch_id) REFERENCES cmmi.settlement_batch_jobs(batch_id),
    FOREIGN KEY (reconciled_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.settlement_reconciliation IS 'Matches internal ledgers to bank settlement statements.';

-- =====================================================================================================================
-- Table: M18-T511 - financial_audit_trail
-- Description: Immutable financial record.
-- Business Case: Sarbanes-Oxley. Financial data must be immutable. This table writes-onlys financial
--                 transaction records, ensuring the "Golden Copy" can never be altered.
-- KPIs: Record Integrity, Append-Only Compliance, Write Latency, Record Verification Hash.
-- Feature Reference: M18-T510 (Settlement Reconciliation)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.financial_audit_trail (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Financial Data
    transaction_type VARCHAR(50) NOT NULL, -- 'Payment', 'Settlement', 'Refund'
    transaction_ref_id VARCHAR(100) NOT NULL,

    -- Amounts
    amount NUMERIC(19, 4) NOT NULL,
    currency CHAR(3) NOT NULL,

    -- Integrity
    record_hash CHAR(64) NOT NULL,

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.financial_audit_trail IS 'Immutable ledger for financial transactions for audit compliance.';

-- =====================================================================================================================
-- Table: M18-T512 - ledger_locking_events
-- Description: Financial year locking.
-- Business Case: Closing the Books. At the end of a period (Quarter/Year), the ledger is locked.
--                 This table tracks locking events to prevent post-closing modifications.
-- KPIs: Lock Accuracy, Lock Timestamp, Unlock Frequency (Exceptional), Compliance Adherence.
-- Feature Reference: M18-T511 (Financial Audit Trail)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.ledger_locking_events (
    lock_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Period
    period_type VARCHAR(20) NOT NULL, -- 'Quarter', 'Annual'
    period_end_date DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Locked', 'Unlocked'
    locked_by UUID,
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    unlocked_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (locked_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.ledger_locking_events IS 'Tracks the locking and unlocking of the financial ledger.';

-- =====================================================================================================================
-- Table: M18-T513 - regulatory_filing_deadlines
-- Description: Tax/Govt deadlines.
-- Business Case: Compliance Calendar. Missing a tax filing deadline is catastrophic. This table tracks all critical regulatory
--                 filing deadlines to ensure alerting and on-time submission.
-- KPIs: On-Time Submission Rate, Deadline Misses, Alert Lead Time, Filing Accuracy %.
-- Feature Reference: M18-T361 (Regulatory Reporting Runs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.regulatory_filing_deadlines (
    deadline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Regulation
    regulation_name VARCHAR(100) NOT NULL,
    jurisdiction VARCHAR(100) NOT NULL, -- 'US-IRS', 'UK-HMRC'

    -- Schedule
    reporting_period_start DATE NOT NULL,
    filing_deadline DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Submitted', 'Accepted'
    actual_filing_date DATE,

    assigned_owner_id UUID,

    FOREIGN KEY (assigned_owner_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.regulatory_filing_deadlines IS 'Tracks critical deadlines for regulatory filings.';

-- =====================================================================================================================
-- Table: M18-T514 - compliance_document_storage
-- Description: The actual PDFs of certs/audits.
-- Business Case: Evidence Repository. Auditors need to see the actual reports (ISO certs, Pen Test PDFs).
--                 This table manages the secure storage of these documents.
-- KPIs: Document Retrieval Time, Storage Cost, Encryption Coverage, Version Control of Docs.
-- Feature Reference: M18-T146 (Compliance Report Generator)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.compliance_document_storage (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Document
    title VARCHAR(255) NOT NULL,
    document_type VARCHAR(50) NOT NULL, -- 'SOC2Report', 'PenTest', 'AuditReport'

    -- Storage
    storage_path TEXT NOT NULL, -- S3/GCS path
    hash_sha256 CHAR(64), -- Integrity
    size_bytes BIGINT,

    -- Access
    is_encrypted BOOLEAN DEFAULT true,
    access_level VARCHAR(20) DEFAULT 'Restricted', -- 'Public', 'Internal', 'Restricted'

    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    uploaded_by UUID
);

COMMENT ON TABLE cmmi.compliance_document_storage IS 'Securely stores audit and certification documents.';

-- =====================================================================================================================
-- Table: M18-T515 - policy_acknowledgement
-- Description: User must click "I read policy".
-- Business Case: Liability Mitigation. If a user violates a policy, claiming "I didn't know" is weak defense.
--                 This table tracks that users have digitally signed/approved the policy.
-- KPIs: Acknowledgement Coverage, Acknowledgement Freshness, User Participation %.
-- Feature Reference: M18-T454 (Governance Policy Versions)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.policy_acknowledgement (
    acknowledgement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL, -- Ref T454
    user_id UUID NOT NULL,

    -- Event
    version VARCHAR(50) NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,

    FOREIGN KEY (policy_id) REFERENCES cmmi.governance_policy_versions(policy_id),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.policy_acknowledgement IS 'Tracks user acknowledgements of governance policies.';

-- =====================================================================================================================
-- Table: M18-T516 - safety_incidents
-- Description: Physical safety (office evacuation).
-- Business Case: Operational Continuity. IT isn't just digital. Fire drills or physical access breaches must be logged
--                 in the same system for comprehensive GRC (Governance, Risk, Compliance) reporting.
-- KPIs: Incident Response Time, Drill Completion %, Safety Incident Rate, Evacuation Time.
-- Feature Reference: M18-T149 (Incidents)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.safety_incidents (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Details
    incident_type VARCHAR(50) NOT NULL, -- 'Fire', 'Flood', 'Theft'
    location VARCHAR(255) NOT NULL,

    -- Lifecycle
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    severity VARCHAR(20),

    report TEXT,

    reported_by UUID,

    FOREIGN KEY (reported_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.safety_incidents IS 'Logs physical security and safety incidents.';

-- =====================================================================================================================
-- Table: M18-T517 - security_clearance_form
-- Description: Background check forms.
-- Business Case: Employee Vetting. Onboarding (T461) often requires security clearance forms (for sensitive data access).
--                 This table stores the form data and approval status.
-- KPIs: Clearance Processing Time, Clearance Denial Rate, Expiring Clearances, Form Completion Rate.
-- Feature Reference: M18-T461 (Onboarding Checklist)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.security_clearance_form (
    form_id UUID DEFAULT uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Form Data (JSON or individual cols)
    clearance_level VARCHAR(50) NOT NULL, -- 'L1', 'L2', 'L3', 'L4'
    background_check_status VARCHAR(20), -- 'Pending', 'Passed', 'Failed'

    -- Timeline
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP WITH TIME ZONE,
    approved_by UUID,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (approved_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.security_clearance_form IS 'Stores security background check forms for personnel.';

-- =====================================================================================================================
-- Table: M18-T518 - vendor_contract_renewals
-- Description: Upcoming renewals.
-- Business Case: Supply Chain Continuity. Missing a renewal on a critical vendor (like a Cloud Provider) is a huge risk.
--                 This table tracks upcoming renewals, ensuring legal and operational continuity.
-- KPIs: Renewal Lead Time, Renewal Rate, Auto-Renewal %, Cost Variance.
-- Feature Reference: M18-T230 (Vendor Contract Terms)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_contract_renewals (
    renewal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL, -- Ref T229

    -- Dates
    expiry_date DATE NOT NULL,
    reminder_date DATE,

    -- Status
    status VARCHAR(20) DEFAULT 'Pending', -- 'Pending', 'Sent', 'Negotiating', 'Renewed'
    next_term_start DATE,

    -- Outcome
    auto_renewed BOOLEAN DEFAULT false,
    cost_change_pct NUMERIC(5, 2),

    FOREIGN KEY (contract_id) REFERENCES cmmi.vendor_contract_terms(contract_id)
);

COMMENT ON TABLE cmmi.vendor_contract_renewals IS 'Tracks upcoming vendor contract renewals and negotiations.';

-- =====================================================================================================================
-- Table: M18-T519 - vendor_performance_reviews
-- Description: Periodic reviews of vendors.
-- Business Case: Vendor Scorecards. Just like employees (T458), vendors need performance reviews. This table records
--                 qualitative and quantitative feedback (SLA adherence, responsiveness).
-- KPIs: Vendor Rating Trend, SLA Breach %, Responsiveness Score, Renewal Recommendation (Yes/No).
-- Feature Reference: M18-T230 (Vendor Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.vendor_performance_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL, -- Ref T110

    -- Review Details
    review_period VARCHAR(50) NOT NULL,
    reviewer_id UUID,

    -- Scores
    quality_score INTEGER CHECK (quality_score >= 1 AND quality_score <= 5),
    responsiveness_score INTEGER CHECK (responsiveness_score >= 1 AND responsiveness_score <= 5),
    overall_rating NUMERIC(3, 1),

    -- Narrative
    strengths TEXT,
    weaknesses TEXT,
    conclusion TEXT, -- 'Renew', 'Probation'

    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id),
    FOREIGN KEY (reviewer_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.vendor_performance_reviews IS 'Stores periodic performance reviews for third-party vendors.';

-- =====================================================================================================================
-- Table: M18-T520 - supply_chain_disruption_logs
-- Description: When a vendor had an outage.
-- Business Case: Impact Analysis. If AWS or a data provider goes down, we need to record the impact and downtime duration.
--                 This table logs vendor disruptions.
-- KPIs: Disruption Duration (Minutes), Disruption Frequency per Vendor, Business Impact (Revenue Lost), RTO Variance.
-- Feature Reference: M18-T110 (Vendor Risk Assessor)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.supply_chain_disruption_logs (
    disruption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Incident
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,

    -- Impact
    impacted_services TEXT[],
    estimated_loss_usd NUMERIC(15, 2),

    -- Description
    root_cause TEXT,
    resolution_summary TEXT,

    FOREIGN KEY (vendor_id) REFERENCES cmmi.vendor_risks(vendor_id)
);

COMMENT ON TABLE cmmi.supply_chain_disruption_logs IS 'Logs outages and disruptions caused by vendors.';

-- =====================================================================================================================
-- Table: M18-T521 - disaster_recovery_simulation_logs
-- Description: Simulation results.
-- Business Case: DR Testing. Testing the Business Continuity Plan (T522) requires running simulations.
--                 This table stores the results (Recovery Time Objective vs Actual) to improve the plan.
-- KPIs: Simulation Success Rate, RTO Variance, Plan Improvement Rate, Simulation Cost.
-- Feature Reference: M18-T363 (Employee Offboarding)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.disaster_recovery_simulation_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scenario
    scenario_name VARCHAR(255) NOT NULL,
    scenario_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Objectives vs Actuals
    target_rto_minutes INTEGER NOT NULL,
    actual_rto_minutes INTEGER,
    target_rpo_percent NUMERIC(3, 2), -- Data Loss
    actual_rpo_percent NUMERIC(3, 2),

    -- Outcome
    success BOOLEAN,
    lessons_learned TEXT,

    FOREIGN KEY (log_id) REFERENCES cmmi.safety_incidents(incident_id) -- Linking DR simulation to safety/security incidents implies context
);

COMMENT ON TABLE cmmi.disaster_recovery_simulation_logs IS 'Stores results of disaster recovery simulations.';

-- =====================================================================================================================
-- Table: M18-T522 - bc_dr_logs
-- Description: Business Continuity plans.
-- Business Case: Operational Resilience. Business Continuity Plans (BCP) are living documents. This table tracks
--                 reviews and updates to the plan to ensure it stays current.
-- KPIs: Plan Review Frequency, Drill Execution vs Plan, Plan Version Control, Access Control on Plan.
-- Feature Reference: M18-T419 (Audit Logs) - Audit context
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.bc_dr_logs (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    plan_name VARCHAR(255) NOT NULL,
    plan_version VARCHAR(20),

    -- Review
    review_date TIMESTAMP WITH TIME ZONE NOT NULL,
    reviewer_id UUID,

    -- Changes
    sections_updated TEXT[],
    approval_status VARCHAR(20) NOT NULL, -- 'Approved', 'Pending', 'Rejected'

    FOREIGN KEY (reviewer_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.bc_dr_logs IS 'Tracks reviews and updates to Business Continuity Plans.';

-- =====================================================================================================================
-- Table: M18-T523 - risk_assessment_sessions
-- Description: Meetings to discuss risk.
-- Business Case: Risk Management. Risks (T199) don't manage themselves; people do. This table records the minutes
--                 and outcomes of risk assessment sessions.
-- KPIs: Session Action Item Closure %, Risk Reduction Rate, Session Attendance, Risk Register Update Frequency.
-- Feature Reference: M18-T199 (Risk Registers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.risk_assessment_sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Context
    meeting_title VARCHAR(255) NOT NULL,
    meeting_date DATE NOT NULL,

    -- Outcomes
    risks_assessed INTEGER,
    risks_mitigated INTEGER,
    risks_accepted INTEGER, -- Deliberately accepted risks

    minutes_document_link TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    FOREIGN KEY (created_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.risk_assessment_sessions IS 'Logs structured sessions for managing organizational risks.';

-- =====================================================================================================================
-- Table: M18-T524 - risk_acceptance_records
-- Description: Signing off on risk.
-- Business Case: Informed Decision. Some risks cannot be mitigated cheaply. This table records the acceptance
--                 of a risk (T199) by authority, with justification.
-- KPIs: Accepted Risk Count, Risk Severity Trend, Justification Quality, Approval Cycle Time.
-- Feature Reference: M18-T199 (Risk Registers)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.risk_acceptance_records (
    acceptance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    risk_id UUID NOT NULL, -- Ref T199

    -- Acceptance
    accepted_by UUID NOT NULL,
    acceptance_date DATE NOT NULL,

    reason TEXT NOT NULL,
    residual_mitigation_plan TEXT,

    review_date DATE, -- Date to re-evaluate acceptance

    FOREIGN KEY (risk_id) REFERENCES cmmi.risk_registers(risk_id),
    FOREIGN KEY (accepted_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.risk_acceptance_records IS 'Records formal acceptance of risks that cannot be fully mitigated.';

-- =====================================================================================================================
-- Table: M18-T525 - ethical_ai_model_records
-- Description: AI Ethics checks.
-- Business Case: Regulatory Compliance for AI. Regulations like EU AI Act require ensuring AI is ethical. This table stores
--                 records of Ethics Impact Assessments.
-- KPIs: Ethics Check Frequency, Bias Mitigation Rate, Model Transparency Score, Ethics Violation Count.
-- Feature Reference: M18-T083 (Algorithmic Bias Detector)
-- =================================================================================================================----
CREATE TABLE IF NOT EXISTS cmmi.ethical_ai_model_records (
    ethics_id UUID DEFAULT uuid_generate_vision() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    -- Check Details
    assessment_type VARCHAR(100) NOT NULL, -- 'Fairness', 'Transparency', 'Accountability'
    result VARCHAR(20) NOT NULL, -- 'Passed', 'Flagged', 'Review'

    -- Details
    assessor_id UUID,
    assessment_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    FOREIGN KEY (assessor_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.ethical_ai_model_records IS 'Stores ethical review results for AI models.';

-- =====================================================================================================================
-- Table: M18-T526 - algorithm_transparency_reports
-- Description: Explaining models to regulators.
-- Business Case: Explainable AI. Regulators increasingly require "Black Box" models to be explainable. This table links
--                 documentation explaining model decisions (feature importance) to the model version.
-- KPIs: Report Generation Speed, Documentation Coverage %, Model Explainability Score, Audit Request Response Time.
-- Feature Reference: M18-T478 (Model Performance History)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.algorithm_transparency_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Model
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),

    -- Report
    report_url TEXT NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Meta
    language VARCHAR(20), -- 'PDF', 'HTML'
    size_bytes BIGINT
);

COMMENT ON TABLE cmmi.algorithm_transparency_reports IS 'Stores reports explaining the logic behind model decisions.';

-- =====================================================================================================================
-- Table: M18-T527 - data_subject_rights_audit
-- Description: Auditing privacy requests.
-- Business Case: GDPR Compliance. A user requests their data (T246). We must prove we deleted it.
--                 This table logs the audit trail of the deletion execution.
-- KPIs: Verification Success Rate, Deletion Latency, Verification Failures, Audit Trail Completeness.
-- Feature Reference: M18-T065 (Consent Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_subject_rights_audit (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dsar_id UUID NOT NULL, -- Ref T246

    -- Verification
    verified_by UUID NOT NULL,
    verification_method VARCHAR(50) NOT NULL, -- 'Automated', 'ManualSpotCheck', 'UserConfirmation'
    result VARCHAR(20) NOT NULL, -- 'Verified', 'NotDeleted', 'PartiallyDeleted'

    evidence_screenshot_url TEXT,
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dsar_id) REFERENCES cmmi.data_subject_requests(dsar_id),
    FOREIGN KEY (verified_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.data_subject_rights_audit IS 'Audits the execution of data subject rights requests (Right to be Forgotten).';

-- =====================================================================================================================
-- Table: M18-T528 - consent_withdrawal_logs
-- Description: GDPR specific.
-- Business Case: Privacy Preference Management. Users withdrawing consent must be respected immediately.
--                 This table logs every withdrawal event to ensure processing stops.
-- KPIs: Withdrawal Processing Time, Withdrawal Success Rate, Withdrawal Volume, Compliance Rate.
-- Feature Reference: M18-T247 (Consent Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.consent_withdrawal_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    consent_point VARCHAR(100) NOT NULL,

    -- Event
    withdrawn_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,

    -- Verification
    processing_status VARCHAR(20) NOT NULL, -- 'Pending', 'Success', 'Failed'
    error_message TEXT,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.consent_withdrawal_logs IS 'Detailed logs of consent withdrawal events.';

-- =====================================================================================================================
-- Table: M18-T529 - data_processing_agreements
-- Description: DPA records.
-- Business Case: Legal binding. Data Processing Agreements (DPAs) are required by GDPR. This table stores the DPA
--                 contracts for personal data processing, specifying purpose and scope.
-- KPIs: DPA Coverage %, DPA Signature Status, DPA Renewal Rate, Scope Adherence Violation.
-- Feature Reference: M18-T244 (Data Classification)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_processing_agreements (
    dpa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Parties
    data_controller VARCHAR(100) NOT NULL, -- PARI
    data_processor VARCHAR(100) NOT NULL, -- Vendor

    -- Details
    purpose_description TEXT NOT NULL,
    data_categories TEXT[], -- 'Financial', 'PaymentLogs', 'PAN'

    -- Lifecycle
    start_date DATE NOT NULL,
    end_date DATE,

    document_url TEXT,

    signed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    signed_by UUID
);

COMMENT ON TABLE cmmi.data_processing_agreements IS 'Stores Data Processing Agreements (DPA) for GDPR compliance.';

-- =====================================================================================================================
-- Table: M18-T530 - data_export_logs
-- Description: Data leaving the system.
-- Business Case: Data Leakage Prevention. Not all data movement is internal. This table logs every data export
--                 (e.g., CSV download, API transfer to 3rd party) to ensure auditability.
-- KPIs: Export Authorization Rate, Export Volume, Failed Export Attempts, Encryption of Export.
-- Feature Reference: M18-T244 (Data Classification)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.data_export_logs (
    export_id UUID DEFAULT uuid_export_generate_v4() PRIMARY KEY,

    -- Details
    exported_by UUID NOT NULL,
    export_type VARCHAR(50) NOT NULL, -- 'UserDownload', 'Backup', 'API'
    record_count INTEGER,

    -- Destination
    destination_system VARCHAR(100) NOT NULL,

    -- Authorization
    authorization_ticket_id VARCHAR(100), -- Jira/ServiceNow ticket

    -- Integrity
    checksum_hash CHAR(64),

    exported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (exported_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.data_export_logs IS 'Audits data exports to track data egress.';

-- =====================================================================================================================
-- Table: M18-T531 - third_party_data_sharing_logs
-- Description: Sharing data with partners.
-- Business Case: Data Sharing Governance. Sharing PII or transaction data with partners (Banks, Tax Auth) must be tracked.
--                 This table records the handshake and data transferred.
-- KPIs: Data Volume Shared, Sharing Agreement Violation Count, Encryption Key Rotation, Partner Compliance.
-- Feature Reference: M18-T244 (Data Classification)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.third_party_data_sharing_logs (
    share_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Parties
    partner_name VARCHAR(100) NOT NULL,
    shared_data_category VARCHAR(100) NOT NULL,

    -- Transaction
    transaction_ref_id VARCHAR(100),
    data_volume_gb NUMERIC(10, 2),

    -- Governance
    dpa_reference_id UUID, -- Ref T529
    encryption_method VARCHAR(50), -- 'TLS', 'PGP'

    shared_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (dpa_reference_id) REFERENCES cmmi.data_processing_agreements(dpa_id)
);

COMMENT ON cmmi.third_party_data_sharing_logs IS 'Logs the sharing of data with third parties under DPAs.';

-- =====================================================================================================================
-- Table: M18-T532 - data_lineage_break
-- Description: When lineage is broken.
-- Business Case: Debugging Data Pipelines. Sometimes the chain of transformation (T470) breaks (e.g.,
--                 source code changes but logic doesn't). This table logs "lineage breaks" for investigation.
-- KPIs: Lineage Break Count, Time to Repair Lineage, Root Cause Category, Data Source Refresh Rate.
-- Feature Reference: M18-T470 (Data Lineage)
-- =================================================================================================================----
CREATE TABLE IF NOT EXISTS cmmi.data_lineage_break (
    break_id UUID DEFAULT uuid_receive_v4() PRIMARY KEY,
    lineage_id UUID NOT NULL, -- Ref T470

    -- The Break
    break_detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    detected_by UUID,

    -- Analysis
    root_cause_category VARCHAR(50), -- 'CodeChange', 'SourceDataChange', 'SchemaDrift'
    impact_analysis TEXT,

    -- Resolution
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Resolved', 'Workaround'

    FOREIGN KEY (detected_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.data_lineage_break IS 'Logs breaks in data lineage traceability.';

-- =====================================================================================================================
-- Table: M18-T533 - schema_evolution_history
-- Description: Evolution of DB schemas.
-- Business Case: Technical Debt & Migration. Database schemas change (migrations). This table tracks the evolution
--                 of table structures, ensuring compatibility between code and DB.
-- KPIs: Schema Version Count, Breaking Change Count, Migration Success Rate, Backward Compatibility Score.
-- Feature Reference: M18-T042 (SQL Performance)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.schema_evolution_history (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    schema_name VARCHAR(100) NOT NULL,
    object_type VARCHAR(50) NOT NULL, -- 'Table', 'View', 'Function'
    object_name VARCHAR(255) NOT NULL,

    -- Change
    change_description TEXT NOT NULL,
    script_snippet TEXT,

    -- Lifecycle
    changed_by UUID NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (changed_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.schema_evolution_history IS 'Tracks the evolution of database object schemas.';

-- =====================================================================================================================
-- Table: M18-T534 - tenant_isolation_policies
-- Description: Config for multi-tenancy.
-- Business Case: Data Privacy. In a multi-tenant platform (SaaS), strict isolation is required. This table defines
--                 policies for tenant isolation (DB schemas, queues, buckets).
-- KPIs: Isolation Violation Count, Cross-Tenant Leakage, Policy Enforcement Rate, Tenant Onboarding Time.
-- Feature Reference: M18-T167 (Users)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.tenant_isolation_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PREMARY KEY,
    tenant_id UUID, -- NULL implies 'Global Default'

    -- Rules
    resource_type VARCHAR(50) NOT NULL, -- 'Database', 'Queue', 'S3Bucket', 'Topic'
    isolation_mode VARCHAR(50) NOT NULL, -- 'DedicatedSchema', 'Prefixing', 'TagBased'

    -- Constraints
    enforce_at_network_level BOOLEAN DEFAULT false, -- AWS VPCs
    enforce_at_application_level BOOLEAN DEFAULT true, -- App logic
    allow_cross_tenant_querying BOOLEAN DEFAULT false, -- Risky

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (tenant_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON cmmi.tenant_isolation_policies IS 'Defines strictness of tenant isolation configurations.';

-- =====================================================================================================================
-- Table: M18-T535 - data_retention_legal_hold
-- Description: Legal hold on deleting data.
-- Business Case: Litigation Hold. Data usually has a retention policy (e.g., 7 years). But if a lawsuit is filed,
--                 data must be kept longer (Legal Hold). This table tracks data that cannot be deleted due to legal requirements.
-- KPIs: Legal Hold Volume, Hold Duration, Hold Release Date, Compliance Violation Risk.
-- Feature Reference: M18-T236 (Data Retention Schedules)
-- =================================================================================================================----
CREATE TABLE IF NOT EXISTS cmmi.data_retention_legal_hold (
    hold_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    data_description TEXT,
    data_classifications TEXT[], -- ['PII', 'Financial', 'AuditLogs']

    -- Constraints
    hold_reason TEXT NOT NULL, -- 'Litigation', 'Audit', 'RegulatoryInvestigation'
    expiry_date DATE,

    -- Status
    released BOOLEAN DEFAULT false,
    released_at TIMESTAMP WITH TIME ZONE,

    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.data_retention_legal_hold IS 'Tracks data retention exceptions due to legal holds.';

-- =================================================================================================================----
-- Table: M18-T536 - anonymization_records
-- Description: Records of data anonymization.
-- Business Case: Privacy Compliance. Testing or Analytics must often use anonymized data. This table records
--                 anonymization events (what was masked) for reproducibility.
-- KPIs: Anonymization Quality, Anonymization Volume, Re-identification Risk, Processing Latency.
-- Feature Reference: M18-T537 (Pseudonymization Mappings)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.anonymization_records (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Scope
    source_data_type VARCHAR(100) NOT NULL, -- 'Logs', 'Database'
    batch_id VARCHAR(255),

    -- Method
    anonymization_technique VARCHAR(50), -- 'Hashing', 'Tokenization', 'Masking'
    reversibility BOOLEAN DEFAULT false,

    -- Details
    records_affected INTEGER,
    quality_score NUMERIC(3, 2), -- How anonymized is it?

    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.anonymization_records IS 'Records details of data anonymization processes.';

-- =====================================================================================================================
-- Table: M18-T537 - pseudonymization_mappings
-- Description: Maps between fake and real IDs.
-- Security Note: This table contains sensitive (real) IDs. Access must be highly restricted.
-- Business Case: Audit Trail. To validate that an anonymized dataset is accurate, we need to map fake IDs back to
--                 real IDs securely. This table stores these secure mappings.
-- KPIs: Mapping Accuracy, Encryption Strength, Access Log Volume, Key Rotation Frequency, Mapping Table Growth.
-- Feature Reference: M18-T536 (Anonymization Records)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.pseudonymization_mappings (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- The Key
    pseudonym_uuid CHAR(36) NOT NULL,
    original_value_hash CHAR(64) NOT NULL,
    original_data_type VARCHAR(50) NOT NULL,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.pseudonymization_mappings is 'Securely maps pseudonyms to real values for audit purposes.';

-- =====================================================================================================================
-- Table: M18-T538 - secure_data_disposal
-- Description: Destroying media.
-- Business Case: Data Disposal. Deleting HDDs or backups securely is critical to prevent data recovery.
--                 This table logs the physical disposal or cryptographic erasure of media assets.
-- KPIs: Disposal Success Rate, Certificates of Destruction, Chain of Custody, Disposal Cost.
-- Feature Reference: M18-T183 (Assets)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.secure_data_disposal (
    disposal_id UUID DEFAULT uuid_entity_v4() PRIMARY KEY,

    -- Asset
    asset_type VARCHAR(50) NOT NULL, -- 'BackupDrive', 'Server', 'Laptop'
    asset_reference_id VARCHAR(255) NOT NULL,

    -- Details
    disposal_method VARCHAR(50) NOT NULL, -- 'PhysicalDestruction', 'Cryptowipe', 'Degaussing'

    -- Actors
    disposed_by UUID NOT NULL,
    witness_1_id UUID,
    witness_2_id UUID,

    disposal_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    certificate_url TEXT, -- Proof of disposal

    FOREIGN KEY (disposed_by) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (witness_1_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (witness_2_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON cmmi.secure_data_disposal IS 'Tracks the secure disposal of data-bearing media assets.';

-- =====================================================================================================================
-- Table: M18-T539 - communication_preferences
-- Description: User notification settings.
-- Business Case: User Experience. Some users want emails, some Slack, some SMS. This table stores preferences
--                 to route notifications (T252) effectively.
-- KPIs: Notification Readiness %, Click-Through Rate, Channel Preference Change Frequency, Unsubscribe Rate.
-- Feature Reference: M18-T252 (Communication Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.communication_preferences (
    pref_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Channels
    email_enabled BOOLEAN DEFAULT true,
    sms_enabled BOOLEAN DEFAULT false,
    slack_enabled BOOLEAN DEFAULT true,
    push_enabled BOOLEAN DEFAULT true,

    -- Frequency/Digests
    digest_frequency VARCHAR(50) DEFAULT 'RealTime', -- 'RealTime', 'Daily', 'Weekly'
    quiet_hours_start TIME,
    quiet_hours_end TIME,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON cmmi.communication_preferences IS 'Stores user preferences for notification channels and digests.';

-- =====================================================================================================================
-- Table: M18-T540 - notification_digests
-- Description: Aggregated notifications (Daily vs Real-time).
-- Business Case: Alert Fatigue Prevention. Too many alerts causes users to ignore them. This table aggregates alerts
--                 into digests (Hourly/Daily summaries) to reduce noise and improve alert signal-to-noise ratio.
-- KPIs: Digest Deliverability, Digest Read Rate, Notification Volume Reduction, User Engagement with Digests.
-- Feature Reference: M18-T155 (Notification Channels)
-- =================================================================================================================----
CREATE TABLE IF NOT EXISTS cmmi.notification_digests (
    digest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Schedule
    user_id UUID NOT NULL,
    digest_type VARCHAR(20) NOT NULL, -- 'Daily', 'Weekly'
    delivery_time TIME WITHOUT TIME ZONE,

    -- Generation
    generated_at TIMESTAMP WITH TIME ZASE ZONE DEFAULT CURRENT_TIMESTAMP,
    content_summary TEXT,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.notification_digests is 'Aggregates notifications into periodic digests to reduce noise.';

-- =====================================================================================================================
-- Table: M18-T541 - email_delivery_logs
-- Description: SMTP logs.
-- Business Case: Deliverability. Email is the primary notification channel. This table logs the delivery status
--                 (Sent, Bounced, Deferred) for debugging and reputation management.
-- KPIs: Delivery Success Rate, Bounce Rate, Blacklist Removal Rate, SMTP Provider Latency.
-- Feature Reference: M18-T542 (SMS Delivery Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.email_delivery_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    message_id UUID NOT NULL, -- Ref T252

    -- SMTP Details
    recipient_email VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'Sent', 'Bounced', 'Deferred'
    provider_response_code INTEGER, -- 250, 550, etc.

    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,

    error_message TEXT
);

COMMENT ON TABLE cmmi.email_delivery_logs IS 'Logs status and details of email deliveries.';

-- =================================================================================================================----
-- Table: M18-T542 - sms_delivery_logs
-- Description: Twilio/SNS logs.
-- Business Case: Critical Alerting. SMS is used for on-call alerts. This table logs SMS delivery status
--                 to ensure critical alerts reach the on-call engineer.
-- KPIs: Delivery Success Rate, Carrier Latency, Delivery Cost per Message, SMS Throughput.
-- Feature Reference: M18-T543 (Push Notification Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.sms_delivery_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    message_id UUID NOT NULL, -- Ref T252

    -- SMS Details
    recipient_number VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'Sent', 'Failed', 'Undeliverable'
    provider_response TEXT, -- API response

    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    cost_usd NUMERIC(10, 2),

    error_message TEXT
);

COMMENT ON TABLE cmmi.sms_delivery_logs is 'Logs delivery of SMS notifications.';

-- =====================================================================================================================
-- Table: M18-T543 - push_notification_logs
-- Description: Mobile push logs.
-- Business Case: User Engagement. Mobile push is key for user notifications. This table logs the delivery
--                 (Receipt ACK) of push notifications.
-- KPIs: Push Delivery Rate, Push Open Rate, Platform Reliability, Opt-Out Rate.
-- Feature Reference: M18-T540 (Communication Preferences)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.push_notification_logs (
    log_id UUID DEFAULT uuid_generate_v4() NOT NULL,

    device_id VARCHAR(255), -- Token ID
    platform VARCHAR(20), -- 'APNS', 'FCM'

    status VARCHAR(20) NOT NULL, -- 'Sent', 'Expired', 'Failed'
    error_message TEXT,

    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    opened_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (log_id) REFERENCES cmmi.notification_digests(digest_id) -- Linking digest to logs for context
);

COMMENT ON TABLE cmmi.push_notification_logs is 'Logs the delivery status of mobile push notifications.';

-- =====================================================================================================================
-- Table: M18-T544 - in_app_notification_center
-- Description: UI notifications.
-- Business Case: User Experience. Instead of email/Slack, users see toasts in the UI. This table tracks these
--                 in-app notifications and user interactions.
-- KPIs: In-App Read Rate, Dismissal Rate, Notification Response Time, UI Alert Performance.
-- Feature Reference: M18-T545 (System Announcement Read Receipts)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.in_app_notification_center (
    notification_id UUID DEFAULT uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Notification
    title VARCHAR(255) NOT NULL,
    body TEXT,
    priority VARCHAR(20), -- 'Critical', 'Info', 'Warning'

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP WITH TIME ZONE,
    dismissed_at TIMESTAMP WITH TIME ZONE,

    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.in_app_notification_center IS 'Manages in-app user notifications.';

-- =====================================================================================================================
-- Table: M18-T545 - system_announcement_read_receipts
-- Description: Who read the announcements.
-- Business Case: Compliance. If an outage is announced, PARI must prove everyone read it. This table tracks read
--                 receipts for announcements (T350).
-- KPIs: Read Percentage, Read Recency, Target Read Receipt Achievement.
-- Feature Reference: M18-T350 (System Announcements)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.system_announcement_read_receipts (
    receipt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    announcement_id UUID NOT NULL, -- Ref T350
    user_id UUID NOT NULL,

    read_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (announcement_id) REFERENCES cmmi.system_announcements(announcement_id),
    FOREIGN KEY (user_id) REFS cmmi.system_announcements ON (announcement_id)
);

COMMENT ON TABLE cmmi.system_announcement_read_receipts IS 'Tracks read receipts for system announcements to ensure compliance.';

-- =====================================================================================================================
-- Table: M18-T546 - knowledge_base_feedback_loops
-- Description: Closing the loop on KB articles.
-- Business Case: Knowledge Management. KB articles get outdated. This table manages the workflow where users flag an article as
--                 inaccurate or confusing, triggering a review and update loop.
-- KPIs: Feedback Submission Rate, Article Update Latency, Feedback Impact on Quality, User Participation.
-- Feature Reference: M18-T272 (KB Feedback)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.knowledge_base_feedback_loops (
    loop_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    article_id UUID NOT NULL,

    -- Feedback
    user_id UUID,
    feedback_type VARCHAR(50) NOT NULL, -- 'Inaccurate', 'Confusing', 'Outdated'
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    comments TEXT,

    -- Outcome
    status VARCHAR(20) DEFAULT 'Open', -- 'Open', 'Resolved', 'Rejected'
    resolved_by UUID,
    resolved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (article_id) REFERENCES cmmi.knowledge_base(article_id),
    FOREIGN KEY (user_id) REFERENCES cmmi.users(user_id),
    FOREIGN KEY (resolved_by) REFERENCES cmmi.users(user_id)
);

CREATE TRIGGER trigger_update_knowledge_base_feedback_loops
    BEFORE UPDATE ON cmmi.knowledge_base_feedback_loops
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

COMMENT ON TABLE cmmi.knowledge_base_feedback_loops IS 'Manages user feedback to drive continuous improvement of the knowledge base.';

-- =====================================================================================================================
-- Table: M18-T547 - knowledge_base_edit_history
-- Description: Who edited what KB article.
-- Business Case: Content Integrity. Seeing the edit history of a KB article helps identify "Who broke it?".
--                 This table tracks versioning of KB articles.
-- KPIs: Edit Volume, Editor Contribution, Revision History Depth, Rollback Frequency, Edit Accuracy.
-- Feature Reference: M18-T272 (Knowledge Base)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.knowledge_base_edit_history (
    history_id UUID DEFAULT uuid_on_epoch_gen_from_timestamps(now()) DEFAULT uuid_generate_v4() PRIMARY KEY,
    article_id UUID NOT NULL,

    -- Edit
    editor_id UUID NOT NULL,
    change_description TEXT,

    -- Version
    article_version INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (article_id) REFERENCES cmmi.knowledge_base(article_id),
    FOREIGN KEY (editor_id) REFERENCES cmmi.users(user_id)
);

COMMENT ON TABLE cmmi.knowledge_base_edit_history IS 'Tracks versioning and history of knowledge base articles.';

-- =====================================================================================================================
-- Table: M18-T548 - search_query_logs
-- Description: What users are searching for.
-- Business Case: Product Insight. Analyzing user searches (T549) reveals "Knowledge Gaps" where docs are missing.
--                 This table logs search queries to guide content creation.
-- KPIs: Search Result Rate, Zero-Result Rate, Search Latency, Top Search Terms, Content Gaps Identified.
-- Feature Reference: M18-T272 (Knowledge Base)
-- =================================================================================================================----
CREATE TABLE IF NOT EXISTS cmmi.search_query_logs (
    search_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Query
    search_term VARCHAR(255),
    filters_applied JSONB,

    -- Results
    results_count INTEGER NOT NULL, -- 0 implies No Results
    clicked_result_id UUID, -- Ref KB Article ID
    search_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) FAILED (SELECT 1 FROM cmmi.users WHERE user_id IS NULL), -- If system searches
    FOREIGN KEY (clicked_result_id) REFERENCES cmmi.knowledge_base(article_id)
);

COMMENT ON TABLE cmmi.search_query_logs IS 'Logs user search queries to identify knowledge gaps.';

-- =====================================================================================================================
-- Table: M18-T549 - failed_search_analytics
-- Description: No results found.
-- Summary of searches that returned 0 results. This table aggregates these failed searches to identify terms that need content creation.
-- Business Case: Product Insight.
-- KPIs: Top Zero-Result Terms, "Zero Result" Frequency %, Content Creation Trigger.
-- Feature Reference: M18-T548 (Search Query Logs)
-- =====================================================================================================================
CREATE TABLE IF NOT EXISTS cmmi.failed_search_analytics (
    analytics_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    search_term VARCHAR(255) NOT NULL,
    failure_count BIGINT NOT NULL,
    last_failed_at TIMESTAMP WITH TIME NOT NULL,

    suggested_action VARCHAR(50) DEFAULT 'Ignore', -- 'Ignore', 'CreateDoc', 'Investigate'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE cmmi.failed_search_analytics IS 'Analyzes search queries that return no results to highlight content gaps.';


-- =====================================================================================================================
-- Triggers for Part 8 (T451-T550)
-- =====================================================================================================================
CREATE TRIGGER trigger_update_compliance_framework_signing
    BEFORE UPDATE ON cmmi.compliance_framework_signing
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_governance_policy_versions
    BEFORE UPDATE ON cmmi.governance_policy_versions
    FOR EACH ROW EXECUTE FUNCTION cmmal.update_modified_column();

CREATE TRIGGER trigger_update_learning_path_progress
    BEFORE UPDATE ON cmmi.learning_path_progress
    FOR EACH ROW EXECUTE FUNCTION cmmi.update_modified_column();

CREATE TRIGGER trigger_update_ml_experiments
    BEFORE UPDATE ON cmmi.ml_experiments
    FOR EACH ROW EXECUTE FUNCTION cmmial.update_modified_column();

CREATE TRIGGER update_system_message_queue
    BEFORE UPDATE ON cmmi.system_message_queue
    FOR EACH ROW EXECUTE FUNCTION cmmial.update_modified_column();

CREATE TRIGGER trigger_update_subscription_management
    UPDATE ON cmmi.subscription_management
    FOR EACH ROW EXECUTE FUNCTION cmmial.update_modified_column();

CREATE TRIGGER trigger_update_dispute_records
    BEFORE UPDATE ON cmmi.billing_dispute_records
    FOR EACH ROW EXECUTE cmmial.update_modified_column();

CREATE TRIGGER trigger_update_compliance_document_storage
    UPDATE ON cmmi.compliance_document_storage
    FOR EACH ROW EXECUTE FUNCTION cmmial.update_modified_column();

CREATE TRIGGER trigger_update_pseudonymization_mappings
    UPDATE ON cmmi.pseudonymization_mappings
    FOR EACH ROW EXECUTE FUNCTION cmmial.update_modified_column();

-- =====================================================================================================================
-- End of Script Segment (Tables 451-550)
-- =====================================================================================================================
